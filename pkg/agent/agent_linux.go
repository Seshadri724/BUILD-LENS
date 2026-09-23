//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/buildlens/buildlens/pkg/runschema"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Record loads eBPF probes, attaches to kernel tracepoints, enriches events with
// procfs metadata (/proc/<pid>/cmdline, cwd), and streams to JSONL.
func Record(opts RecordOptions) error {
	startTime := time.Now()

	if dir := filepath.Dir(opts.OutPath); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}

	readyPath := opts.OutPath + ".ready"
	donePath := opts.OutPath + ".done"

	// Fail-open check: BTF must be present on Linux runner
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		log.Printf("BuildLens agent: /sys/kernel/btf/vmlinux missing — operating in fail-open mode")
		_ = os.WriteFile(readyPath, []byte("ready\n"), 0o644)
		defer os.Remove(readyPath)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		if opts.Duration > 0 {
			select {
			case <-sigCh:
			case <-time.After(opts.Duration):
			}
		} else {
			<-sigCh
		}
		_ = os.WriteFile(donePath, []byte("done\n"), 0o644)
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	objs := AgentObjects{}
	if err := LoadAgentObjects(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()

	probes := opts.Probes
	if probes == "" {
		probes = "all"
	}

	if probes == "all" || probes == "exec" {
		execTp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
		if err != nil {
			return fmt.Errorf("attach exec tracepoint: %w", err)
		}
		defer execTp.Close()
	}

	if probes == "all" || probes == "open" {
		openTp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
		if err != nil {
			return fmt.Errorf("attach openat tracepoint: %w", err)
		}
		defer openTp.Close()

		openExitTp, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.HandleOpenatExit, nil)
		if err != nil {
			return fmt.Errorf("attach openat exit tracepoint: %w", err)
		}
		defer openExitTp.Close()
	}

	if probes == "all" || probes == "connect" {
		connectEntry, err := link.Kprobe("tcp_v4_connect", objs.HandleTcpConnectEntry, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_v4_connect kprobe: %w", err)
		}
		defer connectEntry.Close()

		connectReturn, err := link.Kretprobe("tcp_v4_connect", objs.HandleTcpConnectReturn, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_v4_connect kretprobe: %w", err)
		}
		defer connectReturn.Close()

		connect6Entry, err := link.Kprobe("tcp_v6_connect", objs.HandleTcp6ConnectEntry, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_v6_connect kprobe: %w", err)
		}
		defer connect6Entry.Close()

		connect6Return, err := link.Kretprobe("tcp_v6_connect", objs.HandleTcp6ConnectReturn, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_v6_connect kretprobe: %w", err)
		}
		defer connect6Return.Close()
	}

	if probes == "all" || probes == "send" {
		sendEntry, err := link.Kprobe("tcp_sendmsg", objs.HandleTcpSendmsgEntry, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_sendmsg kprobe: %w", err)
		}
		defer sendEntry.Close()

		sendReturn, err := link.Kretprobe("tcp_sendmsg", objs.HandleTcpSendmsgReturn, nil)
		if err != nil {
			return fmt.Errorf("attach tcp_sendmsg kretprobe: %w", err)
		}
		defer sendReturn.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ring buffer reader: %w", err)
	}
	defer rd.Close()

	var enc *json.Encoder
	var outFile *os.File
	if !opts.NoJSON {
		f, err := os.Create(opts.OutPath)
		if err != nil {
			return fmt.Errorf("create events output file: %w", err)
		}
		defer f.Close()
		outFile = f
		enc = json.NewEncoder(f)
	}

	// Signal readiness to workflow steps
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o644); err != nil {
		return fmt.Errorf("write readiness marker: %w", err)
	}
	defer os.Remove(readyPath)

	log.Printf("BuildLens agent: probes attached [%s]; monitoring (out=%s, debug=%v)", probes, opts.OutPath, opts.Debug)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	doneReader := make(chan struct{})
	go func() {
		if opts.Duration > 0 {
			select {
			case <-sigCh:
			case <-time.After(opts.Duration):
			}
		} else {
			<-sigCh
		}
		_ = rd.Close()
		close(doneReader)
	}()

	var counts struct {
		exec, open, connect, send, dropped uint64
	}

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("ring buffer read error: %v", err)
			break
		}

		var ev rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			counts.dropped++
			continue
		}

		nowNano := time.Now().UnixNano()
		comm := cString(ev.Comm[:])

		switch ev.Kind {
		case evtExec:
			counts.exec++
			// Live process metadata enrichment via /proc
			cmdline := ReadProcessCmdline(ev.PID)
			cwd := ReadProcessCwd(ev.PID)

			e := runschema.Event{
				Kind:    "exec",
				TS:      nowNano,
				PID:     ev.PID,
				PPID:    ev.PPID,
				Comm:    comm,
				Cmdline: cmdline,
				Cwd:     cwd,
			}
			if opts.Debug {
				log.Printf("[debug] exec pid=%d ppid=%d comm=%s cmdline=%q cwd=%q", e.PID, e.PPID, e.Comm, e.Cmdline, e.Cwd)
			}
			if enc != nil {
				_ = enc.Encode(e)
			}

		case evtOpen:
			counts.open++
			path := cString(ev.Path[:])
			e := runschema.Event{
				Kind: "open",
				TS:   nowNano,
				PID:  ev.PID,
				PPID: ev.PPID,
				Comm: comm,
				Path: path,
			}
			if opts.Debug {
				log.Printf("[debug] open pid=%d comm=%s path=%q", e.PID, e.Comm, e.Path)
			}
			if enc != nil {
				_ = enc.Encode(e)
			}

		case evtConnect:
			counts.connect++
			dest := formatDest(ev.Family, ev.Daddr, ev.Dport)
			e := runschema.Event{
				Kind: "connect",
				TS:   nowNano,
				PID:  ev.PID,
				PPID: ev.PPID,
				Comm: comm,
				Dest: dest,
			}
			if opts.Debug {
				log.Printf("[debug] connect pid=%d comm=%s dest=%s", e.PID, e.Comm, e.Dest)
			}
			if enc != nil {
				_ = enc.Encode(e)
			}
		}
	}

	<-doneReader

	// Per-(pid, destination) byte totals, emitted once at shutdown.
	if probes == "all" || probes == "send" {
		var k flowKey
		var sent uint64
		nowNano := time.Now().UnixNano()
		iter := objs.SendBytes.Iterate()
		for iter.Next(&k, &sent) {
			counts.send++
			e := runschema.Event{
				Kind:      "send",
				TS:        nowNano,
				PID:       k.PID,
				Dest:      formatDest(k.Family, k.Daddr, k.Dport),
				BytesSent: sent,
			}
			if opts.Debug {
				log.Printf("[debug] send pid=%d dest=%s bytes=%d", e.PID, e.Dest, e.BytesSent)
			}
			if enc != nil {
				_ = enc.Encode(e)
			}
		}
		if err := iter.Err(); err != nil {
			log.Printf("send_bytes map iteration error: %v", err)
		}
	}

	var ringBufferDrops uint64
	if objs.DropStats != nil {
		var key uint32 = 0
		_ = objs.DropStats.Lookup(&key, &ringBufferDrops)
	}

	var fileSize int64
	if outFile != nil {
		_ = outFile.Sync()
		if fi, err := outFile.Stat(); err == nil {
			fileSize = fi.Size()
		}
	}

	elapsed := time.Since(startTime)
	log.Printf("BuildLens agent: finished in %s. Events: %d exec, %d open, %d connect, %d send flows (drops: %d)",
		elapsed, counts.exec, counts.open, counts.connect, counts.send, ringBufferDrops)

	// Write shutdown marker
	_ = os.WriteFile(donePath, []byte("done\n"), 0o644)

	if opts.StatsOut != "" {
		cpuTime, _ := ReadProcessCPUTimeMs(os.Getpid())
		st := AgentStats{
			RuntimeMS:       elapsed.Milliseconds(),
			EventsTotal:     int(counts.exec + counts.open + counts.connect + counts.send),
			RingBufferDrops: ringBufferDrops,
			FileSize:        fileSize,
			AgentCPUTimeMS:  cpuTime,
			Counts: map[string]int{
				"exec":    int(counts.exec),
				"open":    int(counts.open),
				"connect": int(counts.connect),
				"send":    int(counts.send),
			},
		}
		if b, err := json.MarshalIndent(st, "", "  "); err == nil {
			_ = os.WriteFile(opts.StatsOut, b, 0o644)
		}
	}

	return nil
}

const afInet6 = 10

func formatDest(family uint8, daddr [16]byte, dport [2]byte) string {
	ip := net.IP(daddr[:4])
	if family == afInet6 {
		ip = net.IP(daddr[:])
	}
	return net.JoinHostPort(ip.String(), fmt.Sprint(binary.BigEndian.Uint16(dport[:])))
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
