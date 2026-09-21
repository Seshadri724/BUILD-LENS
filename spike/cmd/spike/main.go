//go:build linux

// Phase 0 spike (M0.1, M0.3, M0.4, M0.5). Answers two questions per
// ROADMAP.md: does this load and emit real events on a GitHub-hosted
// runner (CP-0.1), and is the read-then-egress correlation actually
// visible in raw events (CP-0.3's detection-proof evidence, M0.5).
// Nothing about this file survives into Phase 1 — it is deliberately
// not production code: no kernel-side path filtering, no ancestor-walk
// taint propagation, no DNS/SNI, just enough to answer the question.
//
// Usage: sudo ./spike -duration 30s -out events.jsonl
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -no-global-types Spike ../../bpf/probes.bpf.c -- -I../../bpf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	evtExec    = 1
	evtOpen    = 2
	evtConnect = 3
)

// Matches spike/bpf/probes.bpf.c's packed struct event exactly, field for
// field. encoding/binary decodes struct fields in declaration order with
// no inserted padding, so as long as the C side is __attribute__((packed))
// too, the two layouts agree without guessing at compiler alignment rules.
type rawEvent struct {
	Kind  uint8
	PID   uint32
	PPID  uint32
	Comm  [16]byte
	Path  [128]byte
	Daddr [4]byte
	Dport [2]byte
}

// What a sensitive-file read looks like for the duration of one capture
// window — deliberately just a substring match on ".env". Phase 1's real
// sensitivity policy (PRD.md FR-3) is a configurable glob set; this is
// only meant to prove the mechanism.
const sensitivePathMarker = ".env"

func main() {
	duration := flag.Duration("duration", 30*time.Second, "how long to capture events")
	outPath := flag.String("out", "events.jsonl", "where to write captured events, one JSON object per line")
	probes := flag.String("probes", "all", "probes to attach: all, exec, open, connect")
	noJSON := flag.Bool("no-json", false, "read ring buffer but disable writing JSON to disk")
	debug := flag.Bool("debug", false, "write raw events; if false, only writes detections and evidence")
	statsOut := flag.String("stats-out", "", "optional path to write telemetry JSON stats")
	flag.Parse()

	if err := run(*duration, *outPath, *probes, *noJSON, *debug, *statsOut); err != nil {
		log.Fatalf("spike: %v", err)
	}
}

func run(duration time.Duration, outPath string, probes string, noJSON bool, debug bool, statsOut string) error {
	startTime := time.Now()
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	objs := SpikeObjects{}
	if err := LoadSpikeObjects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects (this is the CP-0.1 answer if it fails): %w", err)
	}
	defer objs.Close()

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
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ring buffer reader: %w", err)
	}
	defer rd.Close()

	var enc *json.Encoder
	var outFile *os.File
	if !noJSON {
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		outFile = f
		enc = json.NewEncoder(f)
	}

	// Signal readiness to whatever is generating traffic for us to observe.
	readyPath := outPath + ".ready"
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o644); err != nil {
		return fmt.Errorf("write readiness marker: %w", err)
	}
	defer os.Remove(readyPath)

	log.Printf("attached [%s]; capturing events for %s (no_json=%v, debug=%v)", probes, duration, noJSON, debug)

	deadline := time.AfterFunc(duration, func() { rd.Close() })
	defer deadline.Stop()

	tainted := map[uint32]taintRecord{}
	var counts struct{ exec, open, connect, taintedEgress int }

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		var ev rawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("skip malformed event: %v", err)
			continue
		}

		now := time.Now()
		comm := cString(ev.Comm[:])

		switch ev.Kind {
		case evtExec:
			counts.exec++
			if debug && enc != nil {
				writeRecord(enc, map[string]any{
					"type": "exec", "ts": now.UnixNano(),
					"pid": ev.PID, "ppid": ev.PPID, "comm": comm,
				})
			}

		case evtOpen:
			counts.open++
			path := cString(ev.Path[:])
			if debug && enc != nil {
				writeRecord(enc, map[string]any{
					"type": "open", "ts": now.UnixNano(),
					"pid": ev.PID, "ppid": ev.PPID, "comm": comm, "path": path,
				})
			}
			if strings.Contains(path, sensitivePathMarker) {
				tainted[ev.PID] = taintRecord{path: path, at: now, comm: comm, ppid: ev.PPID}
			}

		case evtConnect:
			counts.connect++
			dest := net.IP(ev.Daddr[:]).String() + ":" + fmt.Sprint(binary.BigEndian.Uint16(ev.Dport[:]))
			if debug && enc != nil {
				writeRecord(enc, map[string]any{
					"type": "connect", "ts": now.UnixNano(),
					"pid": ev.PID, "ppid": ev.PPID, "comm": comm, "dest": dest,
				})
			}
			if t, ok := tainted[ev.PID]; ok {
				counts.taintedEgress++
				elapsedMS := now.Sub(t.at).Milliseconds()
				log.Printf("TAINTED_EGRESS: pid=%d (%s) read %q then connected to %s after %dms",
					ev.PID, comm, t.path, dest, elapsedMS)
				if enc != nil {
					// In normal mode, ensure evidence open + connect + TAINTED_EGRESS are recorded
					if !debug {
						writeRecord(enc, map[string]any{
							"type": "open", "ts": t.at.UnixNano(),
							"pid": ev.PID, "ppid": t.ppid, "comm": t.comm, "path": t.path,
						})
						writeRecord(enc, map[string]any{
							"type": "connect", "ts": now.UnixNano(),
							"pid": ev.PID, "ppid": ev.PPID, "comm": comm, "dest": dest,
						})
					}
					writeRecord(enc, map[string]any{
						"type": "TAINTED_EGRESS", "ts": now.UnixNano(),
						"pid": ev.PID, "comm": comm, "path": t.path,
						"dest": dest, "elapsed_ms": elapsedMS,
					})
				}
			}
		}
	}

	var ringBufferDrops uint64
	if objs.DropStats != nil {
		var key uint32 = 0
		_ = objs.DropStats.Lookup(&key, &ringBufferDrops)
	}

	var fileSize int64
	if outFile != nil {
		if fi, err := outFile.Stat(); err == nil {
			fileSize = fi.Size()
		}
	}

	totalEvents := counts.exec + counts.open + counts.connect
	elapsedTotal := time.Since(startTime)
	log.Printf("done: %d exec, %d open, %d connect, %d TAINTED_EGRESS (drops=%d, file_size=%d bytes) in %s",
		counts.exec, counts.open, counts.connect, counts.taintedEgress, ringBufferDrops, fileSize, elapsedTotal)

	if statsOut != "" {
		st := map[string]any{
			"runtime_ms":        elapsedTotal.Milliseconds(),
			"events_total":      totalEvents,
			"ring_buffer_drops": ringBufferDrops,
			"file_size_bytes":   fileSize,
			"counts": map[string]int{
				"exec":           counts.exec,
				"open":           counts.open,
				"connect":        counts.connect,
				"tainted_egress": counts.taintedEgress,
			},
		}
		if b, err := json.MarshalIndent(st, "", "  "); err == nil {
			_ = os.WriteFile(statsOut, b, 0o644)
		}
	}

	return nil
}

type taintRecord struct {
	path string
	at   time.Time
	comm string
	ppid uint32
}

func writeRecord(enc *json.Encoder, rec map[string]any) {
	if err := enc.Encode(rec); err != nil {
		log.Printf("write event: %v", err)
	}
}


func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
