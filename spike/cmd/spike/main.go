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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-global-types Spike ../../bpf/probes.bpf.c -- -I../../bpf

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
	flag.Parse()

	if err := run(*duration, *outPath); err != nil {
		log.Fatalf("spike: %v", err)
	}
}

func run(duration time.Duration, outPath string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	objs := SpikeObjects{}
	if err := LoadSpikeObjects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects (this is the CP-0.1 answer if it fails): %w", err)
	}
	defer objs.Close()

	execTp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attach exec tracepoint: %w", err)
	}
	defer execTp.Close()

	openTp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		return fmt.Errorf("attach openat tracepoint: %w", err)
	}
	defer openTp.Close()

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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("open ring buffer reader: %w", err)
	}
	defer rd.Close()

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)

	// Signal readiness to whatever is generating traffic for us to
	// observe. Attaching four probes takes real wall-clock time — a
	// caller that fires traffic immediately after backgrounding this
	// process races it and loses (this bit us on the exec-only version).
	readyPath := outPath + ".ready"
	if err := os.WriteFile(readyPath, []byte("ready\n"), 0o644); err != nil {
		return fmt.Errorf("write readiness marker: %w", err)
	}
	defer os.Remove(readyPath)

	log.Printf("attached; capturing exec/open/connect events for %s", duration)

	deadline := time.AfterFunc(duration, func() { rd.Close() })
	defer deadline.Stop()

	// pid -> path that made it tainted. Deliberately exact-PID only, no
	// ancestor walk (ARCHITECTURE.md's real taint graph does that) — the
	// demo scenario has one process doing both the read and the send.
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
			writeRecord(enc, map[string]any{
				"type": "exec", "ts": now.UnixNano(),
				"pid": ev.PID, "ppid": ev.PPID, "comm": comm,
			})

		case evtOpen:
			counts.open++
			path := cString(ev.Path[:])
			writeRecord(enc, map[string]any{
				"type": "open", "ts": now.UnixNano(),
				"pid": ev.PID, "ppid": ev.PPID, "comm": comm, "path": path,
			})
			if strings.Contains(path, sensitivePathMarker) {
				tainted[ev.PID] = taintRecord{path: path, at: now}
			}

		case evtConnect:
			counts.connect++
			dest := net.IP(ev.Daddr[:]).String() + ":" + fmt.Sprint(binary.BigEndian.Uint16(ev.Dport[:]))
			writeRecord(enc, map[string]any{
				"type": "connect", "ts": now.UnixNano(),
				"pid": ev.PID, "ppid": ev.PPID, "comm": comm, "dest": dest,
			})
			if t, ok := tainted[ev.PID]; ok {
				counts.taintedEgress++
				elapsedMS := now.Sub(t.at).Milliseconds()
				log.Printf("TAINTED_EGRESS: pid=%d (%s) read %q then connected to %s after %dms",
					ev.PID, comm, t.path, dest, elapsedMS)
				writeRecord(enc, map[string]any{
					"type": "TAINTED_EGRESS", "ts": now.UnixNano(),
					"pid": ev.PID, "comm": comm, "path": t.path,
					"dest": dest, "elapsed_ms": elapsedMS,
				})
			}
		}
	}

	log.Printf("done: %d exec, %d open, %d connect, %d TAINTED_EGRESS — written to %s",
		counts.exec, counts.open, counts.connect, counts.taintedEgress, outPath)
	return nil
}

type taintRecord struct {
	path string
	at   time.Time
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
