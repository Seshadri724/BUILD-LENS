// Phase 0 spike (M0.1, M0.3, M0.4). Answers exactly one question per
// ROADMAP.md CP-0.1: does this load and emit real events on a
// GitHub-hosted runner? Nothing about this file survives into Phase 1 —
// it is deliberately not production code.
//
// Usage: sudo ./spike -duration 30s -out events.jsonl
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-global-types Spike ../../bpf/exec.bpf.c -- -I../../bpf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type execEvent struct {
	PID  uint32   `json:"pid"`
	PPID uint32   `json:"ppid"`
	Comm [16]byte `json:"-"`
}

type outputRecord struct {
	TS   int64  `json:"ts"`
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
}

func main() {
	duration := flag.Duration("duration", 30*time.Second, "how long to capture events")
	outPath := flag.String("out", "events.jsonl", "where to write captured events, one JSON object per line")
	flag.Parse()

	if err := run(*duration, *outPath); err != nil {
		log.Fatalf("spike: %v", err)
	}
}

func run(duration time.Duration, outPath string) error {
	// Older kernels need the memlock rlimit removed before loading any BPF
	// object. Harmless no-op on kernels that don't need it.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	objs := SpikeObjects{}
	if err := LoadSpikeObjects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects (this is the CP-0.1 answer if it fails): %w", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint: %w", err)
	}
	defer tp.Close()

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

	log.Printf("attached; capturing exec events for %s", duration)

	deadline := time.AfterFunc(duration, func() { rd.Close() })
	defer deadline.Stop()

	var count int
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		var ev execEvent
		if err := parseEvent(record.RawSample, &ev); err != nil {
			log.Printf("skip malformed event: %v", err)
			continue
		}

		count++
		rec := outputRecord{
			TS:   time.Now().UnixNano(),
			PID:  ev.PID,
			PPID: ev.PPID,
			Comm: cString(ev.Comm[:]),
		}
		if err := enc.Encode(rec); err != nil {
			log.Printf("write event: %v", err)
		}
	}

	log.Printf("done: %d exec events captured, written to %s", count, outPath)
	return nil
}

func parseEvent(raw []byte, ev *execEvent) error {
	return binary.Read(bytes.NewReader(raw), binary.LittleEndian, ev)
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
