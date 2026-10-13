//go:build linux

package agent

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -no-global-types Enforce bpf/enforce.bpf.c -- -Ibpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/buildlens/buildlens/pkg/runschema"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const evtWouldBlock = 4

// rawEnforceEvent mirrors struct enforce_event in bpf/enforce.bpf.c. The C
// side is packed and encoding/binary reads fields sequentially without
// alignment padding, so field ORDER and SIZES must match exactly — never add,
// remove, or reorder a field on one side only.
type rawEnforceEvent struct {
	Kind   uint8
	PID    uint32
	PPID   uint32
	Comm   [16]byte
	Daddr  [16]byte
	Family uint8
}

// enforceHandle is one attached audit hook plus its objects, for teardown.
type enforceHandle struct {
	objs  *EnforceObjects
	link4 link.Link
	link6 link.Link
}

// attachEnforceHook loads the audit object and attaches it to the current
// job's cgroup only — never the machine root (see JobCgroupPath). Any failure
// returns an error having loaded nothing observable: the caller fails open
// back to observe-only.
func attachEnforceHook() (*enforceHandle, error) {
	cg, ok := JobCgroupPath()
	if !ok {
		return nil, fmt.Errorf("no job cgroup available")
	}
	objs := EnforceObjects{}
	if err := LoadEnforceObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load enforce objects: %w", err)
	}
	l4, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cg,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.HandleCgroupConnect4,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach connect4 hook: %w", err)
	}
	l6, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cg,
		Attach:  ebpf.AttachCGroupInet6Connect,
		Program: objs.HandleCgroupConnect6,
	})
	if err != nil {
		_ = l4.Close()
		objs.Close()
		return nil, fmt.Errorf("attach connect6 hook: %w", err)
	}
	return &enforceHandle{objs: &objs, link4: l4, link6: l6}, nil
}

func (h *enforceHandle) Close() {
	_ = h.link4.Close()
	_ = h.link6.Close()
	h.objs.Close()
}

// readEnforceEvents drains would-block records into emit until stop closes.
// Destinations are bare IPs (the trie is IP-based; hostname mapping happens
// in scoring via DNS/SNI like connects). Returns the count emitted.
func (h *enforceHandle) readEnforceEvents(emit func(runschema.Event), stop <-chan struct{}, debug bool) int {
	rd, err := ringbuf.NewReader(h.objs.EnforceEvents)
	if err != nil {
		log.Printf("BuildLens agent: enforce ring buffer unavailable (%v)", err)
		return 0
	}
	defer rd.Close()
	go func() {
		<-stop
		_ = rd.Close()
	}()
	n := 0
	for {
		rec, err := rd.Read()
		if err != nil {
			return n // ErrClosed on stop; anything else also ends audit
		}
		var ev rawEnforceEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		if ev.Kind != evtWouldBlock {
			continue
		}
		ip := net.IP(ev.Daddr[:4])
		if ev.Family == afInet6 {
			ip = net.IP(ev.Daddr[:])
		}
		e := runschema.Event{
			Kind: "wouldblock",
			TS:   time.Now().UnixNano(),
			PID:  ev.PID,
			PPID: ev.PPID,
			Comm: cString(ev.Comm[:]),
			Dest: ip.String(),
		}
		if debug {
			log.Printf("[debug] wouldblock pid=%d comm=%s dest=%s", e.PID, e.Comm, e.Dest)
		}
		emit(e)
		n++
	}
}
