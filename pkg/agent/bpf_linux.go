//go:build linux

package agent

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -no-global-types Agent bpf/probes.bpf.c -- -Ibpf

const (
	evtExec    = 1
	evtOpen    = 2
	evtConnect = 3
)

type rawEvent struct {
	Kind   uint8
	PID    uint32
	PPID   uint32
	Comm   [16]byte
	Path   [128]byte
	Daddr  [16]byte
	Dport  [2]byte
	Family uint8
}

// flowKey mirrors struct flow_key in probes.bpf.c (key of the send_bytes map).
type flowKey struct {
	PID    uint32
	Daddr  [16]byte
	Dport  [2]byte
	Family uint8
	Pad    uint8
}
