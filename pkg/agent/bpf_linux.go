//go:build linux

package agent

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang -no-global-types Agent bpf/probes.bpf.c -- -Ibpf

const (
	evtExec    = 1
	evtOpen    = 2
	evtConnect = 3
)

type rawEvent struct {
	Kind  uint8
	PID   uint32
	PPID  uint32
	Comm  [16]byte
	Path  [128]byte
	Daddr [4]byte
	Dport [2]byte
}
