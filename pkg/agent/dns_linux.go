//go:build linux

package agent

import (
	"errors"
	"log"
	"time"
	"unsafe"

	"github.com/buildlens/buildlens/pkg/runschema"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// sniffDNS reads DNS responses on every interface until stop closes, emitting
// one "dns" event per resolved address. It fails open: if the socket can't be
// set up, destinations just stay as IPs. Returns the number of events emitted.
func sniffDNS(emit func(runschema.Event), stop <-chan struct{}, debug bool) int {
	// Protocol 0 receives nothing until bind, so no unfiltered packets queue up
	// before the filter is attached.
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		log.Printf("BuildLens agent: DNS capture unavailable (%v); destinations stay as IPs", err)
		return 0
	}
	defer unix.Close(fd)

	raw, err := bpf.Assemble(dnsFilter)
	if err != nil {
		log.Printf("BuildLens agent: DNS filter assemble failed (%v); destinations stay as IPs", err)
		return 0
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		log.Printf("BuildLens agent: DNS filter attach failed (%v); destinations stay as IPs", err)
		return 0
	}
	const ethPAll = unix.ETH_P_ALL<<8&0xff00 | unix.ETH_P_ALL>>8 // htons, amd64 only
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ethPAll}); err != nil {
		log.Printf("BuildLens agent: DNS capture bind failed (%v); destinations stay as IPs", err)
		return 0
	}
	// Kernel arrival time per packet: a DNS answer always lands before the
	// connect it leads to, so the correlator can match lookups strictly by time.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
	// Wake up periodically to notice stop.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200_000})

	count := 0
	buf := make([]byte, 65536)
	oob := make([]byte, unix.CmsgSpace(16))
	for {
		select {
		case <-stop:
			return count
		default:
		}
		n, oobn, _, from, err := unix.Recvmsg(fd, buf, oob, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			log.Printf("BuildLens agent: DNS capture stopped: %v", err)
			return count
		}
		// Loopback shows each packet twice (sent and received); keep the received copy.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		ts := packetTime(oob[:oobn])
		host, ips := parseDNSResponse(buf[:n])
		for _, ip := range ips {
			if debug {
				log.Printf("[debug] dns host=%s ip=%s", host, ip)
			}
			emit(runschema.Event{Kind: "dns", TS: ts, Host: host, Dest: ip})
			count++
		}
	}
}

// packetTime reads the SO_TIMESTAMPNS arrival time, falling back to now.
func packetTime(oob []byte) int64 {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err == nil {
		for _, m := range msgs {
			if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMPNS && len(m.Data) >= 16 {
				ts := (*unix.Timespec)(unsafe.Pointer(&m.Data[0]))
				return ts.Nano()
			}
		}
	}
	return time.Now().UnixNano()
}
