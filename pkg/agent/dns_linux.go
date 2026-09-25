//go:build linux

package agent

import (
	"errors"
	"log"
	"time"

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
	// Wake up periodically to notice stop.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200_000})

	count := 0
	buf := make([]byte, 65536)
	for {
		select {
		case <-stop:
			return count
		default:
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
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
		ts := time.Now().UnixNano()
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
