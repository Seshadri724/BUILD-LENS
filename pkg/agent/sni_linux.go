//go:build linux

package agent

import (
	"errors"
	"log"

	"github.com/buildlens/buildlens/pkg/runschema"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// maxSNIFlows bounds the per-flow first-packet table. ClientHellos arrive at
// connection start; once a flow is seen its later packets can never carry a
// new SNI. When full the table resets — worst case is a re-emitted event,
// never a missed new host.
const maxSNIFlows = 4096

// sniffSNI reads TLS ClientHellos to port 443 on every interface until stop
// closes, emitting one "sni" event per connection. It fails open like the DNS
// sniffer: no handshake observed, destinations stay as IPs (or DNS names).
// Returns the number of events emitted.
func sniffSNI(emit func(runschema.Event), stop <-chan struct{}, debug bool) int {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		log.Printf("BuildLens agent: SNI capture unavailable (%v); hostnames fall back to DNS", err)
		return 0
	}
	defer unix.Close(fd)

	raw, err := bpf.Assemble(sniFilter)
	if err != nil {
		log.Printf("BuildLens agent: SNI filter assemble failed (%v); hostnames fall back to DNS", err)
		return 0
	}
	prog := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		prog[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}); err != nil {
		log.Printf("BuildLens agent: SNI filter attach failed (%v); hostnames fall back to DNS", err)
		return 0
	}
	const ethPAll = unix.ETH_P_ALL<<8&0xff00 | unix.ETH_P_ALL>>8 // htons, amd64 only
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: ethPAll}); err != nil {
		log.Printf("BuildLens agent: SNI capture bind failed (%v); hostnames fall back to DNS", err)
		return 0
	}
	// Same arrival-time contract as DNS: the handshake always lands before the
	// data it names, so the correlator matches strictly by time.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
	// Wake up periodically to notice stop.
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 200_000})

	seen := map[string]struct{}{}
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
			log.Printf("BuildLens agent: SNI capture stopped: %v", err)
			return count
		}
		// Loopback shows each packet twice (sent and received); keep the received copy.
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		pkt := buf[:n]
		flow := sniFlowKey(pkt)
		if flow == "" {
			continue
		}
		if _, dup := seen[flow]; dup {
			continue
		}
		if len(seen) >= maxSNIFlows {
			seen = map[string]struct{}{}
		}
		seen[flow] = struct{}{}
		sni, dst, ok := parseClientHelloSNI(pkt)
		if !ok {
			continue
		}
		if debug {
			log.Printf("[debug] sni host=%s ip=%s", sni, dst)
		}
		emit(runschema.Event{Kind: "sni", TS: packetTime(oob[:oobn]), Host: sni, Dest: dst})
		count++
	}
}

// sniFlowKey identifies a TCP flow by endpoints so only its first packet is
// parsed. Empty when the packet isn't TCP-shaped (IPv4 or IPv6).
func sniFlowKey(pkt []byte) string {
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4 && pkt[9] == 6:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+20 {
			return ""
		}
		tcp := pkt[ihl:]
		key := make([]byte, 0, 12)
		key = append(key, pkt[12:16]...)
		key = append(key, tcp[0:4]...)
		key = append(key, pkt[16:20]...)
		return string(key)
	case len(pkt) >= 60 && pkt[0]>>4 == 6 && pkt[6] == 6:
		tcp := pkt[40:]
		key := make([]byte, 0, 36)
		key = append(key, pkt[8:24]...)
		key = append(key, tcp[0:4]...)
		key = append(key, pkt[24:40]...)
		return string(key)
	default:
		return ""
	}
}
