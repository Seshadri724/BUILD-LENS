package agent

import (
	"encoding/binary"
	"net"
	"strings"

	"golang.org/x/net/bpf"
)

// sniFilter is a classic BPF socket filter passing TCP packets to port 443,
// where TLS ClientHellos (and their SNI) live. On an AF_PACKET SOCK_DGRAM
// socket the filter sees the IP header first. Server-to-client packets carry
// an ephemeral destination port and are rejected; payload inspection in
// parseClientHelloSNI drops the rest (ACKs, ServerHellos, bulk data).
var sniFilter = []bpf.Instruction{
	bpf.LoadAbsolute{Off: 0, Size: 1},
	bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipFalse: 5},
	// IPv4: protocol TCP, destination port 443
	bpf.LoadAbsolute{Off: 9, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipFalse: 9},
	bpf.LoadMemShift{Off: 0},
	bpf.LoadIndirect{Off: 2, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 443, SkipTrue: 5, SkipFalse: 6},
	// IPv6: next header TCP (no extension headers), destination port 443
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipFalse: 5},
	bpf.LoadAbsolute{Off: 6, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipFalse: 3},
	bpf.LoadAbsolute{Off: 42, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 443, SkipFalse: 1},
	bpf.RetConstant{Val: 0xffff},
	bpf.RetConstant{Val: 0},
}

// parseClientHelloSNI returns the SNI hostname and the destination IP from a
// TLS ClientHello carried in an IPv4 or IPv6 TCP packet. Anything else —
// non-TLS payloads, truncated handshakes, hellos without SNI, IP-literal SNIs
// — reports ok=false so the destination honestly stays an IP. Every length is
// bounds-checked: attacker-controlled bytes must never panic the agent.
func parseClientHelloSNI(pkt []byte) (sni, dstIP string, ok bool) {
	var tcp []byte
	var dst net.IP
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4 && pkt[9] == 6:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+20 {
			return "", "", false
		}
		dst = net.IP(pkt[16:20])
		tcp = pkt[ihl:]
	case len(pkt) >= 60 && pkt[0]>>4 == 6 && pkt[6] == 6:
		dst = net.IP(pkt[24:40])
		tcp = pkt[40:]
	default:
		return "", "", false
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff+5 {
		return "", "", false
	}
	rec := tcp[dataOff:]
	if rec[0] != 22 { // TLS handshake record
		return "", "", false
	}
	reclen := int(binary.BigEndian.Uint16(rec[3:5]))
	if len(rec) < 5+reclen {
		return "", "", false
	}
	hs := rec[5:]
	if len(hs) < 4 || hs[0] != 1 { // ClientHello
		return "", "", false
	}
	p := hs[4:]
	if _, p, ok = takeBytes(p, 2+32); !ok { // client version + random
		return "", "", false
	}
	if _, p, ok = takeLen8(p); !ok { // session id
		return "", "", false
	}
	if _, p, ok = takeLen16(p); !ok { // cipher suites
		return "", "", false
	}
	if _, p, ok = takeLen8(p); !ok { // compression methods
		return "", "", false
	}
	var exts []byte
	if exts, _, ok = takeLen16(p); !ok { // extensions block
		return "", "", false
	}
	for len(exts) >= 4 {
		etype := binary.BigEndian.Uint16(exts[0:2])
		elen := int(binary.BigEndian.Uint16(exts[2:4]))
		var body []byte
		if body, exts, ok = takeBytes(exts[4:], elen); !ok {
			return "", "", false
		}
		if etype != 0 { // server_name
			continue
		}
		var list []byte
		if list, _, ok = takeLen16(body); !ok {
			return "", "", false
		}
		for len(list) >= 3 {
			if list[0] != 0 { // host_name
				return "", "", false
			}
			nlen := int(binary.BigEndian.Uint16(list[1:3]))
			var name []byte
			if name, list, ok = takeBytes(list[3:], nlen); !ok || len(list) != 0 {
				// Exactly one name expected; trailing junk means a
				// malformed or exotic hello — stay silent.
				return "", "", false
			}
			return cleanSNI(string(name), dst)
		}
		return "", "", false
	}
	return "", "", false
}

// cleanSNI normalizes and validates a candidate hostname. IP literals and
// anything outside a conservative hostname alphabet are rejected: the point
// of SNI capture is a name DNS could never give us, not a second copy of one
// it could.
func cleanSNI(name string, dst net.IP) (string, string, bool) {
	s := strings.ToLower(strings.TrimSuffix(name, "."))
	if len(s) < 1 || len(s) > 253 || net.ParseIP(s) != nil {
		return "", "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			continue
		}
		return "", "", false
	}
	return s, dst.String(), true
}

func takeBytes(b []byte, n int) (head, rest []byte, ok bool) {
	if len(b) < n {
		return nil, b, false
	}
	return b[:n], b[n:], true
}

func takeLen8(b []byte) (head, rest []byte, ok bool) {
	if len(b) < 1 {
		return nil, b, false
	}
	return takeBytes(b[1:], int(b[0]))
}

func takeLen16(b []byte) (head, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, b, false
	}
	return takeBytes(b[2:], int(binary.BigEndian.Uint16(b[0:2])))
}
