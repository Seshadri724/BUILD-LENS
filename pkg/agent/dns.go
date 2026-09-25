package agent

import (
	"encoding/binary"
	"net"
	"strings"

	"golang.org/x/net/bpf"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsFilter is a classic BPF socket filter that passes only UDP packets from
// port 53. On an AF_PACKET SOCK_DGRAM socket the filter sees the IP header first.
// ponytail: UDP DNS only; DoH, DoT and DNS over TCP leave destinations as IPs.
var dnsFilter = []bpf.Instruction{
	bpf.LoadAbsolute{Off: 0, Size: 1},
	bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x40, SkipFalse: 5},
	// IPv4: protocol UDP, source port 53
	bpf.LoadAbsolute{Off: 9, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 9},
	bpf.LoadMemShift{Off: 0},
	bpf.LoadIndirect{Off: 0, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipTrue: 5, SkipFalse: 6},
	// IPv6: next header UDP (no extension headers), source port 53
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x60, SkipFalse: 5},
	bpf.LoadAbsolute{Off: 6, Size: 1},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipFalse: 3},
	bpf.LoadAbsolute{Off: 40, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 53, SkipFalse: 1},
	bpf.RetConstant{Val: 0xffff},
	bpf.RetConstant{Val: 0},
}

// parseDNSResponse returns the queried name and the A/AAAA addresses in a DNS
// response carried in an IPv4 or IPv6 UDP packet. Addresses reached through a
// CNAME chain are reported under the name the client asked for.
func parseDNSResponse(pkt []byte) (host string, ips []string) {
	var udp []byte
	switch {
	case len(pkt) >= 20 && pkt[0]>>4 == 4 && pkt[9] == 17:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl+8 {
			return "", nil
		}
		udp = pkt[ihl:]
	case len(pkt) >= 48 && pkt[0]>>4 == 6 && pkt[6] == 17:
		udp = pkt[40:]
	default:
		return "", nil
	}
	if binary.BigEndian.Uint16(udp[0:2]) != 53 {
		return "", nil
	}

	var p dnsmessage.Parser
	h, err := p.Start(udp[8:])
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return "", nil
	}
	q, err := p.Question()
	if err != nil {
		return "", nil
	}
	host = strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	if err := p.SkipAllQuestions(); err != nil {
		return "", nil
	}
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			break // ErrSectionDone or a malformed record: keep what parsed
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return host, ips
			}
			ips = append(ips, net.IP(r.A[:]).String())
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return host, ips
			}
			ips = append(ips, net.IP(r.AAAA[:]).String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return host, ips
			}
		}
	}
	return host, ips
}
