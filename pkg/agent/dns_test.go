package agent

import (
	"encoding/binary"
	"net"
	"slices"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsAnswer(t *testing.T) []byte {
	t.Helper()
	name := dnsmessage.MustNewName("API.Exfil.example.")
	target := dnsmessage.MustNewName("edge.cdn.example.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(b.StartQuestions())
	must(b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
	must(b.StartAnswers())
	must(b.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET}, dnsmessage.CNAMEResource{CNAME: target}))
	must(b.AResource(dnsmessage.ResourceHeader{Name: target, Class: dnsmessage.ClassINET}, dnsmessage.AResource{A: [4]byte{198, 51, 100, 7}}))
	var v6 [16]byte
	copy(v6[:], net.ParseIP("2001:db8::7"))
	must(b.AAAAResource(dnsmessage.ResourceHeader{Name: target, Class: dnsmessage.ClassINET}, dnsmessage.AAAAResource{AAAA: v6}))
	msg, err := b.Finish()
	must(err)
	return msg
}

func udp(srcPort uint16, payload []byte) []byte {
	u := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], 40000)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(payload)))
	return append(u, payload...)
}

func ipv4(proto byte, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	h[9] = proto
	return append(h, payload...)
}

func ipv6(next byte, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = next
	return append(h, payload...)
}

func TestDNSFilterAndParse(t *testing.T) {
	vm, err := bpf.NewVM(dnsFilter)
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsAnswer(t)

	cases := []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{"ipv4 dns response", ipv4(17, udp(53, msg)), true},
		{"ipv6 dns response", ipv6(17, udp(53, msg)), true},
		{"ipv4 udp other port", ipv4(17, udp(5353, msg)), false},
		{"ipv4 tcp", ipv4(6, udp(53, msg)), false},
		{"ipv6 udp other port", ipv6(17, udp(443, msg)), false},
	}
	for _, tc := range cases {
		n, err := vm.Run(tc.pkt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if (n > 0) != tc.accept {
			t.Errorf("%s: filter accepted=%v, want %v", tc.name, n > 0, tc.accept)
		}
		if !tc.accept {
			continue
		}
		host, ips := parseDNSResponse(tc.pkt)
		if host != "api.exfil.example" {
			t.Errorf("%s: host = %q", tc.name, host)
		}
		if want := []string{"198.51.100.7", "2001:db8::7"}; !slices.Equal(ips, want) {
			t.Errorf("%s: ips = %v, want %v", tc.name, ips, want)
		}
	}

	// Truncated or garbage input must not panic or produce answers.
	for _, bad := range [][]byte{nil, {0x45}, ipv4(17, udp(53, msg[:5])), ipv4(17, udp(53, []byte("not dns")))} {
		if _, ips := parseDNSResponse(bad); len(ips) != 0 {
			t.Errorf("garbage parsed to %v", ips)
		}
	}
}
