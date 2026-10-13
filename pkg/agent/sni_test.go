package agent

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

func clientHello(t *testing.T, serverName string, withSNI bool) []byte {
	t.Helper()
	hello := []byte{0x03, 0x03}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00)                   // session id
	hello = append(hello, 0x00, 0x02, 0x13, 0x01) // cipher suites
	hello = append(hello, 0x01, 0x00)             // compression methods
	var exts []byte
	if withSNI {
		name := []byte(serverName)
		entry := []byte{0x00, byte(len(name) >> 8), byte(len(name))}
		entry = append(entry, name...)
		body := []byte{byte(len(entry) >> 8), byte(len(entry))}
		body = append(body, entry...)
		ext := []byte{0x00, 0x00, byte(len(body) >> 8), byte(len(body))}
		ext = append(ext, body...)
		exts = append(exts, ext...)
	}
	exts = append(exts, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04) // supported_versions
	hello = append(hello, byte(len(exts)>>8), byte(len(exts)))
	hello = append(hello, exts...)
	hs := []byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
	hs = append(hs, hello...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func tcpHeader(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 20)
	h[12] = 0x50 // data offset 5, no options
	binary.BigEndian.PutUint16(h[0:2], sport)
	binary.BigEndian.PutUint16(h[2:4], dport)
	return append(h, payload...)
}

func TestSNIFilter(t *testing.T) {
	vm, err := bpf.NewVM(sniFilter)
	if err != nil {
		t.Fatal(err)
	}
	hello := clientHello(t, "vault.doh-shim.example", true)
	cases := []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{"ipv4 tcp 443", ipv4(6, tcpHeader(40000, 443, hello)), true},
		{"ipv6 tcp 443", ipv6(6, tcpHeader(40000, 443, hello)), true},
		{"ipv4 tcp 80", ipv4(6, tcpHeader(40000, 80, hello)), false},
		{"ipv4 udp 443", ipv4(17, tcpHeader(40000, 443, hello)), false},
		{"ipv4 tcp sport 443 only", ipv4(6, tcpHeader(443, 40000, hello)), false},
		{"ipv6 tcp 80", ipv6(6, tcpHeader(40000, 80, hello)), false},
	}
	for _, tc := range cases {
		n, err := vm.Run(tc.pkt)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if (n > 0) != tc.accept {
			t.Errorf("%s: filter accepted=%v, want %v", tc.name, n > 0, tc.accept)
		}
	}
}

func TestParseClientHelloSNI(t *testing.T) {
	hello := clientHello(t, "vault.doh-shim.example", true)

	v4 := ipv4(6, tcpHeader(40000, 443, hello))
	copy(v4[16:20], net.ParseIP("198.51.100.60").To4())
	sni, dst, ok := parseClientHelloSNI(v4)
	if !ok || sni != "vault.doh-shim.example" || dst != "198.51.100.60" {
		t.Errorf("ipv4: got %q %q %v", sni, dst, ok)
	}

	v6 := ipv6(6, tcpHeader(40000, 443, hello))
	copy(v6[24:40], net.ParseIP("2001:db8::60"))
	sni, dst, ok = parseClientHelloSNI(v6)
	if !ok || sni != "vault.doh-shim.example" || dst != "2001:db8::60" {
		t.Errorf("ipv6: got %q %q %v", sni, dst, ok)
	}

	upper := ipv4(6, tcpHeader(40000, 443, clientHello(t, "VAULT.Example.COM", true)))
	if sni, _, ok := parseClientHelloSNI(upper); !ok || sni != "vault.example.com" {
		t.Errorf("case: got %q %v", sni, ok)
	}

	bad := [][]byte{
		nil,
		{0x45},
		ipv4(6, tcpHeader(40000, 443, hello[:10])),
		ipv4(6, tcpHeader(40000, 443, hello[:30])),
		ipv4(6, tcpHeader(40000, 443, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))),
		ipv4(6, tcpHeader(40000, 443, clientHello(t, "", false))),
		ipv4(6, tcpHeader(40000, 443, clientHello(t, "198.51.100.60", true))),
		ipv4(17, tcpHeader(40000, 443, hello)),
	}
	for i, pkt := range bad {
		if sni, dst, ok := parseClientHelloSNI(pkt); ok {
			t.Errorf("bad[%d]: parsed to %q %q, want reject", i, sni, dst)
		}
	}
}
