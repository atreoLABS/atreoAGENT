package pcp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestResultName(t *testing.T) {
	cases := map[byte]string{
		0:  "SUCCESS",
		2:  "NOT_AUTHORIZED",
		8:  "NO_RESOURCES",
		12: "ADDRESS_MISMATCH",
		99: "UNKNOWN",
	}
	for code, want := range cases {
		if got := resultName(code); got != want {
			t.Errorf("resultName(%d) = %q, want %q", code, got, want)
		}
	}
}

// A rejected MAP must name the failure so operators can self-diagnose.
func TestParseMapResponseNamesRejection(t *testing.T) {
	pkt := make([]byte, headerLen)
	pkt[0] = protocolVersion
	pkt[1] = opcodeMap | responseBit
	pkt[3] = 2 // NOT_AUTHORIZED
	_, matched, err := parseMapResponse(pkt, Nonce{})
	if !matched || err == nil {
		t.Fatalf("expected matched error response, matched=%v err=%v", matched, err)
	}
	if !strings.Contains(err.Error(), "NOT_AUTHORIZED") {
		t.Errorf("error %q should name NOT_AUTHORIZED", err)
	}
}

// fakeServer answers one MAP request on a loopback socket using handle, which
// receives the raw request and returns the raw reply (nil → stay silent).
func fakeServer(t *testing.T, handle func(req []byte) []byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 1100)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			if reply := handle(req); reply != nil {
				_, _ = pc.WriteToUDP(reply, src)
			}
		}
	}()

	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func mapReply(req []byte, result byte, extIP net.IP, extPort uint16, lifetime uint32) []byte {
	resp := make([]byte, msgLen)
	resp[0] = protocolVersion
	resp[1] = opcodeMap | responseBit
	resp[3] = result
	binary.BigEndian.PutUint32(resp[4:8], lifetime)
	copy(resp[headerLen:], req[headerLen:msgLen]) // echo nonce/proto/ports
	binary.BigEndian.PutUint16(resp[headerLen+18:headerLen+20], extPort)
	copy(resp[headerLen+20:headerLen+36], extIP.To16())
	return resp
}

func TestRequestMappingSuccessV6(t *testing.T) {
	v6 := net.ParseIP("2001:db8::1234")
	reqCh := make(chan []byte, 8)
	server := fakeServer(t, func(req []byte) []byte {
		reqCh <- req
		return mapReply(req, resultSuccess, v6, 51820, 1800)
	})

	nonce, _ := NewNonce()
	m, err := RequestMapping(context.Background(), server, v6, v6, ProtoUDP, 51820, 51820, 1800, nonce)
	if err != nil {
		t.Fatalf("RequestMapping: %v", err)
	}
	if !m.ExternalIP.Equal(v6) || m.ExternalPort != 51820 || m.Lifetime != 1800 {
		t.Fatalf("mapping = %+v, want %s:51820 lifetime 1800", m, v6)
	}

	gotReq := <-reqCh
	// Request encoding: header + MAP opcode data.
	if len(gotReq) != msgLen {
		t.Fatalf("request len = %d, want %d", len(gotReq), msgLen)
	}
	if gotReq[0] != protocolVersion || gotReq[1] != opcodeMap {
		t.Errorf("version/opcode = %d/%d", gotReq[0], gotReq[1])
	}
	if got := binary.BigEndian.Uint32(gotReq[4:8]); got != 1800 {
		t.Errorf("lifetime = %d, want 1800", got)
	}
	if !net.IP(gotReq[8:24]).Equal(v6) {
		t.Errorf("client addr = %s, want %s", net.IP(gotReq[8:24]), v6)
	}
	if !bytesEqual(gotReq[24:36], nonce[:]) {
		t.Errorf("nonce not echoed in request")
	}
	if gotReq[36] != ProtoUDP {
		t.Errorf("proto = %d, want %d", gotReq[36], ProtoUDP)
	}
	if got := binary.BigEndian.Uint16(gotReq[40:42]); got != 51820 {
		t.Errorf("internal port = %d, want 51820", got)
	}
	if !net.IP(gotReq[44:60]).Equal(v6) {
		t.Errorf("suggested external IP = %s, want %s", net.IP(gotReq[44:60]), v6)
	}
}

func TestRequestMappingV4MappedEncoding(t *testing.T) {
	v4 := net.ParseIP("192.0.2.10")
	reqCh := make(chan []byte, 8)
	server := fakeServer(t, func(req []byte) []byte {
		reqCh <- req
		// Gateway assigns a public v4 (returned v4-mapped on the wire).
		return mapReply(req, resultSuccess, net.ParseIP("198.51.100.5"), 51820, 1800)
	})

	nonce, _ := NewNonce()
	m, err := RequestMapping(context.Background(), server, v4, net.IPv4zero, ProtoUDP, 51820, 51820, 1800, nonce)
	if err != nil {
		t.Fatalf("RequestMapping: %v", err)
	}
	// Returned IP normalized to 4-byte form.
	if m.ExternalIP.To4() == nil || !m.ExternalIP.Equal(net.ParseIP("198.51.100.5")) {
		t.Fatalf("external IP = %v, want 198.51.100.5 (4-byte)", m.ExternalIP)
	}
	gotReq := <-reqCh
	// IPv4 carried v4-mapped (::ffff:a.b.c.d) in both address fields.
	wantMapped := v4.To16()
	if !bytesEqual(gotReq[8:24], wantMapped) {
		t.Errorf("client addr not v4-mapped: %x", gotReq[8:24])
	}
	if !net.IP(gotReq[44:60]).Equal(net.IPv4zero) {
		t.Errorf("suggested external IP = %s, want unspecified", net.IP(gotReq[44:60]))
	}
}

func TestRequestMappingUnsupportedVersion(t *testing.T) {
	server := fakeServer(t, func(req []byte) []byte {
		return mapReply(req, resultUnsuppVersion, net.IPv6zero, 0, 0)
	})
	nonce, _ := NewNonce()
	_, err := RequestMapping(context.Background(), server, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), ProtoUDP, 51820, 51820, 1800, nonce)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestRequestMappingErrorResult(t *testing.T) {
	server := fakeServer(t, func(req []byte) []byte {
		return mapReply(req, 8 /* NO_RESOURCES */, net.IPv6zero, 0, 0)
	})
	nonce, _ := NewNonce()
	_, err := RequestMapping(context.Background(), server, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), ProtoUDP, 51820, 51820, 1800, nonce)
	if err == nil || errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want generic MAP rejection", err)
	}
}

func TestRequestMappingIgnoresForeignNonce(t *testing.T) {
	// A response carrying a different nonce must be skipped, not mis-parsed
	// as ours; the matching reply follows.
	v6 := net.ParseIP("2001:db8::99")
	var sentForeign bool
	server := fakeServer(t, func(req []byte) []byte {
		if !sentForeign {
			sentForeign = true
			foreign := append([]byte(nil), req...)
			for i := headerLen; i < headerLen+12; i++ {
				foreign[i] ^= 0xff // scramble the nonce
			}
			return mapReply(foreign, resultSuccess, v6, 1234, 1800)
		}
		return mapReply(req, resultSuccess, v6, 51820, 1800)
	})

	nonce, _ := NewNonce()
	// The foreign reply arrives first; RequestMapping must keep reading until
	// its own nonce shows up. Both are sent in response to (re)transmits.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := RequestMapping(ctx, server, v6, v6, ProtoUDP, 51820, 51820, 1800, nonce)
	if err != nil {
		t.Fatalf("RequestMapping: %v", err)
	}
	if m.ExternalPort != 51820 {
		t.Fatalf("external port = %d, want 51820 (matched our nonce)", m.ExternalPort)
	}
}

func TestRequestMappingTimeout(t *testing.T) {
	server := fakeServer(t, func(req []byte) []byte { return nil }) // silent
	nonce, _ := NewNonce()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := RequestMapping(ctx, server, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), ProtoUDP, 51820, 51820, 1800, nonce)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("timeout took too long: %v", time.Since(start))
	}
}

// When clientAddr is a bindable local address, the socket source is bound to
// it (so the gateway's anti-spoofing check passes). 127.0.0.1 reaches the
// loopback fake server, exercising the bind-success path.
func TestRequestMappingBindsSource(t *testing.T) {
	lo := net.ParseIP("127.0.0.1")
	server := fakeServer(t, func(req []byte) []byte {
		return mapReply(req, resultSuccess, lo, 51820, 1800)
	})
	nonce, _ := NewNonce()
	if _, err := RequestMapping(context.Background(), server, lo, lo, ProtoUDP, 51820, 51820, 1800, nonce); err != nil {
		t.Fatalf("RequestMapping with bindable source: %v", err)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
