// Package pcp is a minimal, stateless PCP (Port Control Protocol, RFC 6887)
// MAP client. RFC 6887 supersedes NAT-PMP on the same UDP port 5351 and,
// unlike NAT-PMP, works for both address families: for IPv4 a MAP behind a
// NAT yields an external address+port; for IPv6 (no translation) a MAP opens
// a firewall pinhole for the requested address+port.
//
// The package holds no state and starts no goroutines — a single MAP
// transaction per call. The caller supplies the gateway (discovery lives in
// the orchestrator) and retains the per-mapping Nonce needed to renew or
// delete (lifetime 0) it later.
package pcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ServerPort is the well-known UDP port a PCP server listens on (shared with
// NAT-PMP).
const ServerPort = 5351

// ProtoUDP is the IP protocol number for UDP — the only transport the agent
// maps (WireGuard).
const ProtoUDP byte = 17

const (
	protocolVersion = 2
	opcodeMap       = 1
	responseBit     = 0x80 // set in the opcode byte of a response

	headerLen  = 24
	mapDataLen = 36
	msgLen     = headerLen + mapDataLen

	resultSuccess       = 0
	resultUnsuppVersion = 1
)

// ErrUnsupportedVersion signals that the gateway answered the PCP (v2)
// request with UNSUPP_VERSION — the cue to fall back to NAT-PMP, which shares
// UDP port 5351.
var ErrUnsupportedVersion = errors.New("pcp: gateway does not support PCP (UNSUPP_VERSION)")

// Nonce identifies a mapping across its lifetime. The same value must be
// reused to renew or delete (lifetime 0) a mapping created earlier.
type Nonce [12]byte

// NewNonce returns a random mapping nonce.
func NewNonce() (Nonce, error) {
	var n Nonce
	_, err := rand.Read(n[:])
	return n, err
}

// Mapping is the gateway's response to a successful MAP request.
type Mapping struct {
	ExternalIP   net.IP
	ExternalPort uint16
	Lifetime     uint32
}

// RequestMapping performs a single PCP MAP transaction against server.
//
// clientAddr is the address PCP attributes the request to (the agent's own
// address on the path to the gateway). suggestedExternalIP is the external
// address the client would like: for an IPv6 firewall pinhole this equals
// clientAddr (no translation); for IPv4 behind a NAT pass the unspecified
// address so the gateway chooses. lifetime 0 deletes the mapping identified by
// nonce. The whole exchange is bounded by ctx.
func RequestMapping(ctx context.Context, server netip.AddrPort, clientAddr, suggestedExternalIP net.IP, proto byte, internalPort, suggestedExternalPort uint16, lifetime uint32, nonce Nonce) (Mapping, error) {
	req := encodeMapRequest(clientAddr, suggestedExternalIP, proto, internalPort, suggestedExternalPort, lifetime, nonce)

	// RFC 6887 §8.1 anti-spoofing: the gateway rejects (ADDRESS_MISMATCH) a
	// request whose source address differs from the PCP Client's IP Address
	// field. Bind the source to clientAddr so an IPv6 pinhole is created for
	// the global address — otherwise the kernel picks a link-local source when
	// routing to a link-local gateway and the global header is rejected. Best
	// effort: if clientAddr isn't a bindable local address, fall back to
	// kernel source selection.
	raddr := net.UDPAddrFromAddrPort(server)
	conn := dialFrom(clientAddr, raddr)
	if conn == nil {
		var derr error
		conn, derr = net.DialUDP("udp", nil, raddr)
		if derr != nil {
			return Mapping{}, fmt.Errorf("pcp: dial %s: %w", server, derr)
		}
	}
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 1100)
	// Shorter than RFC 6887 §8.1.1's 3s IRT on purpose: the PCP server is the
	// local default gateway (sub-ms RTT), and the orchestrator must fall back
	// to NAT-PMP/UPnP within a tight startup budget when no PCP server answers.
	for _, wait := range []time.Duration{500 * time.Millisecond, time.Second} {
		if err := ctx.Err(); err != nil {
			return Mapping{}, err
		}
		deadline := time.Now().Add(wait)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)

		if _, err := conn.Write(req); err != nil {
			return Mapping{}, fmt.Errorf("pcp: write %s: %w", server, err)
		}

		// Drain until a response carrying our nonce (or a PCP error) — stray
		// ANNOUNCE/other-mapping packets on 5351 are skipped.
		for {
			n, rerr := conn.Read(buf)
			if rerr != nil {
				break // timed out this attempt; retransmit
			}
			m, matched, perr := parseMapResponse(buf[:n], nonce)
			if !matched {
				continue
			}
			return m, perr
		}
	}
	return Mapping{}, fmt.Errorf("pcp: %s: no response", server)
}

// dialFrom returns a connected socket whose source is bound to clientAddr, or
// nil if clientAddr is unusable as a local source (caller falls back).
func dialFrom(clientAddr net.IP, raddr *net.UDPAddr) *net.UDPConn {
	if clientAddr == nil || clientAddr.IsUnspecified() {
		return nil
	}
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: clientAddr}, raddr)
	if err != nil {
		return nil
	}
	return conn
}

func encodeMapRequest(clientAddr, suggestedExternalIP net.IP, proto byte, internalPort, suggestedExternalPort uint16, lifetime uint32, nonce Nonce) []byte {
	b := make([]byte, msgLen)
	b[0] = protocolVersion
	b[1] = opcodeMap // R bit clear = request
	binary.BigEndian.PutUint32(b[4:8], lifetime)
	copy(b[8:24], to16(clientAddr))

	copy(b[24:36], nonce[:])
	b[36] = proto
	binary.BigEndian.PutUint16(b[40:42], internalPort)
	binary.BigEndian.PutUint16(b[42:44], suggestedExternalPort)
	copy(b[44:60], to16(suggestedExternalIP))
	return b
}

// parseMapResponse reports matched=true once it recognises a PCP MAP response
// addressed to nonce (success) or any PCP MAP error response; matched=false
// means "not ours, keep reading".
func parseMapResponse(pkt []byte, nonce Nonce) (m Mapping, matched bool, err error) {
	if len(pkt) < headerLen || pkt[0] != protocolVersion {
		return Mapping{}, false, nil
	}
	if pkt[1]&responseBit == 0 || pkt[1]&^responseBit != opcodeMap {
		return Mapping{}, false, nil
	}
	result := pkt[3]
	lifetime := binary.BigEndian.Uint32(pkt[4:8])

	if result != resultSuccess {
		// Error responses may omit/garble the echoed nonce, so don't gate on
		// it — any PCP error means "give up and fall back".
		if result == resultUnsuppVersion {
			return Mapping{}, true, ErrUnsupportedVersion
		}
		return Mapping{}, true, fmt.Errorf("pcp: MAP rejected (result code %d)", result)
	}

	if len(pkt) < msgLen {
		return Mapping{}, false, nil
	}
	body := pkt[headerLen:]
	var got Nonce
	copy(got[:], body[0:12])
	if got != nonce {
		return Mapping{}, false, nil // a response for a different mapping
	}
	extPort := binary.BigEndian.Uint16(body[18:20])
	extIP := normalizeIP(net.IP(append([]byte(nil), body[20:36]...)))
	return Mapping{ExternalIP: extIP, ExternalPort: extPort, Lifetime: lifetime}, true, nil
}

// to16 renders an address as the 16-byte form PCP requires; IPv4 is carried
// v4-mapped (::ffff:a.b.c.d) per RFC 6887. A nil/unspecified address becomes
// all-zeros ("let the gateway choose").
func to16(ip net.IP) []byte {
	if ip == nil {
		return make([]byte, 16)
	}
	if v16 := ip.To16(); v16 != nil {
		return v16
	}
	return make([]byte, 16)
}

// normalizeIP collapses a v4-mapped address back to 4-byte form for display.
func normalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
