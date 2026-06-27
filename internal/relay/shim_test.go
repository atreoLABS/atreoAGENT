package relay

import (
	"context"
	"net"
	"testing"
	"time"
)

// testShim wires a shim to a live loopback "WireGuard" listener and a throwaway
// data sink so toWireGuard/reapOnce can be exercised without the full session.
func testShim(t *testing.T) (*shim, func()) {
	t.Helper()
	wgSrv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("wg listener: %v", err)
	}
	dataSink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("data sink: %v", err)
	}
	dataConn, err := net.DialUDP("udp", nil, dataSink.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial data: %v", err)
	}
	s := newShim(dataConn, make([]byte, sessionTokenLen), wgSrv.LocalAddr().(*net.UDPAddr).Port)
	cleanup := func() {
		s.closeAll()
		_ = dataConn.Close()
		_ = dataSink.Close()
		_ = wgSrv.Close()
	}
	return s, cleanup
}

func (s *shim) liveTunnels() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tunnels)
}

// A relay spraying distinct tunnelIDs must not be able to open unbounded
// loopback sockets + goroutines — the live tunnel count is capped.
func TestShimCapsConcurrentTunnels(t *testing.T) {
	s, cleanup := testShim(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < maxTunnels+25; i++ {
		s.toWireGuard(ctx, uint64(i), []byte{0x01})
	}
	if got := s.liveTunnels(); got != maxTunnels {
		t.Fatalf("live tunnels = %d, want capped at %d", got, maxTunnels)
	}
}

// An idle tunnel is reaped (its socket closed) and re-establishes on the next
// datagram, so a relay can't pin sockets open after a client goes away.
func TestShimReapsIdleTunnels(t *testing.T) {
	s, cleanup := testShim(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.toWireGuard(ctx, 1, []byte{0x01})
	s.mu.Lock()
	tc := s.tunnels[1]
	s.mu.Unlock()
	if tc == nil {
		t.Fatal("tunnel not created")
	}

	tc.lastActive.Store(time.Now().Add(-2 * tunnelIdleTimeout).UnixNano())
	s.reapOnce(time.Now())

	if got := s.liveTunnels(); got != 0 {
		t.Fatalf("idle tunnel not reaped, live = %d", got)
	}

	s.toWireGuard(ctx, 1, []byte{0x01})
	if got := s.liveTunnels(); got != 1 {
		t.Fatalf("tunnel did not re-establish after reap, live = %d", got)
	}
}

// A tunnel carrying traffic must survive a reap pass — only genuinely idle ones
// are closed.
func TestShimReapKeepsActiveTunnel(t *testing.T) {
	s, cleanup := testShim(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.toWireGuard(ctx, 1, []byte{0x01}) // fresh ⇒ lastActive ~= now
	s.reapOnce(time.Now())

	if got := s.liveTunnels(); got != 1 {
		t.Fatalf("active tunnel was reaped, live = %d", got)
	}
}

// Once idle tunnels are reaped the freed capacity admits new tunnels again.
func TestShimCapRecoversAfterReap(t *testing.T) {
	s, cleanup := testShim(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < maxTunnels; i++ {
		s.toWireGuard(ctx, uint64(i), []byte{0x01})
	}
	s.toWireGuard(ctx, 9999, []byte{0x01}) // refused at cap
	s.mu.Lock()
	_, present := s.tunnels[9999]
	s.mu.Unlock()
	if present || s.liveTunnels() != maxTunnels {
		t.Fatalf("new tunnel admitted past the cap (present=%v live=%d)", present, s.liveTunnels())
	}

	s.mu.Lock()
	old := time.Now().Add(-2 * tunnelIdleTimeout).UnixNano()
	for _, tc := range s.tunnels {
		tc.lastActive.Store(old)
	}
	s.mu.Unlock()
	s.reapOnce(time.Now())

	s.toWireGuard(ctx, 9999, []byte{0x01})
	s.mu.Lock()
	_, present = s.tunnels[9999]
	s.mu.Unlock()
	if !present {
		t.Fatal("tunnel not admitted after reap freed capacity")
	}
}
