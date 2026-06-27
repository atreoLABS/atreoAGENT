package relay

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

// maxDatagram bounds a single UDP read; WireGuard transport packets sit under
// this and the DATA header adds 9 bytes on the agent leg.
const maxDatagram = 1500

const (
	// Ceiling on concurrent client tunnels (one loopback socket + goroutine
	// each), sized well above a household's connected devices.
	maxTunnels = 256
	// A tunnel idle this long is closed; a live one refreshes well within it
	// via WireGuard keepalives, and a closed one re-establishes on next use.
	tunnelIdleTimeout  = 5 * time.Minute
	tunnelReapInterval = 60 * time.Second
	capWarnInterval    = time.Minute
)

// shim bridges the agent's single outbound UDP association to the relay and the
// local kernel WireGuard socket. It is NOT a WireGuard implementation: it never
// parses or holds WireGuard keys — it moves opaque bytes between a socket and
// 127.0.0.1:<wgPort>, one loopback socket per relayed client tunnel so kernel
// WireGuard demuxes peers by key as usual.
type shim struct {
	dataConn     *net.UDPConn // connected to the relay's data-ingest port
	sessionToken []byte
	wgAddr       *net.UDPAddr // 127.0.0.1:<wg listen port>

	mu          sync.Mutex
	tunnels     map[uint64]*tunnelConn
	lastCapWarn time.Time // rate-limits the at-capacity log; guarded by mu
}

type tunnelConn struct {
	wg         *net.UDPConn
	lastActive atomic.Int64 // unix nanos of the last datagram either direction
	closeOnce  sync.Once
}

func newShim(dataConn *net.UDPConn, sessionToken []byte, wgListenPort int) *shim {
	return &shim{
		dataConn:     dataConn,
		sessionToken: sessionToken,
		wgAddr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: wgListenPort},
		tunnels:      make(map[uint64]*tunnelConn),
	}
}

// run binds the association (BIND), holds it warm (KEEPALIVE), and forwards
// relay↔WireGuard until ctx is cancelled or the association errors.
func (s *shim) run(ctx context.Context) error {
	if _, err := s.dataConn.Write(encodeBind(s.sessionToken)); err != nil {
		return err
	}

	kctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.keepalive(kctx)
	go s.reapTunnels(kctx)
	defer s.closeAll()

	buf := make([]byte, maxDatagram)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := s.dataConn.Read(buf)
		if err != nil {
			return err
		}
		fr, perr := parseFrame(buf[:n])
		if perr != nil {
			continue
		}
		switch fr.typ {
		case frameData:
			s.toWireGuard(ctx, fr.tunnelID, fr.payload)
		case frameClose:
			s.closeTunnel(fr.tunnelID)
		case frameKeepalive:
			// relay-side keepalive; nothing to do
		}
	}
}

func (s *shim) keepalive(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	ka := encodeKeepalive()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.dataConn.Write(ka); err != nil {
				return
			}
		}
	}
}

// toWireGuard forwards a client→agent datagram onto its loopback socket,
// creating the tunnel on first sight. At maxTunnels, a new tunnel is dropped.
func (s *shim) toWireGuard(ctx context.Context, tunnelID uint64, payload []byte) {
	now := time.Now().UnixNano()
	s.mu.Lock()
	tc, ok := s.tunnels[tunnelID]
	if !ok {
		if len(s.tunnels) >= maxTunnels {
			s.warnAtCapLocked()
			s.mu.Unlock()
			return // at capacity — drop rather than queue
		}
		wg, err := net.DialUDP("udp", nil, s.wgAddr)
		if err != nil {
			s.mu.Unlock()
			logging.Error("relay shim: dial local WireGuard: %v", err)
			return
		}
		tc = &tunnelConn{wg: wg}
		tc.lastActive.Store(now)
		s.tunnels[tunnelID] = tc
		go s.replyPump(ctx, tunnelID, tc)
	} else {
		tc.lastActive.Store(now)
	}
	s.mu.Unlock()
	_, _ = tc.wg.Write(payload)
}

// replyPump forwards WireGuard's responses (agent→client) back to the relay,
// framed with the tunnel id.
func (s *shim) replyPump(ctx context.Context, tunnelID uint64, tc *tunnelConn) {
	buf := make([]byte, maxDatagram)
	send := make([]byte, maxDatagram+dataHeaderLen)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := tc.wg.Read(buf)
		if err != nil {
			return
		}
		tc.lastActive.Store(time.Now().UnixNano())
		send = encodeData(send, tunnelID, buf[:n])
		if _, err := s.dataConn.Write(send); err != nil {
			return
		}
	}
}

// reapTunnels closes tunnels idle beyond tunnelIdleTimeout, releasing each
// tunnel's loopback socket and replyPump goroutine.
func (s *shim) reapTunnels(ctx context.Context) {
	t := time.NewTicker(tunnelReapInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.reapOnce(now)
		}
	}
}

func (s *shim) reapOnce(now time.Time) {
	cutoff := now.Add(-tunnelIdleTimeout).UnixNano()
	s.mu.Lock()
	var expired []*tunnelConn
	for id, tc := range s.tunnels {
		if tc.lastActive.Load() < cutoff {
			expired = append(expired, tc)
			delete(s.tunnels, id)
		}
	}
	s.mu.Unlock()
	for _, tc := range expired {
		tc.closeOnce.Do(func() { _ = tc.wg.Close() })
	}
}

// warnAtCapLocked logs at capacity, rate-limited via capWarnInterval.
// Caller holds mu.
func (s *shim) warnAtCapLocked() {
	now := time.Now()
	if now.Sub(s.lastCapWarn) < capWarnInterval {
		return
	}
	s.lastCapWarn = now
	logging.Warn("relay shim: tunnel ceiling (%d) reached — dropping new client tunnels", maxTunnels)
}

func (s *shim) closeTunnel(tunnelID uint64) {
	s.mu.Lock()
	tc, ok := s.tunnels[tunnelID]
	if ok {
		delete(s.tunnels, tunnelID)
	}
	s.mu.Unlock()
	if ok {
		tc.closeOnce.Do(func() { _ = tc.wg.Close() })
	}
}

func (s *shim) closeAll() {
	s.mu.Lock()
	tcs := make([]*tunnelConn, 0, len(s.tunnels))
	for _, tc := range s.tunnels {
		tcs = append(tcs, tc)
	}
	s.tunnels = make(map[uint64]*tunnelConn)
	s.mu.Unlock()
	for _, tc := range tcs {
		tc.closeOnce.Do(func() { _ = tc.wg.Close() })
	}
}
