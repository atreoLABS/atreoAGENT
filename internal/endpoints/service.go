package endpoints

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"net"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/tunnel"
)

// Wrapped so tests don't need to import internal/tunnel.
func tunnelNotAttachedErr() error { return tunnel.ErrNotAttached }

// Returns ("", 0) when no mapping is active → omit public4 candidate.
type PublicEndpointProvider interface {
	PublicEndpoint() (ip string, port int)
}

// Local interface so the endpoints package doesn't import internal/tunnel.
type TunnelSender interface {
	Send(ctx context.Context, msg atreolink.TunnelMessage) error
}

type Config struct {
	DeviceID         string
	WGPort           int
	IfaceSource      InterfaceSource
	PublicEndpoint   PublicEndpointProvider
	Sender           TunnelSender
	PrivateKey       ed25519.PrivateKey
	PeriodicInterval time.Duration         // 0 = 15min; <0 disables
	Clock            func() time.Time      // nil → time.Now
	OnChange         func(lan []Candidate) // called on Service goroutine; must not block
}

// Publishes device:endpoints envelopes when the reachable-address list
// changes. Refresh is serialised through the internal mutex.
type Service struct {
	cfg Config

	mu             sync.Mutex
	lastCandidates []Candidate
	lastEnvelope   atreolink.TunnelMessage // cached for SetOnConnect reuse
	lastEnvelopeOK bool                    // false until first successful build
	lastCanonBytes []byte                  // for byte-exact dedupe

	// Buffer 1 so bursty netlink notifications coalesce.
	triggerCh chan struct{}
}

func NewService(cfg Config) *Service {
	if cfg.PeriodicInterval == 0 {
		cfg.PeriodicInterval = 15 * time.Minute
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Service{
		cfg:       cfg,
		triggerCh: make(chan struct{}, 1),
	}
}

// Coalesces with any refresh already queued in the debounce window.
func (s *Service) Trigger() {
	select {
	case s.triggerCh <- struct{}{}:
	default:
	}
}

// Performs one immediate refresh on entry.
func (s *Service) Run(ctx context.Context) {
	s.doRefresh(ctx)

	// Interface-change notifications are no-op on non-Linux.
	stopWatch := startInterfaceWatcher(ctx, s)
	defer stopWatch()

	var tickC <-chan time.Time
	if s.cfg.PeriodicInterval > 0 {
		t := time.NewTicker(s.cfg.PeriodicInterval)
		defer t.Stop()
		tickC = t.C
	}

	// 1s debounce — netlink bursts on flap (RTM_NEWLINK + RTM_NEWADDR).
	var debounceC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.triggerCh:
			if debounceC == nil {
				debounceC = time.After(1 * time.Second)
			}
		case <-debounceC:
			debounceC = nil
			s.doRefresh(ctx)
		case <-tickC:
			s.doRefresh(ctx)
		}
	}
}

// Used by the tunnel client's onConnect to republish the same signed
// bytes on reattach.
func (s *Service) CurrentMessage() (atreolink.TunnelMessage, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastEnvelopeOK {
		return atreolink.TunnelMessage{}, false
	}
	return s.lastEnvelope, true
}

// Errors logged and swallowed — the service runs forever.
func (s *Service) doRefresh(ctx context.Context) {
	cands, err := s.collectCandidates()
	if err != nil {
		logging.Error("endpoints: enumerate failed: %v", err)
		return
	}

	s.mu.Lock()
	if sameCandidates(cands, s.lastCandidates) && s.lastEnvelopeOK {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	env, err := Build(s.cfg.DeviceID, s.cfg.Clock(), cands, s.cfg.PrivateKey)
	if err != nil {
		logging.Error("endpoints: build envelope failed: %v", err)
		return
	}

	s.mu.Lock()
	// Belt-and-suspenders dedupe for clock-moved-backwards.
	if bytes.Equal(env.PayloadCanon, s.lastCanonBytes) {
		s.mu.Unlock()
		return
	}
	s.lastCandidates = cands
	s.lastCanonBytes = env.PayloadCanon
	s.lastEnvelope = atreolink.TunnelMessage{
		Type:      "device:endpoints",
		Payload:   json.RawMessage(env.PayloadCanon),
		Signature: env.SignatureBase64(),
		SignerID:  "agent",
	}
	s.lastEnvelopeOK = true
	msg := s.lastEnvelope
	s.mu.Unlock()

	if s.cfg.OnChange != nil {
		// Probe server only binds LAN candidates.
		lan := make([]Candidate, 0, len(cands))
		for _, c := range cands {
			if c.Kind == KindLAN {
				lan = append(lan, c)
			}
		}
		s.cfg.OnChange(lan)
	}

	if err := s.cfg.Sender.Send(ctx, msg); err != nil {
		if errors.Is(err, tunnelNotAttachedErr()) {
			// Next WS attach will pick up msg via the onConnect hook.
			logging.Debug("endpoints: WS not attached; deferring envelope publish until reattach")
			return
		}
		logging.Error("endpoints: Send failed: %v", err)
	}
}

// PublicV6 returns the global IPv6 addresses currently advertised as public6
// endpoint candidates (default-route interface; SLAAC temporaries/deprecated
// excluded). Used to drive firewall pinholes so the pinholed set matches the
// advertised set exactly.
func PublicV6() ([]net.IP, error) {
	idx, name, _ := DefaultRoute()
	res, err := Enumerate(NewRealSource(), idx, name)
	if err != nil {
		return nil, err
	}
	return res.PublicV6, nil
}

// Final order: default-route LAN first, other LAN, public4, public6.
func (s *Service) collectCandidates() ([]Candidate, error) {
	defaultIfIdx, defaultIfName, _ := DefaultRoute()
	res, err := Enumerate(s.cfg.IfaceSource, defaultIfIdx, defaultIfName)
	if err != nil {
		return nil, err
	}

	var out []Candidate
	for _, ip := range res.LAN {
		out = append(out, Candidate{Kind: KindLAN, Host: ip.String(), Port: s.cfg.WGPort})
	}
	if s.cfg.PublicEndpoint != nil {
		if extIP, extPort := s.cfg.PublicEndpoint.PublicEndpoint(); extIP != "" && extPort > 0 {
			out = append(out, Candidate{Kind: KindPublic4, Host: extIP, Port: extPort})
		}
	}
	for _, ip := range res.PublicV6 {
		out = append(out, Candidate{Kind: KindPublic6, Host: ip.String(), Port: s.cfg.WGPort})
	}
	return sortCandidates(out), nil
}
