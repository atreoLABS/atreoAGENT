// Package smtp implements the LAN-side SMTP-to-push gateway: parses MIME,
// matches RCPT TO against the ACL, hands off to notify.Server.
//
// LAN-only by design. AUTH (PLAIN/LOGIN, password = notify API key) is
// always required; STARTTLS is opt-in via Config.TLSEnabled.
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"net"
	"sync"
	"time"

	gosmtp "github.com/emersion/go-smtp"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/notify"
)

type Server struct {
	cfg       Config
	acl       *acl.Store
	notify    notifySender
	gosmtp    *gosmtp.Server
	limiter   *ipLimiter
	trusted   []*net.IPNet
	tlsOn     bool
	mu        sync.Mutex
	startedAt time.Time
}

// parseCIDRs is self-contained so the gateway doesn't depend on the proxy
// package just for a handful of LAN ranges.
func parseCIDRs(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		} else {
			logging.Warn("smtp: ignoring invalid trusted_networks CIDR %q: %v", c, err)
		}
	}
	return nets
}

// allowlistIncludesPublic flags an over-broad allowlist by probing whether it
// would admit well-known public addresses — a cheap startup sanity check.
func (s *Server) allowlistIncludesPublic() bool {
	for _, probe := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		ip := net.ParseIP(probe)
		for _, n := range s.trusted {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ipTrusted reports whether host is within the allowlist. An empty allowlist
// trusts any source (the agent always supplies a LAN default, so a truly empty
// list only happens if an operator clears it on purpose).
func (s *Server) ipTrusted(host string) bool {
	if len(s.trusted) == 0 {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range s.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Read on every AUTH attempt so rotations propagate.
func (s *Server) apiKey() string {
	return s.notify.APIKey()
}

type Config struct {
	Listen          string
	MaxMessageBytes int64
	RatePerMinute   int
	TLSEnabled      bool // self-signed STARTTLS cert under DataDir
	DataDir         string
	TrustedNetworks []string // source-IP allowlist; empty = allow any (caller supplies the LAN default)
}

// notifySender — interface so tests can stub.
type notifySender interface {
	SendToMember(ctx context.Context, member *atreolink.MemberACLEntry, req *notify.NotifyRequest) error
	APIKey() string
}

func NewServer(cfg Config, store *acl.Store, ns notifySender) (*Server, error) {
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0:2525"
	}
	if cfg.MaxMessageBytes == 0 {
		cfg.MaxMessageBytes = 1 << 20
	}
	if cfg.RatePerMinute == 0 {
		cfg.RatePerMinute = 5
	}
	s := &Server{
		cfg:     cfg,
		acl:     store,
		notify:  ns,
		limiter: newIPLimiter(cfg.RatePerMinute),
		trusted: parseCIDRs(cfg.TrustedNetworks),
	}
	be := &backend{server: s}
	gs := gosmtp.NewServer(be)
	gs.Addr = cfg.Listen
	gs.Domain = "atreoagent.local" // EHLO banner; routing is by recipient email
	gs.MaxMessageBytes = cfg.MaxMessageBytes
	gs.MaxRecipients = 1
	// Without this, go-smtp refuses AUTH on a non-TLS connection.
	gs.AllowInsecureAuth = true
	gs.WriteTimeout = 30 * time.Second
	gs.ReadTimeout = 30 * time.Second

	// Opt-in opportunistic STARTTLS (self-signed; not server auth).
	if cfg.TLSEnabled {
		if cfg.DataDir == "" {
			return nil, fmt.Errorf("smtp: TLS enabled but no data dir configured")
		}
		cert, err := loadOrGenerateTLSCert(cfg.DataDir)
		if err != nil {
			return nil, err
		}
		// TLS 1.3 floor — STARTTLS here is opportunistic LAN encryption for
		// modern clients (Grafana etc.), so the weaker 1.2 handshake buys nothing.
		gs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		s.tlsOn = true
	}

	s.gosmtp = gs
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	s.startedAt = time.Now()
	s.mu.Unlock()
	tlsNote := "STARTTLS disabled (plaintext only)"
	if s.tlsOn {
		tlsNote = "STARTTLS available (self-signed cert; clients must skip cert verification)"
	}
	logging.Info("smtp: listening on %s (full-email routing, AUTH PLAIN/LOGIN required, password = notify API key, %s)", s.cfg.Listen, tlsNote)
	if s.allowlistIncludesPublic() {
		logging.Warn("smtp: trusted_networks admits public IP space — the gateway is reachable from the internet; ensure this is intentional")
	}

	// Reap idle per-IP buckets so changing source IPs can't grow the map.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.limiter.reap(time.Now(), 5*time.Minute)
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.gosmtp.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.gosmtp.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		if errors.Is(err, gosmtp.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("smtp listener: %w", err)
	}
}

type backend struct {
	server *Server
}

func (b *backend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	host, _, err := net.SplitHostPort(c.Conn().RemoteAddr().String())
	if err != nil {
		host = c.Conn().RemoteAddr().String()
	}
	// Drop off-LAN sources before AUTH so the base64 password never reaches
	// an untrusted peer. The socket binds broadly for host-networked Docker;
	// this allowlist is what enforces the LAN-only contract.
	if !b.server.ipTrusted(host) {
		logging.Warn("smtp: rejected connection from %s (not in trusted_networks)", host)
		return nil, &gosmtp.SMTPError{
			Code:         554,
			EnhancedCode: gosmtp.EnhancedCode{5, 7, 1},
			Message:      "connection not permitted",
		}
	}
	if !b.server.limiter.Allow(host) {
		// 421 so the client retries instead of bouncing permanently.
		return nil, &gosmtp.SMTPError{
			Code:         421,
			EnhancedCode: gosmtp.EnhancedCode{4, 7, 0},
			Message:      "rate limit exceeded; try again later",
		}
	}
	return &session{
		server:    b.server,
		remoteIP:  host,
		recipient: nil,
	}, nil
}
