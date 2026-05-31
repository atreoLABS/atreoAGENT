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
	tlsOn     bool
	mu        sync.Mutex
	startedAt time.Time
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
		gs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
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
