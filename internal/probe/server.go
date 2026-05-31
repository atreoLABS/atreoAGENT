// Package probe serves GET /atreo/ping so paired clients can prove a
// `lan` endpoint candidate is the server they actually paired with. It's
// bound only to the advertised LAN IPs — never 0.0.0.0/:: — and returns
// an Ed25519 signature over {deviceId, nonce, timestamp}.
package probe

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

type Config struct {
	DeviceID   string
	PrivateKey ed25519.PrivateKey
	Clock      func() time.Time // nil → time.Now (test hook)
}

// One listener per LAN IP; the set is mutable via SetBindAddresses.
type Server struct {
	cfg     Config
	handler http.Handler

	mu        sync.Mutex
	listeners map[string]*boundListener // host:port → listener
	ctx       context.Context
	cancel    context.CancelFunc

	rateMu  sync.Mutex
	buckets map[string]*bucket
}

type boundListener struct {
	server  *http.Server
	netL    net.Listener
	stopped chan struct{}
}

// Leaky bucket — capacity 10, leak 1 token/s (10 req per 10 s).
type bucket struct {
	tokens    float64
	updatedAt time.Time
}

func NewServer(cfg Config) *Server {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	s := &Server{
		cfg:       cfg,
		listeners: map[string]*boundListener{},
		buckets:   map[string]*bucket{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/atreo/ping", s.handlePing)
	// Minimise surface area: anything else 404s.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	s.handler = rateLimitMiddleware(s, mux)
	return s
}

// Listener errors are logged and skipped; remaining listeners still serve.
func (s *Server) Start(ctx context.Context) {
	s.mu.Lock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	// Reap idle rate-limit buckets so a scanner cycling source IPs
	// can't grow the map without bound.
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.reapBuckets(s.cfg.Clock())
			}
		}
	}()
}

// Idle ≥5min → fully leaked, so dropping is equivalent to keeping.
func (s *Server) reapBuckets(now time.Time) {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	for host, b := range s.buckets {
		if now.Sub(b.updatedAt) > 5*time.Minute {
			delete(s.buckets, host)
		}
	}
}

// Reconciles listeners against addrs (host:port). Shutdown (not Close)
// lets in-flight signatures finish; the handler is CPU-bound.
func (s *Server) SetBindAddresses(addrs []string) {
	want := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		want[a] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for addr, bl := range s.listeners {
		if _, keep := want[addr]; keep {
			continue
		}
		go s.shutdownListener(bl, addr)
		delete(s.listeners, addr)
	}

	for addr := range want {
		if _, exists := s.listeners[addr]; exists {
			continue
		}
		bl, err := s.startListener(addr)
		if err != nil {
			logging.Warn("probe: failed to bind %s: %v (skipping — other LAN addresses still serve)", addr, err)
			continue
		}
		s.listeners[addr] = bl
	}
}

// Safe to call multiple times.
func (s *Server) Stop() {
	s.mu.Lock()
	bls := s.listeners
	s.listeners = map[string]*boundListener{}
	cancel := s.cancel
	s.mu.Unlock()

	for addr, bl := range bls {
		s.shutdownListener(bl, addr)
	}
	if cancel != nil {
		cancel()
	}
}

func (s *Server) startListener(addr string) (*boundListener, error) {
	// addr is "host:port", never ":port" — binding to ":port" would
	// expose the probe on every interface including the public one.
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:      s.handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
		ErrorLog:     logging.StdLoggerAt(slog.LevelDebug),
	}
	bl := &boundListener{server: srv, netL: l, stopped: make(chan struct{})}
	go func() {
		defer close(bl.stopped)
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Error("probe: listener on %s exited: %v", addr, err)
		}
	}()
	logging.Info("probe: serving /atreo/ping on %s", addr)
	return bl, nil
}

func (s *Server) shutdownListener(bl *boundListener, addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := bl.server.Shutdown(ctx); err != nil {
		logging.Error("probe: shutdown %s: %v", addr, err)
	}
	<-bl.stopped
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	deviceID := q.Get("deviceId")
	nonceB64 := q.Get("nonce")

	// 404 (not 403) so scanners can't distinguish a wrong deviceId
	// from a missing route. Defence in depth.
	if deviceID != s.cfg.DeviceID {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Spec is URL-safe base64; standard is tolerated for ease of curl.
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		nonce, err = base64.StdEncoding.DecodeString(nonceB64)
	}
	if err != nil || len(nonce) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	timestamp := s.cfg.Clock().UTC().Format(time.RFC3339Nano)

	// Must match what clients re-canonicalise. Nonce emitted as
	// standard-base64 — same as every other signed envelope here.
	canon, err := canonjson.Marshal(map[string]any{
		"deviceId":  s.cfg.DeviceID,
		"nonce":     base64.StdEncoding.EncodeToString(nonce),
		"timestamp": timestamp,
	})
	if err != nil {
		// Shouldn't happen — three known-string fields — but never
		// emit an unsigned response.
		http.Error(w, "", http.StatusInternalServerError)
		return
	}

	sig := ed25519.Sign(s.cfg.PrivateKey, canon)

	resp := map[string]string{
		"deviceId":  s.cfg.DeviceID,
		"timestamp": timestamp,
		"signature": base64.StdEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(resp)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// Per-source-IP leaky bucket; wraps the whole mux so scanners on the
// 404 path get throttled too.
func rateLimitMiddleware(s *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !s.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allow(host string) bool {
	const capacity = 10.0
	const leakPerSec = 1.0

	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := s.cfg.Clock()
	b := s.buckets[host]
	if b == nil {
		b = &bucket{tokens: 0, updatedAt: now}
		s.buckets[host] = b
	}
	elapsed := now.Sub(b.updatedAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b.tokens -= elapsed * leakPerSec
	if b.tokens < 0 {
		b.tokens = 0
	}
	b.updatedAt = now
	if b.tokens+1 > capacity {
		return false
	}
	b.tokens++
	return true
}

// host:port strings from IPs for a shared port.
func BindAddressesFor(ips []net.IP, port int) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port)))
	}
	return out
}
