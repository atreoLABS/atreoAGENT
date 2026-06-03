package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/certs"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

// Forward-auth endpoint for Traefik / Caddy / nginx. 200 = allow,
// 403 = deny. X-Forwarded-* honoured only from trusted_proxies.
type AuthServer struct {
	aclStore        *acl.Store
	listen          string
	registry        *certs.Registry
	trustedNetworks []*net.IPNet
	trustedProxies  []*net.IPNet
	httpServer      *http.Server
}

// trustedProxyCIDRs — upstream proxies whose X-Forwarded-* headers
// may be trusted. nil disables those headers.
func NewAuthServer(aclStore *acl.Store, listen string, registry *certs.Registry, trustedCIDRs, trustedProxyCIDRs []string) *AuthServer {
	s := &AuthServer{
		aclStore:        aclStore,
		listen:          listen,
		registry:        registry,
		trustedNetworks: ParseTrustedNetworks(trustedCIDRs),
		trustedProxies:  ParseTrustedNetworks(trustedProxyCIDRs),
	}
	s.httpServer = &http.Server{
		Addr:    listen,
		Handler: s,
		// Slowloris defence; forward-auth subrequests are tiny, so bound the
		// whole request, not just the header read.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          logging.StdLoggerAt(slog.LevelDebug),
	}
	return s
}

func (s *AuthServer) Start(ctx context.Context) error {
	logging.Info("Auth server starting on %s", s.listen)

	go func() {
		<-ctx.Done()
		_ = s.httpServer.Close()
	}()

	err := s.httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// 200 (X-Auth-User) on allow, 403 on deny, 400 on missing info.
func (s *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Without the gate any tunnel peer could spoof another peer's IP
	// or escalate to a trusted-network IP.
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	var sourceIP, host string
	if remoteIP != "" && IsTrusted(remoteIP, s.trustedProxies) {
		sourceIP = r.Header.Get("X-Forwarded-For")
		if sourceIP == "" {
			sourceIP = r.Header.Get("X-Real-IP")
		}
		// XFF may carry multiple IPs — take the first.
		sourceIP, _, _ = strings.Cut(sourceIP, ",")
		sourceIP = strings.TrimSpace(sourceIP)
		if sourceIP == "" {
			sourceIP = remoteIP
		}
		host = r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
	} else {
		sourceIP = remoteIP
		host = r.Host
	}

	if sourceIP == "" {
		http.Error(w, "missing source IP", http.StatusBadRequest)
		return
	}

	if IsTrusted(sourceIP, s.trustedNetworks) {
		w.Header().Set("X-Auth-User", "local")
		w.Header().Set("X-Auth-Role", "admin")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
		return
	}

	var suffixes []string
	if s.registry != nil {
		suffixes = s.registry.Suffixes()
	}
	slug := ExtractSlug(host, suffixes)
	if slug == "" {
		http.Error(w, "unknown host", http.StatusForbidden)
		return
	}

	allowed, _ := s.aclStore.IsAppAllowed(sourceIP, slug)
	if !allowed {
		logging.Warn("Auth denied: %s → %s (slug: %s)", sourceIP, host, slug)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	member := s.aclStore.LookupByTunnelIP(sourceIP)
	if member != nil {
		w.Header().Set("X-Auth-User", member.MemberName)
		w.Header().Set("X-Auth-Member-ID", member.MemberID)
		w.Header().Set("X-Auth-Role", member.Role)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ok")
}
