package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/certs"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

// Per-app routing by Host header: <slug>.<suffix>. The reserved slug
// "atreolink" short-circuits to 204 for the web UI's tunnel status probe.
const atreolinkSlug = "atreolink"

type Server struct {
	aclStore        *acl.Store
	listen          string
	httpListen      string
	registry        *certs.Registry
	trustedNetworks []*net.IPNet
	webOrigin       string
	httpServer      *http.Server
	transport       http.RoundTripper
}

func NewServer(aclStore *acl.Store, httpsListen, httpListen string, registry *certs.Registry, trustedCIDRs []string, webOrigin string) *Server {
	s := &Server{
		aclStore:        aclStore,
		listen:          httpsListen,
		httpListen:      httpListen,
		registry:        registry,
		trustedNetworks: ParseTrustedNetworks(trustedCIDRs),
		webOrigin:       webOrigin,
	}

	if r := newDockerResolver(defaultDockerSock); r != nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = r.dialContext
		s.transport = t
		logging.Info("Docker socket found — container name resolution enabled for app URLs")
	} else {
		s.transport = http.DefaultTransport
	}

	s.httpServer = &http.Server{
		Addr:     httpsListen,
		Handler:  s,
		ErrorLog: logging.StdLoggerAt(slog.LevelDebug),
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.httpServer.Close()
	}()

	if s.registry != nil && s.registry.HasAny() {
		s.httpServer.TLSConfig = &tls.Config{
			GetCertificate: s.registry.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		}
		logging.Info("Proxy server starting on %s (HTTPS, %d cert(s))", s.listen, len(s.registry.Suffixes()))
		// Empty paths → ListenAndServeTLS uses TLSConfig.
		if err := s.httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	if s.httpListen != "" {
		s.listen = s.httpListen
		s.httpServer.Addr = s.httpListen
	}
	logging.Info("Proxy server starting on %s (HTTP — no certs available)", s.listen)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sourceIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	suffixes := s.suffixes()
	slug := ExtractSlug(r.Host, suffixes)

	if slug == atreolinkSlug {
		if s.webOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", s.webOrigin)
			w.Header().Set("Vary", "Origin")
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	logging.Debug("Proxy: %s → Host=%q suffixes=%v slug=%q sourceIP=%s",
		r.Method, r.Host, suffixes, slug, sourceIP)
	if slug == "" {
		logging.Warn("Proxy: 404 — no slug extracted from Host=%q (suffixes=%v)", r.Host, suffixes)
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if IsTrusted(sourceIP, s.trustedNetworks) {
		logging.Debug("Proxy: trusted network, bypassing ACL for %s", sourceIP)
		app := s.aclStore.FindAppBySlug(slug)
		if app == nil {
			logging.Warn("Proxy: 404 — app slug %q not found in ACL", slug)
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		s.proxyTo(w, r, app, slug)
		return
	}

	allowed, app := s.aclStore.IsAppAllowed(sourceIP, slug)
	if !allowed {
		member := s.aclStore.LookupByTunnelIP(sourceIP)
		if member == nil {
			logging.Warn("Proxy: 403 — no member found for tunnel IP %s", sourceIP)
		} else {
			logging.Warn("Proxy: 403 — member %s (role=%s) denied access to slug %q",
				member.MemberName, member.Role, slug)
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	s.proxyTo(w, r, app, slug)
}

func (s *Server) proxyTo(w http.ResponseWriter, r *http.Request, app *atreolink.App, slug string) {
	target, err := url.Parse(app.InternalURL)
	if err != nil {
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	proxy := &httputil.ReverseProxy{
		Transport: s.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Host = pr.In.Host // SetURL blanks Out.Host; preserve vhost passthrough.
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			logging.Error("Proxy error for %s: %v", slug, err)
			http.Error(w, "Bad gateway", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) suffixes() []string {
	if s.registry == nil {
		return nil
	}
	return s.registry.Suffixes()
}

// Longest-suffix-first match against <slug>.<suffix>. Slug must be a
// single label — wildcard certs cover one level.
func ExtractSlug(host string, suffixes []string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || len(suffixes) == 0 {
		return ""
	}

	// Defensive sort — ExtractSlug is exported.
	ordered := append([]string(nil), suffixes...)
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) != len(ordered[j]) {
			return len(ordered[i]) > len(ordered[j])
		}
		return ordered[i] < ordered[j]
	})

	for _, suf := range ordered {
		if suf == "" {
			continue
		}
		full := "." + suf
		if !strings.HasSuffix(host, full) {
			continue
		}
		slug := strings.TrimSuffix(host, full)
		if slug == "" || strings.Contains(slug, ".") {
			continue
		}
		return slug
	}
	return ""
}
