package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/certs"
	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

// Per-app routing by Host header: <slug>.<suffix>. The legacy "atreolink" host
// and the whole "atreo-" prefix are reserved for internal probe hosts (atreo-net,
// atreo-lan) that short-circuit to the reachability response instead of resolving
// an app; reserving the prefix lets new ones be added without a client change.
const (
	atreolinkSlug      = "atreolink"
	reservedSlugPrefix = "atreo-"
)

// atreoLINK rejects these slugs on app write; matching here too is defence in
// depth so a stray record can't shadow a probe host.
func isReservedSlug(slug string) bool {
	return slug == atreolinkSlug || strings.HasPrefix(slug, reservedSlugPrefix)
}

// TLS 1.3 floor: clients are modern browsers / first-party apps, so there
// is no reason to negotiate the weaker 1.2 handshake. Lower here (and in the
// SMTP STARTTLS path) only if a legacy client is ever shown to need it.
const tlsMinVersion = tls.VersionTLS13

type Server struct {
	aclStore        *acl.Store
	listen          string
	httpListen      string
	registry        *certs.Registry
	trustedNetworks []*net.IPNet
	overlayNets     []*net.IPNet
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
		overlayNets:     ParseTrustedNetworks([]string{config.OverlaySubnetV4, config.OverlaySubnetV6}),
		webOrigin:       webOrigin,
	}

	// No upstream keep-alives: a POST that reuses a pooled conn the backend already closed can't be retried and 502s.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableKeepAlives = true
	if r := newDockerResolver(defaultDockerSock); r != nil {
		t.DialContext = r.dialContext
		logging.Info("Docker socket found — container name resolution enabled for app URLs")
	}
	s.transport = t

	s.httpServer = &http.Server{
		Addr:    httpsListen,
		Handler: s,
		// Slowloris defence; the proxy binds 0.0.0.0 so LAN/tunnel clients
		// reach it. Bodies can be large app uploads, so only the header
		// read is bounded here, not the whole request.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logging.StdLoggerAt(slog.LevelDebug),
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
			MinVersion:     tlsMinVersion,
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

	if isReservedSlug(slug) {
		s.serveReserved(w, r, sourceIP)
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
			if pa := s.aclStore.FindPortAppBySlug(slug); isWebPort(pa) {
				s.redirectPortApp(w, r, pa, sourceIP)
				return
			}
			logging.Warn("Proxy: 404 — app slug %q not found in ACL", slug)
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		s.proxyTo(w, r, app, slug)
		return
	}

	allowed, app := s.aclStore.IsAppAllowed(sourceIP, slug)
	if !allowed {
		if ok, pa := s.aclStore.IsPortAppAllowed(sourceIP, slug); ok && isWebPort(pa) {
			s.redirectPortApp(w, r, pa, sourceIP)
			return
		}
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

// serveReserved answers a reserved probe host. GET /net reports which address
// a tunnel/trusted client reached us on (so it can build port-app URLs for
// where it is); every other path stays a bare 204 — the reachability canary.
func (s *Server) serveReserved(w http.ResponseWriter, r *http.Request, sourceIP string) {
	if s.webOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", s.webOrigin)
		w.Header().Set("Vary", "Origin")
	}
	if r.Method == http.MethodGet && r.URL.Path == "/net" {
		via := ""
		switch {
		case IsTrusted(sourceIP, s.overlayNets):
			via = "tunnel"
		case IsTrusted(sourceIP, s.trustedNetworks):
			via = "lan"
		}
		if host := localIP(r); via != "" && host != "" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(map[string]string{"via": via, "host": host})
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// isWebPort reports whether a port app is redirect-able: only http/https can
// be followed by a browser to host:port.
func isWebPort(app *atreolink.App) bool {
	return app != nil && app.IsPort() && (app.Protocol == "http" || app.Protocol == "https") &&
		app.Port >= 1 && app.Port <= 65535
}

// redirectPortApp 307s an http/https port-app slug to the address the client
// reached the proxy on (overlay IP over the tunnel, LAN IP via local DNS) plus
// the app's port. 307 keeps it uncached and method-preserving — the right host
// depends on where the client currently is.
func (s *Server) redirectPortApp(w http.ResponseWriter, r *http.Request, app *atreolink.App, sourceIP string) {
	host := localIP(r)
	if host == "" {
		// No conn info (shouldn't happen under net/http); use the peer family's overlay IP.
		host = config.OverlayServerIPv4
		if ip := net.ParseIP(sourceIP); ip != nil && ip.To4() == nil {
			host = config.OverlayServerIPv6
		}
	}
	target := url.URL{
		Scheme:   app.Protocol,
		Host:     net.JoinHostPort(host, strconv.Itoa(app.Port)),
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}
	http.Redirect(w, r, target.String(), http.StatusTemporaryRedirect)
}

// localIP is the IP this connection was accepted on — the address the client
// dialed, so it is reachable from the client by construction.
func localIP(r *http.Request) string {
	addr, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
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
