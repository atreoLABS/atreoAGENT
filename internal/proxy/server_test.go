package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/certs"
)

func TestExtractSlug(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		suffixes []string
		want     string
	}{
		{"single suffix happy", "nextcloud.mynas.atreo.link", []string{"mynas.atreo.link"}, "nextcloud"},
		{"port stripped", "nextcloud.mynas.atreo.link:443", []string{"mynas.atreo.link"}, "nextcloud"},
		{"custom domain shape", "jellyfin.example.com", []string{"example.com"}, "jellyfin"},
		{"no slug (host == suffix)", "mynas.atreo.link", []string{"mynas.atreo.link"}, ""},
		{"foreign zone", "bad.other.com", []string{"mynas.atreo.link"}, ""},
		{"nested label rejected", "a.b.mynas.atreo.link", []string{"mynas.atreo.link"}, ""},
		{"empty host", "", []string{"mynas.atreo.link"}, ""},
		{"empty suffixes", "jellyfin.example.com", nil, ""},
		// Multi-suffix dispatch: the same host could in theory match two
		// suffixes; longest wins. Both suffixes registered, host matches
		// the more-specific one.
		{"longest match wins", "app.alice.atreo.link",
			[]string{"atreo.link", "alice.atreo.link"}, "app"},
		// Custom domain coexisting with the operator-issued hostname —
		// both registered, request hits the custom one.
		{"custom-domain coexists with operator hostname", "jellyfin.example.com",
			[]string{"alice.atreo.link", "example.com"}, "jellyfin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractSlug(tt.host, tt.suffixes); got != tt.want {
				t.Errorf("ExtractSlug(%q, %v) = %q, want %q", tt.host, tt.suffixes, got, tt.want)
			}
		})
	}
}

// proxyTestSetup builds an ACL store with one regular member, one admin, and a
// backend httptest server, returning a configured *Server and the backend.
// The regular member also holds three port apps (http, https, tcp), mirroring
// how admission stamps port grants into AllowedApps.
func proxyTestSetup(t *testing.T) (*Server, *httptest.Server, *acl.Store) {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "backend-ok:"+r.URL.Path)
	}))
	t.Cleanup(backend.Close)

	app := atreolink.App{
		ID:          "app-1",
		Name:        "Nextcloud",
		Slug:        "nextcloud",
		InternalURL: backend.URL,
	}
	webPortApp := atreolink.App{ID: "app-dash", Name: "Dashboard", Slug: "dashboard", Type: "port", Port: 8080, Protocol: "http"}
	tlsPortApp := atreolink.App{ID: "app-secure", Name: "Secure", Slug: "secure", Type: "port", Port: 8443, Protocol: "https"}
	tcpPortApp := atreolink.App{ID: "app-game", Name: "Game", Slug: "game", Type: "port", Port: 25565, Protocol: "tcp"}
	allApps := []atreolink.App{app, webPortApp, tlsPortApp, tcpPortApp}

	dir := t.TempDir()
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{
			MemberID:    "m-regular",
			MemberName:  "Alice",
			Role:        "member",
			AllowedApps: allApps,
			Clients: []atreolink.ClientRecord{
				{WGPublicKey: "pk-regular", TunnelIP: "100.64.0.10", TunnelIPv6: "fd00:64::a"},
			},
		},
		{
			MemberID:   "m-admin",
			MemberName: "Owner",
			Role:       "admin",
			Clients: []atreolink.ClientRecord{
				{WGPublicKey: "pk-admin", TunnelIP: "100.64.0.20"},
			},
		},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	store.SetAppDefinitions(allApps)

	reg := newTestRegistry(t, "mynas.atreo.link")
	srv := NewServer(store, ":0", "", reg, []string{"127.0.0.0/8"}, "https://app.atreolink.com")
	return srv, backend, store
}

// newTestRegistry builds a Registry with a single suffix registered.
// We don't need a real *tls.Certificate for the slug-extraction tests
// (the proxy looks up Suffixes() not Get()), so a placeholder entry via
// AddSuffix is enough.
func newTestRegistry(t *testing.T, suffix string) *certs.Registry {
	t.Helper()
	reg := certs.NewRegistry(t.TempDir())
	reg.AddSuffix(suffix)
	return reg
}

func mkRequest(method, host, path, remoteAddr string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+path, nil)
	r.Host = host
	r.RemoteAddr = remoteAddr
	return r
}

// withLocalAddr stamps the address the connection was accepted on, as
// net/http does for real connections.
func withLocalAddr(r *http.Request, ip string, port int) *http.Request {
	addr := &net.TCPAddr{IP: net.ParseIP(ip), Port: port}
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, addr))
}

func TestServeHTTP_AtreolinkSubdomain(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	for _, path := range []string{"/", "/anything", "/favicon.ico", "/.well-known/foo"} {
		t.Run(path, func(t *testing.T) {
			r := mkRequest("GET", "atreolink.mynas.atreo.link", path, "10.0.0.1:1234")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Errorf("status=%d, want 204", w.Code)
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.atreolink.com" {
				t.Errorf("CORS origin=%q, want https://app.atreolink.com", got)
			}
			if got := w.Header().Get("Vary"); got != "Origin" {
				t.Errorf("Vary=%q, want Origin", got)
			}
		})
	}
}

func TestServeHTTP_AtreolinkSubdomain_NoOriginConfigured(t *testing.T) {
	store := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	reg := newTestRegistry(t, "mynas.atreo.link")
	srv := NewServer(store, ":0", "", reg, nil, "")
	r := mkRequest("GET", "atreolink.mynas.atreo.link", "/", "10.0.0.1:1234")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Errorf("status=%d, want 204", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("CORS origin=%q, want empty when no origin configured", got)
	}
}

func TestServeHTTP_BadRemoteAddr(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/", "no-port-here")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
}

func TestServeHTTP_NoSlug(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "mynas.atreo.link", "/", "100.64.0.10:1234")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", w.Code)
	}
}

func TestServeHTTP_TrustedNetworkBypass(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/x", "127.0.0.1:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status=%d body=%q, want 200", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "backend-ok:/x") {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestServeHTTP_TrustedNetworkUnknownSlug(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "ghost.mynas.atreo.link", "/", "127.0.0.1:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", w.Code)
	}
}

func TestServeHTTP_ACLDeny_UnknownIP(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/", "100.64.0.99:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", w.Code)
	}
}

func TestServeHTTP_ACLDeny_MemberNoApp(t *testing.T) {
	srv, _, store := proxyTestSetup(t)
	// Strip the AllowedApps from the regular member.
	if !store.SetAllowedApps("m-regular", nil) {
		t.Fatal("SetAllowedApps returned false")
	}
	r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/", "100.64.0.10:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", w.Code)
	}
}

func TestServeHTTP_ACLAllow_Member(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/hello", "100.64.0.10:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status=%d body=%q, want 200", w.Code, w.Body.String())
	}
}

func TestServeHTTP_ACLAllow_Admin(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/hi", "100.64.0.20:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status=%d body=%q, want 200", w.Code, w.Body.String())
	}
}

// The proxy must advertise the real client-facing scheme + host so backends
// emit correct absolute URLs (https links, not http). It must also preserve the
// original Host header for vhost-routing backends.
func TestServeHTTP_ForwardedHeaders(t *testing.T) {
	var gotProto, gotFwdHost, gotFwdFor, gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotFwdHost = r.Header.Get("X-Forwarded-Host")
		gotFwdFor = r.Header.Get("X-Forwarded-For")
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	app := atreolink.App{ID: "app-1", Slug: "nextcloud", InternalURL: backend.URL}
	store := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{{
		MemberID: "m", Role: "admin",
		Clients: []atreolink.ClientRecord{{WGPublicKey: "pk", TunnelIP: "100.64.0.10"}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.SetAppDefinitions([]atreolink.App{app})
	reg := newTestRegistry(t, "mynas.atreo.link")
	// Trusted network so the request reaches the backend without ACL setup.
	srv := NewServer(store, ":0", "", reg, []string{"127.0.0.0/8"}, "")

	t.Run("plain http", func(t *testing.T) {
		r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/", "127.0.0.1:5555")
		srv.ServeHTTP(httptest.NewRecorder(), r)
		if gotProto != "http" {
			t.Errorf("X-Forwarded-Proto=%q, want http", gotProto)
		}
		if gotFwdHost != "nextcloud.mynas.atreo.link" {
			t.Errorf("X-Forwarded-Host=%q, want nextcloud.mynas.atreo.link", gotFwdHost)
		}
		if gotHost != "nextcloud.mynas.atreo.link" {
			t.Errorf("backend Host=%q, want original host preserved", gotHost)
		}
		if !strings.Contains(gotFwdFor, "127.0.0.1") {
			t.Errorf("X-Forwarded-For=%q, want it to contain client IP", gotFwdFor)
		}
	})

	t.Run("tls terminated", func(t *testing.T) {
		r := mkRequest("GET", "nextcloud.mynas.atreo.link", "/", "127.0.0.1:5555")
		r.TLS = &tls.ConnectionState{}
		srv.ServeHTTP(httptest.NewRecorder(), r)
		if gotProto != "https" {
			t.Errorf("X-Forwarded-Proto=%q, want https", gotProto)
		}
	})
}

func TestServeHTTP_BadGatewayOnInvalidURL(t *testing.T) {
	dir := t.TempDir()
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	bad := atreolink.App{ID: "x", Slug: "x", InternalURL: "://broken"}
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{{
		MemberID: "m", Role: "admin",
		Clients: []atreolink.ClientRecord{{WGPublicKey: "pk", TunnelIP: "100.64.0.30"}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.SetAppDefinitions([]atreolink.App{bad})
	reg := newTestRegistry(t, "mynas.atreo.link")
	srv := NewServer(store, ":0", "", reg, nil, "")
	r := mkRequest("GET", "x.mynas.atreo.link", "/", "100.64.0.30:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status=%d, want 502", w.Code)
	}
}

// Browsers get the branded HTML page on every reachable error path; the status
// code and guidance copy must both survive end-to-end through ServeHTTP.
func TestServeHTTP_HTMLErrorNegotiation(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		remoteAddr string
		wantStatus int
		wantKind   errorKind
	}{
		{"no slug", "mynas.atreo.link", "100.64.0.10:1234", http.StatusNotFound, errKindNotFound},
		{"trusted unknown app", "ghost.mynas.atreo.link", "127.0.0.1:5555", http.StatusNotFound, errKindNotFound},
		{"acl deny", "nextcloud.mynas.atreo.link", "100.64.0.99:5555", http.StatusForbidden, errKindForbidden},
		{"bad remote addr", "nextcloud.mynas.atreo.link", "no-port-here", http.StatusBadRequest, errKindBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _ := proxyTestSetup(t)
			r := mkRequest("GET", tt.host, "/", tt.remoteAddr)
			r.Header.Set("Accept", browserAccept)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status=%d, want %d", w.Code, tt.wantStatus)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type=%q, want text/html", ct)
			}
			if guidance := html.EscapeString(errorContents[tt.wantKind].guidance); !strings.Contains(w.Body.String(), guidance) {
				t.Errorf("body missing guidance %q", guidance)
			}
		})
	}
}

// The upstream-down 502 page must never leak the backend address or the raw
// dial error to a family member's browser.
func TestServeHTTP_ErrorPage_NoInternalLeakage(t *testing.T) {
	// A listener opened then immediately closed guarantees connection-refused
	// without depending on a port staying free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	app := atreolink.App{ID: "app-x", Slug: "x", InternalURL: "http://" + deadAddr}
	store := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{{
		MemberID: "m", Role: "admin",
		Clients: []atreolink.ClientRecord{{WGPublicKey: "pk", TunnelIP: "100.64.0.30"}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.SetAppDefinitions([]atreolink.App{app})
	reg := newTestRegistry(t, "mynas.atreo.link")
	srv := NewServer(store, ":0", "", reg, []string{"127.0.0.0/8"}, "")

	r := mkRequest("GET", "x.mynas.atreo.link", "/", "127.0.0.1:5555")
	r.Header.Set("Accept", browserAccept)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", w.Code)
	}
	body := w.Body.String()
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type=%q, want text/html", w.Header().Get("Content-Type"))
	}
	for _, leak := range []string{deadAddr, "connection refused", "dial tcp"} {
		if strings.Contains(body, leak) {
			t.Errorf("502 page leaks internal detail %q", leak)
		}
	}
}

// The invalid-URL 502 page must not echo the raw InternalURL back to the client.
func TestServeHTTP_ErrorPage_InvalidURLNoLeak(t *testing.T) {
	store := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	bad := atreolink.App{ID: "x", Slug: "x", InternalURL: "://broken"}
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{{
		MemberID: "m", Role: "admin",
		Clients: []atreolink.ClientRecord{{WGPublicKey: "pk", TunnelIP: "100.64.0.30"}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.SetAppDefinitions([]atreolink.App{bad})
	reg := newTestRegistry(t, "mynas.atreo.link")
	srv := NewServer(store, ":0", "", reg, nil, "")

	r := mkRequest("GET", "x.mynas.atreo.link", "/", "100.64.0.30:5555")
	r.Header.Set("Accept", browserAccept)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", w.Code)
	}
	if strings.Contains(w.Body.String(), "broken") {
		t.Errorf("502 page leaks raw InternalURL")
	}
}

// Guards the fix: reusing a keep-alive conn the backend already closed can't be retried for a POST, so pooling must stay off.
func TestNewServer_DisablesUpstreamKeepAlives(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	tr, ok := srv.transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport (must always clone)", srv.transport)
	}
	if !tr.DisableKeepAlives {
		t.Error("upstream keep-alives must be disabled to avoid stale-pool 502s")
	}
}

// Post-fix contract (reproducing the pre-fix 502 is timing-sensitive): against a conn-closing backend, every GET/POST dials fresh and none 502.
func TestServeHTTP_POSTSurvivesConnectionClosingBackend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	gotBodies := make(chan string, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				body, _ := io.ReadAll(req.Body)
				_ = req.Body.Close()
				gotBodies <- string(body)
				_, _ = io.WriteString(c,
					"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok")
			}(conn)
		}
	}()

	app := atreolink.App{ID: "app-x", Name: "X", Slug: "x", InternalURL: "http://" + ln.Addr().String()}
	dir := t.TempDir()
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{{
		MemberID: "m", Role: "admin",
		Clients: []atreolink.ClientRecord{{WGPublicKey: "pk", TunnelIP: "100.64.0.30"}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.SetAppDefinitions([]atreolink.App{app})
	reg := newTestRegistry(t, "mynas.atreo.link")
	srv := NewServer(store, ":0", "", reg, []string{"127.0.0.0/8"}, "")

	steps := []struct{ method, body string }{
		{"GET", ""},
		{"POST", "first-post-body"},
		{"POST", "second-post-body"},
	}
	for _, s := range steps {
		var body io.Reader
		if s.body != "" {
			body = strings.NewReader(s.body)
		}
		r := httptest.NewRequest(s.method, "http://x.mynas.atreo.link/", body)
		r.Host = "x.mynas.atreo.link"
		r.RemoteAddr = "127.0.0.1:5555"
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d, want 200 (never 502)", s.method, w.Code)
		}
		select {
		case got := <-gotBodies:
			if got != s.body {
				t.Errorf("%s: backend got body %q, want %q", s.method, got, s.body)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: backend never received the request", s.method)
		}
	}
}

// An http/https port app's slug answers with a 307 to the address the client
// dialed, carrying the app's port and preserving path + query.
func TestServeHTTP_PortAppRedirect(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		path         string
		remoteAddr   string
		localIP      string
		wantLocation string
	}{
		{"tunnel member http", "dashboard.mynas.atreo.link", "/some/page?x=1",
			"100.64.0.10:5555", "100.64.0.1", "http://100.64.0.1:8080/some/page?x=1"},
		{"tunnel member https app", "secure.mynas.atreo.link", "/",
			"100.64.0.10:5555", "100.64.0.1", "https://100.64.0.1:8443/"},
		{"tunnel member v6", "dashboard.mynas.atreo.link", "/",
			"[fd00:64::a]:5555", "fd00:64::1", "http://[fd00:64::1]:8080/"},
		{"trusted lan", "dashboard.mynas.atreo.link", "/",
			"127.0.0.1:5555", "192.168.10.9", "http://192.168.10.9:8080/"},
		// No conn-local address available: overlay fallback per family.
		{"missing local addr v4", "dashboard.mynas.atreo.link", "/",
			"100.64.0.10:5555", "", "http://100.64.0.1:8080/"},
		{"missing local addr v6", "dashboard.mynas.atreo.link", "/",
			"[fd00:64::a]:5555", "", "http://[fd00:64::1]:8080/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _ := proxyTestSetup(t)
			r := mkRequest("GET", tt.host, tt.path, tt.remoteAddr)
			if tt.localIP != "" {
				r = withLocalAddr(r, tt.localIP, 443)
			}
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusTemporaryRedirect {
				t.Fatalf("status=%d body=%q, want 307", w.Code, w.Body.String())
			}
			if got := w.Header().Get("Location"); got != tt.wantLocation {
				t.Errorf("Location=%q, want %q", got, tt.wantLocation)
			}
		})
	}
}

func TestServeHTTP_PortAppRedirect_Denied(t *testing.T) {
	t.Run("member without grant", func(t *testing.T) {
		srv, _, store := proxyTestSetup(t)
		if !store.SetAllowedApps("m-regular", nil) {
			t.Fatal("SetAllowedApps returned false")
		}
		r := withLocalAddr(mkRequest("GET", "dashboard.mynas.atreo.link", "/", "100.64.0.10:5555"), "100.64.0.1", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status=%d, want 403", w.Code)
		}
	})

	t.Run("unknown tunnel IP", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := withLocalAddr(mkRequest("GET", "dashboard.mynas.atreo.link", "/", "100.64.0.99:5555"), "100.64.0.1", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status=%d, want 403", w.Code)
		}
	})

	// tcp/udp slugs stay unroutable: nothing a browser could follow.
	t.Run("tcp app member", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := withLocalAddr(mkRequest("GET", "game.mynas.atreo.link", "/", "100.64.0.10:5555"), "100.64.0.1", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("status=%d, want 403", w.Code)
		}
	})

	t.Run("tcp app trusted", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := withLocalAddr(mkRequest("GET", "game.mynas.atreo.link", "/", "127.0.0.1:5555"), "192.168.10.9", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("status=%d, want 404", w.Code)
		}
	})
}

// GET /net on the reserved subdomain reports the network path and the dialed
// address to tunnel/trusted clients; everyone and everything else keeps the
// bare 204 canary.
func TestServeHTTP_ReservedNet(t *testing.T) {
	decode := func(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
		t.Helper()
		var m map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("bad JSON %q: %v", w.Body.String(), err)
		}
		return m
	}

	t.Run("tunnel peer", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := withLocalAddr(mkRequest("GET", "atreolink.mynas.atreo.link", "/net", "100.64.0.10:5555"), "100.64.0.1", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", w.Code)
		}
		if got := decode(t, w); got["via"] != "tunnel" || got["host"] != "100.64.0.1" {
			t.Errorf("body=%v, want via=tunnel host=100.64.0.1", got)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.atreolink.com" {
			t.Errorf("CORS origin=%q", got)
		}
		if got := w.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control=%q, want no-store", got)
		}
	})

	t.Run("trusted lan", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := withLocalAddr(mkRequest("GET", "atreolink.mynas.atreo.link", "/net", "127.0.0.1:5555"), "192.168.10.9", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d, want 200", w.Code)
		}
		if got := decode(t, w); got["via"] != "lan" || got["host"] != "192.168.10.9" {
			t.Errorf("body=%v, want via=lan host=192.168.10.9", got)
		}
	})

	t.Run("unknown source stays canary", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := withLocalAddr(mkRequest("GET", "atreolink.mynas.atreo.link", "/net", "10.0.0.1:5555"), "203.0.113.7", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Errorf("status=%d, want 204", w.Code)
		}
	})

	t.Run("POST stays canary", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := withLocalAddr(mkRequest("POST", "atreolink.mynas.atreo.link", "/net", "100.64.0.10:5555"), "100.64.0.1", 443)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Errorf("status=%d, want 204", w.Code)
		}
	})

	t.Run("missing local addr stays canary", func(t *testing.T) {
		srv, _, _ := proxyTestSetup(t)
		r := mkRequest("GET", "atreolink.mynas.atreo.link", "/net", "100.64.0.10:5555")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusNoContent {
			t.Errorf("status=%d, want 204", w.Code)
		}
	})
}

// The whole atreo- prefix is a reserved namespace: atreo-net (web probe),
// atreo-lan (mobile probe), and any future internal host short-circuit to the
// reachability response instead of resolving an app.
func TestServeHTTP_ReservedPrefix(t *testing.T) {
	for _, host := range []string{"atreo-net", "atreo-lan", "atreo-future"} {
		t.Run(host+" serves /net", func(t *testing.T) {
			srv, _, _ := proxyTestSetup(t)
			r := withLocalAddr(mkRequest("GET", host+".mynas.atreo.link", "/net", "100.64.0.10:5555"), "100.64.0.1", 443)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d, want 200", w.Code)
			}
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("bad JSON %q: %v", w.Body.String(), err)
			}
			if body["via"] != "tunnel" || body["host"] != "100.64.0.1" {
				t.Errorf("body=%v, want via=tunnel host=100.64.0.1", body)
			}
		})
		t.Run(host+" canary on other paths", func(t *testing.T) {
			srv, _, _ := proxyTestSetup(t)
			r := mkRequest("GET", host+".mynas.atreo.link", "/", "10.0.0.1:1234")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Errorf("status=%d, want 204", w.Code)
			}
		})
	}
}

// Over a real TCP connection (no injected context), net/http stamps the
// conn-local address itself — the redirect host and /net must pick it up.
func TestServeHTTP_RealConnLocalAddr(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	wantHost, _, err := net.SplitHostPort(strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	get := func(t *testing.T, host, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("GET", ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("redirect", func(t *testing.T) {
		res := get(t, "dashboard.mynas.atreo.link", "/p?q=1")
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("status=%d, want 307", res.StatusCode)
		}
		want := "http://" + wantHost + ":8080/p?q=1"
		if got := res.Header.Get("Location"); got != want {
			t.Errorf("Location=%q, want %q", got, want)
		}
	})

	t.Run("net", func(t *testing.T) {
		res := get(t, "atreolink.mynas.atreo.link", "/net")
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status=%d, want 200", res.StatusCode)
		}
		var body map[string]string
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["via"] != "lan" || body["host"] != wantHost {
			t.Errorf("body=%v, want via=lan host=%s", body, wantHost)
		}
	})
}
