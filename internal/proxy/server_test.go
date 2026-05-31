package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
		{"single suffix happy", "nextcloud.mynas.myatreo.com", []string{"mynas.myatreo.com"}, "nextcloud"},
		{"port stripped", "nextcloud.mynas.myatreo.com:443", []string{"mynas.myatreo.com"}, "nextcloud"},
		{"custom domain shape", "jellyfin.example.com", []string{"example.com"}, "jellyfin"},
		{"no slug (host == suffix)", "mynas.myatreo.com", []string{"mynas.myatreo.com"}, ""},
		{"foreign zone", "bad.other.com", []string{"mynas.myatreo.com"}, ""},
		{"nested label rejected", "a.b.mynas.myatreo.com", []string{"mynas.myatreo.com"}, ""},
		{"empty host", "", []string{"mynas.myatreo.com"}, ""},
		{"empty suffixes", "jellyfin.example.com", nil, ""},
		// Multi-suffix dispatch: the same host could in theory match two
		// suffixes; longest wins. Both suffixes registered, host matches
		// the more-specific one.
		{"longest match wins", "app.alice.myatreo.com",
			[]string{"myatreo.com", "alice.myatreo.com"}, "app"},
		// Custom domain coexisting with the operator-issued hostname —
		// both registered, request hits the custom one.
		{"custom-domain coexists with operator hostname", "jellyfin.example.com",
			[]string{"alice.myatreo.com", "example.com"}, "jellyfin"},
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

	dir := t.TempDir()
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{
			MemberID:    "m-regular",
			MemberName:  "Alice",
			Role:        "member",
			AllowedApps: []atreolink.App{app},
			Clients: []atreolink.ClientRecord{
				{WGPublicKey: "pk-regular", TunnelIP: "100.64.0.10"},
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
	store.SetAppDefinitions([]atreolink.App{app})

	reg := newTestRegistry(t, "mynas.myatreo.com")
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

func TestServeHTTP_AtreolinkSubdomain(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	for _, path := range []string{"/", "/anything", "/favicon.ico", "/.well-known/foo"} {
		t.Run(path, func(t *testing.T) {
			r := mkRequest("GET", "atreolink.mynas.myatreo.com", path, "10.0.0.1:1234")
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
	reg := newTestRegistry(t, "mynas.myatreo.com")
	srv := NewServer(store, ":0", "", reg, nil, "")
	r := mkRequest("GET", "atreolink.mynas.myatreo.com", "/", "10.0.0.1:1234")
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
	r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/", "no-port-here")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
}

func TestServeHTTP_NoSlug(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "mynas.myatreo.com", "/", "100.64.0.10:1234")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", w.Code)
	}
}

func TestServeHTTP_TrustedNetworkBypass(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/x", "127.0.0.1:5555")
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
	r := mkRequest("GET", "ghost.mynas.myatreo.com", "/", "127.0.0.1:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", w.Code)
	}
}

func TestServeHTTP_ACLDeny_UnknownIP(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/", "100.64.0.99:5555")
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
	r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/", "100.64.0.10:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", w.Code)
	}
}

func TestServeHTTP_ACLAllow_Member(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/hello", "100.64.0.10:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status=%d body=%q, want 200", w.Code, w.Body.String())
	}
}

func TestServeHTTP_ACLAllow_Admin(t *testing.T) {
	srv, _, _ := proxyTestSetup(t)
	r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/hi", "100.64.0.20:5555")
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
	reg := newTestRegistry(t, "mynas.myatreo.com")
	// Trusted network so the request reaches the backend without ACL setup.
	srv := NewServer(store, ":0", "", reg, []string{"127.0.0.0/8"}, "")

	t.Run("plain http", func(t *testing.T) {
		r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/", "127.0.0.1:5555")
		srv.ServeHTTP(httptest.NewRecorder(), r)
		if gotProto != "http" {
			t.Errorf("X-Forwarded-Proto=%q, want http", gotProto)
		}
		if gotFwdHost != "nextcloud.mynas.myatreo.com" {
			t.Errorf("X-Forwarded-Host=%q, want nextcloud.mynas.myatreo.com", gotFwdHost)
		}
		if gotHost != "nextcloud.mynas.myatreo.com" {
			t.Errorf("backend Host=%q, want original host preserved", gotHost)
		}
		if !strings.Contains(gotFwdFor, "127.0.0.1") {
			t.Errorf("X-Forwarded-For=%q, want it to contain client IP", gotFwdFor)
		}
	})

	t.Run("tls terminated", func(t *testing.T) {
		r := mkRequest("GET", "nextcloud.mynas.myatreo.com", "/", "127.0.0.1:5555")
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
	reg := newTestRegistry(t, "mynas.myatreo.com")
	srv := NewServer(store, ":0", "", reg, nil, "")
	r := mkRequest("GET", "x.mynas.myatreo.com", "/", "100.64.0.30:5555")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadGateway {
		t.Errorf("status=%d, want 502", w.Code)
	}
}
