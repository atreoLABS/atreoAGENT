package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

func authTestStore(t *testing.T) *acl.Store {
	t.Helper()
	dir := t.TempDir()
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	app := atreolink.App{ID: "a", Slug: "nextcloud", InternalURL: "http://example.invalid"}
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{{
		MemberID:    "m1",
		MemberName:  "Alice",
		Role:        "member",
		AllowedApps: []atreolink.App{app},
		Clients:     []atreolink.ClientRecord{{WGPublicKey: "k", TunnelIP: "100.64.0.10"}},
	}}); err != nil {
		t.Fatal(err)
	}
	store.SetAppDefinitions([]atreolink.App{app})
	return store
}

func TestAuthServer_MissingSourceIP(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), nil, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "no-port"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
}

// With no trusted proxy configured, X-Forwarded-For must be ignored: a
// tunnel peer cannot spoof a trusted-network IP to obtain X-Auth-Role:
// admin. The (untrusted) TCP peer address is used instead.
func TestAuthServer_XFFIgnoredWithoutTrustedProxy(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), []string{"192.168.0.0/16"}, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.10:5555" // a tunnel peer (Alice)
	r.Host = "nextcloud.mynas.myatreo.com"
	r.Header.Set("X-Forwarded-For", "192.168.1.5")
	r.Header.Set("X-Forwarded-Host", "junk.example.com")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-User"); got != "Alice" {
		t.Errorf("X-Auth-User=%q, want Alice (spoofed XFF must be ignored)", got)
	}
	if got := w.Header().Get("X-Auth-Role"); got == "admin" {
		t.Errorf("X-Auth-Role=admin: trusted-network bypass reachable via spoofed X-Forwarded-For")
	}
}

// With no trusted proxy configured, X-Forwarded-Host must be ignored so a
// peer can't masquerade as a different app's hostname.
func TestAuthServer_XFHIgnoredWithoutTrustedProxy(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), nil, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.10:5555"
	r.Host = "junk.example.com"
	r.Header.Set("X-Forwarded-Host", "nextcloud.mynas.myatreo.com")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403 (X-Forwarded-Host must be ignored)", w.Code)
	}
}

// When the TCP peer is a configured trusted proxy, X-Forwarded-For is
// honoured (and a leading trusted-network IP grants the LAN bypass).
func TestAuthServer_TrustedProxyHonoursXFF(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"),
		[]string{"192.168.0.0/16"}, []string{"10.1.2.0/24"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.2.3:443" // the trusted proxy
	r.Header.Set("X-Forwarded-For", "  192.168.1.5  , 10.1.2.3")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-User"); got != "local" {
		t.Errorf("X-Auth-User=%q, want local", got)
	}
	if got := w.Header().Get("X-Auth-Role"); got != "admin" {
		t.Errorf("X-Auth-Role=%q, want admin", got)
	}
}

// A trusted proxy may also supply the original Host via X-Forwarded-Host.
func TestAuthServer_TrustedProxyHonoursXFH(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), nil, []string{"10.1.2.0/24"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.2.3:443"
	r.Host = "junk.example.com"
	r.Header.Set("X-Forwarded-For", "100.64.0.10")
	r.Header.Set("X-Forwarded-Host", "nextcloud.mynas.myatreo.com")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-User"); got != "Alice" {
		t.Errorf("X-Auth-User=%q, want Alice", got)
	}
	if got := w.Header().Get("X-Auth-Member-ID"); got != "m1" {
		t.Errorf("X-Auth-Member-ID=%q, want m1", got)
	}
}

func TestAuthServer_UnknownHost(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), nil, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.10:5555"
	r.Host = "junk.example.com"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", w.Code)
	}
}

func TestAuthServer_ACLDeny(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), nil, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.99:5555" // unknown member
	r.Host = "nextcloud.mynas.myatreo.com"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("status=%d, want 403", w.Code)
	}
}

func TestAuthServer_ACLAllow(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), nil, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.10:5555"
	r.Host = "nextcloud.mynas.myatreo.com"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", w.Code)
	}
	if got := w.Header().Get("X-Auth-User"); got != "Alice" {
		t.Errorf("X-Auth-User=%q, want Alice", got)
	}
	if got := w.Header().Get("X-Auth-Member-ID"); got != "m1" {
		t.Errorf("X-Auth-Member-ID=%q, want m1", got)
	}
}

func TestAuthServer_FallbackToHostHeader(t *testing.T) {
	s := NewAuthServer(authTestStore(t), ":0", newTestRegistry(t, "mynas.myatreo.com"), nil, nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "100.64.0.10:1234"
	r.Host = "nextcloud.mynas.myatreo.com"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("status=%d, want 200", w.Code)
	}
}
