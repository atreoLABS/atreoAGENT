package certs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
)

func issuerTestKM(t *testing.T) *crypto.KeyManager {
	t.Helper()
	km, err := crypto.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return km
}

// TestIsAllowedFQDN_DirectPath: cert for atreoLINK's own zone slice,
// where the TXT lives directly at `_acme-challenge.<suffix>`. No
// CNAME delegation involved.
func TestIsAllowedFQDN_DirectPath(t *testing.T) {
	p := &atreoLinkDNSProvider{
		currentSuffix: "6bfc332d-a1c2-47f2-87db-4a41130569be.atreo.link",
		deviceID:      "6bfc332d-a1c2-47f2-87db-4a41130569be",
	}
	if !p.isAllowedFQDN("_acme-challenge.6bfc332d-a1c2-47f2-87db-4a41130569be.atreo.link") {
		t.Error("direct-path FQDN should be allowed")
	}
}

// TestIsAllowedFQDN_CNAMEDelegated: cert for a user-controlled
// custom domain (harvey.xyz). The user's `_acme-challenge.harvey.xyz`
// CNAMEs to `acme.<deviceID>.atreo.link`; lego follows the CNAME and
// asks the provider to write the TXT at the delegated target. The
// scope check must allow it because the deviceID label scopes the
// write to this device's atreoLINK zone slice.
func TestIsAllowedFQDN_CNAMEDelegated(t *testing.T) {
	p := &atreoLinkDNSProvider{
		currentSuffix: "harvey.xyz",
		deviceID:      "6bfc332d-a1c2-47f2-87db-4a41130569be",
	}
	if !p.isAllowedFQDN("acme.6bfc332d-a1c2-47f2-87db-4a41130569be.atreo.link") {
		t.Error("CNAME-delegated FQDN inside the agent's zone slice should be allowed")
	}
}

// TestIsAllowedFQDN_CrossTenantRejected: another device's deviceID
// shows up in the FQDN. Reject — atreoLINK would also refuse, but
// defence in depth.
func TestIsAllowedFQDN_CrossTenantRejected(t *testing.T) {
	p := &atreoLinkDNSProvider{
		currentSuffix: "harvey.xyz",
		deviceID:      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
	}
	// Different deviceID inside the FQDN.
	if p.isAllowedFQDN("acme.bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb.atreo.link") {
		t.Error("another device's zone slice must NOT be allowed")
	}
	// Completely unrelated domain.
	if p.isAllowedFQDN("_acme-challenge.attacker.example") {
		t.Error("unrelated FQDN must NOT be allowed")
	}
}

// TestIsAllowedFQDN_LabelBoundary: the deviceID-as-label check must
// not false-positive on a substring match where the deviceID is part
// of a larger label.
func TestIsAllowedFQDN_LabelBoundary(t *testing.T) {
	p := &atreoLinkDNSProvider{
		currentSuffix: "harvey.xyz",
		deviceID:      "abcd",
	}
	// "abcdef" contains "abcd" as a substring but not a label.
	if p.isAllowedFQDN("acme.abcdef.atreo.link") {
		t.Error("substring-match must NOT count — deviceID must appear as a whole label")
	}
}

// TestDNSProvider_PresentScopeMismatch — Present rejects an FQDN
// that fails both legitimate shapes, and never dispatches to
// atreoLINK.
func TestDNSProvider_PresentScopeMismatch(t *testing.T) {
	var called atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	link := atreolink.NewClient(ts.URL, issuerTestKM(t), "")

	p := &atreoLinkDNSProvider{
		atreolink:     link,
		ctx:           context.Background(),
		currentSuffix: "alice.atreo.link",
		deviceID:      "dev-alice",
	}
	err := p.Present("attacker.example", "tok", "key-auth-stub")
	if err == nil {
		t.Fatal("expected scope-mismatch error from Present")
	}
	if !strings.Contains(err.Error(), "scope mismatch") {
		t.Errorf("err=%q, want scope-mismatch wording", err.Error())
	}
	if called.Load() != 0 {
		t.Errorf("atreoLINK called %d times despite scope mismatch", called.Load())
	}
}

func TestDNSProvider_CleanUpScopeMismatch(t *testing.T) {
	var called atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	link := atreolink.NewClient(ts.URL, issuerTestKM(t), "")

	p := &atreoLinkDNSProvider{
		atreolink:     link,
		ctx:           context.Background(),
		currentSuffix: "alice.atreo.link",
		deviceID:      "dev-alice",
	}
	if err := p.CleanUp("attacker.example", "tok", "key-auth-stub"); err == nil {
		t.Fatal("expected scope-mismatch error from CleanUp")
	}
	if called.Load() != 0 {
		t.Errorf("atreoLINK called %d times despite scope mismatch", called.Load())
	}
}

// TestLoadOrCreateAccountKey_GeneratesAndReloads exercises the
// generate + roundtrip path: first call creates the key at
// `acme_account.key` under keysDir, second call returns the same bytes.
func TestLoadOrCreateAccountKey_GeneratesAndReloads(t *testing.T) {
	keysDir := t.TempDir()
	iss := NewIssuer(keysDir, "ops@example.com", "dev-test", nil)

	k1, err := iss.loadOrCreateAccountKey()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if k1 == nil {
		t.Fatal("nil key from generate path")
	}
	if _, err := os.Stat(filepath.Join(keysDir, "acme_account.key")); err != nil {
		t.Errorf("expected acme_account.key on disk: %v", err)
	}

	k2, err := iss.loadOrCreateAccountKey()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if k2 == nil {
		t.Fatal("nil key from load path")
	}
}

// TestIssueCert_RejectsEmptySuffix is the fast-fail input gate. The
// real ACME path isn't exercised (no atreolink, no ACA), but the
// pre-flight rejection is.
func TestIssueCert_RejectsEmptySuffix(t *testing.T) {
	iss := NewIssuer(t.TempDir(), "ops@example.com", "dev-test", nil)
	err := iss.IssueCert(context.Background(), "", "/tmp/cert.pem", "/tmp/key.pem")
	if err == nil || !strings.Contains(err.Error(), "empty suffix") {
		t.Errorf("got %v, want empty-suffix error", err)
	}
}
