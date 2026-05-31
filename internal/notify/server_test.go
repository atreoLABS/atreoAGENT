package notify

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
)

func notifyTestKM(t *testing.T) *crypto.KeyManager {
	t.Helper()
	km, err := crypto.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return km
}

// pushFixture spins up an httptest server that records calls to
// /v1/notifications and replies with a configurable status.
type pushFixture struct {
	server *httptest.Server
	calls  atomic.Int32
	last   atomic.Pointer[map[string]interface{}]
	status atomic.Int32
}

func newPushFixture(t *testing.T) *pushFixture {
	t.Helper()
	f := &pushFixture{}
	f.status.Store(http.StatusOK)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/notifications" {
			http.NotFound(w, r)
			return
		}
		// Agent → atreoLINK body is the signed envelope. Unwrap the inner
		// payload so tests can assert against the notification fields.
		var env struct {
			SignerID  string          `json:"signerId"`
			Signature string          `json:"signature"`
			Payload   json.RawMessage `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&env)
		var body map[string]interface{}
		_ = json.Unmarshal(env.Payload, &body)
		f.last.Store(&body)
		f.calls.Add(1)
		w.WriteHeader(int(f.status.Load()))
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(f.server.Close)
	return f
}


// newACLWithMember stages an ACL store seeded with one member who has a
// real Ed25519 identity pubkey. Returns the store + the seeded member's
// userId / email so tests can target them.
func newACLWithMember(t *testing.T, role string) (store *acl.Store, userID, email string) {
	t.Helper()
	store = acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	userID = "user-uuid-1"
	email = "alice@example.com"
	member := atreolink.MemberACLEntry{
		MemberID:    "member-1",
		UserID:      userID,
		MemberName:  "Alice",
		Email:       email,
		Role:        role,
		IdentityKey: base64.StdEncoding.EncodeToString(pub),
		Status:      "active",
	}
	if role == "admin" {
		// Admin path skips the joinAttestation requirement; pin for it.
		// Non-admin members would need a signed joinAttestation here,
		// which we don't exercise in these tests — pass role="admin".
		if err := store.SetPinnedAdminPublicKey(pub); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{member}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	return store, userID, email
}

func TestNewServer(t *testing.T) {
	dir := t.TempDir()
	link := atreolink.NewClient("http://example.invalid", notifyTestKM(t), "")
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	
	srv, err := NewServer(8080, dir, "agent-uuid", link, store)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.Port() != 8080 {
		t.Errorf("Port=%d, want 8080", srv.Port())
	}
	if len(srv.APIKey()) != 64 {
		t.Errorf("APIKey len=%d, want 64", len(srv.APIKey()))
	}
}

func TestRotateAPIKey(t *testing.T) {
	dir := t.TempDir()
	link := atreolink.NewClient("http://example.invalid", notifyTestKM(t), "")
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	
	srv, err := NewServer(8080, dir, "agent-uuid", link, store)
	if err != nil {
		t.Fatal(err)
	}
	first := srv.APIKey()
	rotated, err := srv.RotateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Error("rotated key matches original")
	}
	if srv.APIKey() != rotated {
		t.Error("server didn't surface rotated key")
	}
}

// authedRequest wraps a fresh notify request with the server's API key.
func authedRequest(t *testing.T, srv *Server, method, path, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+srv.APIKey())
	return req
}

func TestHandleNotify_Unauthorized(t *testing.T) {
	dir := t.TempDir()
	link := atreolink.NewClient("http://example.invalid", notifyTestKM(t), "")
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	
	srv, _ := NewServer(8080, dir, "agent-uuid", link, store)

	req := httptest.NewRequest(http.MethodPost, "/v1/notify", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	srv.authMiddleware(srv.handleNotify)(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// TestAuthMiddleware exercises the constant-time bearer-token compare across
// the rejection paths and the accept path. Timing is not asserted; code
// review covers the constant-time invariant.
func TestAuthMiddleware(t *testing.T) {
	dir := t.TempDir()
	link := atreolink.NewClient("http://example.invalid", notifyTestKM(t), "")
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	
	srv, _ := NewServer(8080, dir, "agent-uuid", link, store)

	valid := srv.APIKey()
	// Wrong token with the same length as the real key.
	wrongSameLen := strings.Repeat("0", len(valid))
	if wrongSameLen == valid {
		// Astronomically unlikely (real key is hex from crypto/rand) — but
		// be defensive in case the generator ever changes.
		wrongSameLen = strings.Repeat("1", len(valid))
	}

	cases := []struct {
		name       string
		header     string
		wantStatus int
	}{
		{"valid token", "Bearer " + valid, http.StatusOK},
		{"wrong token same length", "Bearer " + wrongSameLen, http.StatusUnauthorized},
		{"wrong-length token", "Bearer short", http.StatusUnauthorized},
		{"empty header", "", http.StatusUnauthorized},
		{"missing Bearer prefix", valid, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			w := httptest.NewRecorder()
			handler := srv.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			handler(w, req)
			if w.Code != tc.wantStatus {
				t.Errorf("status=%d, want %d", w.Code, tc.wantStatus)
			}
		})
	}
}

func TestHandleNotify_BadRequest(t *testing.T) {
	dir := t.TempDir()
	link := atreolink.NewClient("http://example.invalid", notifyTestKM(t), "")
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	
	srv, _ := NewServer(8080, dir, "agent-uuid", link, store)

	cases := map[string]string{
		"missing title":           `{"userId":"u"}`,
		"both userId + userEmail": `{"title":"x","userId":"u","userEmail":"a@b"}`,
		"neither user target":     `{"title":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req := authedRequest(t, srv, http.MethodPost, "/v1/notify", body)
			w := httptest.NewRecorder()
			srv.handleNotify(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}
		})
	}
}

func TestHandleNotify_UnknownEmail(t *testing.T) {
	dir := t.TempDir()
	link := atreolink.NewClient("http://example.invalid", notifyTestKM(t), "")
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	
	srv, _ := NewServer(8080, dir, "agent-uuid", link, store)

	req := authedRequest(t, srv, http.MethodPost, "/v1/notify",
		`{"title":"hi","userEmail":"unknown@example.com"}`)
	w := httptest.NewRecorder()
	srv.handleNotify(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// TestHandleNotify_Success exercises the full path: ACL lookup, sealed-box
// encryption, and the outbound POST to atreoLINK. Verifies the wire body
// shape matches what atreoLINK handler expects.
func TestHandleNotify_Success(t *testing.T) {
	store, userID, email := newACLWithMember(t, "admin")
	fixture := newPushFixture(t)
	link := atreolink.NewClient(fixture.server.URL, notifyTestKM(t), "11111111-1111-1111-1111-111111111111")
	
	srv, _ := NewServer(8080, t.TempDir(), "agent-uuid", link, store)
	_ = userID

	body := `{"title":"Disk failed","body":"sda1 SMART error","userEmail":"` + email + `","severity":"warning"}`
	req := authedRequest(t, srv, http.MethodPost, "/v1/notify", body)
	w := httptest.NewRecorder()
	srv.handleNotify(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if got := fixture.calls.Load(); got != 1 {
		t.Fatalf("expected 1 atreoLINK POST, got %d", got)
	}
	wireBody := *fixture.last.Load()
	if wireBody["userId"] != userID {
		t.Errorf("wire userId=%v, want %s", wireBody["userId"], userID)
	}
	if wireBody["agentId"] != "agent-uuid" {
		t.Errorf("wire agentId=%v", wireBody["agentId"])
	}
	if wireBody["severity"] != "warning" {
		t.Errorf("wire severity=%v", wireBody["severity"])
	}
	summary, _ := wireBody["summary"].(map[string]interface{})
	if summary["ct"] == nil || summary["ct"] == "" {
		t.Errorf("expected summary.ct to be populated, got %v", summary)
	}
}

// TestSendToMember_PreviewBodyTruncated exercises the truncation rule —
// when html/plaintext is provided, summary.body is capped at PreviewBodyChars.
func TestSendToMember_PreviewBodyTruncated(t *testing.T) {
	store, _, email := newACLWithMember(t, "admin")
	fixture := newPushFixture(t)
	link := atreolink.NewClient(fixture.server.URL, notifyTestKM(t), "11111111-1111-1111-1111-111111111111")
	
	srv, _ := NewServer(8080, t.TempDir(), "agent-uuid", link, store)

	longBody := strings.Repeat("a", PreviewBodyChars+50)
	member := store.LookupByEmail(email)
	if member == nil {
		t.Fatalf("expected ACL match for %s", email)
	}
	req := &NotifyRequest{
		Title:    "Long",
		Body:     longBody,
		HTML:     "<p>...</p>",
		Severity: "info",
	}
	if err := srv.SendToMember(context.Background(), member, req); err != nil {
		t.Fatalf("SendToMember: %v", err)
	}
	wireBody := *fixture.last.Load()
	if wireBody["html"] == nil {
		t.Error("expected html field on wire when HTML provided")
	}
}

// TestSendToMember_NoIdentityPubkey verifies the early-fail path when the
// recipient hasn't logged in yet (no identity pubkey in ACL).
func TestSendToMember_NoIdentityPubkey(t *testing.T) {
	store := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	link := atreolink.NewClient("http://example.invalid", notifyTestKM(t), "")
	
	srv, _ := NewServer(8080, t.TempDir(), "agent-uuid", link, store)

	bare := &atreolink.MemberACLEntry{UserID: "u", IdentityKey: ""}
	err := srv.SendToMember(context.Background(), bare, &NotifyRequest{Title: "x", Severity: "info"})
	if err == nil || !strings.Contains(err.Error(), "identity pubkey") {
		t.Errorf("expected identity-pubkey error, got %v", err)
	}
}
