package atreolink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/crypto"
)

// testKeyManager builds a KeyManager backed by a fresh temp keys dir so each
// test gets an isolated keypair.
func testKeyManager(t *testing.T) *crypto.KeyManager {
	t.Helper()
	km, err := crypto.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return km
}

func TestNewClient(t *testing.T) {
	km := testKeyManager(t)
	c := NewClient("https://example.com", km, "dev-123")
	if c.baseURL != "https://example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.deviceID != "dev-123" {
		t.Errorf("deviceID = %q", c.deviceID)
	}
	if c.keyManager != km {
		t.Errorf("keyManager not stored")
	}
}

func TestInitPairing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/device/init" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}

		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["fingerprint"] != "fp123" {
			t.Errorf("fingerprint = %q", body["fingerprint"])
		}
		if body["pairTokenHash"] != "deadbeef" {
			t.Errorf("pairTokenHash = %q", body["pairTokenHash"])
		}

		_ = json.NewEncoder(w).Encode(PairingInitResponse{
			SessionID: "sess-1",
			UserCode:  "ABC123",
			AuthURL:   "https://atreo.link/approve/sess-1",
		})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, testKeyManager(t), "")
	resp, err := c.InitPairing(context.Background(), "fp123", "mynas", "pubkey", "deadbeef")
	if err != nil {
		t.Fatalf("InitPairing: %v", err)
	}
	if resp.SessionID != "sess-1" {
		t.Errorf("SessionID = %q", resp.SessionID)
	}
	if resp.UserCode != "ABC123" {
		t.Errorf("UserCode = %q", resp.UserCode)
	}
}

func TestPollPairing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/device/poll" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("session") != "sess-1" {
			t.Errorf("session = %q", r.URL.Query().Get("session"))
		}
		_ = json.NewEncoder(w).Encode(PairingPollResponse{
			Status:       "approved",
			DeviceID:     "dev-1",
			AppsHostname: "mynas.atreo.link",
		})
	}))
	defer ts.Close()

	c := NewClient(ts.URL, testKeyManager(t), "")
	resp, err := c.PollPairing(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("PollPairing: %v", err)
	}
	if resp.Status != "approved" {
		t.Errorf("Status = %q", resp.Status)
	}
	if resp.DeviceID != "dev-1" {
		t.Errorf("DeviceID = %q", resp.DeviceID)
	}
	if resp.AppsHostname != "mynas.atreo.link" {
		t.Errorf("AppsHostname = %q, want %q", resp.AppsHostname, "mynas.atreo.link")
	}
}

// TestUpdateEndpoint exercises the identity-signed POST path: the outer body
// is a signerId/signature/payload envelope; the inner payload carries the
// endpoint-specific fields alongside the envelope metadata.
func TestUpdateEndpoint(t *testing.T) {
	km := testKeyManager(t)
	deviceID := "11111111-1111-1111-1111-111111111111"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("authPost must not set Authorization header: %q", r.Header.Get("Authorization"))
		}
		var env struct {
			SignerID  string          `json:"signerId"`
			Signature string          `json:"signature"`
			Payload   json.RawMessage `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		if env.SignerID != deviceID {
			t.Errorf("signerId = %q, want %q", env.SignerID, deviceID)
		}
		// Signature verifies against the canonical payload bytes.
		pubBytes, _ := base64.StdEncoding.DecodeString(km.PublicKeyBase64())
		sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), env.Payload, sigBytes) {
			t.Errorf("envelope signature failed to verify against agent pubkey")
		}
		// Inner payload carries the endpoint body + envelope fields.
		var inner map[string]any
		if err := json.Unmarshal(env.Payload, &inner); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if inner["ip"] != "1.2.3.4" {
			t.Errorf("payload.ip = %v", inner["ip"])
		}
		if _, hasPort := inner["port"]; hasPort {
			t.Errorf("payload should not include port (DDNS-only heartbeat now): %v", inner)
		}
		wantIntentPrefix := "device:endpoint-" + deviceID + "-"
		if intent, _ := inner["intent"].(string); intent == "" || !startsWith(intent, wantIntentPrefix) {
			t.Errorf("payload.intent = %v, want prefix %q", inner["intent"], wantIntentPrefix)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"hostname":"dev.tunnel.example.com","ip":"1.2.3.4"}`))
	}))
	defer ts.Close()

	c := NewClient(ts.URL, km, deviceID)
	results, err := c.UpdateEndpoint(context.Background(), "1.2.3.4", nil)
	if err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	// With an override set, UpdateEndpoint fires a single request via the
	// default client (no v4/v6 split — the server can't observe an
	// alternative family when we're already telling it the address).
	if len(results) != 1 {
		t.Fatalf("expected 1 result for override path, got %d: %+v", len(results), results)
	}
	if results[0].Hostname != "dev.tunnel.example.com" || results[0].IP != "1.2.3.4" {
		t.Errorf("EndpointResult = %+v, want {dev.tunnel.example.com 1.2.3.4}", results[0])
	}
}

// No override → no `ip` in the signed payload (atreoLINK then uses the
// observed source IP); a 204 must decode to a zero result, not an error.
func TestUpdateEndpoint_NoOverrideOmitsIP(t *testing.T) {
	km := testKeyManager(t)
	deviceID := "11111111-1111-1111-1111-111111111111"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env struct {
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Fatalf("decode envelope: %v", err)
		}
		var inner map[string]any
		if err := json.Unmarshal(env.Payload, &inner); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if _, hasIP := inner["ip"]; hasIP {
			t.Errorf("payload must omit ip when no override is set: %v", inner)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	// No override → dual-family fire. httptest binds 127.0.0.1 only, so the
	// v6-bound request fails to dial; the v4 succeeds. UpdateEndpoint
	// returns the v4 result (empty body / 204 → zero EndpointResult) and
	// logs the v6 failure as a warning.
	c := NewClient(ts.URL, km, deviceID)
	results, err := c.UpdateEndpoint(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (v4 success, v6 dial fails on 127.0.0.1), got %d: %+v", len(results), results)
	}
	if results[0] != (EndpointResult{}) {
		t.Errorf("expected zero EndpointResult on 204, got %+v", results[0])
	}
}

func TestDNSPresentCleanup(t *testing.T) {
	var presentCalled, cleanupCalled bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/dns/present":
			presentCalled = true
		case "/v1/dns/cleanup":
			cleanupCalled = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := NewClient(ts.URL, testKeyManager(t), "11111111-1111-1111-1111-111111111111")

	if err := c.DNSPresent(context.Background(), "_acme.example.com", "challenge-val"); err != nil {
		t.Fatalf("DNSPresent: %v", err)
	}
	if !presentCalled {
		t.Error("DNSPresent not called")
	}

	if err := c.DNSCleanup(context.Background(), "_acme.example.com", "challenge-val"); err != nil {
		t.Fatalf("DNSCleanup: %v", err)
	}
	if !cleanupCalled {
		t.Error("DNSCleanup not called")
	}
}

// TestAuthPost_RequiresPairing — authPost rejects when no deviceID is set,
// rather than emitting an envelope with empty signerId that would fail
// server-side anyway.
func TestAuthPost_RequiresPairing(t *testing.T) {
	c := NewClient("http://example.invalid", testKeyManager(t), "")
	if _, err := c.UpdateEndpoint(context.Background(), "1.2.3.4", nil); err == nil {
		t.Fatal("expected error when deviceID is empty")
	}
}

func TestHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer ts.Close()

	c := NewClient(ts.URL, testKeyManager(t), "11111111-1111-1111-1111-111111111111")
	_, err := c.UpdateEndpoint(context.Background(), "1.2.3.4", nil)
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// recordingRT is a minimal RoundTripper for testing the dual-family
// fire-out logic without binding actual v4/v6 sockets.
type recordingRT struct {
	calls  int32
	status int
	body   string
	err    error
	delay  time.Duration
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&r.calls, 1)
	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	body := r.body
	if body == "" {
		body = `{"hostname":"dev.example.com","ip":"203.0.113.1"}`
	}
	status := r.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// installRoundTrippers swaps the family-bound and default clients on c so
// tests can intercept dispatch at the transport level.
func installRoundTrippers(c *Client, def, v4, v6 http.RoundTripper) {
	if def != nil {
		c.httpClient = &http.Client{Transport: def, Timeout: 10 * time.Second}
	}
	if v4 != nil {
		c.httpClientV4 = &http.Client{Transport: v4, Timeout: 10 * time.Second}
	}
	if v6 != nil {
		c.httpClientV6 = &http.Client{Transport: v6, Timeout: 10 * time.Second}
	}
}

// Both family clients fire one request each when no override is set.
func TestUpdateEndpoint_FiresBothFamilies(t *testing.T) {
	km := testKeyManager(t)
	c := NewClient("http://example.invalid", km, "11111111-1111-1111-1111-111111111111")
	v4RT := &recordingRT{}
	v6RT := &recordingRT{body: `{"hostname":"dev.example.com","ip":"2001:db8::1"}`}
	installRoundTrippers(c, nil, v4RT, v6RT)

	results, err := c.UpdateEndpoint(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	if atomic.LoadInt32(&v4RT.calls) != 1 {
		t.Errorf("v4 calls = %d, want 1", v4RT.calls)
	}
	if atomic.LoadInt32(&v6RT.calls) != 1 {
		t.Errorf("v6 calls = %d, want 1", v6RT.calls)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d: %+v", len(results), results)
	}
}

// v6 fails, v4 succeeds → returns the v4 result, no error. A transient
// v6 outage must not bubble up as a hard failure.
func TestUpdateEndpoint_PartialFailureV6(t *testing.T) {
	km := testKeyManager(t)
	c := NewClient("http://example.invalid", km, "11111111-1111-1111-1111-111111111111")
	v4RT := &recordingRT{body: `{"hostname":"dev.example.com","ip":"203.0.113.1"}`}
	v6RT := &recordingRT{err: fmt.Errorf("network unreachable")}
	installRoundTrippers(c, nil, v4RT, v6RT)

	results, err := c.UpdateEndpoint(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("expected nil err on partial failure, got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d: %+v", len(results), results)
	}
	if results[0].IP != "203.0.113.1" {
		t.Errorf("expected v4 result, got %+v", results[0])
	}
}

// Both families fail → hard error including both messages.
func TestUpdateEndpoint_BothFailReturnsError(t *testing.T) {
	km := testKeyManager(t)
	c := NewClient("http://example.invalid", km, "11111111-1111-1111-1111-111111111111")
	v4RT := &recordingRT{err: fmt.Errorf("v4 dial refused")}
	v6RT := &recordingRT{err: fmt.Errorf("v6 dial refused")}
	installRoundTrippers(c, nil, v4RT, v6RT)

	_, err := c.UpdateEndpoint(context.Background(), "", nil)
	if err == nil {
		t.Fatal("expected error when both families fail")
	}
	msg := err.Error()
	if !startsWith(msg, "device:endpoint failed on both families") {
		t.Errorf("error prefix = %q", msg)
	}
}

// endpoint_ip override → single request via the default client; the
// family-bound clients see zero calls.
func TestUpdateEndpoint_OverrideUsesGeneralClientOnly(t *testing.T) {
	km := testKeyManager(t)
	c := NewClient("http://example.invalid", km, "11111111-1111-1111-1111-111111111111")
	defRT := &recordingRT{body: `{"hostname":"dev.example.com","ip":"203.0.113.7"}`}
	v4RT := &recordingRT{}
	v6RT := &recordingRT{}
	installRoundTrippers(c, defRT, v4RT, v6RT)

	results, err := c.UpdateEndpoint(context.Background(), "203.0.113.7", nil)
	if err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	if atomic.LoadInt32(&defRT.calls) != 1 {
		t.Errorf("default client calls = %d, want 1", defRT.calls)
	}
	if atomic.LoadInt32(&v4RT.calls) != 0 || atomic.LoadInt32(&v6RT.calls) != 0 {
		t.Errorf("override path must not touch family clients: v4=%d v6=%d", v4RT.calls, v6RT.calls)
	}
	if len(results) != 1 || results[0].IP != "203.0.113.7" {
		t.Errorf("results = %+v", results)
	}
}

// A hung v6 request must not delay the v4 request — independent per-family
// deadlines. Total wall time is bounded by the 10 s per-family timeout
// regardless of what v6 does.
func TestUpdateEndpoint_IndependentTimeouts(t *testing.T) {
	km := testKeyManager(t)
	c := NewClient("http://example.invalid", km, "11111111-1111-1111-1111-111111111111")
	v4RT := &recordingRT{} // returns immediately
	// Block longer than the per-family timeout to force the timeout path.
	v6RT := &recordingRT{delay: 30 * time.Second}
	installRoundTrippers(c, nil, v4RT, v6RT)

	start := time.Now()
	results, err := c.UpdateEndpoint(context.Background(), "", nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected nil err (v4 ok, v6 timeout treated as partial), got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (v4 only), got %d: %+v", len(results), results)
	}
	// Generous upper bound: the per-family timeout is 10 s; allow slack
	// for slow CI. The point of the test is that we don't wait 30 s.
	if elapsed > 15*time.Second {
		t.Errorf("UpdateEndpoint blocked %v — v4 result must not wait on hung v6", elapsed)
	}
}

// familyDialer pins LocalAddr only when one is supplied — this is what forces
// the v6 DDNS request onto a stable source address.
func TestFamilyDialerBindsLocalAddr(t *testing.T) {
	if d := familyDialer(nil); d.LocalAddr != nil {
		t.Errorf("familyDialer(nil).LocalAddr = %v, want nil", d.LocalAddr)
	}
	src := &net.TCPAddr{IP: net.ParseIP("2001:db8::1")}
	if d := familyDialer(src); d.LocalAddr != src {
		t.Errorf("familyDialer(src).LocalAddr = %v, want %v", d.LocalAddr, src)
	}
}

// A non-nil v6Source forces a per-call v6 client (source-bound), so the cached
// v6 client — and any RoundTripper installed on it — is bypassed. v4 still
// fires on its cached client and carries the result on its own.
func TestUpdateEndpoint_V6SourceBypassesCachedClient(t *testing.T) {
	km := testKeyManager(t)
	c := NewClient("http://example.invalid", km, "11111111-1111-1111-1111-111111111111")
	v4RT := &recordingRT{}
	v6RT := &recordingRT{} // must not be called: v6Source rebuilds the client
	installRoundTrippers(c, nil, v4RT, v6RT)

	results, err := c.UpdateEndpoint(context.Background(), "", net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatalf("UpdateEndpoint: %v", err)
	}
	if atomic.LoadInt32(&v4RT.calls) != 1 {
		t.Errorf("v4 calls = %d, want 1", v4RT.calls)
	}
	if got := atomic.LoadInt32(&v6RT.calls); got != 0 {
		t.Errorf("cached v6 client calls = %d, want 0 (source-bound client should replace it)", got)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (v4 only; bound v6 dial to example.invalid fails), got %d: %+v", len(results), results)
	}
}
