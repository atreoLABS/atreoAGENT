package probe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

func newTestServer(t *testing.T) (*Server, ed25519.PublicKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return NewServer(Config{
		DeviceID:   "dev-123",
		PrivateKey: priv,
	}), pub, "dev-123"
}

func nonceB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// httptestServer wraps the probe handler in httptest so we can hit it without
// binding real LAN IPs. The rate-limit + signing logic are the same regardless
// of bind path.
func httptestServer(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	return httptest.NewServer(s.handler)
}

func TestPingHappyPath(t *testing.T) {
	s, pub, deviceID := newTestServer(t)
	ts := httptestServer(t, s)
	defer ts.Close()

	nonce := nonceB64(t, 32)
	resp, err := http.Get(ts.URL + "/atreo/ping?nonce=" + nonce + "&deviceId=" + deviceID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		DeviceID  string `json:"deviceId"`
		Timestamp string `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.DeviceID != deviceID {
		t.Errorf("deviceId = %q, want %q", out.DeviceID, deviceID)
	}

	// Re-canonicalise the payload the server would have signed and verify.
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatalf("nonce decode: %v", err)
	}
	canon, err := canonjson.Marshal(map[string]any{
		"deviceId":  deviceID,
		"nonce":     base64.StdEncoding.EncodeToString(nonceBytes),
		"timestamp": out.Timestamp,
	})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		t.Fatalf("signature decode: %v", err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		t.Error("signature does not verify")
	}
}

func TestPingWrongDeviceIDReturns404(t *testing.T) {
	s, _, _ := newTestServer(t)
	ts := httptestServer(t, s)
	defer ts.Close()

	nonce := nonceB64(t, 32)
	resp, err := http.Get(ts.URL + "/atreo/ping?nonce=" + nonce + "&deviceId=not-this-device")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404 (blends with random scans)", resp.StatusCode)
	}
}

func TestPingBadNonceReturns400(t *testing.T) {
	s, _, deviceID := newTestServer(t)
	ts := httptestServer(t, s)
	defer ts.Close()

	cases := []string{
		"",             // missing
		"notbase64!!!", // invalid encoding
		base64.RawURLEncoding.EncodeToString(make([]byte, 16)), // too short
		base64.RawURLEncoding.EncodeToString(make([]byte, 64)), // too long
	}
	for _, n := range cases {
		resp, err := http.Get(ts.URL + "/atreo/ping?nonce=" + n + "&deviceId=" + deviceID)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("nonce=%q → status %d, want 400", n, resp.StatusCode)
		}
	}
}

func TestPingUnknownRouteReturns404(t *testing.T) {
	s, _, _ := newTestServer(t)
	ts := httptestServer(t, s)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/debug/pprof/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("body = %q, want empty (minimise surface)", body)
	}
}

func TestPingMethodNotAllowed(t *testing.T) {
	s, _, deviceID := newTestServer(t)
	ts := httptestServer(t, s)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/atreo/ping?nonce="+nonceB64(t, 32)+"&deviceId="+deviceID, strings.NewReader(""))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestRateLimitKicksInAfter10RapidRequests(t *testing.T) {
	// Freeze the clock so leak rate doesn't refill the bucket during the
	// loop — otherwise this test is timing-dependent.
	frozen := time.Unix(1700000000, 0)
	s, _, deviceID := newTestServer(t)
	s.cfg.Clock = func() time.Time { return frozen }

	ts := httptestServer(t, s)
	defer ts.Close()

	nonce := nonceB64(t, 32)
	allowed := 0
	throttled := 0
	for i := 0; i < 15; i++ {
		resp, err := http.Get(ts.URL + "/atreo/ping?nonce=" + nonce + "&deviceId=" + deviceID)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case 200:
			allowed++
		case 429:
			throttled++
		default:
			t.Fatalf("request %d: unexpected status %d", i, resp.StatusCode)
		}
	}
	if allowed != 10 {
		t.Errorf("allowed = %d, want 10 (bucket capacity)", allowed)
	}
	if throttled != 5 {
		t.Errorf("throttled = %d, want 5 (remaining rapid requests)", throttled)
	}
}

func TestReapBucketsDropsIdleEntries(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	s, _, _ := newTestServer(t)
	s.cfg.Clock = func() time.Time { return clock }

	s.allow("1.2.3.4")
	clock = clock.Add(time.Minute) // touch the second bucket a minute later
	s.allow("5.6.7.8")

	// Reap at T+5m30s: 1.2.3.4 is 5m30s idle (>5m → gone), 5.6.7.8 is
	// 4m30s idle (≤5m → survives).
	s.reapBuckets(clock.Add(4*time.Minute + 30*time.Second))

	s.rateMu.Lock()
	_, stale := s.buckets["1.2.3.4"]
	_, fresh := s.buckets["5.6.7.8"]
	s.rateMu.Unlock()
	if stale {
		t.Error("idle bucket should have been reaped")
	}
	if !fresh {
		t.Error("recently-touched bucket should survive")
	}
}

func TestRateLimitRefillsOverTime(t *testing.T) {
	// After the leak interval passes, the bucket should drain enough to
	// let a subsequent request through.
	clock := time.Unix(1700000000, 0)
	s, _, deviceID := newTestServer(t)
	s.cfg.Clock = func() time.Time { return clock }

	ts := httptestServer(t, s)
	defer ts.Close()

	nonce := nonceB64(t, 32)
	// Burn the whole bucket.
	for i := 0; i < 10; i++ {
		_, _ = http.Get(ts.URL + "/atreo/ping?nonce=" + nonce + "&deviceId=" + deviceID)
	}
	// Advance 20 s → 20 tokens leaked → bucket well under cap again.
	clock = clock.Add(20 * time.Second)
	resp, err := http.Get(ts.URL + "/atreo/ping?nonce=" + nonce + "&deviceId=" + deviceID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status after cooldown = %d, want 200", resp.StatusCode)
	}
}

func TestPingAcceptsStandardBase64Nonce(t *testing.T) {
	// Spec is url-safe base64, but we tolerate standard base64 to keep
	// manual curl invocations painless. URL-escape the nonce because
	// standard base64 uses '+' and '/', which have special meaning in
	// URL queries.
	s, _, deviceID := newTestServer(t)
	ts := httptestServer(t, s)
	defer ts.Close()

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	nonce := url.QueryEscape(base64.StdEncoding.EncodeToString(b))
	resp, err := http.Get(ts.URL + "/atreo/ping?nonce=" + nonce + "&deviceId=" + deviceID)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200 (standard-base64 nonce accepted)", resp.StatusCode)
	}
}
