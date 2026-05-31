package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
)

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
	link := atreolink.NewClient("http://example.invalid", km, "dev-1")
	c := NewClient(link, "http://atreo.example.com", km, "dev-1")
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.handlers == nil {
		t.Error("handlers map not initialised")
	}
	if c.stopCh == nil {
		t.Error("stopCh not initialised")
	}
	if c.deviceID != "dev-1" {
		t.Errorf("deviceID = %q", c.deviceID)
	}
	if c.keyManager != km {
		t.Error("keyManager not stored")
	}
}

func TestRegisterHandler_AndDispatch(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")

	called := false
	c.RegisterHandler("test:msg", func(m atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
		called = true
		return &atreolink.TunnelMessage{Type: "test:msg:resp", CorrelationID: m.CorrelationID}, nil
	})

	resp := c.dispatch(atreolink.TunnelMessage{Type: "test:msg", CorrelationID: "c1"})
	if !called {
		t.Error("handler not called")
	}
	if resp == nil || resp.Type != "test:msg:resp" || resp.CorrelationID != "c1" {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestDispatch_NoHandler(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	resp := c.dispatch(atreolink.TunnelMessage{Type: "unknown:type"})
	if resp != nil {
		t.Errorf("expected nil for unknown type, got %+v", resp)
	}
}

func TestDispatch_HandlerError(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	c.RegisterHandler("err:msg", func(atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
		return nil, errors.New("boom")
	})
	resp := c.dispatch(atreolink.TunnelMessage{Type: "err:msg"})
	if resp != nil {
		t.Errorf("expected nil on handler error, got %+v", resp)
	}
}

func TestSetOnConnect(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	called := false
	c.SetOnConnect(func() []atreolink.TunnelMessage {
		called = true
		return nil
	})
	c.mu.RLock()
	fn := c.onConnect
	c.mu.RUnlock()
	if fn == nil {
		t.Fatal("onConnect not stored")
	}
	_ = fn()
	if !called {
		t.Error("onConnect not invoked")
	}
}

func TestStop_Idempotent(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	c.Stop()
	c.Stop() // second Stop must not panic on closed channel
	select {
	case <-c.stopCh:
	default:
		t.Error("stopCh not closed after Stop")
	}
}

func TestStart_RespectsStopCh(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	c.Stop() // close stopCh before Start
	done := make(chan error, 1)
	go func() { done <- c.Start(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Start: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not honour pre-closed stopCh within 2s")
	}
}

// TestWSURL_Format verifies the signed-query-string wsURL: every supported
// HTTP scheme maps to the right WS scheme, intent/ts/sig query params are
// present and properly URL-encoded, and the signature verifies against the
// agent's pubkey over the canonical-JSON payload.
func TestWSURL_Format(t *testing.T) {
	km := testKeyManager(t)
	deviceID := "11111111-1111-1111-1111-111111111111"

	cases := []struct {
		in, wantPrefix string
	}{
		{"https://atreo.com/", "wss://atreo.com/v1/tunnel?"},
		{"http://atreo.com", "ws://atreo.com/v1/tunnel?"},
		{"atreo.com", "wss://atreo.com/v1/tunnel?"},
		{"https://atreo.com//", "wss://atreo.com/v1/tunnel?"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			c := NewClient(nil, tc.in, km, deviceID)
			before := time.Now().Unix()
			got, err := c.wsURL()
			after := time.Now().Unix()
			if err != nil {
				t.Fatalf("wsURL: %v", err)
			}
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Fatalf("wsURL=%q, want prefix %q", got, tc.wantPrefix)
			}
			if strings.Contains(got, "token=") {
				t.Errorf("wsURL must not carry ?token= param: %s", got)
			}

			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}
			intent := u.Query().Get("intent")
			tsStr := u.Query().Get("ts")
			sigB64 := u.Query().Get("sig")
			if intent == "" || tsStr == "" || sigB64 == "" {
				t.Fatalf("missing query params: intent=%q ts=%q sig=%q", intent, tsStr, sigB64)
			}
			ts, err := strconv.ParseInt(tsStr, 10, 64)
			if err != nil {
				t.Fatalf("ts not int64: %v", err)
			}
			if ts < before || ts > after {
				t.Errorf("ts=%d outside [%d,%d]", ts, before, after)
			}
			wantIntent := "tunnel:connect-" + deviceID + "-" + tsStr
			if intent != wantIntent {
				t.Errorf("intent=%q, want %q", intent, wantIntent)
			}

			// Reconstruct the canonical-JSON payload and verify the signature
			// against the agent's pubkey — proves the URL is self-authenticating.
			canon, err := canonjson.Marshal(map[string]any{
				"deviceId": deviceID,
				"intent":   intent,
				"ts":       ts,
			})
			if err != nil {
				t.Fatalf("canonjson.Marshal: %v", err)
			}
			pubBytes, _ := base64.StdEncoding.DecodeString(km.PublicKeyBase64())
			sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				t.Fatalf("decode sig: %v", err)
			}
			if !ed25519.Verify(ed25519.PublicKey(pubBytes), canon, sigBytes) {
				t.Errorf("URL signature failed to verify against agent pubkey")
			}
		})
	}
}

// TestWSURL_RequiresPairing — wsURL refuses to build a URL when the agent
// hasn't been paired (no deviceID set). The caller then logs the error and
// retries via reconnect backoff.
func TestWSURL_RequiresPairing(t *testing.T) {
	c := NewClient(nil, "https://atreo.com", nil, "")
	if _, err := c.wsURL(); err == nil {
		t.Fatal("expected error when keyManager/deviceID missing")
	}
}

func TestSend_ReturnsErrNotAttached(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	err := c.Send(context.Background(), atreolink.TunnelMessage{Type: "x"})
	if !errors.Is(err, ErrNotAttached) {
		t.Errorf("err=%v, want ErrNotAttached", err)
	}
}

func TestBackoffDuration(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	cases := []struct {
		attempt int
		base    time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{5, 8 * time.Second},
		{50, 8 * time.Second}, // beyond table — clamps to last
	}
	for _, tc := range cases {
		// ±25% jitter — sample a few times to exercise the randomness.
		for i := 0; i < 50; i++ {
			got := c.backoffDuration(tc.attempt)
			lo := time.Duration(float64(tc.base) * 0.75)
			hi := time.Duration(float64(tc.base) * 1.25)
			if got < lo || got > hi {
				t.Fatalf("backoffDuration(%d)=%v, want within [%v,%v]", tc.attempt, got, lo, hi)
			}
		}
	}
}

// TestBackoffDuration_FitsCloudReplyWindow guards the lockstep contract with
// atreoLINK: the worst-case dial gap (max base × 1.25 jitter) must stay below
// the cloud's 15s /connect reply ceiling, with margin for dial + handshake.
func TestBackoffDuration_FitsCloudReplyWindow(t *testing.T) {
	const ceiling = 10 * time.Second
	c := NewClient(nil, "http://x", nil, "")
	for attempt := 0; attempt < 100; attempt++ {
		for i := 0; i < 200; i++ {
			if got := c.backoffDuration(attempt); got > ceiling {
				t.Fatalf("backoffDuration(%d)=%v exceeds %v — would break atreoLINK's 15s reply window", attempt, got, ceiling)
			}
		}
	}
}

func TestMarshalMessage(t *testing.T) {
	type body struct {
		Foo string `json:"foo"`
	}
	msg, err := MarshalMessage("test:type", "corr-1", body{Foo: "bar"})
	if err != nil {
		t.Fatalf("MarshalMessage: %v", err)
	}
	if msg.Type != "test:type" || msg.CorrelationID != "corr-1" {
		t.Errorf("Type=%q CorrelationID=%q", msg.Type, msg.CorrelationID)
	}
	var got body
	if err := json.Unmarshal(msg.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Foo != "bar" {
		t.Errorf("payload roundtrip: %+v", got)
	}
}

func TestMarshalMessage_BadValue(t *testing.T) {
	// channel can't be marshaled to JSON
	if _, err := MarshalMessage("x", "y", make(chan int)); err == nil {
		t.Error("expected marshal error")
	}
}

func TestWaitForReconnect_HonoursStop(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	c.reconnectAttempt = 0
	c.Stop()
	if err := c.waitForReconnect(context.Background()); err != nil {
		t.Errorf("waitForReconnect: %v", err)
	}
}

func TestWaitForReconnect_HonoursContext(t *testing.T) {
	c := NewClient(nil, "http://x", nil, "")
	c.reconnectAttempt = 5 // long backoff
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.waitForReconnect(ctx); err == nil {
		t.Error("expected context error")
	}
}
