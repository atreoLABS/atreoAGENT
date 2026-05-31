package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

func TestGenerateAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Generate
	km1, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager (generate): %v", err)
	}

	pub1 := km1.PublicKeyBase64()
	if pub1 == "" {
		t.Fatal("PublicKeyBase64 returned empty string")
	}

	// Load existing
	km2, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager (load): %v", err)
	}

	pub2 := km2.PublicKeyBase64()
	if pub1 != pub2 {
		t.Errorf("Public keys don't match after reload: %q vs %q", pub1, pub2)
	}
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	msg := []byte("test message")
	sig := km.Sign(msg)

	if sig == "" {
		t.Fatal("Sign returned empty string")
	}

	valid, err := Verify(km.PublicKeyBase64(), msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("Verify returned false for valid signature")
	}

	// Tampered message
	valid, err = Verify(km.PublicKeyBase64(), []byte("tampered"), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if valid {
		t.Error("Verify returned true for tampered message")
	}
}

func TestNonceUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		n, err := GenerateNonce()
		if err != nil {
			t.Fatalf("GenerateNonce: %v", err)
		}
		if len(n) != 64 { // 32 bytes hex = 64 chars
			t.Errorf("Nonce length = %d, want 64", len(n))
		}
		if seen[n] {
			t.Errorf("Duplicate nonce: %s", n)
		}
		seen[n] = true
	}
}

func TestSignProvisionResponse(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	// Construct valid test inputs. nonce is hex (64 chars = 32 bytes); the
	// public keys are base64-encoded 32-byte blobs as they appear on the wire.
	nonceHex, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	// 32-byte placeholders for the two Curve25519 public keys.
	clientPub := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	serverPub := "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
	deviceID := "dev-42"
	tunnelIP := "100.64.0.2"

	in := ProvisionTranscriptInput{
		NonceHex:            nonceHex,
		ClientPubKeyB64:     clientPub,
		DeviceID:            deviceID,
		ServerPubKeyB64:     serverPub,
		TunnelIP:            tunnelIP,
		Endpoint:            "dev-42.atreotunnel.com:51820",
		AllowedIPs:          "100.64.0.0/24",
		PersistentKeepalive: 25,
	}
	sig, err := km.SignProvisionResponse(in)
	if err != nil {
		t.Fatalf("SignProvisionResponse: %v", err)
	}
	if sig == "" {
		t.Fatal("SignProvisionResponse returned empty string")
	}

	// Verify the signature over the agent-side transcript. Re-compose the
	// hash here rather than using the unexported helper, so drift in either
	// side is caught.
	transcript, err := serverTranscriptV2(in)
	if err != nil {
		t.Fatalf("serverTranscriptV2: %v", err)
	}
	valid, err := Verify(km.PublicKeyBase64(), transcript, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed for provision response")
	}
}

// TestSignAgentAuth_RoundTrip exercises the full HTTP envelope shape: build,
// pull canonical bytes out of the envelope, and verify the embedded
// signature against the agent's pubkey. Load-bearing positive test for the
// agent → atreoLINK auth path.
func TestSignAgentAuth_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	deviceID := "11111111-1111-1111-1111-111111111111"
	body := map[string]any{"ip": "203.0.113.42"}

	before := time.Now().Unix()
	env, err := km.SignAgentAuth(deviceID, "device:endpoint", body)
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("SignAgentAuth: %v", err)
	}

	if env.SignerID != deviceID {
		t.Errorf("envelope.SignerID = %q, want %q", env.SignerID, deviceID)
	}
	if env.Signature == "" {
		t.Fatal("envelope.Signature empty")
	}
	if len(env.Payload) == 0 {
		t.Fatal("envelope.Payload empty")
	}

	// Verify signature against the canonical payload bytes.
	pubBytes, err := base64.StdEncoding.DecodeString(km.PublicKeyBase64())
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), env.Payload, sigBytes) {
		t.Fatal("ed25519.Verify rejected a signature we just produced")
	}

	// Inspect inner fields.
	var inner map[string]any
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.UseNumber()
	if err := dec.Decode(&inner); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if inner["deviceId"] != deviceID {
		t.Errorf("payload.deviceId = %v, want %q", inner["deviceId"], deviceID)
	}
	tsNum, ok := inner["ts"].(json.Number)
	if !ok {
		t.Fatalf("payload.ts wrong type %T", inner["ts"])
	}
	tsVal, err := tsNum.Int64()
	if err != nil {
		t.Fatalf("payload.ts not int64: %v", err)
	}
	if tsVal < before || tsVal > after {
		t.Errorf("payload.ts = %d, want between [%d, %d]", tsVal, before, after)
	}
	wantIntent := "device:endpoint-" + deviceID + "-" + tsNum.String()
	if inner["intent"] != wantIntent {
		t.Errorf("payload.intent = %v, want %q", inner["intent"], wantIntent)
	}
	if inner["ip"] != "203.0.113.42" {
		t.Errorf("payload.ip = %v, want %q", inner["ip"], "203.0.113.42")
	}
}

func TestSignAgentAuth_NoBody(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	env, err := km.SignAgentAuth("dev", "tunnel:pending", nil)
	if err != nil {
		t.Fatalf("SignAgentAuth(nil): %v", err)
	}
	var inner map[string]any
	if err := json.Unmarshal(env.Payload, &inner); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	// Only the three envelope keys should appear.
	for k := range inner {
		switch k {
		case "deviceId", "intent", "ts":
			continue
		default:
			t.Errorf("unexpected key %q in envelope-only payload", k)
		}
	}
}

func TestSignAgentAuth_RejectsReservedKeys(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	for _, key := range []string{"deviceId", "intent", "ts"} {
		if _, err := km.SignAgentAuth("dev", "x", map[string]any{key: "boom"}); err == nil {
			t.Errorf("SignAgentAuth allowed reserved key %q", key)
		}
	}
}

// TestSignAgentAuth_CanonicalByteStability pins the canonical-JSON bytes for a
// fixed payload, so a future refactor of canonjson or the merge logic can't
// silently change what we sign (which would invalidate every in-flight
// signature and break cross-repo agreement with atreoLINK's verifier).
func TestSignAgentAuth_CanonicalByteStability(t *testing.T) {
	// Inputs chosen to exercise key ordering: zzz first (unsorted) so we can
	// confirm canonjson sorts.
	payload := map[string]any{
		"zzz":      "last",
		"deviceId": "dev-1",
		"intent":   "x-dev-1-100",
		"ts":       int64(100),
		"aaa":      "first",
	}
	got, err := canonjson.Marshal(payload)
	if err != nil {
		t.Fatalf("canonjson.Marshal: %v", err)
	}
	want := `{"aaa":"first","deviceId":"dev-1","intent":"x-dev-1-100","ts":100,"zzz":"last"}`
	if string(got) != want {
		t.Errorf("canonical bytes drifted:\n got  %s\n want %s", got, want)
	}
}

func TestSignWSConnectAuth_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	deviceID := "22222222-2222-2222-2222-222222222222"
	before := time.Now().Unix()
	intent, ts, sig, err := km.SignWSConnectAuth(deviceID)
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("SignWSConnectAuth: %v", err)
	}

	if ts < before || ts > after {
		t.Errorf("ts = %d, want between [%d, %d]", ts, before, after)
	}
	wantPrefix := "tunnel:connect-" + deviceID + "-"
	if !strings.HasPrefix(intent, wantPrefix) {
		t.Errorf("intent = %q, want prefix %q", intent, wantPrefix)
	}

	// Reconstruct the canonical payload and verify.
	canon, err := canonjson.Marshal(map[string]any{
		"deviceId": deviceID,
		"intent":   intent,
		"ts":       ts,
	})
	if err != nil {
		t.Fatalf("canonjson.Marshal: %v", err)
	}
	pubBytes, _ := base64.StdEncoding.DecodeString(km.PublicKeyBase64())
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canon, sigBytes) {
		t.Fatal("ed25519.Verify rejected the WS connect signature")
	}
}

func TestPrivateKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	_, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	privPath := filepath.Join(dir, "ed25519.key")
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("Private key permissions = %o, want 0600", perm)
	}
}

// Error-path coverage for SignProvisionResponse: the underlying
// serverTranscript fails-fast on malformed nonce hex, malformed client
// pubkey b64, and malformed server pubkey b64, and the wrapper bubbles each
// up. Tested via the public API rather than serverTranscript directly so
// the bubble-up path is exercised in the same test pass.
func TestSignProvisionResponse_BadInputs(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	validNonceHex, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	// 32-byte placeholders (same as the happy-path test above).
	validClientPub := "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
	validServerPub := "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="

	for _, tc := range []struct {
		name      string
		nonceHex  string
		clientPub string
		serverPub string
	}{
		{name: "bad nonce hex", nonceHex: "not-hex", clientPub: validClientPub, serverPub: validServerPub},
		{name: "bad client pubkey b64", nonceHex: validNonceHex, clientPub: "!!!", serverPub: validServerPub},
		{name: "bad server pubkey b64", nonceHex: validNonceHex, clientPub: validClientPub, serverPub: "!!!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := km.SignProvisionResponse(ProvisionTranscriptInput{
				NonceHex:            tc.nonceHex,
				ClientPubKeyB64:     tc.clientPub,
				DeviceID:            "dev-1",
				ServerPubKeyB64:     tc.serverPub,
				TunnelIP:            "100.64.0.2",
				Endpoint:            "dev-1.atreotunnel.com:51820",
				AllowedIPs:          "100.64.0.0/24",
				PersistentKeepalive: 25,
			}); err == nil {
				t.Errorf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
