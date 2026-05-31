package endpoints

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// Fixed Ed25519 keypair for deterministic fixture output. The private key
// seed is zero — DO NOT use this anywhere but tests.
func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	// Seed of 32 zeros — reproducible across test runs.
	seed := make([]byte, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func TestBuildCanonicalOutput(t *testing.T) {
	_, priv := testKeypair(t)

	// Fixed timestamp for a byte-exact comparison. The canonical payload
	// is what cross-implementation agreement depends on — every signer and
	// verifier on the wire must reproduce this byte-for-byte.
	ts := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	cands := []Candidate{
		{Kind: KindLAN, Host: "192.168.1.10", Port: 51820},
		{Kind: KindLAN, Host: "10.0.0.5", Port: 51820},
		{Kind: KindPublic4, Host: "1.2.3.4", Port: 51820},
		{Kind: KindPublic6, Host: "2001:db8::1", Port: 51820},
	}
	env, err := Build("dev-abc", ts, cands, priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := `{"candidates":[` +
		`{"host":"192.168.1.10","kind":"lan","port":51820},` +
		`{"host":"10.0.0.5","kind":"lan","port":51820},` +
		`{"host":"1.2.3.4","kind":"public4","port":51820},` +
		`{"host":"2001:db8::1","kind":"public6","port":51820}` +
		`],"deviceId":"dev-abc","timestamp":"2026-04-19T12:00:00Z"}`
	if string(env.PayloadCanon) != want {
		t.Errorf("PayloadCanon mismatch:\n got: %s\nwant: %s", env.PayloadCanon, want)
	}
}

func TestBuildSignatureVerifies(t *testing.T) {
	pub, priv := testKeypair(t)
	ts := time.Now().UTC()
	env, err := Build("dev-xyz", ts, []Candidate{{Kind: KindLAN, Host: "192.168.1.10", Port: 51820}}, priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !ed25519.Verify(pub, env.PayloadCanon, env.Signature) {
		t.Fatal("signature does not verify against the public key")
	}

	// Tampering with the payload must invalidate the signature — the
	// whole point of canonical JSON is to give verifiers a well-defined
	// byte sequence to re-check.
	tampered := append([]byte(nil), env.PayloadCanon...)
	tampered[0] = '#'
	if ed25519.Verify(pub, tampered, env.Signature) {
		t.Fatal("signature verified over tampered payload — canonicalisation is broken")
	}
}

func TestBuildRejectsInvalidKind(t *testing.T) {
	_, priv := testKeypair(t)
	_, err := Build("dev", time.Now(), []Candidate{{Kind: "wan", Host: "1.2.3.4", Port: 51820}}, priv)
	if err == nil {
		t.Fatal("expected error on unknown kind")
	}
}

func TestBuildRejectsEmptyHost(t *testing.T) {
	_, priv := testKeypair(t)
	_, err := Build("dev", time.Now(), []Candidate{{Kind: KindLAN, Host: "", Port: 51820}}, priv)
	if err == nil {
		t.Fatal("expected error on empty host")
	}
}

func TestBuildRejectsZeroPort(t *testing.T) {
	_, priv := testKeypair(t)
	_, err := Build("dev", time.Now(), []Candidate{{Kind: KindLAN, Host: "192.168.1.1", Port: 0}}, priv)
	if err == nil {
		t.Fatal("expected error on zero port")
	}
}

func TestBuildRejectsMissingDeviceID(t *testing.T) {
	_, priv := testKeypair(t)
	_, err := Build("", time.Now(), nil, priv)
	if err == nil {
		t.Fatal("expected error on empty deviceId")
	}
}

func TestSignatureBase64Format(t *testing.T) {
	_, priv := testKeypair(t)
	env, err := Build("d", time.Now(), []Candidate{{Kind: KindLAN, Host: "10.0.0.1", Port: 1}}, priv)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.SignatureBase64())
	if err != nil {
		t.Fatalf("SignatureBase64 decode: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature length = %d, want %d", len(sig), ed25519.SignatureSize)
	}
}
