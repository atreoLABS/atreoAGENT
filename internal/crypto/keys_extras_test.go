package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestRandRead(t *testing.T) {
	b := make([]byte, 32)
	n, err := RandRead(b)
	if err != nil {
		t.Fatalf("RandRead: %v", err)
	}
	if n != 32 {
		t.Errorf("n=%d, want 32", n)
	}
	if bytes.Equal(b, make([]byte, 32)) {
		t.Error("buffer is all zeros — RandRead probably did not write")
	}
}

func TestPrivateKey(t *testing.T) {
	dir := t.TempDir()
	km, err := NewKeyManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	priv := km.PrivateKey()
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("priv len=%d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	// Public key derived from PrivateKey() must match PublicKeyBase64().
	derived := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if derived != km.PublicKeyBase64() {
		t.Errorf("derived pub %q != PublicKeyBase64 %q", derived, km.PublicKeyBase64())
	}
}

func TestNewKeyManager_LoadsExistingKey(t *testing.T) {
	dir := t.TempDir()
	first, err := NewKeyManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewKeyManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.PublicKeyBase64() != second.PublicKeyBase64() {
		t.Error("expected same key on second load")
	}
}

func TestNewKeyManager_BadKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ed25519.key"), []byte("not-base64"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyManager(dir); err == nil {
		t.Error("expected decode error for corrupt key file")
	}
}

func TestVerify_BadInputs(t *testing.T) {
	cases := []struct {
		name  string
		pub   string
		msg   []byte
		sig   string
		isErr bool
	}{
		{"bad-pubkey-base64", "!!!", []byte("x"), "AAAA", true},
		{"bad-sig-base64", base64.StdEncoding.EncodeToString(make([]byte, 32)), []byte("x"), "!!!", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.pub, tc.msg, tc.sig)
			if tc.isErr && err == nil {
				t.Error("expected error")
			}
		})
	}
}

// TestSealToUser_NonEmpty exercises the happy-path: convert an Ed25519
// pubkey to X25519 and seal a payload. We can't decrypt without the
// matching identity privkey (which lives client-side), so the assertion
// is bounded to "ciphertext is non-empty + ephemeral-pubkey-prefix length".
func TestSealToUser_NonEmpty(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate ed25519 keypair: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(edPub)

	ctB64, err := SealToUser(pubB64, []byte("hello"))
	if err != nil {
		t.Fatalf("SealToUser: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		t.Fatalf("decode ct: %v", err)
	}
	// Sealed-box output = ephemeral X25519 pubkey (32 bytes) || crypto_box
	// (xsalsa20+poly1305 over plaintext, 16-byte tag prefix). For a 5-byte
	// plaintext this is 32 + 16 + 5 = 53 bytes minimum.
	if len(ct) < 53 {
		t.Errorf("sealed-box output too short: got %d bytes", len(ct))
	}
}

// TestSealToUser_FreshEphemeralPerCall verifies sealed-box generates a
// fresh ephemeral keypair per call — two seals of the same plaintext to
// the same recipient must produce different ciphertexts.
func TestSealToUser_FreshEphemeralPerCall(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(edPub)

	ct1, err := SealToUser(pubB64, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := SealToUser(pubB64, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if ct1 == ct2 {
		t.Error("two seals of identical plaintext must differ (fresh ephemeral required)")
	}
}

func TestSealToUser_BadPubkey(t *testing.T) {
	if _, err := SealToUser("not-base64!!!", []byte("x")); err == nil {
		t.Error("expected error on non-base64 pubkey")
	}
	if _, err := SealToUser(base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), []byte("x")); err == nil {
		t.Error("expected error on wrong-length pubkey")
	}
}
