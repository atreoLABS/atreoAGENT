package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

// Stand-in NAS pubkey (base64) for tests that reach the decode path.
const testNASB64 = "TmFzS2V5QmFzZTY0QUFBQUFBQUFBQUFBQUFBQUFBQUE="

// buildApprovalBlob mirrors what the operator-side approver does at pair
// time: canonical-JSON the inner payload, sign it under the
// owner's identity key, then AES-256-GCM encrypt (canonical-JSON ||
// ownerSelfSig) under HKDF(pairToken, "atreos-pair-v1").
func buildApprovalBlob(t *testing.T, pairToken []byte, ownerPub ed25519.PublicKey, ownerPriv ed25519.PrivateKey, pairSessionID, approvedAt string) atreolink.PairApprovalBlob {
	t.Helper()
	inner := map[string]any{
		"pairSessionId":       pairSessionID,
		"ownerIdentityPubkey": base64.StdEncoding.EncodeToString(ownerPub),
		"approvedAt":          approvedAt,
	}
	canon, err := canonjson.Marshal(inner)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	sig := ed25519.Sign(ownerPriv, canon)
	plain := append(canon, sig...)

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, pairToken, nil, []byte(PairInfoString))
	if _, err := io.ReadFull(r, key); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ct := gcm.Seal(nil, nonce, plain, nil)

	return atreolink.PairApprovalBlob{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
}

func TestDecodePairApprovalBlob_HappyPath(t *testing.T) {
	pairToken := make([]byte, 32)
	if _, err := rand.Read(pairToken); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ownerPub, ownerPriv := genKey(t)

	blob := buildApprovalBlobNAS(t, pairToken, ownerPub, ownerPriv, "dev-1", "dev-1", testNASB64, nil)
	gotPub, gotCanon, gotApprovedAt, err := DecodePairApprovalBlob(blob, pairToken, "dev-1", testNASB64)
	if err != nil {
		t.Fatalf("DecodePairApprovalBlob: %v", err)
	}
	if string(gotPub) != string(ownerPub) {
		t.Errorf("pubkey mismatch")
	}
	if len(gotCanon) == 0 {
		t.Error("payloadCanon is empty")
	}
	if gotApprovedAt != "2026-05-18T00:00:00Z" {
		t.Errorf("approvedAt = %q", gotApprovedAt)
	}
}

func TestDecodePairApprovalBlob_RejectsWrongToken(t *testing.T) {
	realToken := make([]byte, 32)
	wrongToken := make([]byte, 32)
	if _, err := rand.Read(realToken); err != nil {
		t.Fatalf("rand.Read realToken: %v", err)
	}
	if _, err := rand.Read(wrongToken); err != nil {
		t.Fatalf("rand.Read wrongToken: %v", err)
	}
	ownerPub, ownerPriv := genKey(t)

	blob := buildApprovalBlob(t, realToken, ownerPub, ownerPriv, "dev-1", "2026-04-19T00:00:00Z")
	_, _, _, err := DecodePairApprovalBlob(blob, wrongToken, "dev-1", "")
	if !errors.Is(err, ErrPairApprovalDecrypt) {
		t.Errorf("err = %v, want ErrPairApprovalDecrypt", err)
	}
}

func TestDecodePairApprovalBlob_RejectsForgedSignature(t *testing.T) {
	pairToken := make([]byte, 32)
	if _, err := rand.Read(pairToken); err != nil {
		t.Fatalf("rand.Read pairToken: %v", err)
	}
	// Build the inner payload with a "claimed" owner pubkey that doesn't match
	// the signing key. AES-GCM still decrypts successfully (the attacker holds
	// pairToken in this scenario — e.g. compromised browser RAM), but the
	// signature verification step catches it.
	claimedPub, _ := genKey(t)
	_, attackerPriv := genKey(t)

	// Hand-build the encrypted blob with a mismatched signer/claimed key.
	inner := map[string]any{
		"pairSessionId":       "sess-1",
		"ownerIdentityPubkey": base64.StdEncoding.EncodeToString(claimedPub),
		"approvedAt":          "2026-04-19T00:00:00Z",
	}
	canon, _ := canonjson.Marshal(inner)
	sig := ed25519.Sign(attackerPriv, canon) // signed with WRONG key
	plain := append(canon, sig...)

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, pairToken, nil, []byte(PairInfoString))
	_, _ = io.ReadFull(r, key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read nonce: %v", err)
	}
	ct := gcm.Seal(nil, nonce, plain, nil)

	blob := atreolink.PairApprovalBlob{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	_, _, _, err := DecodePairApprovalBlob(blob, pairToken, "sess-1", "")
	if !errors.Is(err, ErrPairApprovalSig) {
		t.Errorf("err = %v, want ErrPairApprovalSig", err)
	}
}

func TestDecodePairApprovalBlob_RejectsSessionMismatch(t *testing.T) {
	pairToken := make([]byte, 32)
	if _, err := rand.Read(pairToken); err != nil {
		t.Fatalf("rand.Read pairToken: %v", err)
	}
	ownerPub, ownerPriv := genKey(t)
	blob := buildApprovalBlob(t, pairToken, ownerPub, ownerPriv, "sess-A", "2026-04-19T00:00:00Z")
	_, _, _, err := DecodePairApprovalBlob(blob, pairToken, "sess-B", "")
	if !errors.Is(err, ErrPairApprovalSessionMismatch) {
		t.Errorf("err = %v, want ErrPairApprovalSessionMismatch", err)
	}
}

func TestDecodePairApprovalBlob_AcceptsMatchingSession(t *testing.T) {
	pairToken := make([]byte, 32)
	if _, err := rand.Read(pairToken); err != nil {
		t.Fatalf("rand.Read pairToken: %v", err)
	}
	ownerPub, ownerPriv := genKey(t)
	const sessionID = "11111111-1111-1111-1111-111111111111"
	blob := buildApprovalBlobNAS(t, pairToken, ownerPub, ownerPriv, sessionID, "dev-1", testNASB64, nil)
	gotPub, _, _, err := DecodePairApprovalBlob(blob, pairToken, sessionID, testNASB64)
	if err != nil {
		t.Fatalf("DecodePairApprovalBlob with matching session id: %v", err)
	}
	if string(gotPub) != string(ownerPub) {
		t.Error("pubkey mismatch")
	}
}

// Like buildApprovalBlob, plus inner nasPubkey + a standalone owner
// signature over canonical({nasPubkey}). attOverride non-nil forges it.
func buildApprovalBlobNAS(t *testing.T, pairToken []byte, ownerPub ed25519.PublicKey, ownerPriv ed25519.PrivateKey, sessionID, deviceID, nasPubkey string, attOverride []byte) atreolink.PairApprovalBlob {
	t.Helper()
	attSig := attOverride
	if attSig == nil {
		attCanon, err := canonjson.Marshal(nasAttestationBody{NASPubkey: nasPubkey})
		if err != nil {
			t.Fatalf("att canon: %v", err)
		}
		attSig = ed25519.Sign(ownerPriv, attCanon)
	}
	inner := map[string]any{
		"pairSessionId":       sessionID,
		"ownerIdentityPubkey": base64.StdEncoding.EncodeToString(ownerPub),
		"approvedAt":          "2026-05-18T00:00:00Z",
		"deviceId":            deviceID,
		"nasPubkey":           nasPubkey,
		"nasAttestationSig":   base64.StdEncoding.EncodeToString(attSig),
	}
	canon, err := canonjson.Marshal(inner)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	plain := append(canon, ed25519.Sign(ownerPriv, canon)...)

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, pairToken, nil, []byte(PairInfoString))
	if _, err := io.ReadFull(r, key); err != nil {
		t.Fatalf("hkdf: %v", err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ct := gcm.Seal(nil, nonce, plain, nil)
	return atreolink.PairApprovalBlob{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
}

func TestDecodePairApprovalBlob_NASAnchor(t *testing.T) {
	pairToken := make([]byte, 32)
	if _, err := rand.Read(pairToken); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ownerPub, ownerPriv := genKey(t)
	const sess = "s1"
	const dev = "dev-1"
	const realNAS = testNASB64

	t.Run("accepts matching nasPubkey + valid attestation", func(t *testing.T) {
		blob := buildApprovalBlobNAS(t, pairToken, ownerPub, ownerPriv, sess, dev, realNAS, nil)
		if _, _, _, err := DecodePairApprovalBlob(blob, pairToken, sess, realNAS); err != nil {
			t.Fatalf("want accept, got %v", err)
		}
	})

	t.Run("rejects substituted nasPubkey", func(t *testing.T) {
		blob := buildApprovalBlobNAS(t, pairToken, ownerPub, ownerPriv, sess, dev, "c3Vic3RpdHV0ZWRLZXlBQUFBQUFBQUFBQUFBQUFBQUE=", nil)
		_, _, _, err := DecodePairApprovalBlob(blob, pairToken, sess, realNAS)
		if !errors.Is(err, ErrPairApprovalNASMismatch) {
			t.Fatalf("err = %v, want ErrPairApprovalNASMismatch", err)
		}
	})

	t.Run("rejects missing nasPubkey when this NAS requires it", func(t *testing.T) {
		blob := buildApprovalBlob(t, pairToken, ownerPub, ownerPriv, sess, "2026-05-18T00:00:00Z")
		_, _, _, err := DecodePairApprovalBlob(blob, pairToken, sess, realNAS)
		if !errors.Is(err, ErrPairApprovalNASMismatch) {
			t.Fatalf("err = %v, want ErrPairApprovalNASMismatch", err)
		}
	})

	t.Run("rejects forged nasAttestationSig", func(t *testing.T) {
		_, attackerPriv := genKey(t)
		attCanon, _ := canonjson.Marshal(nasAttestationBody{NASPubkey: realNAS})
		forged := ed25519.Sign(attackerPriv, attCanon)
		blob := buildApprovalBlobNAS(t, pairToken, ownerPub, ownerPriv, sess, dev, realNAS, forged)
		_, _, _, err := DecodePairApprovalBlob(blob, pairToken, sess, realNAS)
		if !errors.Is(err, ErrPairApprovalNASAttestation) {
			t.Fatalf("err = %v, want ErrPairApprovalNASAttestation", err)
		}
	})

	t.Run("rejects empty expectedNASPubkey (anchor never skipped)", func(t *testing.T) {
		blob := buildApprovalBlobNAS(t, pairToken, ownerPub, ownerPriv, sess, dev, realNAS, nil)
		_, _, _, err := DecodePairApprovalBlob(blob, pairToken, sess, "")
		if !errors.Is(err, ErrPairApprovalNASKeyUnknown) {
			t.Fatalf("err = %v, want ErrPairApprovalNASKeyUnknown", err)
		}
	})
}
