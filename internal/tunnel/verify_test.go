package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

// genKey is a tiny helper that returns a fresh Ed25519 keypair. Tests use
// fresh keys so failures don't depend on global state.
func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// signCanon signs the canonical-JSON of a Go value with `priv` and returns the
// base64 signature, mirroring what a client producer would do.
func signCanon(t *testing.T, v any, priv ed25519.PrivateKey) string {
	t.Helper()
	canon, err := canonjson.Marshal(v)
	if err != nil {
		t.Fatalf("canon marshal: %v", err)
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
}

func TestVerifyEnvelope_AdminSignedHappyPath(t *testing.T) {
	ownerPub, ownerPriv := genKey(t)
	ownerB64 := base64.StdEncoding.EncodeToString(ownerPub)

	body := map[string]any{"memberId": "m1"}
	bodyBytes, _ := json.Marshal(body)
	msg := atreolink.TunnelMessage{
		Type:      "member:removed",
		Payload:   bodyBytes,
		SignerID:  "m-owner",
		Signature: signCanon(t, body, ownerPriv),
	}

	lookup := func(id string) (string, bool) {
		if id == "m-owner" {
			return ownerB64, true
		}
		return "", false
	}
	if err := VerifyEnvelope(msg, lookup); err != nil {
		t.Errorf("VerifyEnvelope: %v", err)
	}
}

func TestVerifyEnvelope_MemberSignedHappyPath(t *testing.T) {
	memberPub, memberPriv := genKey(t)
	memberB64 := base64.StdEncoding.EncodeToString(memberPub)

	body := map[string]any{"memberId": "m42", "leftAt": "2026-04-19T00:00:00Z"}
	bodyBytes, _ := json.Marshal(body)
	msg := atreolink.TunnelMessage{
		Type:      "member:left",
		Payload:   bodyBytes,
		SignerID:  "m42",
		Signature: signCanon(t, body, memberPriv),
	}

	lookup := func(id string) (string, bool) {
		if id == "m42" {
			return memberB64, true
		}
		return "", false
	}
	if err := VerifyEnvelope(msg, lookup); err != nil {
		t.Errorf("VerifyEnvelope: %v", err)
	}
}

func TestVerifyEnvelope_RejectsWhenUnsigned(t *testing.T) {
	msg := atreolink.TunnelMessage{Type: "member:removed", Payload: []byte(`{"memberId":"m1"}`)}
	err := VerifyEnvelope(msg, func(string) (string, bool) { return "", false })
	if !errors.Is(err, ErrUnsigned) {
		t.Errorf("err = %v, want ErrUnsigned", err)
	}
}

func TestVerifyEnvelope_RejectsUnknownSigner(t *testing.T) {
	_, priv := genKey(t)
	body := map[string]any{"x": 1}
	bodyBytes, _ := json.Marshal(body)
	msg := atreolink.TunnelMessage{
		Type:      "member:left",
		Payload:   bodyBytes,
		SignerID:  "ghost",
		Signature: signCanon(t, body, priv),
	}
	err := VerifyEnvelope(msg, func(string) (string, bool) { return "", false })
	if !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("err = %v, want ErrUnknownSigner", err)
	}
}

func TestVerifyEnvelope_RejectsTamperedPayload(t *testing.T) {
	ownerPub, ownerPriv := genKey(t)
	ownerB64 := base64.StdEncoding.EncodeToString(ownerPub)

	signed := map[string]any{"memberId": "m1"}
	tampered := map[string]any{"memberId": "m2"} // payload swapped post-signing
	tamperedBytes, _ := json.Marshal(tampered)
	msg := atreolink.TunnelMessage{
		Type:      "member:removed",
		Payload:   tamperedBytes,
		SignerID:  "m-owner",
		Signature: signCanon(t, signed, ownerPriv),
	}

	lookup := func(id string) (string, bool) {
		if id == "m-owner" {
			return ownerB64, true
		}
		return "", false
	}
	err := VerifyEnvelope(msg, lookup)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyEnvelope_RejectsWrongSignerKey(t *testing.T) {
	// Signer claims memberId "m1" but signs with a different key than what's
	// in the ACL — the substitution attack the envelope verification exists
	// to detect.
	body := map[string]any{"x": 1}
	bodyBytes, _ := json.Marshal(body)
	_, attackerPriv := genKey(t)
	realPub, _ := genKey(t)

	msg := atreolink.TunnelMessage{
		Type:      "member:left",
		Payload:   bodyBytes,
		SignerID:  "m1",
		Signature: signCanon(t, body, attackerPriv),
	}
	lookup := func(id string) (string, bool) {
		if id == "m1" {
			return base64.StdEncoding.EncodeToString(realPub), true
		}
		return "", false
	}
	err := VerifyEnvelope(msg, lookup)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

// --- verifyCommand + Auth variants -----------------------------------------

// commandFixture builds a minimal Handlers wired to a fresh ACL containing an
// admin member ("m-owner") plus a non-admin member ("m-test"). Both private
// keys are returned so tests can produce signed envelopes.
type commandFixture struct {
	h          *Handlers
	ownerPub   ed25519.PublicKey
	ownerPriv  ed25519.PrivateKey
	memberPub  ed25519.PublicKey
	memberPriv ed25519.PrivateKey
	memberID   string
}

func setupCommandFixture(t *testing.T) *commandFixture {
	t.Helper()
	dir := t.TempDir()
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	ownerPub, ownerPriv := genKey(t)
	if err := store.SetPinnedAdminPublicKey(ownerPub); err != nil {
		t.Fatalf("SetPinnedAdminPublicKey: %v", err)
	}
	memberPub, memberPriv := genKey(t)
	memberID := "m-test"
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{
			MemberID:    "m-owner",
			Role:        "admin",
			IdentityKey: base64.StdEncoding.EncodeToString(ownerPub),
		},
		{
			MemberID:    memberID,
			Role:        "member",
			IdentityKey: base64.StdEncoding.EncodeToString(memberPub),
		},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	return &commandFixture{
		h:          &Handlers{aclStore: store},
		ownerPub:   ownerPub,
		ownerPriv:  ownerPriv,
		memberPub:  memberPub,
		memberPriv: memberPriv,
		memberID:   memberID,
	}
}

// makeSignedCommand builds a TunnelMessage carrying a signed envelope over the
// supplied payload. The payload is JSON-marshalled, then canonicalised, then
// signed with `priv` so the agent's VerifyEnvelope (which re-canonicalises
// raw bytes) will accept it.
func makeSignedCommand(t *testing.T, msgType, signerID string, priv ed25519.PrivateKey, payload any) atreolink.TunnelMessage {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	canon, err := canonjson.MarshalRaw(body)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	return atreolink.TunnelMessage{
		Type:      msgType,
		Payload:   body,
		SignerID:  signerID,
		Signature: sig,
	}
}

func TestVerifyCommand_AdminHappyPath(t *testing.T) {
	f := setupCommandFixture(t)
	now := time.Now().Unix()
	intent := fmt.Sprintf("notify:apikey-dev-1-%d", now)
	payload := map[string]any{"deviceId": "dev-1", "intent": intent, "ts": now}
	msg := makeSignedCommand(t, "notify:apikey", "m-owner", f.ownerPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: now}
	if err := f.h.verifyCommand(msg, AdminAuth(), env, intent); err != nil {
		t.Errorf("verifyCommand: %v", err)
	}
}

func TestVerifyCommand_AdminRejectsNonAdminSigner(t *testing.T) {
	f := setupCommandFixture(t)
	// Non-admin member tries to sign an admin-only command.
	now := time.Now().Unix()
	intent := fmt.Sprintf("notify:apikey-dev-1-%d", now)
	payload := map[string]any{"deviceId": "dev-1", "intent": intent, "ts": now}
	msg := makeSignedCommand(t, "notify:apikey", f.memberID, f.memberPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: now}
	err := f.h.verifyCommand(msg, AdminAuth(), env, intent)
	if !errors.Is(err, ErrNotAdmin) {
		t.Errorf("err = %v, want ErrNotAdmin", err)
	}
}

func TestVerifyCommand_MemberHappyPath(t *testing.T) {
	f := setupCommandFixture(t)
	now := time.Now().Unix()
	intent := fmt.Sprintf("member:left-%s-%d", f.memberID, now)
	payload := map[string]any{"memberId": f.memberID, "intent": intent, "ts": now}
	msg := makeSignedCommand(t, "member:left", f.memberID, f.memberPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: now}
	if err := f.h.verifyCommand(msg, MemberAuth(f.memberID), env, intent); err != nil {
		t.Errorf("verifyCommand: %v", err)
	}
}

func TestVerifyCommand_AttestedHappyPath(t *testing.T) {
	f := setupCommandFixture(t)
	// AttestedAuth verifies against a pubkey supplied at the call site (used
	// for member:added where the new member isn't in the ACL yet). The
	// memberPub from the fixture stands in for the attested identity key.
	now := time.Now().Unix()
	intent := fmt.Sprintf("member:added-%s-%d", f.memberID, now)
	payload := map[string]any{"memberId": f.memberID, "intent": intent, "ts": now}
	msg := makeSignedCommand(t, "member:added", f.memberID, f.memberPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: now}
	if err := f.h.verifyCommand(msg, AttestedAuth(f.memberPub), env, intent); err != nil {
		t.Errorf("verifyCommand: %v", err)
	}
}

func TestVerifyCommand_MemberAdminCanSelfAct(t *testing.T) {
	// Admin members are just members for self-scoped actions — MemberAuth
	// keyed on the admin's own memberID accepts them without role checks.
	// (E.g. an owner pairing their own mobile signs push:pair:complete with
	// their membership UUID and goes through MemberAuth, not AdminAuth.)
	f := setupCommandFixture(t)
	now := time.Now().Unix()
	intent := fmt.Sprintf("wg:challenge-%s-%d", "m-owner", now)
	payload := map[string]any{"memberId": "m-owner", "intent": intent, "ts": now}
	msg := makeSignedCommand(t, "wg:challenge", "m-owner", f.ownerPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: now}
	if err := f.h.verifyCommand(msg, MemberAuth("m-owner"), env, intent); err != nil {
		t.Errorf("verifyCommand: %v", err)
	}
}

func TestVerifyCommand_RejectsIntentMismatch(t *testing.T) {
	f := setupCommandFixture(t)
	now := time.Now().Unix()
	signedIntent := fmt.Sprintf("notify:apikey-dev-1-%d", now)
	payload := map[string]any{"deviceId": "dev-1", "intent": signedIntent, "ts": now}
	msg := makeSignedCommand(t, "notify:apikey", "m-owner", f.ownerPriv, payload)

	env := CommandEnvelopeFields{Intent: signedIntent, Timestamp: now}
	wrongIntent := fmt.Sprintf("notify:apikey:rotate-dev-1-%d", now)
	err := f.h.verifyCommand(msg, AdminAuth(), env, wrongIntent)
	if !errors.Is(err, ErrIntentMismatch) {
		t.Errorf("err = %v, want ErrIntentMismatch", err)
	}
}

func TestVerifyCommand_RejectsStaleTimestamp(t *testing.T) {
	f := setupCommandFixture(t)
	stale := time.Now().Add(-10 * time.Minute).Unix()
	intent := fmt.Sprintf("notify:apikey-dev-1-%d", stale)
	payload := map[string]any{"deviceId": "dev-1", "intent": intent, "ts": stale}
	msg := makeSignedCommand(t, "notify:apikey", "m-owner", f.ownerPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: stale}
	err := f.h.verifyCommand(msg, AdminAuth(), env, intent)
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Errorf("err = %v, want ErrStaleTimestamp", err)
	}
}

func TestVerifyCommand_RejectsFutureTimestamp(t *testing.T) {
	f := setupCommandFixture(t)
	future := time.Now().Add(10 * time.Minute).Unix()
	intent := fmt.Sprintf("notify:apikey-dev-1-%d", future)
	payload := map[string]any{"deviceId": "dev-1", "intent": intent, "ts": future}
	msg := makeSignedCommand(t, "notify:apikey", "m-owner", f.ownerPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: future}
	err := f.h.verifyCommand(msg, AdminAuth(), env, intent)
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Errorf("err = %v, want ErrStaleTimestamp", err)
	}
}

func TestVerifyCommand_RejectsBadSignature(t *testing.T) {
	f := setupCommandFixture(t)
	// signerId claims m-owner but envelope signed by the member's key —
	// VerifyEnvelope surfaces ErrInvalidSignature (key in ACL for m-owner
	// doesn't match the signing key).
	now := time.Now().Unix()
	intent := fmt.Sprintf("notify:apikey-dev-1-%d", now)
	payload := map[string]any{"deviceId": "dev-1", "intent": intent, "ts": now}
	msg := makeSignedCommand(t, "notify:apikey", "m-owner", f.memberPriv, payload)

	env := CommandEnvelopeFields{Intent: intent, Timestamp: now}
	err := f.h.verifyCommand(msg, AdminAuth(), env, intent)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifySignatureAgainst_HappyPath(t *testing.T) {
	pub, priv := genKey(t)
	body, _ := json.Marshal(map[string]any{"x": 1})
	canon, _ := canonjson.MarshalRaw(body)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))
	msg := atreolink.TunnelMessage{
		Type:      "member:added",
		Payload:   body,
		SignerID:  "anything",
		Signature: sig,
	}
	if err := verifySignatureAgainst(msg, pub); err != nil {
		t.Errorf("verifySignatureAgainst: %v", err)
	}
}

func TestVerifySignatureAgainst_RejectsUnsigned(t *testing.T) {
	pub, _ := genKey(t)
	msg := atreolink.TunnelMessage{
		Type:    "member:added",
		Payload: []byte(`{"x":1}`),
	}
	err := verifySignatureAgainst(msg, pub)
	if !errors.Is(err, ErrUnsigned) {
		t.Errorf("err = %v, want ErrUnsigned", err)
	}
}

func TestVerifySignatureAgainst_RejectsTampered(t *testing.T) {
	pub, priv := genKey(t)
	signed, _ := json.Marshal(map[string]any{"x": 1})
	canon, _ := canonjson.MarshalRaw(signed)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon))

	tampered, _ := json.Marshal(map[string]any{"x": 2})
	msg := atreolink.TunnelMessage{
		Type:      "member:added",
		Payload:   tampered,
		SignerID:  "anything",
		Signature: sig,
	}
	err := verifySignatureAgainst(msg, pub)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("err = %v, want ErrInvalidSignature", err)
	}
}
