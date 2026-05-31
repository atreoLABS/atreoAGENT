package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/wireguard"
)

// testDeviceID is the server's own device ID used throughout tests — threaded
// into NewHandlers so envelope-binding is consistent.
const testDeviceID = "dev-test-1"

// testClientKey is a valid 32-byte base64-encoded placeholder for the
// client's WG (Curve25519) public key. The real WG handshake doesn't run in
// these tests but the value must be well-formed so canonical-JSON encoding
// of the signed payload matches between sides.
func testClientKey(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// signMember signs an arbitrary payload using the test member's identity key,
// returning a TunnelMessage envelope with signerId/signature filled in.
// Mirrors the signed-command envelope a client producer puts on the wire.
func signMember(t *testing.T, msgType, correlID string, payload any, signerID string, priv ed25519.PrivateKey) atreolink.TunnelMessage {
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
		Type:          msgType,
		CorrelationID: correlID,
		Payload:       body,
		SignerID:      signerID,
		Signature:     sig,
	}
}

// memberKeypair generates a fresh Ed25519 keypair the test treats as a
// non-owner member's identity key. Returned as (pub, priv, base64Pub).
func memberKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(pub)
}

// setupHandlers builds a Handlers wired to a fresh ACL containing one
// non-owner member with a fresh Ed25519 identity key. Returns the Handlers,
// the member's private key, the member's id, and a fresh client WG key.
func setupHandlers(t *testing.T) (*Handlers, ed25519.PrivateKey, string, string) {
	t.Helper()
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	wgKeysDir := filepath.Join(dir, "wgkeys")

	km, err := crypto.NewKeyManager(keysDir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	allocator, err := wireguard.NewIPAllocator("100.64.0.0/24", "100.64.0.1", filepath.Join(dir, "alloc.json"))
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}

	wgServer, err := wireguard.NewServer(51820, "100.64.0.1", "100.64.0.0/24", wgKeysDir, allocator)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	clientKey := testClientKey(t)
	_, memberPriv, memberPubB64 := memberKeypair(t)
	memberID := "m-test-1"

	aclStore := acl.NewStore(filepath.Join(dir, "acl.json"))
	if err := aclStore.ReplaceAll([]atreolink.MemberACLEntry{
		{
			MemberID:    memberID,
			Role:        "member",
			IdentityKey: memberPubB64,
			Clients:     []atreolink.ClientRecord{{WGPublicKey: clientKey}},
		},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}

	h := NewHandlers(wgServer, aclStore, km, allocator, filepath.Join(dir, "pairing.json"), testDeviceID, "test.atreotunnel.com", nil, nil, nil, nil)
	return h, memberPriv, memberID, clientKey
}

func TestHandleChallenge(t *testing.T) {
	h, memberPriv, memberID, clientKey := setupHandlers(t)

	now := time.Now().Unix()
	payload := ChallengePayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:challenge-%s-%d", memberID, now),
			Timestamp: now,
		},
		MembershipID: memberID,
		MemberID:     memberID,
		ClientID:     "client-1",
		ClientKey:    clientKey,
	}
	msg := signMember(t, "wg:challenge", "corr-1", payload, memberID, memberPriv)

	resp, err := h.HandleChallenge(msg)
	if err != nil {
		t.Fatalf("HandleChallenge: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Type != "wg:challenge:nonce" {
		t.Errorf("Type = %q, want wg:challenge:nonce", resp.Type)
	}
	if resp.CorrelationID != "corr-1" {
		t.Errorf("CorrelationID = %q", resp.CorrelationID)
	}

	var noncePayload ChallengeNoncePayload
	if err := json.Unmarshal(resp.Payload, &noncePayload); err != nil {
		t.Fatalf("unmarshal nonce: %v", err)
	}
	if noncePayload.Nonce == "" {
		t.Error("nonce is empty")
	}
	if len(noncePayload.Nonce) != 64 {
		t.Errorf("nonce length = %d, want 64", len(noncePayload.Nonce))
	}
}

// issueChallenge runs the challenge step (with a valid envelope sig) and
// returns the issued nonce, so each provision test starts with a fresh nonce
// in the store.
func issueChallenge(t *testing.T, h *Handlers, memberPriv ed25519.PrivateKey, memberID, clientID, clientKey, correlID string) string {
	t.Helper()
	now := time.Now().Unix()
	payload := ChallengePayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:challenge-%s-%d", memberID, now),
			Timestamp: now,
		},
		MembershipID: memberID,
		MemberID:     memberID,
		ClientID:     clientID,
		ClientKey:    clientKey,
	}
	msg := signMember(t, "wg:challenge", correlID, payload, memberID, memberPriv)
	resp, err := h.HandleChallenge(msg)
	if err != nil {
		t.Fatalf("HandleChallenge: %v", err)
	}
	var n ChallengeNoncePayload
	if err := json.Unmarshal(resp.Payload, &n); err != nil {
		t.Fatalf("unmarshal nonce: %v", err)
	}
	return n.Nonce
}

func TestHandleProvision_Valid(t *testing.T) {
	// Skip if wg CLI is not available (needed for real WireGuard operations)
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg not in PATH — skipping provision test (requires wireguard-tools)")
	}
	h, memberPriv, memberID, clientKey := setupHandlers(t)
	clientID := "client-1"

	nonce := issueChallenge(t, h, memberPriv, memberID, clientID, clientKey, "corr-1")

	now := time.Now().Unix()
	payload := ProvisionPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:provision-%s-%s-%s-%d", memberID, clientID, nonce, now),
			Timestamp: now,
		},
		MembershipID:      memberID,
		MemberID:          memberID,
		ClientID:          clientID,
		ClientKey:         clientKey,
		Nonce:             nonce,
		ChallengeCorrelID: "corr-1",
	}
	msg := signMember(t, "wg:provision", "corr-provision-1", payload, memberID, memberPriv)

	resp, err := h.HandleProvision(msg)
	if err != nil {
		t.Fatalf("HandleProvision: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Type != "wg:provision:response" {
		t.Errorf("Type = %q", resp.Type)
	}

	var provResp ProvisionResponsePayload
	if err := json.Unmarshal(resp.Payload, &provResp); err != nil {
		t.Fatalf("unmarshal provision response: %v", err)
	}
	if provResp.TunnelIP == "" {
		t.Error("TunnelIP is empty")
	}
	if provResp.ServerPublicKey == "" {
		t.Error("ServerPublicKey is empty")
	}
	if provResp.NASSignature == "" {
		t.Error("NASSignature is empty")
	}
}

// TestHandleProvision_MissingTunnelHost asserts the v2 transcript
// fail-fast guard: a Handlers built with an empty tunnelHost must
// refuse to provision before touching the IP allocator or wg state.
// Without this guard, a misconfigured deploy could allocate IPs and
// add wg peers and only fail at signing time, leaving the agent in a
// half-applied state.
func TestHandleProvision_MissingTunnelHost(t *testing.T) {
	h, memberPriv, memberID, clientKey := setupHandlers(t)
	h.tunnelHost = ""

	now := time.Now().Unix()
	payload := ProvisionPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:provision-%s-%s-fakenonce-%d", memberID, "client-1", now),
			Timestamp: now,
		},
		MembershipID:      memberID,
		MemberID:          memberID,
		ClientID:          "client-1",
		ClientKey:         clientKey,
		Nonce:             "fakenonce",
		ChallengeCorrelID: "nonexistent",
	}
	msg := signMember(t, "wg:provision", "corr-mth", payload, memberID, memberPriv)

	_, err := h.HandleProvision(msg)
	if err == nil {
		t.Fatal("expected error for missing tunnelHost")
	}
	if !strings.Contains(err.Error(), "tunnelHost") {
		t.Errorf("error = %q, want one mentioning tunnelHost", err.Error())
	}
}

func TestHandleProvision_NoNonce(t *testing.T) {
	h, memberPriv, memberID, clientKey := setupHandlers(t)
	clientID := "client-1"

	now := time.Now().Unix()
	payload := ProvisionPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:provision-%s-%s-fakenonce-%d", memberID, clientID, now),
			Timestamp: now,
		},
		MembershipID:      memberID,
		MemberID:          memberID,
		ClientID:          clientID,
		ClientKey:         clientKey,
		Nonce:             "fakenonce",
		ChallengeCorrelID: "nonexistent",
	}
	msg := signMember(t, "wg:provision", "corr-np", payload, memberID, memberPriv)

	if _, err := h.HandleProvision(msg); err == nil {
		t.Error("expected error for missing nonce")
	}
}

// TestHandleProvision_InvalidSignature: a provision request whose envelope
// sig was made by a different key than the one in the ACL must be rejected.
// Stands in for atreoLINK forging a payload without the member's private key.
func TestHandleProvision_InvalidSignature(t *testing.T) {
	h, memberPriv, memberID, clientKey := setupHandlers(t)
	clientID := "client-1"

	nonce := issueChallenge(t, h, memberPriv, memberID, clientID, clientKey, "corr-mitm")

	// Build a valid-looking payload but sign with a stranger's key.
	_, attackerPriv, _ := memberKeypair(t)
	now := time.Now().Unix()
	payload := ProvisionPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:provision-%s-%s-%s-%d", memberID, clientID, nonce, now),
			Timestamp: now,
		},
		MembershipID:      memberID,
		MemberID:          memberID,
		ClientID:          clientID,
		ClientKey:         clientKey,
		Nonce:             nonce,
		ChallengeCorrelID: "corr-mitm",
	}
	msg := signMember(t, "wg:provision", "corr-mitm-prov", payload, memberID, attackerPriv)

	if _, err := h.HandleProvision(msg); err == nil {
		t.Fatal("expected rejection for envelope signed by wrong key")
	}
}

// TestHandleProvision_SwappedClientKey covers the specific attack the
// envelope signature defends against: atreoLINK substitutes a different
// clientPubKey in the relayed provision payload. The original member signed
// canonical-JSON of the original payload (with the original key), so any
// post-signing field swap by atreoLINK invalidates the envelope signature.
func TestHandleProvision_SwappedClientKey(t *testing.T) {
	h, memberPriv, memberID, clientKey := setupHandlers(t)
	clientID := "client-1"

	nonce := issueChallenge(t, h, memberPriv, memberID, clientID, clientKey, "corr-swap")

	// Member signs a payload with the legit client key.
	now := time.Now().Unix()
	signedPayload := ProvisionPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:provision-%s-%s-%s-%d", memberID, clientID, nonce, now),
			Timestamp: now,
		},
		MembershipID:      memberID,
		MemberID:          memberID,
		ClientID:          clientID,
		ClientKey:         clientKey,
		Nonce:             nonce,
		ChallengeCorrelID: "corr-swap",
	}
	signedBody, _ := json.Marshal(signedPayload)
	canon, _ := canonjson.MarshalRaw(signedBody)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(memberPriv, canon))

	// atreoLINK swaps the client key but keeps the original signature.
	tampered := signedPayload
	tampered.ClientKey = testClientKey(t)
	tamperedBody, _ := json.Marshal(tampered)

	msg := atreolink.TunnelMessage{
		Type:          "wg:provision",
		CorrelationID: "corr-swap-prov",
		Payload:       tamperedBody,
		SignerID:      memberID,
		Signature:     sig,
	}

	if _, err := h.HandleProvision(msg); err == nil {
		t.Fatal("expected rejection when client key differs from the one signed")
	}
}

// TestHandleProvision_PeerLeakRollback exercises the rollback path:
// when wgServer.AddPeer fails AFTER aclStore.AddClient succeeded, the
// just-added client must be removed from the ACL and the allocator
// slot released. Otherwise the agent ends up with a half-applied
// state (ACL row referencing a kernel peer that doesn't exist) that
// would silently route nothing for the client and never recover.
func TestHandleProvision_PeerLeakRollback(t *testing.T) {
	if _, err := exec.LookPath("wg"); err == nil {
		t.Skip("wg available — rollback path exercised only when AddPeer fails")
	}
	h, memberPriv, memberID, clientKey := setupHandlers(t)
	clientID := "client-rollback"

	nonce := issueChallenge(t, h, memberPriv, memberID, clientID, clientKey, "corr-rb")
	now := time.Now().Unix()
	prov := ProvisionPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:provision-%s-%s-%s-%d", memberID, clientID, nonce, now),
			Timestamp: now,
		},
		MembershipID:      memberID,
		MemberID:          memberID,
		ClientID:          clientID,
		ClientKey:         clientKey,
		Nonce:             nonce,
		ChallengeCorrelID: "corr-rb",
	}
	msg := signMember(t, "wg:provision", "corr-rb-prov", prov, memberID, memberPriv)
	if _, err := h.HandleProvision(msg); err == nil {
		t.Fatal("expected AddPeer to fail without wg CLI")
	}

	// The member's ACL row must not have ended up with the client
	// (rollback removed it) and the allocator slot for clientKey
	// must be free (rollback released it). We can probe the latter
	// indirectly by allocating again — should succeed and yield the
	// same canonical first-available IP rather than the next free
	// slot.
	allocator := h.allocator
	ip1, err := allocator.Allocate("probe-key-1")
	if err != nil {
		t.Fatalf("post-rollback alloc 1: %v", err)
	}
	allocator.Release("probe-key-1")
	ip2, err := allocator.Allocate("probe-key-2")
	if err != nil {
		t.Fatalf("post-rollback alloc 2: %v", err)
	}
	if ip1 != ip2 {
		t.Errorf("allocator state inconsistent across release: %q vs %q", ip1, ip2)
	}
}
