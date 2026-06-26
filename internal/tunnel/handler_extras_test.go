package tunnel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/wireguard"
)

// ownedFixture builds a Handlers wired to a fresh ACL store, real wireguard
// server (subprocess calls degrade gracefully when `wg` isn't installed), and
// a pinned owner identity. The returned ownerPriv is what tests use to forge
// owner-signed envelopes; memberPriv is the identity for "m-bob" who has been
// added to the ACL via direct UpsertMember (bypassing attestation since these
// tests don't exercise the attestation path).
type ownedFixture struct {
	h          *Handlers
	store      *acl.Store
	km         *crypto.KeyManager
	dir        string
	ownerPub   ed25519.PublicKey
	ownerPriv  ed25519.PrivateKey
	memberPub  ed25519.PublicKey
	memberPriv ed25519.PrivateKey
}

func setupOwnedFixture(t *testing.T) *ownedFixture {
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
	wgServer, err := wireguard.NewServer(51820, "100.64.0.1", "100.64.0.0/24", "fd00:64::1", "fd00:64::/64", wgKeysDir, allocator)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	store := acl.NewStore(filepath.Join(dir, "acl.json"))

	ownerPub, ownerPriv := genKey(t)
	memberPub, memberPriv := genKey(t)

	if err := store.SetPinnedAdminPublicKey(ownerPub); err != nil {
		t.Fatalf("SetPinnedAdminPublicKey: %v", err)
	}

	// Seed an owner ACL entry (so requireOwner pin check passes ReplaceAll)
	// plus a regular member with a real identity key the tests sign with.
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{
			MemberID:    "m-owner",
			Role:        "admin",
			IdentityKey: base64.StdEncoding.EncodeToString(ownerPub),
		},
		{
			MemberID:    "m-bob",
			Role:        "member",
			IdentityKey: base64.StdEncoding.EncodeToString(memberPub),
			Clients: []atreolink.ClientRecord{
				{WGPublicKey: "wgkey-bob-1", TunnelIP: "100.64.0.50"},
			},
		},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}

	h := NewHandlers(wgServer, store, km, allocator, filepath.Join(dir, "pairing.json"), testDeviceID, "test.atreotunnel.com", nil, nil, nil, nil)
	return &ownedFixture{
		h: h, store: store, km: km, dir: dir,
		ownerPub: ownerPub, ownerPriv: ownerPriv,
		memberPub: memberPub, memberPriv: memberPriv,
	}
}

// envelope builds a signed TunnelMessage. signerID may be "m-owner" or a
// memberID; priv is the matching private key.
func envelope(t *testing.T, msgType, signerID string, priv ed25519.PrivateKey, payload any) atreolink.TunnelMessage {
	t.Helper()
	bodyBytes, _ := json.Marshal(payload)
	return atreolink.TunnelMessage{
		Type:      msgType,
		Payload:   bodyBytes,
		SignerID:  signerID,
		Signature: signCanon(t, payload, priv),
	}
}

// --- requireOwner / requireMember --------------------------------------------

func TestRequireAdmin_UnknownSigner(t *testing.T) {
	dir := t.TempDir()
	store := acl.NewStore(filepath.Join(dir, "acl.json"))
	h := &Handlers{aclStore: store}

	msg := atreolink.TunnelMessage{SignerID: "m-owner", Signature: "sig"}
	err := h.requireAdmin(msg)
	if !errors.Is(err, ErrUnknownSigner) {
		t.Errorf("err=%v, want ErrUnknownSigner", err)
	}
}

func TestRequireAdmin_NonAdminSigner(t *testing.T) {
	f := setupOwnedFixture(t)
	// m-bob is a regular member, not an admin — must reject.
	msg := envelope(t, "x", "m-bob", f.memberPriv, map[string]any{"hello": "world"})
	err := f.h.requireAdmin(msg)
	if !errors.Is(err, ErrNotAdmin) {
		t.Errorf("err=%v, want ErrNotAdmin", err)
	}
}

func TestRequireAdmin_Valid(t *testing.T) {
	f := setupOwnedFixture(t)
	msg := envelope(t, "x", "m-owner", f.ownerPriv, map[string]any{"hello": "world"})
	if err := f.h.requireAdmin(msg); err != nil {
		t.Errorf("requireAdmin: %v", err)
	}
}

func TestRequireMember_WrongSignerID(t *testing.T) {
	f := setupOwnedFixture(t)
	msg := atreolink.TunnelMessage{SignerID: "m-bob"}
	if err := f.h.requireMember(msg, "m-alice"); err == nil {
		t.Error("expected error when signerId != expected member")
	}
}

func TestRequireMember_Valid(t *testing.T) {
	f := setupOwnedFixture(t)
	msg := envelope(t, "x", "m-bob", f.memberPriv, map[string]any{"hi": "there"})
	if err := f.h.requireMember(msg, "m-bob"); err != nil {
		t.Errorf("requireMember: %v", err)
	}
}

func TestACLLookup(t *testing.T) {
	f := setupOwnedFixture(t)
	lookup := f.h.aclLookup()

	if got, ok := lookup("m-bob"); !ok || got != base64.StdEncoding.EncodeToString(f.memberPub) {
		t.Errorf("lookup(m-bob)=%q,%v", got, ok)
	}
	if _, ok := lookup("ghost"); ok {
		t.Error("lookup(ghost) returned ok=true")
	}
}

func TestOwnerPub_ReturnsPinned(t *testing.T) {
	f := setupOwnedFixture(t)
	got := f.h.ownerPub()
	if !got.Equal(f.ownerPub) {
		t.Errorf("ownerPub mismatch")
	}
}

// --- RegisterAll -------------------------------------------------------------

func TestRegisterAll(t *testing.T) {
	f := setupOwnedFixture(t)
	c := NewClient(nil, "http://x", nil, "")
	f.h.RegisterAll(c)

	expected := []string{
		"wg:challenge", "wg:provision",
		"device:state", "device:state:gz", "acl:heartbeat:ack",
		"device:unpaired",
		"notify:apikey", "notify:apikey:rotate",
	}
	for _, gone := range []string{
		"member:added", "member:status", "app:upserted", "device:custom-domain-set",
	} {
		c.mu.RLock()
		_, ok := c.handlers[gone]
		c.mu.RUnlock()
		if ok {
			t.Errorf("legacy handler %q must no longer be registered", gone)
		}
	}
	for _, msgType := range expected {
		c.mu.RLock()
		_, ok := c.handlers[msgType]
		c.mu.RUnlock()
		if !ok {
			t.Errorf("handler %q not registered", msgType)
		}
	}
}

// --- HandleUnpaired (rejection paths only — happy path calls os.Exit) -------

func TestHandleUnpaired_RejectsUnsigned(t *testing.T) {
	f := setupOwnedFixture(t)
	msg := atreolink.TunnelMessage{Type: "device:unpaired", Payload: []byte(`{}`)}
	if _, err := f.h.HandleUnpaired(msg); err == nil {
		t.Error("expected rejection of unsigned envelope")
	}
}

func TestHandleUnpaired_RejectsBadIntent(t *testing.T) {
	f := setupOwnedFixture(t)
	now := time.Now().Unix()
	msg := envelope(t, "device:unpaired", "m-owner", f.ownerPriv, DeviceUnpairedPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    "wrong-intent",
			Timestamp: now,
		},
		DeviceID: testDeviceID,
	})
	if _, err := f.h.HandleUnpaired(msg); err == nil {
		t.Error("expected intent mismatch rejection")
	}
}

func TestHandleUnpaired_RejectsBadDeviceID(t *testing.T) {
	f := setupOwnedFixture(t)
	now := time.Now().Unix()
	msg := envelope(t, "device:unpaired", "m-owner", f.ownerPriv, DeviceUnpairedPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("unpair-device-%s-%d", testDeviceID, now),
			Timestamp: now,
		},
		DeviceID: "other-device",
	})
	if _, err := f.h.HandleUnpaired(msg); err == nil {
		t.Error("expected deviceId mismatch rejection")
	}
}

func TestHandleUnpaired_RejectsStaleTimestamp(t *testing.T) {
	f := setupOwnedFixture(t)
	stale := time.Now().Add(-10 * time.Minute).Unix()
	msg := envelope(t, "device:unpaired", "m-owner", f.ownerPriv, DeviceUnpairedPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("unpair-device-%s-%d", testDeviceID, stale),
			Timestamp: stale,
		},
		DeviceID: testDeviceID,
	})
	if _, err := f.h.HandleUnpaired(msg); !errors.Is(err, ErrStaleTimestamp) {
		t.Errorf("err=%v, want ErrStaleTimestamp", err)
	}
}
