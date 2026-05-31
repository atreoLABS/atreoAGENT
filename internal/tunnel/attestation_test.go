package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

// buildAttestation produces a verifiable JoinAttestation for the given
// owner+invitee keypair pair. Mirrors the producer-side flow a client performs.
func buildAttestation(t *testing.T, ownerPriv ed25519.PrivateKey, inviteePub ed25519.PublicKey, nasPubB64 string) atreolink.JoinAttestation {
	t.Helper()
	return buildAttestationExp(t, ownerPriv, inviteePub, nasPubB64, "2030-01-01T00:00:00Z")
}

// buildAttestationExp is buildAttestation with a caller-chosen expiresAt.
func buildAttestationExp(t *testing.T, ownerPriv ed25519.PrivateKey, inviteePub ed25519.PublicKey, nasPubB64, expiresAt string) atreolink.JoinAttestation {
	t.Helper()

	// Synthetic invite token + derived invite keypair.
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatalf("rand: %v", err)
	}
	invitePub, invitePriv, err := DeriveInvitePubFromToken(token)
	if err != nil {
		t.Fatalf("DeriveInvitePubFromToken: %v", err)
	}

	inv := map[string]any{
		"inviteId":      "inv-1",
		"deviceId":      "dev-1",
		"nasPubkey":     nasPubB64,
		"allowedAppIds": []any{"app1"},
		"expiresAt":     expiresAt,
		"tokenHash":     base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		"invitePub":     base64.StdEncoding.EncodeToString(invitePub),
	}
	canonInv, err := canonjson.Marshal(inv)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	ownerSig := ed25519.Sign(ownerPriv, canonInv)
	acceptanceSig := ed25519.Sign(invitePriv, inviteePub)

	return atreolink.JoinAttestation{
		InvitePayload: base64.StdEncoding.EncodeToString(canonInv),
		OwnerSig:      base64.StdEncoding.EncodeToString(ownerSig),
		AcceptanceSig: base64.StdEncoding.EncodeToString(acceptanceSig),
	}
}

func TestVerifyJoinAttestation_HappyPath(t *testing.T) {
	ownerPub, ownerPriv := genKey(t)
	inviteePub, _ := genKey(t)
	nasPub, _ := genKey(t)
	nasB64 := base64.StdEncoding.EncodeToString(nasPub)

	att := buildAttestation(t, ownerPriv, inviteePub, nasB64)
	member := atreolink.MemberACLEntry{
		MemberID:        "m1",
		Role:            "member",
		IdentityKey:     base64.StdEncoding.EncodeToString(inviteePub),
		JoinAttestation: &att,
	}

	inv, err := VerifyJoinAttestation(member, ownerPub, nasB64, time.Now())
	if err != nil {
		t.Errorf("VerifyJoinAttestation: %v", err)
	}
	if len(inv.AllowedAppIDs) != 1 || inv.AllowedAppIDs[0] != "app1" {
		t.Errorf("AllowedAppIDs = %v, want [app1]", inv.AllowedAppIDs)
	}
}

func TestVerifyJoinAttestation_RejectsWhenAttestationMissing(t *testing.T) {
	ownerPub, _ := genKey(t)
	inviteePub, _ := genKey(t)
	member := atreolink.MemberACLEntry{
		MemberID:    "m1",
		Role:        "member",
		IdentityKey: base64.StdEncoding.EncodeToString(inviteePub),
	}
	_, err := VerifyJoinAttestation(member, ownerPub, "", time.Now())
	if !errors.Is(err, ErrInviteMissing) {
		t.Errorf("err = %v, want ErrInviteMissing", err)
	}
}

func TestVerifyJoinAttestation_RejectsForgedOwnerSig(t *testing.T) {
	// Invite payload signed under a different "owner" key — the pinned
	// owner pubkey on the agent doesn't match, so verification fails.
	_, attackerOwnerPriv := genKey(t)
	realOwnerPub, _ := genKey(t)
	inviteePub, _ := genKey(t)

	att := buildAttestation(t, attackerOwnerPriv, inviteePub, "")
	member := atreolink.MemberACLEntry{
		MemberID:        "m1",
		Role:            "member",
		IdentityKey:     base64.StdEncoding.EncodeToString(inviteePub),
		JoinAttestation: &att,
	}
	_, err := VerifyJoinAttestation(member, realOwnerPub, "", time.Now())
	if !errors.Is(err, ErrInviteOwnerSig) {
		t.Errorf("err = %v, want ErrInviteOwnerSig", err)
	}
}

func TestVerifyJoinAttestation_RejectsWrongAcceptanceKey(t *testing.T) {
	// Attestation was built for inviteeA's identity pubkey; the ACL entry
	// carries inviteeB's pubkey instead. The acceptance signature can't
	// verify against the swapped pubkey.
	ownerPub, ownerPriv := genKey(t)
	inviteePubA, _ := genKey(t)
	inviteePubB, _ := genKey(t)
	nasKey, _ := genKey(t)
	nasB64 := base64.StdEncoding.EncodeToString(nasKey)

	att := buildAttestation(t, ownerPriv, inviteePubA, nasB64)
	member := atreolink.MemberACLEntry{
		MemberID:        "m1",
		Role:            "member",
		IdentityKey:     base64.StdEncoding.EncodeToString(inviteePubB), // wrong subject
		JoinAttestation: &att,
	}
	_, err := VerifyJoinAttestation(member, ownerPub, nasB64, time.Now())
	if !errors.Is(err, ErrInviteAcceptanceSig) {
		t.Errorf("err = %v, want ErrInviteAcceptanceSig", err)
	}
}

func TestVerifyJoinAttestation_RejectsExpiredInvite(t *testing.T) {
	// member:added replayed for an invite that lapsed weeks ago. The
	// attestation chain is otherwise valid; expiry must still reject it.
	ownerPub, ownerPriv := genKey(t)
	inviteePub, _ := genKey(t)
	nasKey, _ := genKey(t)
	nasB64 := base64.StdEncoding.EncodeToString(nasKey)

	att := buildAttestationExp(t, ownerPriv, inviteePub, nasB64, "2020-06-01T00:00:00Z")
	member := atreolink.MemberACLEntry{
		MemberID:        "m1",
		Role:            "member",
		IdentityKey:     base64.StdEncoding.EncodeToString(inviteePub),
		JoinAttestation: &att,
	}
	if _, err := VerifyJoinAttestation(member, ownerPub, nasB64, time.Now()); !errors.Is(err, ErrInviteExpired) {
		t.Errorf("err = %v, want ErrInviteExpired", err)
	}

	// Within the clock-skew tolerance the same attestation still verifies.
	now := time.Date(2020, 6, 1, 0, 2, 0, 0, time.UTC) // 2 min past expiry
	if _, err := VerifyJoinAttestation(member, ownerPub, nasB64, now); err != nil {
		t.Errorf("within skew: err = %v, want nil", err)
	}
}

func TestVerifyJoinAttestation_RejectsMalformedExpiresAt(t *testing.T) {
	ownerPub, ownerPriv := genKey(t)
	inviteePub, _ := genKey(t)
	att := buildAttestationExp(t, ownerPriv, inviteePub, "", "not-a-timestamp")
	member := atreolink.MemberACLEntry{
		MemberID:        "m1",
		Role:            "member",
		IdentityKey:     base64.StdEncoding.EncodeToString(inviteePub),
		JoinAttestation: &att,
	}
	if _, err := VerifyJoinAttestation(member, ownerPub, "", time.Now()); !errors.Is(err, ErrInvitePayload) {
		t.Errorf("err = %v, want ErrInvitePayload", err)
	}
}

func TestVerifyJoinAttestation_RejectsCrossDeviceReplay(t *testing.T) {
	// The invite was scoped to one server pubkey; presenting it to a
	// different agent must be rejected (cross-server replay).
	ownerPub, ownerPriv := genKey(t)
	inviteePub, _ := genKey(t)
	otherNasPub, _ := genKey(t)
	otherNasB64 := base64.StdEncoding.EncodeToString(otherNasPub)
	thisNasPub, _ := genKey(t)
	thisNasB64 := base64.StdEncoding.EncodeToString(thisNasPub)

	att := buildAttestation(t, ownerPriv, inviteePub, otherNasB64)
	member := atreolink.MemberACLEntry{
		MemberID:        "m1",
		Role:            "member",
		IdentityKey:     base64.StdEncoding.EncodeToString(inviteePub),
		JoinAttestation: &att,
	}
	_, err := VerifyJoinAttestation(member, ownerPub, thisNasB64, time.Now())
	if !errors.Is(err, ErrInvitePayload) {
		t.Errorf("err = %v, want ErrInvitePayload (cross-server rejection)", err)
	}
}

func TestVerifyJoinAttestation_RejectsWhenNASKeyUnknown(t *testing.T) {
	ownerPub, ownerPriv := genKey(t)
	inviteePub, _ := genKey(t)
	nasPub, _ := genKey(t)
	nasB64 := base64.StdEncoding.EncodeToString(nasPub)

	att := buildAttestation(t, ownerPriv, inviteePub, nasB64)
	member := atreolink.MemberACLEntry{
		MemberID:        "m1",
		Role:            "member",
		IdentityKey:     base64.StdEncoding.EncodeToString(inviteePub),
		JoinAttestation: &att,
	}
	if _, err := VerifyJoinAttestation(member, ownerPub, "", time.Now()); !errors.Is(err, ErrNASKeyUnknown) {
		t.Errorf("err = %v, want ErrNASKeyUnknown", err)
	}
}
