package tunnel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

var (
	ErrInviteOwnerSig      = errors.New("attestation: ownerSig over invitePayload is invalid")
	ErrInviteAcceptanceSig = errors.New("attestation: acceptanceSig is invalid")
	ErrInviteMissing       = errors.New("attestation: non-owner member has no joinAttestation")
	ErrInvitePayload       = errors.New("attestation: invitePayload malformed")
	ErrInviteExpired       = errors.New("attestation: invitePayload has expired")
	ErrNASKeyUnknown       = errors.New("attestation: this NAS has no identity key to scope the invite against")
)

const inviteExpirySkew = 5 * time.Minute

type invitePayload struct {
	InviteID      string   `json:"inviteId"`
	DeviceID      string   `json:"deviceId"`
	NASPubkey     string   `json:"nasPubkey"`
	AllowedAppIDs []string `json:"allowedAppIds"`
	ExpiresAt     string   `json:"expiresAt"`
	TokenHash     string   `json:"tokenHash"`
	InvitePub     string   `json:"invitePub"`
}

// Verifies ownerSig over the canonical invitePayload, then acceptanceSig
// (signed by invitePub) over the member's identityPublic. expiresAt is
// enforced so a lapsed invite can't be replayed indefinitely.
// expectedNASPubkey scopes the invite to this server. Returns the parsed
// payload so callers can use the owner-authorised allowedAppIds.
func VerifyJoinAttestation(member atreolink.MemberACLEntry, ownerPub ed25519.PublicKey, expectedNASPubkey string, now time.Time) (invitePayload, error) {
	var inv invitePayload
	if member.JoinAttestation == nil {
		return inv, ErrInviteMissing
	}
	att := member.JoinAttestation
	if att.InvitePayload == "" || att.OwnerSig == "" || att.AcceptanceSig == "" {
		return inv, fmt.Errorf("%w: empty attestation field(s)", ErrInviteMissing)
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(att.InvitePayload)
	if err != nil {
		return inv, fmt.Errorf("%w: decode invitePayload: %v", ErrInvitePayload, err)
	}
	canon, err := canonjson.MarshalRaw(payloadBytes)
	if err != nil {
		return inv, fmt.Errorf("%w: canonicalize invitePayload: %v", ErrInvitePayload, err)
	}

	ownerSig, err := base64.StdEncoding.DecodeString(att.OwnerSig)
	if err != nil {
		return inv, fmt.Errorf("%w: decode ownerSig: %v", ErrInviteOwnerSig, err)
	}
	if ownerPub == nil {
		return inv, fmt.Errorf("%w: no pinned owner pubkey to verify against", ErrInviteOwnerSig)
	}
	if !ed25519.Verify(ownerPub, canon, ownerSig) {
		return inv, ErrInviteOwnerSig
	}

	if err := json.Unmarshal(payloadBytes, &inv); err != nil {
		return invitePayload{}, fmt.Errorf("%w: parse invitePayload: %v", ErrInvitePayload, err)
	}
	if inv.InvitePub == "" {
		return invitePayload{}, fmt.Errorf("%w: invitePub missing", ErrInvitePayload)
	}
	if inv.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, inv.ExpiresAt)
		if err != nil {
			return invitePayload{}, fmt.Errorf("%w: expiresAt %q not RFC3339: %v", ErrInvitePayload, inv.ExpiresAt, err)
		}
		if now.After(exp.Add(inviteExpirySkew)) {
			return invitePayload{}, fmt.Errorf("%w: expired at %s (now %s)", ErrInviteExpired, exp.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		}
	}
	if expectedNASPubkey == "" {
		return invitePayload{}, ErrNASKeyUnknown
	}
	if inv.NASPubkey == "" {
		return invitePayload{}, fmt.Errorf("%w: invite carries no nasPubkey", ErrInvitePayload)
	}
	if inv.NASPubkey != expectedNASPubkey {
		return invitePayload{}, fmt.Errorf("%w: invite scoped to NAS %s, this is %s", ErrInvitePayload, inv.NASPubkey, expectedNASPubkey)
	}

	invitePub, err := base64.StdEncoding.DecodeString(inv.InvitePub)
	if err != nil || len(invitePub) != ed25519.PublicKeySize {
		return invitePayload{}, fmt.Errorf("%w: invitePub invalid", ErrInvitePayload)
	}

	memberPubB64 := member.IdentityKey
	memberPub, err := base64.StdEncoding.DecodeString(memberPubB64)
	if err != nil || len(memberPub) != ed25519.PublicKeySize {
		return invitePayload{}, fmt.Errorf("%w: member identityKey invalid", ErrInvitePayload)
	}

	acceptanceSig, err := base64.StdEncoding.DecodeString(att.AcceptanceSig)
	if err != nil {
		return invitePayload{}, fmt.Errorf("%w: decode acceptanceSig: %v", ErrInviteAcceptanceSig, err)
	}

	// Invitee signs the raw 32-byte pubkey bytes; clients must match exactly.
	if !ed25519.Verify(ed25519.PublicKey(invitePub), memberPub, acceptanceSig) {
		return invitePayload{}, ErrInviteAcceptanceSig
	}
	return inv, nil
}

// seed = HKDF-SHA256(token, ∅, "atreos-invite-v1", 32); Ed25519 from seed.
// Test helper — production code never sees the raw token.
func DeriveInvitePubFromToken(token []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	r := hkdf.New(sha256.New, token, nil, []byte("atreos-invite-v1"))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, fmt.Errorf("hkdf expand: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv, nil
}
