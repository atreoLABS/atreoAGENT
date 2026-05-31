package tunnel

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

// CommandTimestampSkew bounds replay of a captured envelope. 120s is
// the JWT/SAML clock-skew norm.
const CommandTimestampSkew = 120 * time.Second

var (
	ErrUnsigned         = errors.New("tunnel: state-changing message has no signerId/signature")
	ErrUnknownSigner    = errors.New("tunnel: unknown signer")
	ErrInvalidSignature = errors.New("tunnel: invalid envelope signature")
	ErrNotAdmin         = errors.New("tunnel: signer is not an admin of this device")
	ErrIntentMismatch   = errors.New("tunnel: command intent mismatch")
	ErrStaleTimestamp   = errors.New("tunnel: command timestamp out of window")
)

// ACLLookup returns the base64 identity pubkey for a member ID.
// Decoupled from acl.Store so VerifyEnvelope is testable without it.
type ACLLookup func(memberID string) (pubB64 string, ok bool)

type MemberLookupFromStore func(memberID string) (identityKeyB64 string, ok bool)

// VerifyEnvelope verifies msg.Signature over the canonical-JSON
// re-encoding of msg.Payload. Re-canonicalising makes verification
// tolerant of in-transit whitespace or key-order rewrites.
func VerifyEnvelope(msg atreolink.TunnelMessage, aclLookup ACLLookup) error {
	if msg.SignerID == "" || msg.Signature == "" {
		return ErrUnsigned
	}
	pubB64, ok := aclLookup(msg.SignerID)
	if !ok || pubB64 == "" {
		return fmt.Errorf("%w: %q", ErrUnknownSigner, msg.SignerID)
	}
	decoded, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return fmt.Errorf("decode signer pubkey for %q: %w", msg.SignerID, err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return fmt.Errorf("signer pubkey for %q wrong length: %d", msg.SignerID, len(decoded))
	}
	pub := ed25519.PublicKey(decoded)

	sig, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	canon, err := canonjson.MarshalRaw([]byte(msg.Payload))
	if err != nil {
		return fmt.Errorf("canonicalize payload: %w", err)
	}

	if !ed25519.Verify(pub, canon, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// verifySignatureAgainst is VerifyEnvelope with the pubkey known
// out-of-band (AttestedAuth path).
func verifySignatureAgainst(msg atreolink.TunnelMessage, pub ed25519.PublicKey) error {
	if msg.SignerID == "" || msg.Signature == "" {
		return ErrUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	canon, err := canonjson.MarshalRaw([]byte(msg.Payload))
	if err != nil {
		return fmt.Errorf("canonicalize payload: %w", err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// Embedded into every signed payload struct. The intent binds the
// signature to a specific (command, targets) tuple; ts bounds replay
// via CommandTimestampSkew.
type CommandEnvelopeFields struct {
	Intent    string `json:"intent"`
	Timestamp int64  `json:"ts"`
}

type CommandAuth interface {
	verify(h *Handlers, msg atreolink.TunnelMessage) error
}

// Requires the signer to have ACL Role == "admin"/"owner". The admin
// entry's identityKey is invariantly the pinned admin pubkey.
func AdminAuth() CommandAuth { return adminAuth{} }

// Requires signerId == memberID. Used for self-scoped actions.
func MemberAuth(memberID string) CommandAuth { return memberAuth{memberID: memberID} }

// Member self-action OR admin override; lets the owner kick peers
// without the member's help.
func MemberOrAdminAuth(memberID string) CommandAuth {
	return memberOrAdminAuth{memberID: memberID}
}

// Verifies against pubkey directly — for member:added where the new
// member's key isn't in the ACL yet but is transitively attested by
// the inner joinAttestation chain.
func AttestedAuth(pubkey ed25519.PublicKey) CommandAuth {
	return attestedAuth{pubkey: pubkey}
}

type adminAuth struct{}
type memberAuth struct{ memberID string }
type memberOrAdminAuth struct{ memberID string }
type attestedAuth struct{ pubkey ed25519.PublicKey }

func (adminAuth) verify(h *Handlers, msg atreolink.TunnelMessage) error {
	return h.requireAdmin(msg)
}

func (a memberAuth) verify(h *Handlers, msg atreolink.TunnelMessage) error {
	return h.requireMember(msg, a.memberID)
}

func (a memberOrAdminAuth) verify(h *Handlers, msg atreolink.TunnelMessage) error {
	if msg.SignerID == a.memberID {
		return h.requireMember(msg, a.memberID)
	}
	return h.requireAdmin(msg)
}

func (a attestedAuth) verify(_ *Handlers, msg atreolink.TunnelMessage) error {
	return verifySignatureAgainst(msg, a.pubkey)
}

// verifyCommand checks intent + ts freshness + envelope signature.
// Use for fresh, never-replayed commands. expectedIntent is built by
// the caller from the command name + binding fields + env.Timestamp.
func (h *Handlers) verifyCommand(msg atreolink.TunnelMessage, auth CommandAuth, env CommandEnvelopeFields, expectedIntent string) error {
	if env.Intent != expectedIntent {
		return fmt.Errorf("%w: got %q, expected %q", ErrIntentMismatch, env.Intent, expectedIntent)
	}
	skew := time.Now().Unix() - env.Timestamp
	if skew < 0 {
		skew = -skew
	}
	if skew > int64(CommandTimestampSkew.Seconds()) {
		return fmt.Errorf("%w: skew %ds exceeds max %s", ErrStaleTimestamp, skew, CommandTimestampSkew)
	}
	return auth.verify(h, msg)
}

// verifyAuthorization is verifyCommand without the ts check, for
// long-lived state envelopes atreoLINK replays on every reconnect.
// Replay protection comes from intent binding (device + target) and
// idempotent handlers.
func (h *Handlers) verifyAuthorization(msg atreolink.TunnelMessage, auth CommandAuth, env CommandEnvelopeFields, expectedIntent string) error {
	if env.Intent != expectedIntent {
		return fmt.Errorf("%w: got %q, expected %q", ErrIntentMismatch, env.Intent, expectedIntent)
	}
	return auth.verify(h, msg)
}
