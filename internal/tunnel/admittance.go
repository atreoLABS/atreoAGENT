package tunnel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

var (
	ErrAdmittanceMalformed = errors.New("admittance: certificate malformed")
	ErrAdmittanceBinding   = errors.New("admittance: certificate binding mismatch")
	ErrAdmittanceSig       = errors.New("admittance: signature invalid")
)

// MintAdmittanceCertificate produces a self-signed cert binding the member
// to this agent. AttestationHash commits to the raw invite bytes.
func MintAdmittanceCertificate(
	memberID, identityKey, nasPubkey string,
	attestationBytes []byte,
	initialAllowedAppIDs []string,
	signer ed25519.PrivateKey,
	now time.Time,
) (*atreolink.AdmittanceCertificate, error) {
	if memberID == "" || identityKey == "" || nasPubkey == "" {
		return nil, fmt.Errorf("%w: empty binding field(s)", ErrAdmittanceMalformed)
	}
	if len(attestationBytes) == 0 {
		return nil, fmt.Errorf("%w: empty attestation bytes", ErrAdmittanceMalformed)
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signer key wrong size %d", ErrAdmittanceMalformed, len(signer))
	}
	hash := sha256.Sum256(attestationBytes)
	if initialAllowedAppIDs == nil {
		initialAllowedAppIDs = []string{}
	}
	cert := &atreolink.AdmittanceCertificate{
		MemberID:             memberID,
		IdentityKey:          identityKey,
		NASPubkey:            nasPubkey,
		AdmittedAt:           now.Unix(),
		AttestationHash:      base64.StdEncoding.EncodeToString(hash[:]),
		InitialAllowedAppIDs: initialAllowedAppIDs,
	}
	body, err := certSignedBytes(cert)
	if err != nil {
		return nil, fmt.Errorf("canonicalising cert body: %w", err)
	}
	cert.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signer, body))
	return cert, nil
}

// VerifyAdmittanceCertificate checks the self-signature and the three
// bindings. Expected fields come from the caller; sig must verify under nasPub.
func VerifyAdmittanceCertificate(
	cert *atreolink.AdmittanceCertificate,
	expectedMemberID, expectedIdentityKey, expectedNASPubkey string,
	nasPub ed25519.PublicKey,
) error {
	if cert == nil {
		return fmt.Errorf("%w: nil cert", ErrAdmittanceMalformed)
	}
	if cert.MemberID != expectedMemberID {
		return fmt.Errorf("%w: memberId %q in cert, %q in DSMember", ErrAdmittanceBinding, cert.MemberID, expectedMemberID)
	}
	if cert.IdentityKey != expectedIdentityKey {
		return fmt.Errorf("%w: identityKey mismatch", ErrAdmittanceBinding)
	}
	if cert.NASPubkey != expectedNASPubkey {
		return fmt.Errorf("%w: nasPubkey in cert is not this agent", ErrAdmittanceBinding)
	}
	if cert.Signature == "" {
		return fmt.Errorf("%w: empty signature", ErrAdmittanceSig)
	}
	sig, err := base64.StdEncoding.DecodeString(cert.Signature)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrAdmittanceSig, err)
	}
	body, err := certSignedBytes(cert)
	if err != nil {
		return fmt.Errorf("%w: canonicalising body: %v", ErrAdmittanceMalformed, err)
	}
	if nasPub == nil {
		return fmt.Errorf("%w: no agent pubkey to verify against", ErrAdmittanceSig)
	}
	if !ed25519.Verify(nasPub, body, sig) {
		return ErrAdmittanceSig
	}
	return nil
}

// certSignedBytes is the canonical body both mint and verify sign over.
func certSignedBytes(cert *atreolink.AdmittanceCertificate) ([]byte, error) {
	apps := cert.InitialAllowedAppIDs
	if apps == nil {
		apps = []string{}
	}
	return canonjson.Marshal(map[string]any{
		"memberId":             cert.MemberID,
		"identityKey":          cert.IdentityKey,
		"nasPubkey":            cert.NASPubkey,
		"admittedAt":           cert.AdmittedAt,
		"attestationHash":      cert.AttestationHash,
		"initialAllowedAppIds": apps,
	})
}

// BuildAdmittanceMessage wraps a cert in the outbound envelope, signed by
// the agent's identity key. Intent: member:admittance-<deviceID>-<memberID>-<admittedAt>.
func BuildAdmittanceMessage(deviceID string, cert *atreolink.AdmittanceCertificate, signer ed25519.PrivateKey, now time.Time) (atreolink.TunnelMessage, error) {
	if cert == nil {
		return atreolink.TunnelMessage{}, fmt.Errorf("%w: nil cert", ErrAdmittanceMalformed)
	}
	intent := fmt.Sprintf("member:admittance-%s-%s-%d", deviceID, cert.MemberID, cert.AdmittedAt)
	ts := now.Unix()
	apps := cert.InitialAllowedAppIDs
	if apps == nil {
		apps = []string{}
	}
	canon, err := canonjson.Marshal(map[string]any{
		"cert": map[string]any{
			"memberId":             cert.MemberID,
			"identityKey":          cert.IdentityKey,
			"nasPubkey":            cert.NASPubkey,
			"admittedAt":           cert.AdmittedAt,
			"attestationHash":      cert.AttestationHash,
			"initialAllowedAppIds": apps,
			"signature":            cert.Signature,
		},
		"intent": intent,
		"ts":     ts,
	})
	if err != nil {
		return atreolink.TunnelMessage{}, fmt.Errorf("canonicalising envelope: %w", err)
	}
	sig := ed25519.Sign(signer, canon)
	return atreolink.TunnelMessage{
		Type:      "member:admittance",
		Payload:   canon,
		SignerID:  deviceID,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}
