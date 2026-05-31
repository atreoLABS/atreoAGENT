package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

// HKDF info string for the AES-256-GCM key derivation.
const PairInfoString = "atreos-pair-v1"

type approvalInner struct {
	PairSessionID       string `json:"pairSessionId"`
	OwnerIdentityPubkey string `json:"ownerIdentityPubkey"`
	ApprovedAt          string `json:"approvedAt"`
	NASPubkey           string `json:"nasPubkey"`
	NASAttestationSig   string `json:"nasAttestationSig"`
}

// Canonical-JSON of this is what nasAttestationSig signs.
type nasAttestationBody struct {
	NASPubkey string `json:"nasPubkey"`
}

var (
	ErrPairApprovalDecrypt         = errors.New("pair approval: decrypt failed")
	ErrPairApprovalSig             = errors.New("pair approval: ownerSelfSig invalid")
	ErrPairApprovalSessionMismatch = errors.New("pair approval: pairSessionId in inner payload doesn't match the pairing session")
	ErrPairApprovalNASMismatch     = errors.New("pair approval: nasPubkey in approval is not this NAS's key")
	ErrPairApprovalNASAttestation  = errors.New("pair approval: nasAttestationSig missing or invalid")
	ErrPairApprovalNASKeyUnknown   = errors.New("pair approval: this NAS has no identity key to anchor the approval against")
)

// An empty expectedSessionID skips the session-replay check (tests).
func DecodePairApprovalBlob(blob atreolink.PairApprovalBlob, pairToken []byte, expectedSessionID, expectedNASPubkey string) (ownerPub []byte, payloadCanon []byte, approvedAt string, err error) {
	if len(pairToken) == 0 {
		return nil, nil, "", errors.New("pair approval: pairToken is empty")
	}

	nonce, err := base64.StdEncoding.DecodeString(blob.Nonce)
	if err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: decode nonce: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(blob.Ciphertext)
	if err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: decode ciphertext: %w", err)
	}

	key := make([]byte, 32)
	r := hkdf.New(sha256.New, pairToken, nil, []byte(PairInfoString))
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: hkdf: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: gcm: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, nil, "", fmt.Errorf("pair approval: nonce wrong size: %d", len(nonce))
	}

	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: %v", ErrPairApprovalDecrypt, err)
	}

	// Wire: canonical-JSON(payload) || ownerSelfSig (64 bytes).
	if len(plain) <= ed25519.SignatureSize {
		return nil, nil, "", fmt.Errorf("pair approval: plaintext too short: %d", len(plain))
	}
	innerJSONEnd := len(plain) - ed25519.SignatureSize
	innerJSON := plain[:innerJSONEnd]
	ownerSelfSig := plain[innerJSONEnd:]

	canon, err := canonjson.MarshalRaw(innerJSON)
	if err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: canonicalize inner payload: %w", err)
	}

	var inner approvalInner
	if err := json.Unmarshal(innerJSON, &inner); err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: parse inner payload: %w", err)
	}
	if inner.OwnerIdentityPubkey == "" {
		return nil, nil, "", errors.New("pair approval: inner payload missing ownerIdentityPubkey")
	}
	pub, err := base64.StdEncoding.DecodeString(inner.OwnerIdentityPubkey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("pair approval: decode ownerIdentityPubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, nil, "", fmt.Errorf("pair approval: ownerIdentityPubkey wrong size: %d", len(pub))
	}

	if expectedSessionID != "" && inner.PairSessionID != "" && inner.PairSessionID != expectedSessionID {
		return nil, nil, "", fmt.Errorf("%w: inner=%q expected=%q", ErrPairApprovalSessionMismatch, inner.PairSessionID, expectedSessionID)
	}

	if !ed25519.Verify(ed25519.PublicKey(pub), canon, ownerSelfSig) {
		return nil, nil, "", ErrPairApprovalSig
	}

	if expectedNASPubkey == "" {
		return nil, nil, "", ErrPairApprovalNASKeyUnknown
	}
	if inner.NASPubkey == "" {
		return nil, nil, "", fmt.Errorf("%w: approval carries no nasPubkey", ErrPairApprovalNASMismatch)
	}
	if inner.NASPubkey != expectedNASPubkey {
		return nil, nil, "", fmt.Errorf("%w: scoped to %s, this is %s", ErrPairApprovalNASMismatch, inner.NASPubkey, expectedNASPubkey)
	}
	if inner.NASAttestationSig == "" {
		return nil, nil, "", fmt.Errorf("%w: nasAttestationSig missing", ErrPairApprovalNASAttestation)
	}
	attCanon, cerr := canonjson.Marshal(nasAttestationBody{NASPubkey: inner.NASPubkey})
	if cerr != nil {
		return nil, nil, "", fmt.Errorf("pair approval: canonicalize nas attestation: %w", cerr)
	}
	attSig, derr := base64.StdEncoding.DecodeString(inner.NASAttestationSig)
	if derr != nil {
		return nil, nil, "", fmt.Errorf("%w: decode: %v", ErrPairApprovalNASAttestation, derr)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), attCanon, attSig) {
		return nil, nil, "", ErrPairApprovalNASAttestation
	}

	return pub, canon, inner.ApprovedAt, nil
}
