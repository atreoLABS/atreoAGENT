package tunnel

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

var (
	ErrIPLeaseMalformed = errors.New("ip-lease: malformed")
	ErrIPLeaseBinding   = errors.New("ip-lease: binding mismatch")
	ErrIPLeaseSig       = errors.New("ip-lease: signature invalid")
)

// leaseSignedBytes is the canonical body both mint and verify sign over.
func leaseSignedBytes(deviceID, wgPublicKey, tunnelIP string) ([]byte, error) {
	return canonjson.Marshal(map[string]any{
		"deviceId":    deviceID,
		"wgPublicKey": wgPublicKey,
		"tunnelIp":    tunnelIP,
	})
}

// MintTunnelIPLease self-signs the (device, pubkey → IP) binding with the
// agent's identity key.
func MintTunnelIPLease(deviceID, wgPublicKey, tunnelIP string, signer ed25519.PrivateKey) (*atreolink.TunnelIPLease, error) {
	if deviceID == "" || wgPublicKey == "" || tunnelIP == "" {
		return nil, fmt.Errorf("%w: empty binding field(s)", ErrIPLeaseMalformed)
	}
	if len(signer) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: signer key wrong size %d", ErrIPLeaseMalformed, len(signer))
	}
	body, err := leaseSignedBytes(deviceID, wgPublicKey, tunnelIP)
	if err != nil {
		return nil, fmt.Errorf("canonicalising lease body: %w", err)
	}
	return &atreolink.TunnelIPLease{
		DeviceID:     deviceID,
		WGPublicKey:  wgPublicKey,
		TunnelIP:     tunnelIP,
		NASSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(signer, body)),
	}, nil
}

// VerifyTunnelIPLease checks the self-signature and the device + pubkey
// binding. nasPub MUST be the agent's own identity pubkey.
func VerifyTunnelIPLease(lease *atreolink.TunnelIPLease, expectedDeviceID, expectedWGPublicKey string, nasPub ed25519.PublicKey) error {
	if lease == nil {
		return fmt.Errorf("%w: nil lease", ErrIPLeaseMalformed)
	}
	if lease.DeviceID != expectedDeviceID {
		return fmt.Errorf("%w: deviceId %q, expected %q", ErrIPLeaseBinding, lease.DeviceID, expectedDeviceID)
	}
	if lease.WGPublicKey != expectedWGPublicKey {
		return fmt.Errorf("%w: wgPublicKey", ErrIPLeaseBinding)
	}
	if lease.TunnelIP == "" {
		return fmt.Errorf("%w: empty tunnelIp", ErrIPLeaseMalformed)
	}
	if lease.NASSignature == "" {
		return fmt.Errorf("%w: empty signature", ErrIPLeaseSig)
	}
	sig, err := base64.StdEncoding.DecodeString(lease.NASSignature)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrIPLeaseSig, err)
	}
	body, err := leaseSignedBytes(lease.DeviceID, lease.WGPublicKey, lease.TunnelIP)
	if err != nil {
		return fmt.Errorf("%w: canonicalising body: %v", ErrIPLeaseMalformed, err)
	}
	if nasPub == nil {
		return fmt.Errorf("%w: no agent pubkey to verify against", ErrIPLeaseSig)
	}
	if !ed25519.Verify(nasPub, body, sig) {
		return ErrIPLeaseSig
	}
	return nil
}

// shortKey truncates a WG pubkey for logs (the key is public, not secret).
func shortKey(k string) string {
	if len(k) > 12 {
		return k[:12] + "…"
	}
	return k
}
