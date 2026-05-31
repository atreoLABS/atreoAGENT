package endpoints

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

// Bytes are stored verbatim; signature must verify against the same
// PayloadCanon after any round-trip across implementations.
type EnvelopeBytes struct {
	PayloadCanon []byte
	Signature    []byte // raw Ed25519, 64 bytes
}

// Payload shape:
//
//	{
//	  "deviceId":   "<uuid>",
//	  "timestamp":  "<RFC3339Nano UTC>",
//	  "candidates": [ {kind, host, port}, ... ]
//	}
//
// candidates[].kind ∈ {"lan","public4","public6"}; host bare; port WG
// listen port; array order = signer's preference.
func Build(deviceID string, now time.Time, candidates []Candidate, priv ed25519.PrivateKey) (EnvelopeBytes, error) {
	if deviceID == "" {
		return EnvelopeBytes{}, fmt.Errorf("endpoints: deviceID is required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return EnvelopeBytes{}, fmt.Errorf("endpoints: invalid ed25519 private key length %d", len(priv))
	}
	for i, c := range candidates {
		if c.Kind != KindLAN && c.Kind != KindPublic4 && c.Kind != KindPublic6 {
			return EnvelopeBytes{}, fmt.Errorf("endpoints: candidate[%d] invalid kind %q", i, c.Kind)
		}
		if c.Host == "" {
			return EnvelopeBytes{}, fmt.Errorf("endpoints: candidate[%d] empty host", i)
		}
		if c.Port <= 0 || c.Port > 65535 {
			return EnvelopeBytes{}, fmt.Errorf("endpoints: candidate[%d] invalid port %d", i, c.Port)
		}
	}

	// map-of-any so the wire-shape stays obvious next to client canonicalisers.
	cands := make([]any, 0, len(candidates))
	for _, c := range candidates {
		cands = append(cands, map[string]any{
			"kind": c.Kind,
			"host": c.Host,
			"port": c.Port,
		})
	}
	payload := map[string]any{
		"deviceId":   deviceID,
		"timestamp":  now.UTC().Format(time.RFC3339Nano),
		"candidates": cands,
	}
	canon, err := canonjson.Marshal(payload)
	if err != nil {
		return EnvelopeBytes{}, fmt.Errorf("endpoints: canonicalize: %w", err)
	}
	sig := ed25519.Sign(priv, canon)
	return EnvelopeBytes{PayloadCanon: canon, Signature: sig}, nil
}

func (e EnvelopeBytes) SignatureBase64() string {
	return base64.StdEncoding.EncodeToString(e.Signature)
}
