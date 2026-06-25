// Package relay is the agent's CGNAT-relay client: when the coordination
// service grants this device a relay, the agent dials the relay (outbound,
// CGNAT-friendly), authenticates, and bridges opaque WireGuard datagrams
// between the relay and the local kernel WireGuard socket. It never holds the
// relay's trust and never parses WireGuard — it forwards ciphertext only.
package relay

import (
	"encoding/json"
	"fmt"
)

// SignedGrant is the coordination-signed relay grant as it arrives over the
// tunnel WS. The agent forwards it verbatim to the relay (which verifies the
// signature); the agent only parses it to learn where to dial.
type SignedGrant struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// Grant is the parsed grant payload.
type Grant struct {
	DeviceID        string `json:"deviceId"`
	AgentEd25519Pub string `json:"agentEd25519Pub"`
	RelayHost       string `json:"relayHost"`
	RelayPort       int    `json:"relayPort"`
	ControlURL      string `json:"controlUrl"`
	IssuedAt        int64  `json:"iat"`
	ExpiresAt       int64  `json:"exp"`
}

func (s SignedGrant) Parse() (Grant, error) {
	var g Grant
	if err := json.Unmarshal(s.Payload, &g); err != nil {
		return Grant{}, fmt.Errorf("parse relay grant: %w", err)
	}
	if g.ControlURL == "" || g.RelayHost == "" || g.RelayPort == 0 {
		return Grant{}, fmt.Errorf("relay grant missing controlUrl/relayHost/relayPort")
	}
	return g, nil
}
