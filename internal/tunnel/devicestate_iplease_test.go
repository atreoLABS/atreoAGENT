package tunnel

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

func buildClientRegisterDSEnvelope(t *testing.T, memberPriv ed25519.PrivateKey, memberID, wgPubKey string) *atreolink.DSEnvelope {
	t.Helper()
	ts := time.Now().Unix()
	payload := ClientRegisterPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("wg:client-register-%s-%s-%s-%d", testDeviceID, memberID, wgPubKey, ts),
			Timestamp: ts,
		},
		DeviceID:  testDeviceID,
		MemberID:  memberID,
		PublicKey: wgPubKey,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal client register: %v", err)
	}
	return &atreolink.DSEnvelope{
		Payload:   body,
		SignerID:  memberID,
		Signature: signCanon(t, payload, memberPriv),
	}
}

// leaseMemberState builds a device:state with one attested member owning a
// single client, optionally carrying an IP lease on that client.
func leaseMemberState(t *testing.T, f *ownedFixture, memberPub ed25519.PublicKey, memberPriv ed25519.PrivateKey, wgPubKey string, lease *atreolink.TunnelIPLease) atreolink.DeviceState {
	t.Helper()
	att := buildJoinAttestation(t, f.ownerPriv, memberPub, f.km.PublicKeyBase64(), nil)
	return atreolink.DeviceState{
		DeviceID:   testDeviceID,
		Generation: 1,
		Members: []atreolink.DSMember{{
			MemberID:        "m-lease",
			MemberName:      "Lease",
			Role:            "member",
			IdentityKey:     base64.StdEncoding.EncodeToString(memberPub),
			JoinAttestation: &att,
			Clients: []atreolink.DSClient{{
				WGPublicKey:          wgPubKey,
				RegistrationEnvelope: buildClientRegisterDSEnvelope(t, memberPriv, "m-lease", wgPubKey),
				IPLease:              lease,
			}},
		}},
	}
}

func TestHandleDeviceState_RestoresIPFromValidLease(t *testing.T) {
	f := setupOwnedFixture(t)
	memberPub, memberPriv := genKey(t)
	const wgKey = "wg-lease-1"

	// Fresh allocator (local state loss): only a signed lease restores the IP.
	lease, err := MintTunnelIPLease(testDeviceID, wgKey, "100.64.0.77", f.km.PrivateKey())
	if err != nil {
		t.Fatalf("MintTunnelIPLease: %v", err)
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, leaseMemberState(t, f, memberPub, memberPriv, wgKey, lease))); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}
	if got := f.h.allocator.Lookup(wgKey); got != "100.64.0.77" {
		t.Errorf("allocator IP = %q, want 100.64.0.77 (restored from lease)", got)
	}
}

func TestHandleDeviceState_IgnoresLeaseSignedByForeignKey(t *testing.T) {
	f := setupOwnedFixture(t)
	memberPub, memberPriv := genKey(t)
	const wgKey = "wg-lease-1"

	// A lease not signed by this agent must be ignored (agent allocates instead).
	_, foreignPriv := genKey(t)
	forged, err := MintTunnelIPLease(testDeviceID, wgKey, "100.64.0.77", foreignPriv)
	if err != nil {
		t.Fatalf("MintTunnelIPLease: %v", err)
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, leaseMemberState(t, f, memberPub, memberPriv, wgKey, forged))); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}
	got := f.h.allocator.Lookup(wgKey)
	if got == "100.64.0.77" {
		t.Fatal("agent adopted an IP from a foreign-signed lease")
	}
	if got == "" {
		t.Fatal("client got no IP at all (should have fallen back to Allocate)")
	}
}

func TestHandleDeviceState_ExistingAllocationWinsOverLease(t *testing.T) {
	f := setupOwnedFixture(t)
	memberPub, memberPriv := genKey(t)
	const wgKey = "wg-lease-1"

	// An existing binding must win over a lease for a different IP.
	f.h.allocator.MarkUsed(wgKey, "100.64.0.90")
	lease, err := MintTunnelIPLease(testDeviceID, wgKey, "100.64.0.77", f.km.PrivateKey())
	if err != nil {
		t.Fatalf("MintTunnelIPLease: %v", err)
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, leaseMemberState(t, f, memberPub, memberPriv, wgKey, lease))); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}
	if got := f.h.allocator.Lookup(wgKey); got != "100.64.0.90" {
		t.Errorf("allocator IP = %q, want 100.64.0.90 (existing allocation must win over lease)", got)
	}
}
