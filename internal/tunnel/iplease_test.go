package tunnel

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

const (
	leaseTestDevice = "dev-123"
	leaseTestPubkey = "wgPubKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	leaseTestIP     = "100.64.0.42"
)

func TestTunnelIPLeaseRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	lease, err := MintTunnelIPLease(leaseTestDevice, leaseTestPubkey, leaseTestIP, priv)
	if err != nil {
		t.Fatalf("MintTunnelIPLease: %v", err)
	}
	if err := VerifyTunnelIPLease(lease, leaseTestDevice, leaseTestPubkey, pub); err != nil {
		t.Fatalf("VerifyTunnelIPLease on a fresh lease: %v", err)
	}
}

func TestTunnelIPLeaseRejectsTamperedIP(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	lease, _ := MintTunnelIPLease(leaseTestDevice, leaseTestPubkey, leaseTestIP, priv)

	lease.TunnelIP = "100.64.0.99" // move the IP without re-signing
	if err := VerifyTunnelIPLease(lease, leaseTestDevice, leaseTestPubkey, pub); !errors.Is(err, ErrIPLeaseSig) {
		t.Fatalf("err = %v, want ErrIPLeaseSig", err)
	}
}

func TestTunnelIPLeaseRejectsWrongBinding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	lease, _ := MintTunnelIPLease(leaseTestDevice, leaseTestPubkey, leaseTestIP, priv)

	if err := VerifyTunnelIPLease(lease, "other-device", leaseTestPubkey, pub); !errors.Is(err, ErrIPLeaseBinding) {
		t.Errorf("wrong device: err = %v, want ErrIPLeaseBinding", err)
	}
	if err := VerifyTunnelIPLease(lease, leaseTestDevice, "wgOtherKey", pub); !errors.Is(err, ErrIPLeaseBinding) {
		t.Errorf("wrong pubkey: err = %v, want ErrIPLeaseBinding", err)
	}
}

func TestTunnelIPLeaseRejectsForeignSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	lease, _ := MintTunnelIPLease(leaseTestDevice, leaseTestPubkey, leaseTestIP, priv)

	// A lease minted by some other key must not verify under our identity.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := VerifyTunnelIPLease(lease, leaseTestDevice, leaseTestPubkey, otherPub); !errors.Is(err, ErrIPLeaseSig) {
		t.Fatalf("err = %v, want ErrIPLeaseSig", err)
	}
}

func TestMintTunnelIPLeaseRejectsEmptyFields(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	for _, tc := range []struct{ dev, pub, ip string }{
		{"", leaseTestPubkey, leaseTestIP},
		{leaseTestDevice, "", leaseTestIP},
		{leaseTestDevice, leaseTestPubkey, ""},
	} {
		if _, err := MintTunnelIPLease(tc.dev, tc.pub, tc.ip, priv); !errors.Is(err, ErrIPLeaseMalformed) {
			t.Errorf("Mint(%q,%q,%q) err = %v, want ErrIPLeaseMalformed", tc.dev, tc.pub, tc.ip, err)
		}
	}
}
