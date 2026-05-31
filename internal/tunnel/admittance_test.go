package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func newSignerPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(pub)
}

func TestAdmittanceCert_MintVerify_HappyPath(t *testing.T) {
	nasPub, nasPriv, nasB64 := newSignerPair(t)
	cert, err := MintAdmittanceCertificate(
		"member-uuid", "member-identity-b64", nasB64,
		[]byte(`{"inviteId":"x"}`),
		[]string{"app-a", "app-b"},
		nasPriv, time.Unix(1_700_000_000, 0),
	)
	if err != nil {
		t.Fatalf("MintAdmittanceCertificate: %v", err)
	}
	if cert.MemberID != "member-uuid" || cert.IdentityKey != "member-identity-b64" || cert.NASPubkey != nasB64 {
		t.Errorf("bindings not populated: %+v", cert)
	}
	if cert.AdmittedAt != 1_700_000_000 {
		t.Errorf("AdmittedAt = %d, want 1700000000", cert.AdmittedAt)
	}
	if cert.AttestationHash == "" {
		t.Error("AttestationHash empty")
	}
	if cert.Signature == "" {
		t.Error("Signature empty")
	}
	if err := VerifyAdmittanceCertificate(cert, "member-uuid", "member-identity-b64", nasB64, nasPub); err != nil {
		t.Errorf("VerifyAdmittanceCertificate happy: %v", err)
	}
}

func TestAdmittanceCert_Verify_RejectsBindingTamper(t *testing.T) {
	nasPub, nasPriv, nasB64 := newSignerPair(t)
	cert, err := MintAdmittanceCertificate(
		"member-uuid", "member-identity-b64", nasB64,
		[]byte("attestation"), nil, nasPriv, time.Now(),
	)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cases := []struct {
		name           string
		expectedMember string
		expectedIdent  string
		expectedNAS    string
	}{
		{"wrong memberID", "other-uuid", "member-identity-b64", nasB64},
		{"wrong identityKey", "member-uuid", "other-identity", nasB64},
		{"wrong nasPubkey", "member-uuid", "member-identity-b64", "other-nas-b64"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyAdmittanceCertificate(cert, c.expectedMember, c.expectedIdent, c.expectedNAS, nasPub)
			if !errors.Is(err, ErrAdmittanceBinding) {
				t.Errorf("err = %v, want ErrAdmittanceBinding", err)
			}
		})
	}
}

func TestAdmittanceCert_Verify_RejectsCrossNASKey(t *testing.T) {
	_, nasPriv, nasB64 := newSignerPair(t)
	otherPub, _, _ := newSignerPair(t)

	cert, err := MintAdmittanceCertificate(
		"member-uuid", "ik", nasB64,
		[]byte("att"), nil, nasPriv, time.Now(),
	)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := VerifyAdmittanceCertificate(cert, "member-uuid", "ik", nasB64, otherPub); !errors.Is(err, ErrAdmittanceSig) {
		t.Errorf("err = %v, want ErrAdmittanceSig (wrong verifier key)", err)
	}
}

func TestAdmittanceCert_Verify_RejectsAttestationHashTamper(t *testing.T) {
	nasPub, nasPriv, nasB64 := newSignerPair(t)
	cert, err := MintAdmittanceCertificate(
		"member-uuid", "ik", nasB64,
		[]byte("att"), nil, nasPriv, time.Now(),
	)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cert.AttestationHash = base64.StdEncoding.EncodeToString([]byte("different-hash-32-bytes--------!"))
	if err := VerifyAdmittanceCertificate(cert, "member-uuid", "ik", nasB64, nasPub); !errors.Is(err, ErrAdmittanceSig) {
		t.Errorf("err = %v, want ErrAdmittanceSig (tampered attestationHash)", err)
	}
}

func TestAdmittanceCert_Verify_RejectsNil(t *testing.T) {
	pub, _, _ := newSignerPair(t)
	if err := VerifyAdmittanceCertificate(nil, "x", "y", "z", pub); !errors.Is(err, ErrAdmittanceMalformed) {
		t.Errorf("err = %v, want ErrAdmittanceMalformed", err)
	}
}

func TestBuildAdmittanceMessage_SignsEnvelope(t *testing.T) {
	nasPub, nasPriv, nasB64 := newSignerPair(t)
	cert, err := MintAdmittanceCertificate(
		"member-uuid", "ik", nasB64,
		[]byte("att"), []string{"app-a"}, nasPriv, time.Unix(1_700_000_000, 0),
	)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	msg, err := BuildAdmittanceMessage("device-uuid", cert, nasPriv, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("BuildAdmittanceMessage: %v", err)
	}
	if msg.Type != "member:admittance" {
		t.Errorf("Type = %q, want member:admittance", msg.Type)
	}
	if msg.SignerID != "device-uuid" {
		t.Errorf("SignerID = %q, want device-uuid", msg.SignerID)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if !ed25519.Verify(nasPub, []byte(msg.Payload), sigBytes) {
		t.Error("outer signature does not verify against agent identity pubkey")
	}
}
