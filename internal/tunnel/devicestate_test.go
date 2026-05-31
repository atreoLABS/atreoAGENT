package tunnel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

// buildJoinAttestation builds a verifiable JoinAttestation with
// caller-chosen allowedAppIds.
func buildJoinAttestation(t *testing.T, ownerPriv ed25519.PrivateKey, inviteePub ed25519.PublicKey, nasPubB64 string, allowedAppIDs []string) atreolink.JoinAttestation {
	t.Helper()

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatalf("rand: %v", err)
	}
	invitePub, invitePriv, err := DeriveInvitePubFromToken(token)
	if err != nil {
		t.Fatalf("DeriveInvitePubFromToken: %v", err)
	}

	apps := make([]any, len(allowedAppIDs))
	for i, id := range allowedAppIDs {
		apps[i] = id
	}
	inv := map[string]any{
		"inviteId":      "inv-1",
		"deviceId":      testDeviceID,
		"nasPubkey":     nasPubB64,
		"allowedAppIds": apps,
		"expiresAt":     "2030-01-01T00:00:00Z",
		"tokenHash":     base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		"invitePub":     base64.StdEncoding.EncodeToString(invitePub),
	}
	canon, err := canonjson.Marshal(inv)
	if err != nil {
		t.Fatalf("canon: %v", err)
	}
	ownerSig := ed25519.Sign(ownerPriv, canon)
	acceptanceSig := ed25519.Sign(invitePriv, inviteePub)
	return atreolink.JoinAttestation{
		InvitePayload: base64.StdEncoding.EncodeToString(canon),
		OwnerSig:      base64.StdEncoding.EncodeToString(ownerSig),
		AcceptanceSig: base64.StdEncoding.EncodeToString(acceptanceSig),
	}
}

// buildAppDSEnvelope produces an owner-signed app:upserted DSApp.
func buildAppDSEnvelope(t *testing.T, ownerPriv ed25519.PrivateKey, app atreolink.App) *atreolink.DSEnvelope {
	t.Helper()
	payload := AppUpsertedPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent: fmt.Sprintf("app:upserted-%s-%s", testDeviceID, app.ID),
		},
		DeviceID: testDeviceID,
		App:      app,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal app payload: %v", err)
	}
	return &atreolink.DSEnvelope{
		Payload:   body,
		SignerID:  "m-owner",
		Signature: signCanon(t, payload, ownerPriv),
	}
}

// buildPermissionsDSEnvelope produces an owner-signed
// member:permissions envelope bound to deviceId + memberId + ts.
func buildPermissionsDSEnvelope(t *testing.T, ownerPriv ed25519.PrivateKey, memberID string, allowedAppIDs []string) *atreolink.DSEnvelope {
	t.Helper()
	ts := time.Now().Unix()
	payload := MemberPermissionsPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("member:permissions-%s-%s-%d", testDeviceID, memberID, ts),
			Timestamp: ts,
		},
		DeviceID:      testDeviceID,
		MemberID:      memberID,
		AllowedAppIDs: allowedAppIDs,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal perms payload: %v", err)
	}
	return &atreolink.DSEnvelope{
		Payload:   body,
		SignerID:  "m-owner",
		Signature: signCanon(t, payload, ownerPriv),
	}
}

// deviceStateMsg wraps a DeviceState as a device:state TunnelMessage.
func deviceStateMsg(t *testing.T, st atreolink.DeviceState) atreolink.TunnelMessage {
	t.Helper()
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	return atreolink.TunnelMessage{Type: "device:state", Payload: body}
}

// catalogueWithApps returns N apps registered as owner-signed DSApps.
func catalogueWithApps(t *testing.T, ownerPriv ed25519.PrivateKey, apps []atreolink.App) []atreolink.DSApp {
	t.Helper()
	out := make([]atreolink.DSApp, 0, len(apps))
	for _, a := range apps {
		out = append(out, atreolink.DSApp{
			ID:          a.ID,
			Name:        a.Name,
			Slug:        a.Slug,
			InternalURL: a.InternalURL,
			Icon:        a.Icon,
			Envelope:    buildAppDSEnvelope(t, ownerPriv, a),
		})
	}
	return out
}

// findMember returns the reconciled ACL entry for memberID, or fails the test.
func findMember(t *testing.T, members []atreolink.MemberACLEntry, memberID string) atreolink.MemberACLEntry {
	t.Helper()
	for _, m := range members {
		if m.MemberID == memberID {
			return m
		}
	}
	t.Fatalf("member %q not found in reconciled ACL", memberID)
	return atreolink.MemberACLEntry{}
}

func TestHandleDeviceState_BootstrapsAllowedAppsFromJoinAttestation(t *testing.T) {
	// No PermissionsEnvelope on the member — AllowedApps must come from
	// the attestation's owner-signed allowedAppIds.
	f := setupOwnedFixture(t)
	nasB64 := f.km.PublicKeyBase64()

	cloudApp := atreolink.App{ID: "app-cloud", Name: "Cloud", Slug: "cloud", InternalURL: "http://127.0.0.1:8080"}
	homeApp := atreolink.App{ID: "app-home", Name: "Home", Slug: "home", InternalURL: "http://127.0.0.1:8081"}

	memberPub, _ := genKey(t)
	att := buildJoinAttestation(t, f.ownerPriv, memberPub, nasB64, []string{"app-cloud"})

	st := atreolink.DeviceState{
		DeviceID:   testDeviceID,
		Generation: 1,
		Members: []atreolink.DSMember{{
			MemberID:        "m-hope",
			MemberName:      "Hope",
			Role:            "member",
			IdentityKey:     base64.StdEncoding.EncodeToString(memberPub),
			JoinAttestation: &att,
		}},
		Apps: catalogueWithApps(t, f.ownerPriv, []atreolink.App{cloudApp, homeApp}),
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, st)); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}

	got := findMember(t, f.store.AllMembers(), "m-hope")
	if len(got.AllowedApps) != 1 || got.AllowedApps[0].ID != "app-cloud" {
		t.Errorf("AllowedApps = %+v, want exactly [app-cloud]", got.AllowedApps)
	}
}

func TestHandleDeviceState_PermissionsEnvelopeWinsOverJoinAttestation(t *testing.T) {
	// A present PermissionsEnvelope overrides the invite-derived list,
	// for both adding and removing apps.
	f := setupOwnedFixture(t)
	nasB64 := f.km.PublicKeyBase64()

	cloudApp := atreolink.App{ID: "app-cloud", Name: "Cloud", Slug: "cloud", InternalURL: "http://127.0.0.1:8080"}
	homeApp := atreolink.App{ID: "app-home", Name: "Home", Slug: "home", InternalURL: "http://127.0.0.1:8081"}

	memberPub, _ := genKey(t)
	// Invite originally granted only "cloud".
	att := buildJoinAttestation(t, f.ownerPriv, memberPub, nasB64, []string{"app-cloud"})
	// Owner has since signed a permissions envelope flipping the set to "home".
	permsEnv := buildPermissionsDSEnvelope(t, f.ownerPriv, "m-hope", []string{"app-home"})

	st := atreolink.DeviceState{
		DeviceID:   testDeviceID,
		Generation: 1,
		Members: []atreolink.DSMember{{
			MemberID:            "m-hope",
			MemberName:          "Hope",
			Role:                "member",
			IdentityKey:         base64.StdEncoding.EncodeToString(memberPub),
			JoinAttestation:     &att,
			PermissionsEnvelope: permsEnv,
		}},
		Apps: catalogueWithApps(t, f.ownerPriv, []atreolink.App{cloudApp, homeApp}),
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, st)); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}

	got := findMember(t, f.store.AllMembers(), "m-hope")
	if len(got.AllowedApps) != 1 || got.AllowedApps[0].ID != "app-home" {
		t.Errorf("AllowedApps = %+v, want exactly [app-home] (envelope must override invite)", got.AllowedApps)
	}
}

func TestHandleDeviceState_JoinAttestationFiltersUnknownAppIDs(t *testing.T) {
	// An invite may reference an app no longer in the device's catalogue;
	// AllowedApps must only contain verified catalogue entries.
	f := setupOwnedFixture(t)
	nasB64 := f.km.PublicKeyBase64()

	cloudApp := atreolink.App{ID: "app-cloud", Name: "Cloud", Slug: "cloud", InternalURL: "http://127.0.0.1:8080"}

	memberPub, _ := genKey(t)
	att := buildJoinAttestation(t, f.ownerPriv, memberPub, nasB64, []string{"app-cloud", "app-deleted"})

	st := atreolink.DeviceState{
		DeviceID:   testDeviceID,
		Generation: 1,
		Members: []atreolink.DSMember{{
			MemberID:        "m-hope",
			MemberName:      "Hope",
			Role:            "member",
			IdentityKey:     base64.StdEncoding.EncodeToString(memberPub),
			JoinAttestation: &att,
		}},
		Apps: catalogueWithApps(t, f.ownerPriv, []atreolink.App{cloudApp}),
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, st)); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}

	got := findMember(t, f.store.AllMembers(), "m-hope")
	if len(got.AllowedApps) != 1 || got.AllowedApps[0].ID != "app-cloud" {
		t.Errorf("AllowedApps = %+v, want exactly [app-cloud] (unknown IDs filtered)", got.AllowedApps)
	}
}

// A valid cert must be honoured even when the original invite's expiresAt
// has passed: the wall-clock check belongs at first admission only.
func TestHandleDeviceState_AcceptsCertWithExpiredInvite(t *testing.T) {
	f := setupOwnedFixture(t)
	nasB64 := f.km.PublicKeyBase64()

	cloudApp := atreolink.App{ID: "app-cloud", Name: "Cloud", Slug: "cloud", InternalURL: "http://127.0.0.1:8080"}
	memberPub, _ := genKey(t)
	memberIK := base64.StdEncoding.EncodeToString(memberPub)

	cert, err := MintAdmittanceCertificate(
		"m-late", memberIK, nasB64,
		[]byte("the-original-invite-payload"),
		[]string{"app-cloud"},
		f.km.PrivateKey(), time.Now(),
	)
	if err != nil {
		t.Fatalf("MintAdmittanceCertificate: %v", err)
	}

	st := atreolink.DeviceState{
		DeviceID:   testDeviceID,
		Generation: 1,
		Members: []atreolink.DSMember{{
			MemberID:    "m-late",
			MemberName:  "Late",
			Role:        "member",
			IdentityKey: memberIK,
			Admittance:  cert,
		}},
		Apps: catalogueWithApps(t, f.ownerPriv, []atreolink.App{cloudApp}),
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, st)); err != nil {
		t.Fatalf("HandleDeviceState (cert path): %v", err)
	}

	got := findMember(t, f.store.AllMembers(), "m-late")
	if got.Admittance == nil {
		t.Error("entry.Admittance not persisted")
	}
	if len(got.AllowedApps) != 1 || got.AllowedApps[0].ID != "app-cloud" {
		t.Errorf("AllowedApps = %+v, want [app-cloud] (initial perms from cert)", got.AllowedApps)
	}
}

func TestHandleDeviceState_FirstAdmission_MintsAndPersistsCert(t *testing.T) {
	f := setupOwnedFixture(t)
	nasB64 := f.km.PublicKeyBase64()

	cloudApp := atreolink.App{ID: "app-cloud", Name: "Cloud", Slug: "cloud", InternalURL: "http://127.0.0.1:8080"}
	memberPub, _ := genKey(t)
	att := buildJoinAttestation(t, f.ownerPriv, memberPub, nasB64, []string{"app-cloud"})

	st := atreolink.DeviceState{
		DeviceID:   testDeviceID,
		Generation: 1,
		Members: []atreolink.DSMember{{
			MemberID:        "m-new",
			MemberName:      "New",
			Role:            "member",
			IdentityKey:     base64.StdEncoding.EncodeToString(memberPub),
			JoinAttestation: &att,
		}},
		Apps: catalogueWithApps(t, f.ownerPriv, []atreolink.App{cloudApp}),
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, st)); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}

	got := findMember(t, f.store.AllMembers(), "m-new")
	if got.Admittance == nil {
		t.Fatal("expected entry.Admittance after first admission")
	}
	if got.JoinAttestation != nil {
		t.Error("expected entry.JoinAttestation cleared after cert mint")
	}
	if err := VerifyAdmittanceCertificate(got.Admittance, "m-new", base64.StdEncoding.EncodeToString(memberPub), nasB64, f.km.PublicKey()); err != nil {
		t.Errorf("minted cert fails self-verification: %v", err)
	}
}

func TestHandleDeviceState_AdminGetsFullCatalogue(t *testing.T) {
	// admin/owner sees every app regardless of envelopes.
	f := setupOwnedFixture(t)

	cloudApp := atreolink.App{ID: "app-cloud", Name: "Cloud", Slug: "cloud", InternalURL: "http://127.0.0.1:8080"}
	homeApp := atreolink.App{ID: "app-home", Name: "Home", Slug: "home", InternalURL: "http://127.0.0.1:8081"}

	st := atreolink.DeviceState{
		DeviceID:   testDeviceID,
		Generation: 1,
		Members: []atreolink.DSMember{{
			MemberID:    "m-owner",
			MemberName:  "Owner",
			Role:        "admin",
			IdentityKey: base64.StdEncoding.EncodeToString(f.ownerPub),
		}},
		Apps: catalogueWithApps(t, f.ownerPriv, []atreolink.App{cloudApp, homeApp}),
	}
	if _, err := f.h.HandleDeviceState(deviceStateMsg(t, st)); err != nil {
		t.Fatalf("HandleDeviceState: %v", err)
	}

	got := findMember(t, f.store.AllMembers(), "m-owner")
	if len(got.AllowedApps) != 2 {
		t.Errorf("AllowedApps len = %d, want 2 (full catalogue for admin)", len(got.AllowedApps))
	}
}
