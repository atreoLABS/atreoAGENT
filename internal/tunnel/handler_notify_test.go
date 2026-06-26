package tunnel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/notify"
)

// withNotifyServer attaches a real notify.Server to an existing fixture's
// handlers. notify.Server's NewServer needs a writable data dir for the API
// key file but otherwise works without a live HTTP listener — `Start` is
// only called by production code, not the handlers under test here.
func withNotifyServer(t *testing.T, f *ownedFixture) {
	t.Helper()
	notifyDir := filepath.Join(f.dir, "notify")
	if err := os.MkdirAll(notifyDir, 0o755); err != nil {
		t.Fatalf("mkdir notify dir: %v", err)
	}
	ns, err := notify.NewServer(0, notifyDir, testDeviceID, nil, f.store)
	if err != nil {
		t.Fatalf("notify.NewServer: %v", err)
	}
	f.h.notifyServer = ns
}

// --- HandleNotifyAPIKey -----------------------------------------------------

func TestHandleNotifyAPIKey_HappyPath(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)

	now := time.Now().Unix()
	payload := NotifyAPIKeyPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey-%s-%d", testDeviceID, now),
			Timestamp: now,
		},
		DeviceID: testDeviceID,
	}
	msg := envelope(t, "notify:apikey", "m-owner", f.ownerPriv, payload)
	msg.CorrelationID = "c-notify-1"

	resp, err := f.h.HandleNotifyAPIKey(msg)
	if err != nil {
		t.Fatalf("HandleNotifyAPIKey: %v", err)
	}
	if resp.Type != "notify:apikey:response" || resp.CorrelationID != "c-notify-1" {
		t.Errorf("unexpected envelope: %+v", resp)
	}
	var body map[string]any
	if err := json.Unmarshal(resp.Payload, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["apiKey"] == nil || body["apiKey"] == "" {
		t.Error("apiKey missing from response")
	}
	if _, ok := body["port"]; !ok {
		t.Error("port missing from response")
	}
}

func TestHandleNotifyAPIKey_RejectsUnsigned(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)

	now := time.Now().Unix()
	payload := NotifyAPIKeyPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey-%s-%d", testDeviceID, now),
			Timestamp: now,
		},
		DeviceID: testDeviceID,
	}
	body, _ := json.Marshal(payload)
	msg := atreolink.TunnelMessage{Type: "notify:apikey", Payload: body}
	if _, err := f.h.HandleNotifyAPIKey(msg); err == nil {
		t.Error("expected rejection of unsigned envelope")
	}
}

func TestHandleNotifyAPIKey_RejectsMemberSigner(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)
	// Member-signed envelope on an owner-only command must be rejected.
	now := time.Now().Unix()
	payload := NotifyAPIKeyPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey-%s-%d", testDeviceID, now),
			Timestamp: now,
		},
		DeviceID: testDeviceID,
	}
	msg := envelope(t, "notify:apikey", "m-bob", f.memberPriv, payload)
	if _, err := f.h.HandleNotifyAPIKey(msg); err == nil {
		t.Error("expected rejection of member-signed envelope on owner-only command")
	}
}

// Group C: a cross-device envelope (payload.DeviceID != h.deviceID) is
// rejected by the precondition check. The h.deviceID-bound intent prevents
// a signature-valid envelope from being applied to the wrong agent.
func TestHandleNotifyAPIKey_RejectsCrossDevice(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)
	now := time.Now().Unix()
	payload := NotifyAPIKeyPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey-%s-%d", "OTHER-DEVICE", now),
			Timestamp: now,
		},
		DeviceID: "OTHER-DEVICE",
	}
	msg := envelope(t, "notify:apikey", "m-owner", f.ownerPriv, payload)
	if _, err := f.h.HandleNotifyAPIKey(msg); err == nil {
		t.Error("expected deviceId mismatch rejection")
	}
}

// payload.DeviceID matches but intent uses a different device id (defence
// against a same-owner same-user-account different-device signature replay
// caught at the intent layer rather than the precondition).
func TestHandleNotifyAPIKey_RejectsIntentWithWrongDeviceID(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)
	now := time.Now().Unix()
	payload := NotifyAPIKeyPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey-%s-%d", "OTHER-DEVICE", now),
			Timestamp: now,
		},
		DeviceID: testDeviceID, // matches precondition; intent doesn't
	}
	msg := envelope(t, "notify:apikey", "m-owner", f.ownerPriv, payload)
	_, err := f.h.HandleNotifyAPIKey(msg)
	if !errors.Is(err, ErrIntentMismatch) {
		t.Errorf("err=%v, want ErrIntentMismatch", err)
	}
}

func TestHandleNotifyAPIKey_RejectsWhenNotConfigured(t *testing.T) {
	// notifyServer left nil — handler must reject early with a clear error.
	f := setupOwnedFixture(t)
	now := time.Now().Unix()
	payload := NotifyAPIKeyPayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey-%s-%d", testDeviceID, now),
			Timestamp: now,
		},
		DeviceID: testDeviceID,
	}
	msg := envelope(t, "notify:apikey", "m-owner", f.ownerPriv, payload)
	_, err := f.h.HandleNotifyAPIKey(msg)
	if err == nil {
		t.Error("expected error when notify server is nil")
	}
}

// --- HandleNotifyAPIKeyRotate ----------------------------------------------

func TestHandleNotifyAPIKeyRotate_HappyPath(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)

	previousKey := f.h.notifyServer.APIKey()

	now := time.Now().Unix()
	payload := NotifyAPIKeyRotatePayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey:rotate-%s-%d", testDeviceID, now),
			Timestamp: now,
		},
		DeviceID: testDeviceID,
	}
	msg := envelope(t, "notify:apikey:rotate", "m-owner", f.ownerPriv, payload)
	msg.CorrelationID = "c-rotate-1"

	resp, err := f.h.HandleNotifyAPIKeyRotate(msg)
	if err != nil {
		t.Fatalf("HandleNotifyAPIKeyRotate: %v", err)
	}
	if resp.Type != "notify:apikey:rotate:response" {
		t.Errorf("unexpected envelope type: %s", resp.Type)
	}
	var body map[string]string
	if err := json.Unmarshal(resp.Payload, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["apiKey"] == "" {
		t.Error("new apiKey missing from response")
	}
	if body["apiKey"] == previousKey {
		t.Error("rotated apiKey is the same as the previous one")
	}
	if f.h.notifyServer.APIKey() != body["apiKey"] {
		t.Error("server's APIKey() doesn't match what the handler returned")
	}
}

func TestHandleNotifyAPIKeyRotate_RejectsUnsigned(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)
	now := time.Now().Unix()
	payload := NotifyAPIKeyRotatePayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey:rotate-%s-%d", testDeviceID, now),
			Timestamp: now,
		},
		DeviceID: testDeviceID,
	}
	body, _ := json.Marshal(payload)
	msg := atreolink.TunnelMessage{Type: "notify:apikey:rotate", Payload: body}
	if _, err := f.h.HandleNotifyAPIKeyRotate(msg); err == nil {
		t.Error("expected rejection of unsigned envelope")
	}
}

func TestHandleNotifyAPIKeyRotate_RejectsStaleTimestamp(t *testing.T) {
	f := setupOwnedFixture(t)
	withNotifyServer(t, f)
	// Signed envelope with a 10-minute-old timestamp: replay-window check fails.
	stale := time.Now().Add(-10 * time.Minute).Unix()
	payload := NotifyAPIKeyRotatePayload{
		CommandEnvelopeFields: CommandEnvelopeFields{
			Intent:    fmt.Sprintf("notify:apikey:rotate-%s-%d", testDeviceID, stale),
			Timestamp: stale,
		},
		DeviceID: testDeviceID,
	}
	msg := envelope(t, "notify:apikey:rotate", "m-owner", f.ownerPriv, payload)
	_, err := f.h.HandleNotifyAPIKeyRotate(msg)
	if !errors.Is(err, ErrStaleTimestamp) {
		t.Errorf("err = %v, want ErrStaleTimestamp", err)
	}
}
