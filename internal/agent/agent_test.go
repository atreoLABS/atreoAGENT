package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/notify"
)

func agentTestKM(t *testing.T) *crypto.KeyManager {
	t.Helper()
	km, err := crypto.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return km
}

// Regression: the agent stores the privileged row as either "owner" (at pair
// time) or "admin" (after a DeviceState push). The router-config alert path
// must reach both.
func TestNotifyOwner_AdminRole(t *testing.T) {
	var calls atomic.Int32
	push := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/notifications" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(push.Close)

	pubAdmin, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubMember, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	aclStore := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	if err := aclStore.SetPinnedAdminPublicKey(pubAdmin); err != nil {
		t.Fatal(err)
	}
	members := []atreolink.MemberACLEntry{
		{
			MemberID:    "admin-1",
			UserID:      "u-admin",
			Email:       "admin@example.com",
			Role:        "admin",
			IdentityKey: base64.StdEncoding.EncodeToString(pubAdmin),
			Status:      "active",
		},
		{
			MemberID:    "member-1",
			UserID:      "u-member",
			Email:       "m@example.com",
			Role:        "member",
			IdentityKey: base64.StdEncoding.EncodeToString(pubMember),
			Status:      "active",
		},
	}
	if err := aclStore.ReplaceAll(members); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}

	link := atreolink.NewClient(push.URL, agentTestKM(t), "tok")
	
	if err != nil {
		t.Fatal(err)
	}
	srv, err := notify.NewServer(0, t.TempDir(), "agent-uuid", link, aclStore)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	a := &Agent{notifyServer: srv, aclStore: aclStore}
	if !a.notifyOwner(context.Background(), &notify.NotifyRequest{Title: "x", Severity: "error"}) {
		t.Fatal("notifyOwner returned false, want true")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cloud calls=%d, want 1", got)
	}
}

func TestNotifyOwner_NilNotifyServer(t *testing.T) {
	a := &Agent{}
	if a.notifyOwner(context.Background(), &notify.NotifyRequest{Title: "x", Severity: "info"}) {
		t.Error("notifyOwner returned true with nil notifyServer")
	}
}

func TestNotifyOwner_NoAdminEntry(t *testing.T) {
	var calls atomic.Int32
	push := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(push.Close)

	pubMember, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aclStore := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	members := []atreolink.MemberACLEntry{
		{
			MemberID:    "member-1",
			UserID:      "u-member",
			Email:       "m@example.com",
			Role:        "member",
			IdentityKey: base64.StdEncoding.EncodeToString(pubMember),
			Status:      "active",
		},
	}
	if err := aclStore.ReplaceAll(members); err != nil {
		t.Fatal(err)
	}

	link := atreolink.NewClient(push.URL, agentTestKM(t), "tok")
	
	if err != nil {
		t.Fatal(err)
	}
	srv, err := notify.NewServer(0, t.TempDir(), "agent-uuid", link, aclStore)
	if err != nil {
		t.Fatal(err)
	}

	a := &Agent{notifyServer: srv, aclStore: aclStore}
	if a.notifyOwner(context.Background(), &notify.NotifyRequest{Title: "x", Severity: "info"}) {
		t.Error("notifyOwner returned true with no admin entry")
	}
	if calls.Load() != 0 {
		t.Errorf("expected no cloud calls, got %d", calls.Load())
	}
}

// portMappingAlert must short-circuit on cooldown so a container restart
// loop can't spam the owner. clearPortMappingAlertCooldown removes the
// marker so the next failure episode can alert again.
func TestPortMappingAlert_Cooldown(t *testing.T) {
	var calls atomic.Int32
	push := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(push.Close)

	pubAdmin, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	aclStore := acl.NewStore(filepath.Join(t.TempDir(), "acl.json"))
	if err := aclStore.ReplaceAll([]atreolink.MemberACLEntry{{
		MemberID:    "admin-1",
		UserID:      "u-admin",
		Email:       "admin@example.com",
		Role:        "admin",
		IdentityKey: base64.StdEncoding.EncodeToString(pubAdmin),
		Status:      "active",
	}}); err != nil {
		t.Fatal(err)
	}

	link := atreolink.NewClient(push.URL, agentTestKM(t), "tok")
	
	if err != nil {
		t.Fatal(err)
	}
	srv, err := notify.NewServer(0, t.TempDir(), "agent-uuid", link, aclStore)
	if err != nil {
		t.Fatal(err)
	}

	a := &Agent{
		cfg:          &config.Config{DataDir: t.TempDir()},
		notifyServer: srv,
		aclStore:     aclStore,
	}

	req := &notify.NotifyRequest{Title: "Port forwarding required", Severity: "error"}
	if !a.portMappingAlert(context.Background(), req) {
		t.Fatal("first call returned false, want true")
	}
	if calls.Load() != 1 {
		t.Fatalf("first call cloud calls=%d, want 1", calls.Load())
	}

	if !a.portMappingAlert(context.Background(), req) {
		t.Fatal("second call returned false, want true (suppressed)")
	}
	if calls.Load() != 1 {
		t.Fatalf("second call cloud calls=%d, want 1 (cooldown should suppress)", calls.Load())
	}

	a.clearPortMappingAlertCooldown()
	if !a.portMappingAlert(context.Background(), req) {
		t.Fatal("third call returned false, want true")
	}
	if calls.Load() != 2 {
		t.Fatalf("third call cloud calls=%d, want 2", calls.Load())
	}
}
