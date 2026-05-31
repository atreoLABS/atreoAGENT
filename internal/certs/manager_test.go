package certs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// We can't drive Manager.EnsureCert through a real ACME server in tests,
// but we can exercise the "cert is already valid on disk" fast-path.
// Write a self-signed cert, then EnsureCert should find it valid and
// load it into the registry without calling the issuer.

func TestManager_EnsureCert_LoadsValidExistingCert(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, dir, dir, "ops@example.com", "dev-test", nil) // nil atreolink — issuer never runs
	suffix := "alice.myatreo.com"
	certPath := filepath.Join(dir, suffix, "cert.pem")
	keyPath := filepath.Join(dir, suffix, "key.pem")
	writeSelfSignedCert(t, suffix, certPath, keyPath, 60*24*time.Hour)

	if err := m.EnsureCert(context.Background(), suffix); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	if !m.Registry.Has(suffix) {
		t.Errorf("Registry should have loaded cert for %s", suffix)
	}
}

func TestManager_EnsureCert_RejectsEmptySuffix(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir(), t.TempDir(), "ops@example.com", "dev-test", nil)
	err := m.EnsureCert(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "empty suffix") {
		t.Errorf("expected empty-suffix error, got %v", err)
	}
}

func TestManager_EnsureCert_NormalisesSuffix(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, dir, dir, "ops@example.com", "dev-test", nil)
	// Write the cert under the canonical lowercase name; pass ugly form.
	suffix := "alice.myatreo.com"
	certPath := filepath.Join(dir, suffix, "cert.pem")
	keyPath := filepath.Join(dir, suffix, "key.pem")
	writeSelfSignedCert(t, suffix, certPath, keyPath, 60*24*time.Hour)

	if err := m.EnsureCert(context.Background(), "  *.ALICE.MyAtreo.com.  "); err != nil {
		t.Fatalf("EnsureCert: %v", err)
	}
	if !m.Registry.Has(suffix) {
		t.Errorf("expected cert loaded under canonical key %q", suffix)
	}
}

// renewAll iterates every registered suffix. With a stale (expiring)
// cert and a nil atreolink, the issuer call fails — but renewAll
// continues to the next suffix. We assert "didn't crash" + that the
// expiring suffix is still registered (the manager's EnsureCert
// fallback re-loads it from disk on issuer failure).
func TestManager_RenewAll_ContinuesOnIssuerFailure(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir, dir, dir, "ops@example.com", "dev-test", nil)

	// Two suffixes — one with a fresh cert (no renewal needed), one
	// expiring (renewAll will try to renew, fail because atreolink is
	// nil, fall back to the on-disk cert).
	freshSuffix := "alice.myatreo.com"
	expSuffix := "example.com"
	writeSelfSignedCert(t, freshSuffix,
		filepath.Join(dir, freshSuffix, "cert.pem"),
		filepath.Join(dir, freshSuffix, "key.pem"),
		60*24*time.Hour)
	writeSelfSignedCert(t, expSuffix,
		filepath.Join(dir, expSuffix, "cert.pem"),
		filepath.Join(dir, expSuffix, "key.pem"),
		5*24*time.Hour) // within renewBefore

	if err := m.Registry.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Should not panic; both suffixes stay in the registry afterwards.
	m.renewAll(context.Background())

	for _, s := range []string{freshSuffix, expSuffix} {
		if !m.Registry.Has(s) {
			t.Errorf("suffix %q should still be loaded after renewAll", s)
		}
	}
}

// --- renewal-failure tracking (A5) ---------------------------------------

// TestRecordRenewalFailure_BelowThreshold accumulates failures without
// hitting the notifier — the manager should bump the counter but not
// fire the alert until the threshold is reached.
func TestRecordRenewalFailure_BelowThreshold(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir(), t.TempDir(), "ops@example.com", "dev-test", nil)
	var fired atomic.Int32
	m.SetOwnerNotifier(func(string, int) { fired.Add(1) })

	suffix := "alice.myatreo.com"
	for i := 0; i < renewalAlertThreshold-1; i++ {
		m.recordRenewalFailure(suffix)
	}
	// Give any (unwanted) notifier goroutine a chance to run.
	time.Sleep(20 * time.Millisecond)
	if fired.Load() != 0 {
		t.Errorf("notifier fired %d times below threshold", fired.Load())
	}
	state := m.RenewalSnapshot()[suffix]
	if state.ConsecutiveFailures != renewalAlertThreshold-1 {
		t.Errorf("ConsecutiveFailures=%d, want %d", state.ConsecutiveFailures, renewalAlertThreshold-1)
	}
}

// TestRecordRenewalFailure_AtThresholdFires verifies the notifier is
// called exactly once when the threshold is first hit, with the
// snapshot count.
func TestRecordRenewalFailure_AtThresholdFires(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir(), t.TempDir(), "ops@example.com", "dev-test", nil)
	gotCount := make(chan int, 4)
	m.SetOwnerNotifier(func(_ string, count int) { gotCount <- count })

	suffix := "alice.myatreo.com"
	for i := 0; i < renewalAlertThreshold; i++ {
		m.recordRenewalFailure(suffix)
	}
	select {
	case c := <-gotCount:
		if c != renewalAlertThreshold {
			t.Errorf("notifier got count=%d, want %d", c, renewalAlertThreshold)
		}
	case <-time.After(time.Second):
		t.Fatal("notifier never fired")
	}

	// Additional failure within the cooldown window must not re-fire.
	m.recordRenewalFailure(suffix)
	select {
	case <-gotCount:
		t.Error("notifier re-fired inside cooldown")
	case <-time.After(20 * time.Millisecond):
	}
}

// TestRecordRenewalSuccess_ResetsCounter verifies a successful renewal
// zeroes the failure counter and stamps LastSuccess.
func TestRecordRenewalSuccess_ResetsCounter(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir(), t.TempDir(), "ops@example.com", "dev-test", nil)
	suffix := "alice.myatreo.com"
	for i := 0; i < renewalAlertThreshold; i++ {
		m.recordRenewalFailure(suffix)
	}
	m.recordRenewalSuccess(suffix)
	state := m.RenewalSnapshot()[suffix]
	if state.ConsecutiveFailures != 0 {
		t.Errorf("ConsecutiveFailures=%d after success, want 0", state.ConsecutiveFailures)
	}
	if state.LastSuccess.IsZero() {
		t.Error("LastSuccess not stamped")
	}
}

// TestRenewalState_Persistence checks the state survives a Manager
// rebuild — the failure counter must reload from disk so a daemon
// restart doesn't reset the alerting window.
func TestRenewalState_Persistence(t *testing.T) {
	dataDir := t.TempDir()
	m1 := NewManager(t.TempDir(), t.TempDir(), dataDir, "ops@example.com", "dev-test", nil)
	suffix := "alice.myatreo.com"
	m1.recordRenewalFailure(suffix)
	m1.recordRenewalFailure(suffix)

	// Rebuild against the same dataDir.
	m2 := NewManager(t.TempDir(), t.TempDir(), dataDir, "ops@example.com", "dev-test", nil)
	state := m2.RenewalSnapshot()[suffix]
	if state.ConsecutiveFailures != 2 {
		t.Errorf("reloaded ConsecutiveFailures=%d, want 2", state.ConsecutiveFailures)
	}
}

// TestLoadRenewalState_CorruptFile resets on parse failure — a
// half-written or hand-edited state file should never wedge the agent
// at startup.
func TestLoadRenewalState_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert_renewal_state.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	got := loadRenewalState(path)
	if len(got) != 0 {
		t.Errorf("expected empty map on corrupt state, got %d entries", len(got))
	}
}

// TestLoadRenewalState_RoundTrip confirms the persisted JSON shape is
// stable across write→read.
func TestLoadRenewalState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	in := map[string]*RenewalState{
		"alice.myatreo.com": {
			ConsecutiveFailures: 5,
			LastAttempt:         time.Now().Truncate(time.Second),
		},
	}
	data, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got := loadRenewalState(path)
	if got["alice.myatreo.com"].ConsecutiveFailures != 5 {
		t.Errorf("got %+v", got["alice.myatreo.com"])
	}
}

// TestCertFileIsValidForSuffix exercises the suffix-bound validity
// helper. The renewal loop uses this to skip a cert that already
// covers the suffix and has > renewBefore left.
func TestCertFileIsValidForSuffix(t *testing.T) {
	dir := t.TempDir()
	suffix := "alice.myatreo.com"
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	t.Run("valid wildcard cert", func(t *testing.T) {
		writeSelfSignedCert(t, suffix, certPath, keyPath, 90*24*time.Hour)
		if !certFileIsValidForSuffix(certPath, suffix) {
			t.Error("expected wildcard cert with > 30d to validate")
		}
	})
	t.Run("expiring cert rejected", func(t *testing.T) {
		writeSelfSignedCert(t, suffix, certPath, keyPath, 5*24*time.Hour)
		if certFileIsValidForSuffix(certPath, suffix) {
			t.Error("expected expiring cert to be invalid")
		}
	})
	t.Run("suffix mismatch rejected", func(t *testing.T) {
		writeSelfSignedCert(t, "other.example", certPath, keyPath, 90*24*time.Hour)
		if certFileIsValidForSuffix(certPath, suffix) {
			t.Error("expected mismatched suffix to fail validation")
		}
	})
	t.Run("missing file is invalid", func(t *testing.T) {
		if certFileIsValidForSuffix(filepath.Join(dir, "nope.pem"), suffix) {
			t.Error("missing file should be invalid")
		}
	})
}
