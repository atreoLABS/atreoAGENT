package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCustomDomainStore_GetMissingFile(t *testing.T) {
	s := NewCustomDomainStore(filepath.Join(t.TempDir(), "custom_domain.json"))
	got, err := s.Get()
	if err != nil {
		t.Fatalf("Get on missing file: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestCustomDomainStore_SetGetRoundTrip(t *testing.T) {
	s := NewCustomDomainStore(filepath.Join(t.TempDir(), "custom_domain.json"))
	in := &CustomDomain{
		ParentZone:       "example.com",
		EnvelopePayload:  []byte(`{"intent":"custom-domain-set"}`),
		EnvelopeOwnerSig: "base64-sig",
		VerifiedAt:       "2026-04-26T12:00:00Z",
	}
	if err := s.Set(in); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ParentZone != in.ParentZone {
		t.Errorf("ParentZone: got %q, want %q", got.ParentZone, in.ParentZone)
	}
	if string(got.EnvelopePayload) != string(in.EnvelopePayload) {
		t.Errorf("EnvelopePayload: got %s, want %s", got.EnvelopePayload, in.EnvelopePayload)
	}
	if got.EnvelopeOwnerSig != in.EnvelopeOwnerSig {
		t.Errorf("EnvelopeOwnerSig: got %q, want %q", got.EnvelopeOwnerSig, in.EnvelopeOwnerSig)
	}
}

func TestCustomDomainStore_SetOverwrites(t *testing.T) {
	s := NewCustomDomainStore(filepath.Join(t.TempDir(), "custom_domain.json"))
	if err := s.Set(&CustomDomain{ParentZone: "example.com"}); err != nil {
		t.Fatalf("Set 1: %v", err)
	}
	if err := s.Set(&CustomDomain{ParentZone: "other.test"}); err != nil {
		t.Fatalf("Set 2: %v", err)
	}
	got, err := s.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ParentZone != "other.test" {
		t.Errorf("expected overwrite to other.test, got %q", got.ParentZone)
	}
}

func TestCustomDomainStore_SetRejectsEmpty(t *testing.T) {
	s := NewCustomDomainStore(filepath.Join(t.TempDir(), "custom_domain.json"))
	if err := s.Set(nil); err == nil {
		t.Errorf("expected error for nil")
	}
	if err := s.Set(&CustomDomain{}); err == nil {
		t.Errorf("expected error for empty parentZone")
	}
}

func TestCustomDomainStore_Clear(t *testing.T) {
	s := NewCustomDomainStore(filepath.Join(t.TempDir(), "custom_domain.json"))
	if err := s.Set(&CustomDomain{ParentZone: "example.com"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	got, err := s.Get()
	if err != nil {
		t.Fatalf("Get after Clear: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after Clear, got %+v", got)
	}
}

func TestCustomDomainStore_ClearMissingIsNoOp(t *testing.T) {
	s := NewCustomDomainStore(filepath.Join(t.TempDir(), "custom_domain.json"))
	if err := s.Clear(); err != nil {
		t.Errorf("Clear on missing file should be no-op, got %v", err)
	}
}

func TestCustomDomainStore_AtomicWrite_NoTempLeftover(t *testing.T) {
	dir := t.TempDir()
	s := NewCustomDomainStore(filepath.Join(dir, "custom_domain.json"))
	if err := s.Set(&CustomDomain{ParentZone: "example.com"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// After a successful write, the directory should contain only the
	// final file — no `.custom_domain.*.tmp` leftovers from the
	// atomic write-and-rename.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".custom_domain.") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

func TestCustomDomainStore_GetCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom_domain.json")
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewCustomDomainStore(path)
	if _, err := s.Get(); err == nil {
		t.Errorf("expected parse error for corrupt file")
	}
}

func TestCustomDomainStore_GetEmptyParentZone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom_domain.json")
	// An empty-zone row is treated the same as no row — defends against
	// a half-cleared state from a buggy upgrade.
	data, _ := json.Marshal(CustomDomain{ParentZone: ""})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := NewCustomDomainStore(path)
	got, err := s.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for empty-zone row, got %+v", got)
	}
}

func TestCustomDomainStore_FilePerms0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom_domain.json")
	s := NewCustomDomainStore(path)
	if err := s.Set(&CustomDomain{ParentZone: "example.com"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("perm: got %o, want 0600", perm)
	}
}

// Sanity check — just confirms the package's missing-file handling
// matches the standard ErrNotExist contract.
func TestCustomDomainStore_GetReturnsNilOnNotExist(t *testing.T) {
	s := NewCustomDomainStore("/nonexistent/path/does/not/exist.json")
	got, err := s.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for nonexistent path, got %+v", got)
	}
	// Sanity — a real ENOENT from os.ReadFile is what triggers the
	// short-circuit. Verifies the helper logic in case someone changes
	// the error sentinel.
	_, err = os.ReadFile("/nonexistent/path/does/not/exist.json")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got %v", err)
	}
}
