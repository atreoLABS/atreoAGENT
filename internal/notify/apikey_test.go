package notify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAPIKey(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateAPIKey(dir)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	if len(key) != 64 {
		t.Errorf("key length=%d, want 64 (hex of 32 bytes)", len(key))
	}

	path := filepath.Join(dir, "notify_api_key")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("perms=%o, want 0600", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != key {
		t.Errorf("file contents %q != returned key %q", data, key)
	}
}

func TestLoadOrGenerateAPIKey_Generates(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrGenerateAPIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 64 {
		t.Errorf("len=%d, want 64", len(key))
	}
}

func TestLoadOrGenerateAPIKey_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrGenerateAPIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrGenerateAPIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("expected idempotent load, got %q then %q", first, second)
	}
}

func TestLoadOrGenerateAPIKey_RegeneratesIfBad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notify_api_key")
	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadOrGenerateAPIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 64 {
		t.Errorf("len=%d, want 64 after regenerate", len(key))
	}
}

func TestGenerateAPIKey_BadDir(t *testing.T) {
	if _, err := GenerateAPIKey("/nonexistent/path/that/does/not/exist"); err == nil {
		t.Error("expected error writing to bad path")
	}
}
