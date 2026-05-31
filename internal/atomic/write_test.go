package atomic

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.key")

	if err := WriteFile(path, []byte("v1"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "v1" {
		t.Fatalf("read = %q, %v; want v1", got, err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0600 {
		t.Errorf("perm = %v, want 0600", fi.Mode().Perm())
	}
	// No stray temp file left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file not cleaned up: %v", err)
	}

	// Overwrite is also atomic.
	if err := WriteFile(path, []byte("v2"), 0600); err != nil {
		t.Fatalf("WriteFile overwrite: %v", err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != "v2" {
		t.Errorf("read = %q, want v2", got)
	}
}
