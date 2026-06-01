package upnp

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/atreoLABS/atreoAGENT/internal/pcp"
)

func TestPinholeNoncesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pcp_nonces.json")

	c := NewClient(51820)
	c.SetStatePath(path) // empty file → no-op load

	n1 := pcp.Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	c.storePinhole("2001:db8::1", &pinhole{nonce: n1, remove: func() {}})

	// A fresh client pointed at the same file must recover the nonce so a
	// renewal after restart reuses it.
	c2 := NewClient(51820)
	c2.SetStatePath(path)
	got, ok := c2.v6pinholes["2001:db8::1"]
	if !ok {
		t.Fatalf("nonce for 2001:db8::1 not loaded")
	}
	if got.nonce != n1 {
		t.Fatalf("loaded nonce = %v, want %v", got.nonce, n1)
	}
	if got.remove == nil {
		t.Fatalf("loaded pinhole must carry a teardown closure")
	}
}

func TestPinholeNoncesSkipsZeroNonce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pcp_nonces.json")

	c := NewClient(51820)
	c.SetStatePath(path)
	// UPnP-path pinholes have no nonce; they must not reach disk.
	c.storePinhole("2001:db8::2", &pinhole{remove: func() {}})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if string(data) != "{}" {
		t.Fatalf("zero-nonce pinhole should not persist, got %q", data)
	}
}

func TestPinholeNoncesMissingFileIsNoOp(t *testing.T) {
	c := NewClient(51820)
	c.SetStatePath(filepath.Join(t.TempDir(), "absent.json"))
	if len(c.v6pinholes) != 0 {
		t.Fatalf("missing file should load nothing, got %d", len(c.v6pinholes))
	}
}

// Unparseable JSON and malformed entries are skipped, not fatal.
func TestPinholeNoncesSkipsCorruptEntries(t *testing.T) {
	good := pcp.Nonce{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	stored := map[string]string{
		"2001:db8::1": hex.EncodeToString(good[:]), // valid → loaded
		"2001:db8::2": "zzzz",                      // bad hex → skipped
		"2001:db8::3": "0102",                      // wrong length → skipped
		"not-an-ip":   hex.EncodeToString(good[:]), // bad IP → skipped
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "pcp_nonces.json")
	data, _ := json.Marshal(stored)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := NewClient(51820)
	c.SetStatePath(path)
	if len(c.v6pinholes) != 1 {
		t.Fatalf("only the valid entry should load, got %d", len(c.v6pinholes))
	}

	// Garbage JSON must not panic or load anything.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	c2 := NewClient(51820)
	c2.SetStatePath(bad)
	if len(c2.v6pinholes) != 0 {
		t.Fatalf("corrupt file should load nothing, got %d", len(c2.v6pinholes))
	}
}

// An upgrade from the old v6_pinholes.json filename must keep live nonces.
func TestPinholeNoncesMigratesLegacyFile(t *testing.T) {
	dir := t.TempDir()
	n := pcp.Nonce{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2}
	legacy := map[string]string{"2001:db8::5": hex.EncodeToString(n[:])}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir, "v6_pinholes.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	c := NewClient(51820)
	c.SetStatePath(filepath.Join(dir, "pcp_nonces.json")) // absent → reads legacy
	got, ok := c.v6pinholes["2001:db8::5"]
	if !ok || got.nonce != n {
		t.Fatalf("legacy nonce not migrated: ok=%v got=%v", ok, got)
	}
}

// The IPv4 mapping nonce must be stable across calls (so renewals refresh the
// same mapping) and survive a restart via the shared state file.
func TestV4MappingNoncePersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pcp_nonces.json")

	c := NewClient(51820)
	c.SetStatePath(path)

	n1, err := c.v4MappingNonce("192.0.2.10")
	if err != nil {
		t.Fatalf("v4MappingNonce: %v", err)
	}
	n2, _ := c.v4MappingNonce("192.0.2.10")
	if n1 != n2 {
		t.Fatalf("nonce not reused for same localIP: %v vs %v", n1, n2)
	}
	// A changed internal IP starts a fresh mapping → fresh nonce.
	if n3, _ := c.v4MappingNonce("192.0.2.11"); n3 == n1 {
		t.Fatalf("nonce should change when localIP changes")
	}

	// Persist whatever the client currently holds, then reload in a fresh
	// client and confirm the same internal IP recovers the same nonce.
	cur, _ := c.v4MappingNonce("192.0.2.11")
	c.persistNonces()
	c2 := NewClient(51820)
	c2.SetStatePath(path)
	got, _ := c2.v4MappingNonce("192.0.2.11")
	if got != cur {
		t.Fatalf("reloaded v4 nonce = %v, want %v", got, cur)
	}
}
