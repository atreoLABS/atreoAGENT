package wireguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func newTestAllocator(t *testing.T) *IPAllocator {
	t.Helper()
	a, err := NewIPAllocator("100.64.0.0/24", "100.64.0.1", filepath.Join(t.TempDir(), "alloc.json"))
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}
	return a
}

func TestSequentialAllocation(t *testing.T) {
	a := newTestAllocator(t)

	ip1, err := a.Allocate("key1")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip1 != "100.64.0.2" {
		t.Errorf("ip1 = %q, want 100.64.0.2", ip1)
	}

	ip2, err := a.Allocate("key2")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip2 != "100.64.0.3" {
		t.Errorf("ip2 = %q, want 100.64.0.3", ip2)
	}
}

func TestExistingAllocationReturned(t *testing.T) {
	a := newTestAllocator(t)

	ip1, _ := a.Allocate("key1")
	ip2, _ := a.Allocate("key1")

	if ip1 != ip2 {
		t.Errorf("expected same IP, got %q and %q", ip1, ip2)
	}
}

func TestReleaseAndReallocate(t *testing.T) {
	a := newTestAllocator(t)

	ip1, _ := a.Allocate("key1")
	_, _ = a.Allocate("key2")
	a.Release("key1")

	// Should reuse the released IP
	ip3, _ := a.Allocate("key3")
	if ip3 != ip1 {
		t.Errorf("expected reuse of %q, got %q", ip1, ip3)
	}
}

func TestSubnetLimits(t *testing.T) {
	a := newTestAllocator(t)

	// Allocate all available IPs (2-254 = 253 IPs)
	for i := 0; i < 253; i++ {
		_, err := a.Allocate(string(rune('A' + i)))
		if err != nil {
			// rune approach won't work for 253 keys, use a better key
			break
		}
	}

	// Re-test with proper keys
	a2 := newTestAllocator(t)
	for i := 0; i < 253; i++ {
		key := "key-" + string(rune(i))
		_, err := a2.Allocate(key)
		if err != nil {
			t.Fatalf("Allocate failed at i=%d: %v", i, err)
		}
	}

	_, err := a2.Allocate("overflow")
	if err == nil {
		t.Error("expected error when subnet is full")
	}
}

func TestLookup(t *testing.T) {
	a := newTestAllocator(t)

	_, _ = a.Allocate("key1")

	if ip := a.Lookup("key1"); ip != "100.64.0.2" {
		t.Errorf("Lookup = %q, want 100.64.0.2", ip)
	}
	if ip := a.Lookup("nonexistent"); ip != "" {
		t.Errorf("Lookup nonexistent = %q, want empty", ip)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alloc.json")

	a1, _ := NewIPAllocator("100.64.0.0/24", "100.64.0.1", path)
	_, _ = a1.Allocate("key1")
	_, _ = a1.Allocate("key2")
	if err := a1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	a2, _ := NewIPAllocator("100.64.0.0/24", "100.64.0.1", path)
	if ip := a2.Lookup("key1"); ip != "100.64.0.2" {
		t.Errorf("After load, key1 = %q, want 100.64.0.2", ip)
	}
	if ip := a2.Lookup("key2"); ip != "100.64.0.3" {
		t.Errorf("After load, key2 = %q, want 100.64.0.3", ip)
	}

	// Next allocation should not reuse existing IPs
	ip3, _ := a2.Allocate("key3")
	if ip3 != "100.64.0.4" {
		t.Errorf("After load, new alloc = %q, want 100.64.0.4", ip3)
	}
}

func TestInvalidSubnet(t *testing.T) {
	_, err := NewIPAllocator("invalid", "100.64.0.1", "")
	if err == nil {
		t.Error("expected error for invalid subnet")
	}
}

func TestMarkUsedPreventsCollisionAfterCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alloc.json")

	// Original run: allocate 3 peers.
	a1, _ := NewIPAllocator("100.64.0.0/24", "100.64.0.1", path)
	ipA, _ := a1.Allocate("keyA")
	ipB, _ := a1.Allocate("keyB")
	ipC, _ := a1.Allocate("keyC")

	// Simulate a SIGKILL: only an earlier Save() (with just keyA) made it
	// to disk; keyB/keyC were allocated afterwards and never persisted.
	data, _ := json.MarshalIndent(ipAllocState{Allocated: map[string]string{"keyA": ipA}}, "", "  ")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}

	// Restart: load the stale file, then reconcile from the ACL (which
	// still records keyB/keyC's IPs) via MarkUsed.
	a2, err := NewIPAllocator("100.64.0.0/24", "100.64.0.1", path)
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}
	a2.MarkUsed("keyB", ipB)
	a2.MarkUsed("keyC", ipC)

	ipD, err := a2.Allocate("keyD")
	if err != nil {
		t.Fatalf("Allocate keyD: %v", err)
	}
	for name, ip := range map[string]string{"keyA": ipA, "keyB": ipB, "keyC": ipC} {
		if ipD == ip {
			t.Fatalf("new allocation %s collided with %s's IP %s", ipD, name, ip)
		}
	}
	if got := a2.Lookup("keyB"); got != ipB {
		t.Errorf("Lookup keyB = %q, want %q", got, ipB)
	}
}
