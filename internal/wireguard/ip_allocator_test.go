package wireguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestTryAdoptRejectsCollisionWithOtherPeer(t *testing.T) {
	a := newTestAllocator(t)
	ip, err := a.Allocate("peerB")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	// peerA must not be able to take peerB's IP.
	if a.TryAdopt("peerA", ip) {
		t.Fatalf("TryAdopt let peerA steal peerB's IP %q", ip)
	}
	if got := a.Lookup("peerA"); got != "" {
		t.Errorf("peerA allocation = %q, want empty", got)
	}
	if got := a.Lookup("peerB"); got != ip {
		t.Errorf("peerB allocation = %q, want %q (unchanged)", got, ip)
	}
}

func TestTryAdoptRejectsReservedOutOfSubnetAndMalformed(t *testing.T) {
	for _, ip := range []string{
		"100.64.0.1",   // server IP (reserved)
		"100.64.0.0",   // network (reserved)
		"100.64.0.255", // broadcast (reserved)
		"10.0.0.5",     // outside the /24
		"0.0.0.0/0",    // CIDR, not a host literal
		"100.64.0.05",  // non-canonical (leading zero)
		"not-an-ip",
		"",
	} {
		if a := newTestAllocator(t); a.TryAdopt("peer", ip) {
			t.Errorf("TryAdopt accepted unsafe IP %q", ip)
		}
	}
}

func TestTryAdoptAcceptsFreeInSubnetAddressAndIsIdempotent(t *testing.T) {
	a := newTestAllocator(t)
	if !a.TryAdopt("peer", "100.64.0.50") {
		t.Fatal("TryAdopt rejected a free, in-subnet address")
	}
	if got := a.Lookup("peer"); got != "100.64.0.50" {
		t.Errorf("Lookup = %q, want 100.64.0.50", got)
	}
	// Re-adopting the same IP for the same peer is a no-op success; a
	// different free IP must not silently move an existing allocation.
	if !a.TryAdopt("peer", "100.64.0.50") {
		t.Error("TryAdopt not idempotent for the same (peer, ip)")
	}
	if a.TryAdopt("peer", "100.64.0.51") {
		t.Error("TryAdopt silently moved an existing allocation")
	}
	// The adopted IP is now reserved against a fresh allocation.
	other, err := a.Allocate("other")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if other == "100.64.0.50" {
		t.Error("Allocate handed out an already-adopted IP")
	}
}

func TestLoadDiscardsAllocationsFromAnotherSubnet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip_alloc.json")
	if err := os.WriteFile(path, []byte(`{"allocated":{"oldpeer":"100.64.0.5","newpeer":"100.70.5.9"}}`), 0640); err != nil {
		t.Fatal(err)
	}
	a, err := NewIPAllocator("100.70.5.0/24", "100.70.5.1", path)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Lookup("oldpeer"); got != "" {
		t.Errorf("kept %q from a previous subnet; the peer would get a route it cannot use", got)
	}
	if got := a.Lookup("newpeer"); got != "100.70.5.9" {
		t.Errorf("dropped a valid allocation: %q", got)
	}
	ip, err := a.Allocate("oldpeer")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ip, "100.70.5.") {
		t.Errorf("reallocated outside the current subnet: %q", ip)
	}
}

func TestMarkUsedIgnoresOutOfPrefixIP(t *testing.T) {
	a := newTestAllocator(t)
	a.MarkUsed("peer1", "100.65.0.5")
	if got := a.Lookup("peer1"); got != "" {
		t.Errorf("MarkUsed kept out-of-prefix IP: %q", got)
	}
	ip, err := a.Allocate("peer1")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if !strings.HasPrefix(ip, "100.64.0.") {
		t.Errorf("allocated outside subnet: %q", ip)
	}
}

func TestMarkUsedIgnoresReservedAddress(t *testing.T) {
	a := newTestAllocator(t)
	a.MarkUsed("peer1", "100.64.0.1")
	if got := a.Lookup("peer1"); got != "" {
		t.Errorf("MarkUsed bound server gateway to peer: %q", got)
	}
	ip, err := a.Allocate("peer1")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if ip == "100.64.0.1" {
		t.Error("allocated the server gateway")
	}
}

func TestMarkUsedRejectsNonCanonicalAddress(t *testing.T) {
	a := newTestAllocator(t)
	// Accepting it would strand the peer: InSubnet rejects it, but Allocate
	// would keep returning it for the known pubkey.
	a.MarkUsed("peer1", "100.64.0.05")
	if got := a.Lookup("peer1"); got != "" {
		t.Errorf("MarkUsed accepted non-canonical IP: %q", got)
	}
	ip, err := a.Allocate("peer1")
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if !strings.HasPrefix(ip, "100.64.0.") {
		t.Errorf("allocated outside subnet: %q", ip)
	}
}

func TestLoadSkipsReservedInPrefixAddress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ip_alloc.json")
	if err := os.WriteFile(path, []byte(`{"allocated":{"peer1":"100.70.5.1","peer2":"100.70.5.10"}}`), 0640); err != nil {
		t.Fatal(err)
	}
	a, err := NewIPAllocator("100.70.5.0/24", "100.70.5.1", path)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Lookup("peer1"); got != "" {
		t.Errorf("kept server gateway allocation: %q", got)
	}
	if got := a.Lookup("peer2"); got != "100.70.5.10" {
		t.Errorf("dropped valid allocation: %q", got)
	}
}

func TestInSubnet(t *testing.T) {
	a := newTestAllocator(t)
	tests := []struct {
		ip   string
		want bool
		desc string
	}{
		{"100.64.0.50", true, "canonical in-subnet"},
		{"100.64.0.1", false, "server gateway (reserved)"},
		{"100.64.0.0", false, "network address (reserved)"},
		{"100.64.0.255", false, "broadcast (reserved)"},
		{"100.65.0.5", false, "out-of-prefix"},
		{"100.64.0.05", false, "non-canonical leading zero"},
		{"::1", false, "IPv6"},
		{"not-an-ip", false, "garbage"},
		{"", false, "empty"},
	}
	for _, tt := range tests {
		got := a.InSubnet(tt.ip)
		if got != tt.want {
			t.Errorf("InSubnet(%q) = %v, want %v (%s)", tt.ip, got, tt.want, tt.desc)
		}
	}
}

// Run with -race.
func TestSaveConcurrentWithAllocate(t *testing.T) {
	a := newTestAllocator(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = a.Allocate(fmt.Sprintf("key%d", i))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = a.Save()
		}
	}()
	wg.Wait()
}
