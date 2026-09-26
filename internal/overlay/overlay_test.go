package overlay

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubnetAtMapsIndexToAddress(t *testing.T) {
	cases := []struct {
		idx                                  int64
		subnet, gateway, subnetV6, gatewayV6 string
	}{
		{1, "100.64.1.0/24", "100.64.1.1", "fd00:64:0:1::/64", "fd00:64:0:1::1"},
		{255, "100.64.255.0/24", "100.64.255.1", "fd00:64:0:ff::/64", "fd00:64:0:ff::1"},
		{256, "100.65.0.0/24", "100.65.0.1", "fd00:64:1::/64", "fd00:64:1::1"},
		{16383, "100.127.255.0/24", "100.127.255.1", "fd00:64:3f:ff::/64", "fd00:64:3f:ff::1"},
	}
	for _, c := range cases {
		got := subnetAt(c.idx)
		if got.SubnetV4 != c.subnet || got.GatewayV4 != c.gateway {
			t.Errorf("subnetAt(%d) v4 = %s/%s, want %s/%s", c.idx, got.SubnetV4, got.GatewayV4, c.subnet, c.gateway)
		}
		if got.SubnetV6 != c.subnetV6 || got.GatewayV6 != c.gatewayV6 {
			t.Errorf("subnetAt(%d) v6 = %s/%s, want %s/%s", c.idx, got.SubnetV6, got.GatewayV6, c.subnetV6, c.gatewayV6)
		}
	}
}

func TestIndexZeroMatchesLegacyInBothFamilies(t *testing.T) {
	got := subnetAt(0)
	if got.SubnetV4 != LegacySubnetV4 || got.GatewayV4 != LegacyGatewayV4 {
		t.Fatalf("subnetAt(0) v4 = %s/%s, want the legacy pair %s/%s", got.SubnetV4, got.GatewayV4, LegacySubnetV4, LegacyGatewayV4)
	}
	if got.SubnetV6 != LegacySubnetV6 || got.GatewayV6 != LegacyGatewayV6 {
		t.Fatalf("subnetAt(0) v6 = %s/%s, want the legacy pair %s/%s", got.SubnetV6, got.GatewayV6, LegacySubnetV6, LegacyGatewayV6)
	}
}

func TestDeriveStaysInBaseAndSkipsLegacy(t *testing.T) {
	_, base, err := net.ParseCIDR(Base)
	if err != nil {
		t.Fatalf("Base does not parse: %v", err)
	}
	for i := 0; i < 500; i++ {
		o, err := Derive()
		if err != nil {
			t.Fatalf("Derive: %v", err)
		}
		ip, ipnet, err := net.ParseCIDR(o.SubnetV4)
		if err != nil {
			t.Fatalf("Derive produced unparseable subnet %q: %v", o.SubnetV4, err)
		}
		if ones, _ := ipnet.Mask.Size(); ones != 24 {
			t.Fatalf("Derive produced /%d, want /24", ones)
		}
		if !base.Contains(ip) {
			t.Fatalf("Derive produced %s, outside %s", o.SubnetV4, Base)
		}
		if o.SubnetV4 == LegacySubnetV4 {
			t.Fatal("Derive produced the reserved legacy subnet")
		}
		if o.GatewayV4 != strings.TrimSuffix(ipnet.IP.String(), ".0")+".1" {
			t.Fatalf("gateway %s is not the .1 of %s", o.GatewayV4, o.SubnetV4)
		}
		if o.RolledAt.IsZero() {
			t.Fatal("RolledAt not stamped")
		}

		if o.SubnetV6 == LegacySubnetV6 {
			t.Fatal("Derive produced the reserved legacy v6 subnet")
		}
		wantSubnetV6, wantGatewayV6, err := v6FromV4(o.SubnetV4)
		if err != nil {
			t.Fatalf("v6FromV4(%q): %v", o.SubnetV4, err)
		}
		if o.SubnetV6 != wantSubnetV6 || o.GatewayV6 != wantGatewayV6 {
			t.Fatalf("Derive produced v6 %s/%s not paired with its own v4 %s (want %s/%s)",
				o.SubnetV6, o.GatewayV6, o.SubnetV4, wantSubnetV6, wantGatewayV6)
		}
	}
}

func TestLoadOrCreateIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if first.SubnetV4 != second.SubnetV4 || first.GatewayV4 != second.GatewayV4 {
		t.Errorf("subnet changed across restarts: %s then %s", first.SubnetV4, second.SubnetV4)
	}
	if first.SubnetV6 != second.SubnetV6 || first.GatewayV6 != second.GatewayV6 {
		t.Errorf("v6 addressing changed across restarts: %s/%s then %s/%s", first.SubnetV6, first.GatewayV6, second.SubnetV6, second.GatewayV6)
	}
}

// A v4-only file (pre-IPv6) is backfilled and persisted, never re-rolled.
func TestLoadOrCreateMigratesV6FromV4Only(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	legacyBody := `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.5.1","rolledAt":"2024-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacyBody), 0640); err != nil {
		t.Fatal(err)
	}

	got, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate on a v4-only file: %v", err)
	}
	if got.SubnetV4 != "100.70.5.0/24" || got.GatewayV4 != "100.70.5.1" {
		t.Fatalf("v4 addressing changed during migration: %s/%s", got.SubnetV4, got.GatewayV4)
	}
	wantSubnetV6, wantGatewayV6, err := v6FromV4(got.SubnetV4)
	if err != nil {
		t.Fatal(err)
	}
	if got.SubnetV6 != wantSubnetV6 || got.GatewayV6 != wantGatewayV6 {
		t.Errorf("migrated v6 = %s/%s, want %s/%s", got.SubnetV6, got.GatewayV6, wantSubnetV6, wantGatewayV6)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Overlay
	if err := json.Unmarshal(onDisk, &persisted); err != nil {
		t.Fatalf("migrated file does not parse: %v", err)
	}
	if persisted.SubnetV6 != wantSubnetV6 || persisted.GatewayV6 != wantGatewayV6 {
		t.Errorf("migration was not persisted: on-disk v6 = %s/%s, want %s/%s", persisted.SubnetV6, persisted.GatewayV6, wantSubnetV6, wantGatewayV6)
	}

	again, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if again.SubnetV6 != wantSubnetV6 || again.GatewayV6 != wantGatewayV6 {
		t.Errorf("second LoadOrCreate: v6 = %s/%s, want %s/%s", again.SubnetV6, again.GatewayV6, wantSubnetV6, wantGatewayV6)
	}
}

// A read-only data dir must not stop an upgraded daemon from booting.
func TestLoadOrCreateSurvivesFailedMigrationPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	legacyBody := `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.5.1","rolledAt":"2024-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacyBody), 0640); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	got, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("LoadOrCreate returned an error when only the migration persist failed: %v", err)
	}
	wantSubnetV6, wantGatewayV6, err := v6FromV4(got.SubnetV4)
	if err != nil {
		t.Fatal(err)
	}
	if got.SubnetV6 != wantSubnetV6 || got.GatewayV6 != wantGatewayV6 {
		t.Errorf("v6 = %s/%s, want %s/%s even though the persist failed", got.SubnetV6, got.GatewayV6, wantSubnetV6, wantGatewayV6)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != legacyBody {
		t.Errorf("file changed despite the write being expected to fail: %q", onDisk)
	}
}

// Load backfills v6 in memory but never writes.
func TestLoadMigratesV6InMemoryWithoutPersisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	legacyBody := `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.5.1","rolledAt":"2024-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacyBody), 0640); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load on a v4-only file: %v", err)
	}
	wantSubnetV6, wantGatewayV6, err := v6FromV4(got.SubnetV4)
	if err != nil {
		t.Fatal(err)
	}
	if got.SubnetV6 != wantSubnetV6 || got.GatewayV6 != wantGatewayV6 {
		t.Errorf("Load did not backfill v6 in memory: got %s/%s, want %s/%s", got.SubnetV6, got.GatewayV6, wantSubnetV6, wantGatewayV6)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != legacyBody {
		t.Errorf("Load mutated the file on disk: got %q, want unchanged %q", onDisk, legacyBody)
	}
}

func TestLoadRejectsCorruptState(t *testing.T) {
	cases := map[string]string{
		"outside base":  `{"subnetV4":"10.0.0.0/24","gatewayV4":"10.0.0.1"}`,
		"wrong prefix":  `{"subnetV4":"100.70.0.0/16","gatewayV4":"100.70.0.1"}`,
		"gateway drift": `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.6.1"}`,
		"host bits set": `{"subnetV4":"100.70.5.1/24","gatewayV4":"100.70.5.1"}`,
		"not json":      `{`,
		// Only "both v6 fields absent" is a migration; anything else is corrupt.
		"v6 subnet mismatched with v4":  `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.5.1","subnetV6":"fd00:64:0:99::/64","gatewayV6":"fd00:64:0:5::1"}`,
		"v6 gateway mismatched with v4": `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.5.1","subnetV6":"fd00:64:0:5::/64","gatewayV6":"fd00:64:0:99::1"}`,
		"only v6 subnet present":        `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.5.1","subnetV6":"fd00:64:0:5::/64"}`,
		"only v6 gateway present":       `{"subnetV4":"100.70.5.0/24","gatewayV4":"100.70.5.1","gatewayV6":"fd00:64:0:5::1"}`,
	}
	for name, body := range cases {
		path := filepath.Join(t.TempDir(), "overlay.json")
		if err := os.WriteFile(path, []byte(body), 0640); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrCreate(path); err == nil {
			t.Errorf("%s: LoadOrCreate accepted corrupt state", name)
		}
	}
}

func TestRerollMovesBothFamilies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.json")
	before, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Reroll(path)
	if err != nil {
		t.Fatalf("Reroll: %v", err)
	}
	if after.SubnetV4 == before.SubnetV4 {
		t.Error("Reroll returned the same subnet")
	}
	if after.SubnetV6 == before.SubnetV6 {
		t.Error("Reroll moved v4 but not v6 — collision domains are no longer paired")
	}
	wantSubnetV6, wantGatewayV6, err := v6FromV4(after.SubnetV4)
	if err != nil {
		t.Fatal(err)
	}
	if after.SubnetV6 != wantSubnetV6 || after.GatewayV6 != wantGatewayV6 {
		t.Errorf("Reroll v6 = %s/%s, not paired with its own v4 %s (want %s/%s)", after.SubnetV6, after.GatewayV6, after.SubnetV4, wantSubnetV6, wantGatewayV6)
	}
	reloaded, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.SubnetV4 != after.SubnetV4 {
		t.Errorf("Reroll did not persist: %s on disk, %s returned", reloaded.SubnetV4, after.SubnetV4)
	}
	if reloaded.SubnetV6 != after.SubnetV6 || reloaded.GatewayV6 != after.GatewayV6 {
		t.Errorf("Reroll did not persist v6: %s/%s on disk, %s/%s returned", reloaded.SubnetV6, reloaded.GatewayV6, after.SubnetV6, after.GatewayV6)
	}
}

func TestExpandLegacyMirrorsOntoDerived(t *testing.T) {
	got := ExpandLegacy([]string{"127.0.0.0/8", LegacySubnetV4}, "100.70.5.0/24")
	if len(got) != 3 || got[2] != "100.70.5.0/24" {
		t.Errorf("ExpandLegacy = %v, want the derived subnet appended", got)
	}
	untouched := ExpandLegacy([]string{"192.168.1.0/24"}, "100.70.5.0/24")
	if len(untouched) != 1 {
		t.Errorf("ExpandLegacy widened an allowlist that never trusted the overlay: %v", untouched)
	}
	twice := ExpandLegacy(got, "100.70.5.0/24")
	if len(twice) != 3 {
		t.Errorf("ExpandLegacy is not idempotent: %v", twice)
	}
}

// Widening a trusted /32 into the /24 would hand every peer the trusted-network
// ACL bypass.
func TestExpandLegacyMirrorsGatewayHostLikeForLike(t *testing.T) {
	got := ExpandLegacy([]string{"127.0.0.0/8", LegacyGatewayV4 + "/32"}, "100.70.5.0/24")
	if len(got) != 3 || got[2] != "100.70.5.1/32" {
		t.Fatalf("ExpandLegacy = %v, want the derived gateway /32 appended", got)
	}
	for _, c := range got {
		if c == "100.70.5.0/24" {
			t.Fatalf("ExpandLegacy widened a /32 gateway entry into the derived /24: %v", got)
		}
	}
	twice := ExpandLegacy(got, "100.70.5.0/24")
	if len(twice) != 3 {
		t.Errorf("ExpandLegacy is not idempotent for the gateway case: %v", twice)
	}
}

func TestExpandLegacyMirrorsBothFormsWhenBothPresent(t *testing.T) {
	got := ExpandLegacy([]string{LegacySubnetV4, LegacyGatewayV4 + "/32"}, "100.70.5.0/24")
	want := map[string]bool{
		LegacySubnetV4:          true,
		LegacyGatewayV4 + "/32": true,
		"100.70.5.0/24":         true,
		"100.70.5.1/32":         true,
	}
	if len(got) != len(want) {
		t.Fatalf("ExpandLegacy = %v, want 4 entries", got)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected entry %q in %v", c, got)
		}
	}
}
