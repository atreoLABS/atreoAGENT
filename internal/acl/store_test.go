package acl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

// mustReplace fails the test if ReplaceAll returns an error. Use it
// when the test inputs respect the admin pin.
func mustReplace(t *testing.T, s *Store, members []atreolink.MemberACLEntry) {
	t.Helper()
	if err := s.ReplaceAll(members); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
}

func testMembers() []atreolink.MemberACLEntry {
	return []atreolink.MemberACLEntry{
		{
			MemberID: "m1",
			Role:     "admin",
			Clients: []atreolink.ClientRecord{
				{WGPublicKey: "key-a", TunnelIP: "100.64.0.2"},
			},
			AllowedApps: []atreolink.App{
				{ID: "app1", Name: "Nextcloud", Slug: "nextcloud", InternalURL: "http://localhost:8080"},
				{ID: "app2", Name: "Plex", Slug: "plex", InternalURL: "http://localhost:32400"},
			},
		},
		{
			MemberID: "m2",
			Role:     "member",
			Clients: []atreolink.ClientRecord{
				{WGPublicKey: "key-b", TunnelIP: "100.64.0.3"},
			},
			AllowedApps: []atreolink.App{
				{ID: "app1", Name: "Nextcloud", Slug: "nextcloud", InternalURL: "http://localhost:8080"},
			},
		},
	}
}

func TestIsAppAllowed_AdminBypass(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	// Admin can access any app
	allowed, app := store.IsAppAllowed("100.64.0.2", "plex")
	if !allowed {
		t.Error("admin should be allowed to access plex")
	}
	if app == nil || app.Slug != "plex" {
		t.Error("expected plex app")
	}

	// Admin can access nextcloud too
	allowed, app = store.IsAppAllowed("100.64.0.2", "nextcloud")
	if !allowed {
		t.Error("admin should be allowed to access nextcloud")
	}
	if app == nil || app.Slug != "nextcloud" {
		t.Error("expected nextcloud app")
	}
}

func TestIsAppAllowed_MemberAllowed(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	allowed, app := store.IsAppAllowed("100.64.0.3", "nextcloud")
	if !allowed {
		t.Error("member should be allowed to access nextcloud")
	}
	if app == nil || app.Slug != "nextcloud" {
		t.Error("expected nextcloud app")
	}
}

func TestIsAppAllowed_MemberDenied(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	allowed, _ := store.IsAppAllowed("100.64.0.3", "plex")
	if allowed {
		t.Error("member should not be allowed to access plex")
	}
}

func TestIsAppAllowed_UnknownIP(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	allowed, _ := store.IsAppAllowed("100.64.0.99", "nextcloud")
	if allowed {
		t.Error("unknown IP should not be allowed")
	}
}

func TestIsAppAllowed_UnknownSlug(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	allowed, _ := store.IsAppAllowed("100.64.0.2", "nonexistent")
	if allowed {
		t.Error("nonexistent slug should not be allowed")
	}
}

func portTestMembers() []atreolink.MemberACLEntry {
	return []atreolink.MemberACLEntry{
		{
			MemberID: "m1",
			Role:     "admin",
			Status:   "active",
			Clients:  []atreolink.ClientRecord{{WGPublicKey: "key-a", TunnelIP: "100.64.0.2"}},
			AllowedApps: []atreolink.App{
				{ID: "a1", Name: "Nextcloud", Slug: "nextcloud", InternalURL: "http://localhost:8080"},
				{ID: "a2", Name: "SSH", Slug: "ssh", Type: "port", Port: 22, Protocol: "tcp"},
				{ID: "a3", Name: "Minecraft", Slug: "minecraft", Type: "port", Port: 25565, Protocol: "tcp"},
				{ID: "a4", Name: "DNS", Slug: "dns", Type: "port", Port: 53, Protocol: "udp"},
				{ID: "a5", Name: "Jellyfin", Slug: "jellyfin", Type: "port", Port: 8096, Protocol: "http"},
			},
		},
		{
			MemberID: "m2",
			Role:     "member",
			Status:   "active",
			Clients:  []atreolink.ClientRecord{{WGPublicKey: "key-b", TunnelIP: "100.64.0.3"}},
			AllowedApps: []atreolink.App{
				{ID: "a3", Name: "Minecraft", Slug: "minecraft", Type: "port", Port: 25565, Protocol: "tcp"},
			},
		},
		{
			MemberID: "m3",
			Role:     "member",
			Status:   "suspended",
			Clients:  []atreolink.ClientRecord{{WGPublicKey: "key-c", TunnelIP: "100.64.0.4"}},
			AllowedApps: []atreolink.App{
				{ID: "a3", Name: "Minecraft", Slug: "minecraft", Type: "port", Port: 25565, Protocol: "tcp"},
			},
		},
		{
			MemberID: "m4",
			Role:     "member",
			Status:   "active",
			Clients:  []atreolink.ClientRecord{{WGPublicKey: "key-d", TunnelIP: "100.64.0.5"}},
			AllowedApps: []atreolink.App{
				{ID: "a1", Name: "Nextcloud", Slug: "nextcloud", InternalURL: "http://localhost:8080"},
			},
		},
	}
}

func TestPortGrants(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, portTestMembers())

	grants := store.PortGrants()
	byIP := map[string]PortGrant{}
	for _, g := range grants {
		byIP[g.TunnelIP] = g
	}

	// Admin: all port apps split by protocol; proxy app ignored.
	g1, ok := byIP["100.64.0.2"]
	if !ok {
		t.Fatal("expected grant for admin tunnel IP")
	}
	if !intsSetEqual(g1.TCP, []int{22, 25565, 8096}) || !intsSetEqual(g1.UDP, []int{53}) {
		t.Errorf("admin grant = tcp:%v udp:%v, want tcp:[22 25565 8096] udp:[53]", g1.TCP, g1.UDP)
	}

	// Member with a single port grant.
	g2, ok := byIP["100.64.0.3"]
	if !ok || !intsSetEqual(g2.TCP, []int{25565}) || len(g2.UDP) != 0 {
		t.Errorf("member grant = %+v, want tcp:[25565]", g2)
	}

	// Suspended member: no grant.
	if _, ok := byIP["100.64.0.4"]; ok {
		t.Error("suspended member must not receive a port grant")
	}

	// Proxy-only member: no grant.
	if _, ok := byIP["100.64.0.5"]; ok {
		t.Error("proxy-only member must not receive a port grant")
	}
}

func TestPortAppNotReachableOverProxy(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, portTestMembers())

	// Admin bypass must NOT resolve a port app by slug.
	if allowed, _ := store.IsAppAllowed("100.64.0.2", "minecraft"); allowed {
		t.Error("admin must not reach a port app over the proxy")
	}
	// Member granted the port app must not reach it over the proxy either.
	if allowed, _ := store.IsAppAllowed("100.64.0.3", "minecraft"); allowed {
		t.Error("member must not reach a port app over the proxy")
	}
	// FindAppBySlug never returns a port app.
	if app := store.FindAppBySlug("minecraft"); app != nil {
		t.Error("FindAppBySlug must skip port apps")
	}
}

func intsSetEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[int]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
	}
	for _, c := range seen {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.json")

	store1 := NewStore(path)
	mustReplace(t, store1, testMembers())
	if err := store1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	store2 := NewStore(path)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	members := store2.AllMembers()
	if len(members) != 2 {
		t.Fatalf("len = %d, want 2", len(members))
	}

	// Verify indexes work after load
	m := store2.LookupByTunnelIP("100.64.0.2")
	if m == nil || m.MemberID != "m1" {
		t.Error("LookupByTunnelIP failed after load")
	}

	m = store2.LookupByMemberID("m2")
	if m == nil || m.MemberID != "m2" {
		t.Error("LookupByMemberID failed after load")
	}
}

func TestReplaceAll(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	if len(store.AllMembers()) != 2 {
		t.Fatal("expected 2 members")
	}

	if err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{MemberID: "m3", Clients: []atreolink.ClientRecord{{TunnelIP: "100.64.0.10"}}},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}

	if len(store.AllMembers()) != 1 {
		t.Fatal("expected 1 member after replace")
	}

	// Old indexes should be gone
	if m := store.LookupByTunnelIP("100.64.0.2"); m != nil {
		t.Error("old tunnel IP should not be found")
	}
}

func TestAllApps(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	// AllApps now reflects the device-level app catalogue (populated via
	// app:upserted → SetAppDefinitions), NOT the union of members'
	// AllowedApps. Seed the catalogue explicitly for the assertion.
	store.SetAppDefinitions([]atreolink.App{
		{ID: "app1", Name: "Nextcloud", Slug: "nextcloud", InternalURL: "http://localhost:8080"},
		{ID: "app2", Name: "Plex", Slug: "plex", InternalURL: "http://localhost:32400"},
	})

	apps := store.AllApps()
	if len(apps) != 2 {
		t.Errorf("AllApps len = %d, want 2", len(apps))
	}
}

func TestRemoveMember(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, testMembers())

	store.RemoveMember("m1")
	if len(store.AllMembers()) != 1 {
		t.Error("expected 1 member after remove")
	}
	if m := store.LookupByMemberID("m1"); m != nil {
		t.Error("removed member should not be found")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	store := NewStore("/nonexistent/acl.json")
	if err := store.Load(); err != nil {
		t.Fatalf("Load should not error for nonexistent file: %v", err)
	}
	if len(store.AllMembers()) != 0 {
		t.Error("expected 0 members for nonexistent file")
	}
}

// genTestPubkey returns an Ed25519 pubkey (deterministically random per test)
// for use in pin tests. Both bytes and base64 form are returned because the
// store stores bytes but the wire format is base64.
func genTestPubkey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, base64.StdEncoding.EncodeToString(pub)
}

func TestSetPinnedAdminPublicKey_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.json")

	pub, _ := genTestPubkey(t)
	store := NewStore(path)
	if err := store.SetPinnedAdminPublicKey(pub); err != nil {
		t.Fatalf("SetPinnedAdminPublicKey: %v", err)
	}

	// Same store reports the pin in memory.
	got := store.PinnedAdminPublicKey()
	if got == nil || string(got) != string(pub) {
		t.Errorf("PinnedAdminPublicKey mismatch")
	}

	// Fresh store reading from disk also sees the pin.
	store2 := NewStore(path)
	if err := store2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got2 := store2.PinnedAdminPublicKey()
	if got2 == nil || string(got2) != string(pub) {
		t.Errorf("PinnedAdminPublicKey not persisted across Load")
	}
}

func TestSetPinnedAdminPublicKey_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "acl.json"))

	pub1, _ := genTestPubkey(t)
	if err := store.SetPinnedAdminPublicKey(pub1); err != nil {
		t.Fatalf("first set: %v", err)
	}

	pub2, _ := genTestPubkey(t)
	err := store.SetPinnedAdminPublicKey(pub2)
	if err == nil {
		t.Fatal("expected ErrAdminPinAlreadySet on second set")
	}

	// After clear, set succeeds again.
	if err := store.ClearPinnedAdminPublicKey(); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if err := store.SetPinnedAdminPublicKey(pub2); err != nil {
		t.Fatalf("set after clear: %v", err)
	}
}

func TestReplaceAll_EnforcesAdminPin(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "acl.json"))

	pinPub, pinB64 := genTestPubkey(t)
	if err := store.SetPinnedAdminPublicKey(pinPub); err != nil {
		t.Fatalf("pin: %v", err)
	}

	// Honest sync — admin entry's identityKey matches the pin. Should succeed.
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "owner", Role: "admin", IdentityKey: pinB64},
	})

	// A ReplaceAll where the admin entry's identityKey differs from the
	// pin must be rejected — that's what the pin is for.
	_, otherB64 := genTestPubkey(t)
	err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{MemberID: "owner", Role: "admin", IdentityKey: otherB64},
	})
	if err == nil {
		t.Fatal("expected ErrAdminPinViolation when admin identityKey differs from pin")
	}
	// Existing members stay — the rejection is atomic.
	if got := store.LookupByMemberID("owner"); got == nil || got.IdentityKey != pinB64 {
		t.Error("rejected ReplaceAll should not have mutated state")
	}
}

// TestAdminEntry returns the admin/owner row when present and nil
// otherwise. Cert renewal alerting depends on this to address the
// sealed-box notification.
func TestAdminEntry(t *testing.T) {
	store := NewStore("")
	if got := store.AdminEntry(); got != nil {
		t.Errorf("empty store should have no admin, got %+v", got)
	}

	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "member", IdentityKey: "kmember"},
		{MemberID: "owner", Role: "admin", IdentityKey: "kowner"},
	})
	got := store.AdminEntry()
	if got == nil || got.MemberID != "owner" {
		t.Errorf("expected admin row, got %+v", got)
	}
	// Returned value is a copy — mutating it must not mutate the store.
	got.MemberID = "tampered"
	if again := store.AdminEntry(); again.MemberID != "owner" {
		t.Error("AdminEntry leaked aliased pointer; store mutated")
	}
}

// TestReplaceAll_RejectsAdminWithEmptyIdentityKey closes the
// pin-bypass-via-empty-key gap. An admin row with rewritten
// Email/UserID/MemberName and IdentityKey="" must be rejected at
// ACL-store time — the metadata (email for SMTP routing, userId for
// notify addressing) is consumed by downstream code before any signed
// command arrives, so the signature check on a later command isn't
// enough to protect it.
func TestReplaceAll_RejectsAdminWithEmptyIdentityKey(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "acl.json"))

	pinPub, pinB64 := genTestPubkey(t)
	if err := store.SetPinnedAdminPublicKey(pinPub); err != nil {
		t.Fatalf("pin: %v", err)
	}
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "owner", Role: "admin", IdentityKey: pinB64},
	})

	err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{MemberID: "owner", Role: "admin", IdentityKey: "", Email: "mallory@example.com"},
	})
	if err == nil {
		t.Fatal("expected ErrAdminPinViolation for empty admin identityKey")
	}
	if !errors.Is(err, ErrAdminPinViolation) {
		t.Errorf("err=%v, want ErrAdminPinViolation", err)
	}
	if got := store.LookupByMemberID("owner"); got == nil || got.Email == "mallory@example.com" {
		t.Error("rejected sync must not have leaked the row's metadata")
	}
}

func TestUpsertMember_PreservesTunnelIPOnReplay(t *testing.T) {
	// On reconnect atreoLINK replays member:added with Clients populated
	// (WGPublicKey set, TunnelIP empty since atreoLINK doesn't track IPs).
	// Per-client merge must keep the agent's just-allocated IP or the
	// proxy's byTunnelIP lookup goes blank and apps return Forbidden.
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "acl.json"))
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "member", IdentityKey: "k", Clients: []atreolink.ClientRecord{
			{WGPublicKey: "wg1", TunnelIP: "10.0.0.5", Label: "iPhone", Platform: "ios"},
		}},
	})

	if err := store.UpsertMember(atreolink.MemberACLEntry{
		MemberID: "m1", Role: "member", IdentityKey: "k", Clients: []atreolink.ClientRecord{
			{WGPublicKey: "wg1"}, // atreolink-style: key only, no IP/label/platform
		},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got := store.LookupByTunnelIP("10.0.0.5")
	if got == nil || got.MemberID != "m1" {
		t.Fatalf("expected byTunnelIP[10.0.0.5] -> m1, got %+v", got)
	}
	if c := got.Clients[0]; c.Label != "iPhone" || c.Platform != "ios" {
		t.Errorf("label/platform should also be preserved, got %+v", c)
	}
}

func TestUpsertMember_EnforcesAdminPin(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "acl.json"))
	pinPub, pinB64 := genTestPubkey(t)
	if err := store.SetPinnedAdminPublicKey(pinPub); err != nil {
		t.Fatalf("pin: %v", err)
	}
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "owner", Role: "admin", IdentityKey: pinB64},
	})

	_, otherB64 := genTestPubkey(t)
	err := store.UpsertMember(atreolink.MemberACLEntry{
		MemberID: "owner", Role: "admin", IdentityKey: otherB64,
	})
	if err == nil {
		t.Error("expected pin violation on UpsertMember of a divergent admin entry")
	}
}

// --- LookupByEmail ----------------------------------------------------------

func TestLookupByEmail_FullMatchCaseInsensitive(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "admin", Email: "Alice@Example.COM"},
		{MemberID: "m2", Role: "admin", Email: "bob@example.com"},
	})

	// Mixed-case input matches the lowercased index entry.
	got := store.LookupByEmail("alice@example.com")
	if got == nil || got.MemberID != "m1" {
		t.Errorf("expected m1 for alice@example.com, got %+v", got)
	}
	got = store.LookupByEmail("ALICE@EXAMPLE.COM")
	if got == nil || got.MemberID != "m1" {
		t.Errorf("expected m1 for ALICE@EXAMPLE.COM, got %+v", got)
	}
	// Whitespace trimming.
	got = store.LookupByEmail("  bob@example.com  ")
	if got == nil || got.MemberID != "m2" {
		t.Errorf("expected m2 for whitespace-padded bob@example.com, got %+v", got)
	}
	// Unknown email returns nil rather than a zero-value entry.
	if got := store.LookupByEmail("nobody@example.com"); got != nil {
		t.Errorf("expected nil for unknown email, got %+v", got)
	}
}

func TestLookupByEmail_EmptyEmailMembersIgnored(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "m-no-email", Role: "admin"},
		{MemberID: "m-with-email", Role: "admin", Email: "ok@example.com"},
	})
	if got := store.LookupByEmail(""); got != nil {
		t.Errorf("empty input should not match the email-less member, got %+v", got)
	}
	if got := store.LookupByEmail("ok@example.com"); got == nil {
		t.Error("expected to find m-with-email")
	}
}

func TestDropMembersFailing(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{MemberID: "owner", Role: "owner", Clients: []atreolink.ClientRecord{}},
		{MemberID: "good", Role: "member", Clients: []atreolink.ClientRecord{{WGPublicKey: "k1", TunnelIP: "100.64.0.5"}}},
		{MemberID: "bad", Role: "member", Clients: []atreolink.ClientRecord{{WGPublicKey: "k2", TunnelIP: "100.64.0.6"}}},
	})

	dropped := store.DropMembersFailing(func(m atreolink.MemberACLEntry) error {
		if m.MemberID == "bad" {
			return errors.New("forged attestation")
		}
		return nil
	})
	if len(dropped) != 1 || dropped[0].MemberID != "bad" {
		t.Fatalf("dropped = %+v, want [bad]", dropped)
	}
	if store.LookupByMemberID("bad") != nil {
		t.Error("bad member should be gone")
	}
	if store.LookupByMemberID("good") == nil || store.LookupByMemberID("owner") == nil {
		t.Error("good/owner members should remain")
	}
	// Index for the dropped member's IP must be cleared too.
	if m := store.LookupByTunnelIP("100.64.0.6"); m != nil {
		t.Error("tunnel-IP index still resolves a dropped member")
	}

	// No failures → no-op, returns nil.
	if got := store.DropMembersFailing(func(atreolink.MemberACLEntry) error { return nil }); got != nil {
		t.Errorf("expected nil when nothing dropped, got %+v", got)
	}
}

func TestIsAppAllowed_SuspendedMemberDenied(t *testing.T) {
	store := NewStore("")
	mustReplace(t, store, []atreolink.MemberACLEntry{
		{
			MemberID: "admin", Role: "admin", Status: "suspended",
			Clients:     []atreolink.ClientRecord{{WGPublicKey: "ka", TunnelIP: "100.64.0.2"}},
			AllowedApps: []atreolink.App{{ID: "app1", Slug: "nextcloud", InternalURL: "http://x"}},
		},
		{
			MemberID: "member", Role: "member", Status: "suspended",
			Clients:     []atreolink.ClientRecord{{WGPublicKey: "kb", TunnelIP: "100.64.0.3"}},
			AllowedApps: []atreolink.App{{ID: "app1", Slug: "nextcloud", InternalURL: "http://x"}},
		},
	})

	if allowed, _ := store.IsAppAllowed("100.64.0.2", "nextcloud"); allowed {
		t.Error("suspended admin must be denied")
	}
	if allowed, _ := store.IsAppAllowed("100.64.0.3", "nextcloud"); allowed {
		t.Error("suspended member must be denied")
	}
}

// --- Reconcile + generation ----------------------------------------------

func TestReconcile_PrunesAbsentMembersAndApps(t *testing.T) {
	s := NewStore("")
	mustReplace(t, s, testMembers())
	s.SetAppDefinitions([]atreolink.App{
		{ID: "app1", Name: "Nextcloud", Slug: "nextcloud", InternalURL: "http://localhost:8080"},
		{ID: "app2", Name: "Plex", Slug: "plex", InternalURL: "http://localhost:32400"},
	})

	// New state: only m1 survives; app2 dropped.
	next := []atreolink.MemberACLEntry{{
		MemberID: "m1", Role: "admin",
		Clients:     []atreolink.ClientRecord{{WGPublicKey: "key-a", TunnelIP: "100.64.0.2"}},
		AllowedApps: []atreolink.App{},
	}}
	nextApps := []atreolink.App{{ID: "app1", Name: "Nextcloud", Slug: "nextcloud", InternalURL: "http://localhost:8080"}}

	removedMembers, removedClientKeys, removedAppIDs, err := s.Reconcile(next, nextApps)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(removedMembers) != 1 || removedMembers[0].MemberID != "m2" {
		t.Fatalf("removedMembers = %+v, want [m2]", removedMembers)
	}
	if len(removedClientKeys) != 1 || removedClientKeys[0] != "key-b" {
		t.Fatalf("removedClientKeys = %v, want [key-b]", removedClientKeys)
	}
	if len(removedAppIDs) != 1 || removedAppIDs[0] != "app2" {
		t.Fatalf("removedAppIDs = %v, want [app2]", removedAppIDs)
	}
	if s.LookupByMemberID("m2") != nil {
		t.Error("m2 should have been pruned")
	}
	if s.LookupByMemberID("m1") == nil {
		t.Error("m1 should remain")
	}
}

// A client removed from a member who is still present must still be
// reported so the caller drops its WireGuard peer (the revocation hole).
func TestReconcile_PrunesDroppedClientOfSurvivingMember(t *testing.T) {
	s := NewStore("")
	mustReplace(t, s, []atreolink.MemberACLEntry{{
		MemberID: "m1", Role: "member",
		Clients: []atreolink.ClientRecord{
			{WGPublicKey: "phone", TunnelIP: "100.64.0.2"},
			{WGPublicKey: "laptop", TunnelIP: "100.64.0.3"},
		},
	}})

	// m1 survives but the phone is gone.
	next := []atreolink.MemberACLEntry{{
		MemberID: "m1", Role: "member",
		Clients: []atreolink.ClientRecord{{WGPublicKey: "laptop", TunnelIP: "100.64.0.3"}},
	}}

	removedMembers, removedClientKeys, _, err := s.Reconcile(next, nil)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(removedMembers) != 0 {
		t.Fatalf("removedMembers = %+v, want none (m1 survives)", removedMembers)
	}
	if len(removedClientKeys) != 1 || removedClientKeys[0] != "phone" {
		t.Fatalf("removedClientKeys = %v, want [phone]", removedClientKeys)
	}
}

func TestReconcile_EnforcesAdminPin(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "acl.json"))
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := s.SetPinnedAdminPublicKey(pub); err != nil {
		t.Fatalf("pin: %v", err)
	}
	// Admin entry whose IdentityKey != pin must be rejected, ACL untouched.
	bad := []atreolink.MemberACLEntry{{MemberID: "m1", Role: "admin", IdentityKey: "AAAA"}}
	if _, _, _, err := s.Reconcile(bad, nil); !errors.Is(err, ErrAdminPinViolation) {
		t.Fatalf("Reconcile err = %v, want ErrAdminPinViolation", err)
	}
	if len(s.AllMembers()) != 0 {
		t.Error("ACL must be untouched on pin violation")
	}
}

func TestGeneration_PersistRoundTripAndDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.json")

	s1 := NewStore(path)
	if s1.AppliedGeneration() != 0 || !s1.LastAppliedAt().IsZero() {
		t.Fatal("fresh store must report generation 0 / zero lastAppliedAt")
	}
	mustReplace(t, s1, testMembers())
	at := time.Now().UTC()
	s1.SetAppliedGeneration(42, at)
	if err := s1.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s2 := NewStore(path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if s2.AppliedGeneration() != 42 {
		t.Fatalf("generation = %d, want 42", s2.AppliedGeneration())
	}
	if s2.LastAppliedAt().IsZero() {
		t.Fatal("lastAppliedAt must round-trip")
	}
}
