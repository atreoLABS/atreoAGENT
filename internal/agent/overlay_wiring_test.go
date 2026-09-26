package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/overlay"
	"github.com/atreoLABS/atreoAGENT/internal/wireguard"
)

func TestNewUsesTheDerivedOverlay(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.DataDir = dir
	cfg.DeviceID = "11111111-1111-1111-1111-111111111111"

	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.overlay.SubnetV4 == overlay.LegacySubnetV4 {
		t.Fatal("agent came up on the legacy subnet")
	}
	if got := a.wgServer.AllowedIPs(); got != a.overlay.SubnetV4+","+a.overlay.SubnetV6 {
		t.Errorf("AllowedIPs = %q, want the derived subnet", got)
	}
	if a.overlay.SubnetV6 == overlay.LegacySubnetV6 {
		t.Fatal("agent came up on the legacy v6 subnet")
	}
	ip, err := a.allocator.Allocate("throwaway-key")
	if err != nil {
		t.Fatalf("allocator.Allocate: %v", err)
	}
	// Not a.allocator.InSubnet, which would be tautological here.
	_, derivedNet, err := net.ParseCIDR(a.overlay.SubnetV4)
	if err != nil {
		t.Fatalf("parse derived subnet %q: %v", a.overlay.SubnetV4, err)
	}
	if parsed := net.ParseIP(ip); parsed == nil || !derivedNet.Contains(parsed) {
		t.Errorf("allocator handed out %q, not in the derived subnet %s — allocator/WG server built on different subnets", ip, a.overlay.SubnetV4)
	}

	// Restarting must not renumber.
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("second New: %v", err)
	}
	if b.overlay.SubnetV4 != a.overlay.SubnetV4 {
		t.Errorf("subnet changed across restart: %s then %s", a.overlay.SubnetV4, b.overlay.SubnetV4)
	}
	if _, err := overlay.LoadOrCreate(filepath.Join(dir, "overlay.json")); err != nil {
		t.Errorf("overlay state not persisted under the data dir: %v", err)
	}
}

func TestReconcilePeersReallocatesAddressOutsideCurrentSubnet(t *testing.T) {
	dir := t.TempDir()
	ov, err := overlay.Derive()
	if err != nil {
		t.Fatalf("overlay.Derive: %v", err)
	}

	allocator, err := wireguard.NewIPAllocator(ov.SubnetV4, ov.GatewayV4, filepath.Join(dir, "ip_alloc.json"))
	if err != nil {
		t.Fatalf("NewIPAllocator: %v", err)
	}
	wgServer, err := wireguard.NewServer(51820, ov.GatewayV4, ov.SubnetV4, ov.GatewayV6, ov.SubnetV6, dir, allocator)
	if err != nil {
		t.Fatalf("wireguard.NewServer: %v", err)
	}

	aclStore := acl.NewStore(filepath.Join(dir, "acl.json"))
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	wgPubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	members := []atreolink.MemberACLEntry{
		{
			MemberID:    "m1",
			UserID:      "u1",
			Role:        "member",
			Status:      "active",
			IdentityKey: base64.StdEncoding.EncodeToString(pub),
			Clients: []atreolink.ClientRecord{
				// From the legacy shared subnet.
				{WGPublicKey: wgPubKey, TunnelIP: "100.64.0.55", Platform: "ios"},
			},
		},
	}
	if err := aclStore.ReplaceAll(members); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}

	a := &Agent{aclStore: aclStore, allocator: allocator, wgServer: wgServer}
	a.reconcilePeers()

	got := allocator.Lookup(wgPubKey)
	if got == "" {
		t.Fatal("reconcilePeers did not allocate an address for the peer")
	}
	if got == "100.64.0.55" {
		t.Fatal("reconcilePeers kept the stale out-of-subnet address instead of reallocating")
	}
	if !allocator.InSubnet(got) {
		t.Errorf("reallocated address %q is not in the derived subnet %s", got, ov.SubnetV4)
	}
}

// The field names are wire protocol.
func TestMetadataPayloadCarriesTheOverlay(t *testing.T) {
	ov := overlay.Overlay{
		SubnetV4:  "100.70.5.0/24",
		GatewayV4: "100.70.5.1",
		SubnetV6:  "fd00:64:0:5::/64",
		GatewayV6: "fd00:64:0:5::1",
	}
	raw, err := json.Marshal(metadataPayload(443, ov))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["proxyHttpsPort"] != float64(443) {
		t.Errorf("proxyHttpsPort = %v", got["proxyHttpsPort"])
	}
	if got["overlayGatewayIpv4"] != "100.70.5.1" {
		t.Errorf("overlayGatewayIpv4 = %v", got["overlayGatewayIpv4"])
	}
	if got["overlaySubnetIpv4"] != "100.70.5.0/24" {
		t.Errorf("overlaySubnetIpv4 = %v", got["overlaySubnetIpv4"])
	}
	if got["overlayGatewayIpv6"] != "fd00:64:0:5::1" {
		t.Errorf("overlayGatewayIpv6 = %v", got["overlayGatewayIpv6"])
	}
	if got["overlaySubnetIpv6"] != "fd00:64:0:5::/64" {
		t.Errorf("overlaySubnetIpv6 = %v", got["overlaySubnetIpv6"])
	}
}
