package endpoints

import (
	"net"
	"reflect"
	"testing"
)

// fakeSource is a test-only InterfaceSource that returns whatever the test
// asks for, without touching real OS state.
type fakeSource struct{ ifs []Interface }

func (f fakeSource) Interfaces() ([]Interface, error) { return f.ifs, nil }

func ipnet(cidr string) net.IPNet {
	// Preserve the input IP — ParseCIDR returns the network address
	// (with host bits masked off), but we want the exact addr as it
	// appears on the interface.
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return *n
}

func TestEnumerateSkipsVirtualInterfaces(t *testing.T) {
	// Docker bridges, our own wg tunnel, and Tailscale/ZeroTier overlays
	// must never appear as candidates — routing into them from a client
	// on a real LAN would be a dead end.
	src := fakeSource{ifs: []Interface{
		{
			Name:  "eth0",
			Index: 1,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("192.168.1.10/24")},
		},
		{
			Name:  "docker0",
			Index: 2,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("172.17.0.1/16")},
		},
		{
			Name:  "wg-atreo",
			Index: 3,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("100.64.0.1/24")},
		},
		{
			Name:  "tailscale0",
			Index: 4,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("100.101.102.103/32")},
		},
		{
			Name:  "br-abc123",
			Index: 5,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("172.20.0.1/16")},
		},
	}}

	res, err := Enumerate(src, 0, "")
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(res.LAN) != 1 || res.LAN[0].String() != "192.168.1.10" {
		t.Errorf("LAN = %v, want [192.168.1.10]", res.LAN)
	}
}

func TestEnumerateSkipsLoopbackAndLinkLocal(t *testing.T) {
	src := fakeSource{ifs: []Interface{
		{
			Name:  "lo",
			Index: 1,
			Flags: net.FlagUp | net.FlagLoopback,
			Addrs: []net.IPNet{ipnet("127.0.0.1/8")},
		},
		{
			Name:  "eth0",
			Index: 2,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{
				ipnet("192.168.1.10/24"),
				ipnet("169.254.99.99/16"), // link-local — must be skipped
			},
		},
	}}
	res, _ := Enumerate(src, 0, "")
	if len(res.LAN) != 1 || res.LAN[0].String() != "192.168.1.10" {
		t.Errorf("LAN = %v, want [192.168.1.10]", res.LAN)
	}
}

func TestEnumerateSkipsCGNAT(t *testing.T) {
	// 100.64.0.0/10 is the CGNAT range — our own WG tunnel lives there.
	// Advertising it as LAN would route clients into their own tunnel.
	src := fakeSource{ifs: []Interface{
		{
			Name:  "eth0",
			Index: 1,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("100.64.0.5/24")},
		},
	}}
	res, _ := Enumerate(src, 0, "")
	if len(res.LAN) != 0 {
		t.Errorf("LAN = %v, want empty (CGNAT must be skipped)", res.LAN)
	}
}

func TestEnumeratePrefersDefaultRoute(t *testing.T) {
	// When multiple LAN interfaces exist, the one carrying the default
	// route should come first — clients treat the first entry as the hint.
	src := fakeSource{ifs: []Interface{
		{
			Name:  "eth1",
			Index: 1,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("10.0.0.5/8")},
		},
		{
			Name:  "eth0",
			Index: 2,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("192.168.1.10/24")},
		},
	}}
	res, _ := Enumerate(src, 2, "eth0")
	if len(res.LAN) != 2 {
		t.Fatalf("LAN = %v, want 2 addrs", res.LAN)
	}
	if res.LAN[0].String() != "192.168.1.10" {
		t.Errorf("first LAN = %s, want 192.168.1.10 (the default-route iface)", res.LAN[0])
	}
}

func TestEnumerateIPv6OnlyOnDefaultRoute(t *testing.T) {
	// Global-scope v6 on the default-route interface is included as
	// public6; v6 on secondary interfaces is dropped.
	src := fakeSource{ifs: []Interface{
		{
			Name:  "eth0",
			Index: 1,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{
				ipnet("192.168.1.10/24"),
				ipnet("2001:db8::1/64"),
			},
		},
		{
			Name:  "eth1",
			Index: 2,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{
				ipnet("10.0.0.5/8"),
				ipnet("2001:db8:ffff::1/64"),
			},
		},
	}}
	res, _ := Enumerate(src, 1, "eth0")
	if len(res.PublicV6) != 1 || res.PublicV6[0].String() != "2001:db8::1" {
		t.Errorf("PublicV6 = %v, want [2001:db8::1]", res.PublicV6)
	}
}

func TestEnumerateSkipsLinkLocalV6(t *testing.T) {
	// fe80::/10 is a dead end — must be skipped.
	src := fakeSource{ifs: []Interface{
		{
			Name:  "eth0",
			Index: 1,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{
				ipnet("192.168.1.10/24"),
				ipnet("fe80::1/64"),
			},
		},
	}}
	res, _ := Enumerate(src, 1, "eth0")
	if len(res.PublicV6) != 0 {
		t.Errorf("PublicV6 = %v, want empty (link-local must be skipped)", res.PublicV6)
	}
}

func TestEnumerateSkipsULAV6(t *testing.T) {
	// ULA (fc00::/7) is not globally routable and overlaps across networks,
	// so it can't serve as a reachable endpoint candidate — skip.
	src := fakeSource{ifs: []Interface{
		{
			Name:  "eth0",
			Index: 1,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{ipnet("fd00::1/64")},
		},
	}}
	res, _ := Enumerate(src, 1, "eth0")
	if len(res.PublicV6) != 0 {
		t.Errorf("PublicV6 = %v, want empty (ULA must be skipped)", res.PublicV6)
	}
}

func TestEnumerateSkipsTemporaryV6(t *testing.T) {
	// SLAAC privacy-extension temporaries rotate every few hours — we
	// can't pin them in a signed envelope.
	src := fakeSource{ifs: []Interface{
		{
			Name:  "eth0",
			Index: 1,
			Flags: net.FlagUp,
			Addrs: []net.IPNet{
				ipnet("2001:db8::1/64"),
				ipnet("2001:db8::dead:beef/64"),
			},
			V6Flags: map[string]uint32{
				"2001:db8::1":         0,
				"2001:db8::dead:beef": ifaFlagTemporary,
			},
		},
	}}
	// Temporary filtering depends on ifaFlagTemporary being non-zero.
	// On Linux the init in enumerator_linux.go populates it; on other
	// platforms it stays zero and this test effectively becomes a
	// no-op (both addresses would be kept). Guard the assertion.
	if ifaFlagTemporary == 0 {
		t.Skip("ifaFlagTemporary is zero on this platform; V6 flag filtering is a Linux-only feature")
	}
	res, _ := Enumerate(src, 1, "eth0")
	if len(res.PublicV6) != 1 || res.PublicV6[0].String() != "2001:db8::1" {
		t.Errorf("PublicV6 = %v, want [2001:db8::1] (temporary must be skipped)", res.PublicV6)
	}
}

func TestEnumerateSkipsDownInterfaces(t *testing.T) {
	src := fakeSource{ifs: []Interface{
		{Name: "eth0", Index: 1, Flags: 0, Addrs: []net.IPNet{ipnet("192.168.1.10/24")}},
	}}
	res, _ := Enumerate(src, 0, "")
	if len(res.LAN) != 0 {
		t.Errorf("LAN = %v, want empty (interface is down)", res.LAN)
	}
}

func TestSortCandidatesKindOrder(t *testing.T) {
	// Final wire order must be lan, public4, public6 regardless of input.
	in := []Candidate{
		{Kind: KindPublic6, Host: "2001:db8::1", Port: 51820},
		{Kind: KindPublic4, Host: "1.2.3.4", Port: 51820},
		{Kind: KindLAN, Host: "192.168.1.10", Port: 51820},
		{Kind: KindLAN, Host: "10.0.0.5", Port: 51820},
	}
	out := sortCandidates(in)
	want := []Candidate{
		{Kind: KindLAN, Host: "192.168.1.10", Port: 51820},
		{Kind: KindLAN, Host: "10.0.0.5", Port: 51820},
		{Kind: KindPublic4, Host: "1.2.3.4", Port: 51820},
		{Kind: KindPublic6, Host: "2001:db8::1", Port: 51820},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("sortCandidates = %+v\nwant %+v", out, want)
	}
}
