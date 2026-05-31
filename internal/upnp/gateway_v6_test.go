package upnp

import (
	"strings"
	"testing"
)

func TestParseDefaultV6Gateway(t *testing.T) {
	// Columns: dest(32) destLen(2) src(32) srcLen(2) nexthop(32) metric refcnt use flags iface
	const fixture = `00000000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000000 00000000 00000003 eth0
`
	got, err := parseDefaultV6Gateway(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("parseDefaultV6Gateway: %v", err)
	}
	if got.Port() != 5351 {
		t.Errorf("port = %d, want 5351", got.Port())
	}
	if got.Addr().String() != "fe80::1%eth0" {
		t.Errorf("gateway = %s, want fe80::1%%eth0 (link-local carries egress zone)", got.Addr())
	}
}

func TestParseDefaultV6GatewayGlobalNextHop(t *testing.T) {
	// A global next-hop must not get a zone appended.
	const fixture = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000000 00000000 00000003 ppp0
`
	got, err := parseDefaultV6Gateway(strings.NewReader(fixture))
	if err != nil {
		t.Fatalf("parseDefaultV6Gateway: %v", err)
	}
	if got.Addr().String() != "2001:db8::1" {
		t.Errorf("gateway = %s, want 2001:db8::1 (no zone)", got.Addr())
	}
}

func TestParseDefaultV6GatewayNone(t *testing.T) {
	// Only a connected on-link route, no default — must error, not panic.
	const fixture = `20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000000 00000000 00000001 eth0
`
	if _, err := parseDefaultV6Gateway(strings.NewReader(fixture)); err == nil {
		t.Fatal("expected error when no default route present")
	}
}
