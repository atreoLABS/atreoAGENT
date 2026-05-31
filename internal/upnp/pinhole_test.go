package upnp

import (
	"context"
	"net"
	"testing"
)

func TestIPToAddr(t *testing.T) {
	a, ok := ipToAddr(net.ParseIP("192.0.2.7"))
	if !ok || !a.Is4() {
		t.Errorf("v4: got (%v, %v), want Is4", a, ok)
	}
	a, ok = ipToAddr(net.ParseIP("2001:db8::1"))
	if !ok || !a.Is6() {
		t.Errorf("v6: got (%v, %v), want Is6", a, ok)
	}
}

func TestStopTearsDownV4AndV6(t *testing.T) {
	c := NewClient(51820)

	v4called := false
	c.v4cleanup = func() { v4called = true }
	calls := map[string]bool{}
	c.v6pinholes["2001:db8::1"] = &pinhole{remove: func() { calls["a"] = true }}
	c.v6pinholes["2001:db8::2"] = &pinhole{remove: func() { calls["b"] = true }}

	c.Stop()

	if !v4called {
		t.Error("v4cleanup not invoked")
	}
	if !calls["a"] || !calls["b"] {
		t.Errorf("v6 removers not all invoked: %v", calls)
	}
	if c.v4cleanup != nil || len(c.v6pinholes) != 0 {
		t.Errorf("state not cleared: v4cleanup=%v pinholes=%d", c.v4cleanup != nil, len(c.v6pinholes))
	}
}

// RefreshV6Pinholes must drop pinholes whose address is no longer advertised.
// Driving it with an empty/IPv4-only desired set exercises removal without the
// network-dependent create path.
func TestRefreshV6PinholesRemovesStale(t *testing.T) {
	c := NewClient(51820)
	removed := map[string]bool{}
	c.v6pinholes["2001:db8::1"] = &pinhole{remove: func() { removed["1"] = true }}
	c.v6pinholes["2001:db8::2"] = &pinhole{remove: func() { removed["2"] = true }}

	// IPv4 addresses are filtered out → desired set is empty → all stale.
	if err := c.RefreshV6Pinholes(context.Background(), []net.IP{net.ParseIP("192.0.2.1")}); err != nil {
		t.Fatalf("RefreshV6Pinholes: %v", err)
	}
	if !removed["1"] || !removed["2"] {
		t.Errorf("stale pinholes not removed: %v", removed)
	}
	if len(c.v6pinholes) != 0 {
		t.Errorf("stale pinholes not deleted from map: %d remain", len(c.v6pinholes))
	}
}

func TestRefreshV6PinholesNoAddrs(t *testing.T) {
	c := NewClient(51820)
	if err := c.RefreshV6Pinholes(context.Background(), nil); err != nil {
		t.Errorf("empty refresh should be a no-op, got %v", err)
	}
}
