package endpoints

import "testing"

// PublicV6 wraps the real OS enumeration, so this is a smoke test: it must not
// error on a normal host and must only ever return global IPv6 addresses
// (never IPv4), matching what the public6 candidates advertise.
func TestPublicV6(t *testing.T) {
	addrs, err := PublicV6()
	if err != nil {
		t.Fatalf("PublicV6: %v", err)
	}
	for _, ip := range addrs {
		if ip.To4() != nil {
			t.Errorf("PublicV6 returned an IPv4 address: %s", ip)
		}
		if !isGlobalV6(ip) {
			t.Errorf("PublicV6 returned a non-global IPv6 address: %s", ip)
		}
	}
}
