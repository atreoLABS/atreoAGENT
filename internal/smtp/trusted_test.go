package smtp

import "testing"

func TestIPTrusted_LANDefault(t *testing.T) {
	s := &Server{trusted: parseCIDRs([]string{
		"127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "100.64.0.0/24",
	})}
	allowed := []string{"127.0.0.1", "10.1.2.3", "192.168.1.50", "100.64.0.7"}
	for _, ip := range allowed {
		if !s.ipTrusted(ip) {
			t.Errorf("%s should be trusted (LAN/WG range)", ip)
		}
	}
	denied := []string{"8.8.8.8", "1.1.1.1", "203.0.113.5"}
	for _, ip := range denied {
		if s.ipTrusted(ip) {
			t.Errorf("%s is public and must not be trusted", ip)
		}
	}
}

func TestIPTrusted_EmptyAllowlistAllowsAny(t *testing.T) {
	s := &Server{trusted: nil}
	if !s.ipTrusted("8.8.8.8") {
		t.Error("an empty allowlist should trust any source (caller supplies the LAN default)")
	}
}

func TestIPTrusted_GarbageDenied(t *testing.T) {
	s := &Server{trusted: parseCIDRs([]string{"10.0.0.0/8"})}
	if s.ipTrusted("not-an-ip") {
		t.Error("unparseable host must be denied when an allowlist is set")
	}
}

func TestAllowlistIncludesPublic(t *testing.T) {
	if (&Server{trusted: parseCIDRs([]string{"192.168.0.0/16"})}).allowlistIncludesPublic() {
		t.Error("a private-only allowlist must not be flagged as public")
	}
	if !(&Server{trusted: parseCIDRs([]string{"0.0.0.0/0"})}).allowlistIncludesPublic() {
		t.Error("0.0.0.0/0 admits public space and should be flagged")
	}
	if !(&Server{trusted: parseCIDRs([]string{"::/0"})}).allowlistIncludesPublic() {
		t.Error("::/0 admits public v6 space and should be flagged")
	}
}
