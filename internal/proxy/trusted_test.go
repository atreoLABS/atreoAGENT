package proxy

import "testing"

func TestParseTrustedNetworks(t *testing.T) {
	cidrs := []string{"192.168.1.0/24", "10.0.0.0/8", "not-a-cidr", "::1/128"}
	nets := ParseTrustedNetworks(cidrs)
	if len(nets) != 3 {
		t.Fatalf("expected 3 valid nets, got %d", len(nets))
	}
}

func TestIsTrusted(t *testing.T) {
	nets := ParseTrustedNetworks([]string{"192.168.1.0/24", "10.0.0.0/8"})
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.5", true},
		{"192.168.2.5", false},
		{"10.5.5.5", true},
		{"172.16.0.1", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsTrusted(tt.ip, nets); got != tt.want {
			t.Errorf("IsTrusted(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
	if IsTrusted("192.168.1.5", nil) {
		t.Error("nil networks should never trust")
	}
}
