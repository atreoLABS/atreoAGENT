package proxy

import (
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"net"
)

// ParseTrustedNetworks parses a list of CIDR strings into net.IPNet objects.
func ParseTrustedNetworks(cidrs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			logging.Warn("Warning: invalid trusted network CIDR %q: %v", cidr, err)
			continue
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// IsTrusted checks if an IP is within any of the trusted networks.
func IsTrusted(ip string, trusted []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
