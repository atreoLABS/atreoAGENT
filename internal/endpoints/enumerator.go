package endpoints

import (
	"net"
	"strings"
)

// Abstracted so tests can inject fixtures.
type InterfaceSource interface {
	Interfaces() ([]Interface, error)
}

// V6Flags: IP.String() → IFA_F_* bitmask (Linux only; empty elsewhere).
type Interface struct {
	Name    string
	Index   int
	Flags   net.Flags
	Addrs   []net.IPNet
	V6Flags map[string]uint32
}

type PublicV6Address struct {
	IP net.IP
}

// OS-backed source. V6Flags is populated on Linux only; lifetime pinning
// is best-effort.
type realSource struct{}

func NewRealSource() InterfaceSource { return realSource{} }

// Case-insensitive prefix match (Docker, other VPN tunnels, etc).
var skippedInterfacePrefixes = []string{
	"docker",
	"br-",
	"virbr",
	"wg",
	"tun",
	"tap",
	"utun",
	"cni",
	"flannel",
	"cali",
	"zt",        // ZeroTier
	"tailscale", // Tailscale
	"ts",
}

func isSkippedInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range skippedInterfacePrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

var rfc1918Nets = []*net.IPNet{
	mustCIDR("10.0.0.0/8"),
	mustCIDR("172.16.0.0/12"),
	mustCIDR("192.168.0.0/16"),
}

// CGNAT is never reachable externally; the WG tunnel itself lives there.
var cgNATNet = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func isPrivateV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if cgNATNet.Contains(v4) {
		return false
	}
	for _, n := range rfc1918Nets {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// Excludes loopback, link-local, ULA, v4-mapped.
func isGlobalV6(ip net.IP) bool {
	if ip.To4() != nil {
		return false
	}
	if ip.To16() == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	// ULA fc00::/7.
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return false
	}
	return ip.IsGlobalUnicast()
}

type EnumerateResult struct {
	LAN      []net.IP
	PublicV6 []net.IP // default-route iface only
	// Subset of PublicV6 flagged IFA_F_PERMANENT (static / DHCPv6). Empty on
	// platforms without netlink flag data, so callers fall back to PublicV6.
	PublicV6Permanent []net.IP
	DefaultIfIndex    int
	DefaultIfName     string
}

// LAN order: default-route iface first, then others. v6 is only collected
// on the default-route iface — addresses on secondaries would fail
// reverse-path filtering on most routers.
func Enumerate(src InterfaceSource, defaultIfIndex int, defaultIfName string) (EnumerateResult, error) {
	ifs, err := src.Interfaces()
	if err != nil {
		return EnumerateResult{}, err
	}
	res := EnumerateResult{DefaultIfIndex: defaultIfIndex, DefaultIfName: defaultIfName}

	var lanOnDefault, lanOnOther []net.IP
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isSkippedInterface(iface.Name) {
			continue
		}

		onDefault := defaultIfIndex != 0 && iface.Index == defaultIfIndex
		if !onDefault && defaultIfName != "" && iface.Name == defaultIfName {
			onDefault = true
		}

		for _, ipnet := range iface.Addrs {
			ip := ipnet.IP
			if ip == nil {
				continue
			}
			v4 := ip.To4()
			if v4 != nil {
				if !isPrivateV4(v4) {
					continue
				}
				dup := append(net.IP(nil), v4...)
				if onDefault {
					lanOnDefault = append(lanOnDefault, dup)
				} else {
					lanOnOther = append(lanOnOther, dup)
				}
				continue
			}
			if !onDefault {
				continue
			}
			if !isGlobalV6(ip) {
				continue
			}
			// Skip SLAAC privacy-extension temporaries and deprecated
			// addresses — promising one that's about to disappear is
			// worse than not advertising it.
			flags, hasFlags := iface.V6Flags[ip.String()]
			if hasFlags && (flags&ifaFlagTemporary != 0 || flags&ifaFlagDeprecated != 0) {
				continue
			}
			dup := append(net.IP(nil), ip.To16()...)
			res.PublicV6 = append(res.PublicV6, dup)
			if hasFlags && flags&ifaFlagPermanent != 0 {
				res.PublicV6Permanent = append(res.PublicV6Permanent, dup)
			}
		}
	}
	res.LAN = append(lanOnDefault, lanOnOther...)
	return res, nil
}

// Platform-specific (set in enumerator_linux.go); zero elsewhere.
var (
	ifaFlagTemporary  uint32
	ifaFlagDeprecated uint32
	ifaFlagPermanent  uint32
)
