package agent

import "net/netip"

// reachability classifies the WAN IP a gateway reports for a port mapping: a
// usable public path (direct works) vs a carrier-NAT/private path (the gateway
// is itself behind another NAT, so the mapping is unreachable from outside).
type reachability int

const (
	reachUnknown    reachability = iota // no mapping, or an address we can't classify
	reachPublic                         // usable public IP — a direct inbound path exists
	reachCarrierNAT                     // CGNAT (RFC 6598) or private — behind another NAT
)

// RFC 6598 shared address space — the textbook carrier-grade NAT signature: a
// home gateway whose own WAN IP falls here is behind the ISP's NAT.
var cgnatRange = netip.MustParsePrefix("100.64.0.0/10")

func classifyMappedIP(ip string) reachability {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return reachUnknown
	}
	addr = addr.Unmap()
	if cgnatRange.Contains(addr) || addr.IsPrivate() {
		return reachCarrierNAT
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified() {
		return reachUnknown
	}
	return reachPublic
}

func (r reachability) usablePublic() bool { return r == reachPublic }

// relayWanted reports whether the agent should advertise the relay (fallback)
// endpoint: true when there is no operator override and no *usable* public
// inbound path. A UPnP mapping that returns a CGNAT/private WAN IP is not a
// usable path — the gateway mapped a port, but it's unreachable from outside.
func relayWanted(endpointIP, mappedIP string, mappedPort int) bool {
	if endpointIP != "" {
		return false // operator asserts a reachable public IP
	}
	if mappedPort == 0 {
		return true // nothing auto-opened a port
	}
	return !classifyMappedIP(mappedIP).usablePublic()
}

// transportState is the agent's externally-reachable transport, reported on the
// device:transport channel. transportUnknown is the zero value and doubles as
// "not observed/reported yet" (the initial `last`) and, as a decision, "nothing
// to report this tick".
type transportState int

const (
	transportUnknown transportState = iota
	transportDirect                 // a usable public inbound path exists
	transportRelay                  // no public path; reachable only via the relay
)

// transportReportDecision decides what (if anything) to report about the agent's
// transport reachability, given the current observation (cur), the last state
// reported (last), and the run of consecutive relay observations. It debounces
// the flip TO relay — requiring two consecutive relay reads so a transient UPnP
// miss can't masquerade as a lost public path — while reporting recovery to a
// direct path immediately. Returns transportUnknown when there's nothing new to
// report.
func transportReportDecision(cur, last transportState, relayStreak int) transportState {
	switch {
	case cur == transportDirect && last != transportDirect:
		return transportDirect
	case cur == transportRelay && last != transportRelay && relayStreak >= 2:
		return transportRelay
	default:
		return transportUnknown
	}
}
