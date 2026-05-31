// Package endpoints publishes a signed list of reachable WG-listener
// addresses so paired clients can pick the right one — bypassing DNS
// rebinding-protection resolvers and avoiding hairpin NAT on the LAN.
package endpoints

import "sort"

// Wire values; lowercase, exact.
const (
	KindLAN     = "lan"
	KindPublic4 = "public4"
	KindPublic6 = "public6"
)

// Host: bare IP or hostname (no brackets, no zone id, no port).
// Port: WG listen port at that endpoint (UPnP may map to a different
// external port than the internal one).
type Candidate struct {
	Kind string `json:"kind"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// LAN first, then public4, then public6. Order is signed, so must be
// stable across runs.
func sortCandidates(cs []Candidate) []Candidate {
	rank := func(k string) int {
		switch k {
		case KindLAN:
			return 0
		case KindPublic4:
			return 1
		case KindPublic6:
			return 2
		default:
			return 3
		}
	}
	out := make([]Candidate, len(cs))
	copy(out, cs)
	sort.SliceStable(out, func(i, j int) bool {
		return rank(out[i].Kind) < rank(out[j].Kind)
	})
	return out
}

// Skips a marshal round-trip on the happy path before canonjson runs.
func sameCandidates(a, b []Candidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
