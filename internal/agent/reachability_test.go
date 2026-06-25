package agent

import "testing"

func TestClassifyMappedIP(t *testing.T) {
	cases := map[string]reachability{
		"203.0.113.10":      reachPublic,
		"8.8.8.8":           reachPublic,
		"100.64.1.2":        reachCarrierNAT, // RFC 6598 CGNAT
		"100.127.255.255":   reachCarrierNAT, // top of 100.64.0.0/10
		"10.0.0.5":          reachCarrierNAT, // RFC 1918
		"172.16.4.4":        reachCarrierNAT,
		"192.168.1.1":       reachCarrierNAT,
		"::ffff:100.64.0.1": reachCarrierNAT, // v4-mapped CGNAT
		"2001:db8::1":       reachPublic,     // global v6 (documentation range is global unicast)
		"127.0.0.1":         reachUnknown,
		"169.254.1.1":       reachUnknown, // link-local
		"0.0.0.0":           reachUnknown,
		"":                  reachUnknown,
		"not-an-ip":         reachUnknown,
		"100.128.0.1":       reachPublic, // just outside 100.64.0.0/10
	}
	for ip, want := range cases {
		if got := classifyMappedIP(ip); got != want {
			t.Errorf("classifyMappedIP(%q) = %d, want %d", ip, got, want)
		}
	}
}

func TestTransportReportDecision(t *testing.T) {
	tests := []struct {
		name        string
		cur, last   transportState
		relayStreak int
		want        transportState
	}{
		{"first read direct reports direct", transportDirect, transportUnknown, 0, transportDirect},
		{"first relay read waits for debounce", transportRelay, transportUnknown, 1, transportUnknown},
		{"second relay read reports relay", transportRelay, transportUnknown, 2, transportRelay},
		{"direct then sustained relay transitions", transportRelay, transportDirect, 2, transportRelay},
		{"single transient relay miss is suppressed", transportRelay, transportDirect, 1, transportUnknown},
		{"recovery to direct reported immediately", transportDirect, transportRelay, 0, transportDirect},
		{"steady relay is not re-reported", transportRelay, transportRelay, 5, transportUnknown},
		{"steady direct is not re-reported", transportDirect, transportDirect, 0, transportUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := transportReportDecision(tc.cur, tc.last, tc.relayStreak); got != tc.want {
				t.Fatalf("transportReportDecision(%d,%d,%d) = %d, want %d",
					tc.cur, tc.last, tc.relayStreak, got, tc.want)
			}
		})
	}
}

func TestRelayWanted(t *testing.T) {
	cases := []struct {
		name       string
		endpointIP string
		mappedIP   string
		mappedPort int
		want       bool
	}{
		{"operator override wins", "203.0.113.9", "", 0, false},
		{"no mapping → relay", "", "", 0, true},
		{"usable public mapping → direct", "", "203.0.113.10", 51820, false},
		{"cgnat mapping → relay", "", "100.64.0.7", 51820, true},
		{"private mapping → relay", "", "192.168.0.1", 51820, true},
		{"override beats cgnat mapping", "203.0.113.9", "100.64.0.7", 51820, false},
	}
	for _, c := range cases {
		if got := relayWanted(c.endpointIP, c.mappedIP, c.mappedPort); got != c.want {
			t.Errorf("%s: relayWanted(%q,%q,%d) = %v, want %v",
				c.name, c.endpointIP, c.mappedIP, c.mappedPort, got, c.want)
		}
	}
}
