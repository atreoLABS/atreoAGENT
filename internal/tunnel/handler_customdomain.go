package tunnel

import "strings"

// normaliseZone makes the parent-zone comparison byte-exact regardless of
// signer-side encoding.
func normaliseZone(zone string) string {
	zone = strings.ToLower(strings.TrimSpace(zone))
	zone = strings.TrimSuffix(zone, ".")
	zone = strings.TrimPrefix(zone, "*.")
	return zone
}
