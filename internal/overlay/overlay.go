// Package overlay derives and persists this install's WireGuard overlay
// addressing. Each install picks its own IPv4 /24 from 100.64.0.0/10 at first
// boot and keeps it, so a client peered with several servers can route to
// each. The IPv6 /64 is derived from the same draw, so the two families
// collide together or not at all.
package overlay

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atomic"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

const (
	// Base is the RFC 6598 range the per-install /24 is drawn from: 16,384 /24s.
	Base = "100.64.0.0/10"

	// The fixed addresses every install used before per-install addressing.
	// Both gateways stay bound as aliases for existing operator configs, so
	// index 0 (which derives exactly these) is never handed out.
	LegacySubnetV4  = "100.64.0.0/24"
	LegacyGatewayV4 = "100.64.0.1"
	LegacySubnetV6  = "fd00:64::/64"
	LegacyGatewayV6 = "fd00:64::1"

	subnetCount = 1 << 14
)

// Overlay is the persisted addressing. The gateways are stored rather than
// recomputed so a hand-edited file that disagrees is caught at load.
type Overlay struct {
	SubnetV4  string    `json:"subnetV4"`
	GatewayV4 string    `json:"gatewayV4"`
	SubnetV6  string    `json:"subnetV6"`
	GatewayV6 string    `json:"gatewayV6"`
	RolledAt  time.Time `json:"rolledAt"`
}

// subnetAt maps idx onto 100.<64+idx/256>.<idx%256>.0/24 and
// fd00:64:<idx/256>:<idx%256>::/64. IPv4 host N maps to IPv6 host N, which
// deriveTunnelIPv6 in internal/wireguard relies on.
func subnetAt(idx int64) Overlay {
	second := 64 + idx/256
	third := idx % 256
	subnetV6, gatewayV6 := v6At(idx/256, third)
	return Overlay{
		SubnetV4:  fmt.Sprintf("100.%d.%d.0/24", second, third),
		GatewayV4: fmt.Sprintf("100.%d.%d.1", second, third),
		SubnetV6:  subnetV6,
		GatewayV6: gatewayV6,
		RolledAt:  time.Now().UTC(),
	}
}

// v6At builds the address from bytes rather than a format string so the
// result is always canonical (e.g. index 0 is "fd00:64::/64", not "fd00:64:0:0::/64").
func v6At(b64, third int64) (subnetV6, gatewayV6 string) {
	ip := make(net.IP, net.IPv6len)
	ip[0], ip[1] = 0xfd, 0x00
	ip[2], ip[3] = 0x00, 0x64
	ip[4], ip[5] = byte(b64>>8), byte(b64)
	ip[6], ip[7] = byte(third>>8), byte(third)
	subnet := &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}
	gw := make(net.IP, net.IPv6len)
	copy(gw, ip)
	gw[15] = 1
	return subnet.String(), gw.String()
}

// v6FromV4 returns the IPv6 pairing for an existing IPv4 subnet.
func v6FromV4(subnetV4 string) (subnetV6, gatewayV6 string, err error) {
	_, ipnet, err := net.ParseCIDR(subnetV4)
	if err != nil {
		return "", "", fmt.Errorf("overlay: parse v4 subnet %q: %w", subnetV4, err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return "", "", fmt.Errorf("overlay: %q is not an IPv4 subnet", subnetV4)
	}
	subnetV6, gatewayV6 = v6At(int64(ip4[1])-64, int64(ip4[2]))
	return subnetV6, gatewayV6, nil
}

// Derive picks a uniformly random /24, skipping the reserved legacy index.
func Derive() (Overlay, error) {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(subnetCount))
		if err != nil {
			return Overlay{}, fmt.Errorf("overlay: read randomness: %w", err)
		}
		if n.Int64() == 0 {
			continue
		}
		return subnetAt(n.Int64()), nil
	}
}

// Load returns the persisted overlay and never writes to disk, so it is safe
// for read-only callers. A missing file returns an error matching
// os.ErrNotExist.
func Load(path string) (Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Overlay{}, err
	}
	o, _, err := parseAndMigrate(data)
	if err != nil {
		return Overlay{}, fmt.Errorf("overlay: parse %s: %w", path, err)
	}
	return o, nil
}

// LoadOrCreate returns the persisted overlay, deriving and saving one on first
// boot. An invalid file is an error, never a fresh roll: re-deriving would
// renumber every existing peer.
func LoadOrCreate(path string) (Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return Overlay{}, err
		}
		o, err := Derive()
		if err != nil {
			return Overlay{}, err
		}
		if err := save(path, o); err != nil {
			return Overlay{}, err
		}
		return o, nil
	}

	o, migrated, err := parseAndMigrate(data)
	if err != nil {
		return Overlay{}, fmt.Errorf("overlay: parse %s: %w", path, err)
	}
	if migrated {
		// Non-fatal: the backfill is deterministic, so it is simply redone next load.
		if err := save(path, o); err != nil {
			logging.Warn("overlay: failed to persist migrated v6 addressing to %s (will retry on next load): %v", path, err)
		}
	}
	return o, nil
}

// Reroll picks and persists a fresh /24 and its paired /64, different from
// the current one.
func Reroll(path string) (Overlay, error) {
	cur, err := Load(path)
	if err != nil {
		return Overlay{}, err
	}
	for {
		next, err := Derive()
		if err != nil {
			return Overlay{}, err
		}
		if next.SubnetV4 == cur.SubnetV4 {
			continue
		}
		if err := save(path, next); err != nil {
			return Overlay{}, err
		}
		return next, nil
	}
}

// ExpandLegacy mirrors allowlist entries naming the legacy overlay onto this
// install's derived addressing, like-for-like: the legacy /24 mirrors onto the
// derived /24, and the legacy gateway /32 onto the derived gateway /32 only.
// Trusting one host must not widen into trusting every peer.
func ExpandLegacy(cidrs []string, derivedSubnet string) []string {
	derivedGateway, err := gatewayOf(derivedSubnet)
	if err != nil {
		return cidrs
	}
	derivedGatewayCIDR := derivedGateway + "/32"

	have := make(map[string]bool, len(cidrs))
	for _, c := range cidrs {
		have[c] = true
	}

	var add []string
	for _, c := range cidrs {
		switch c {
		case LegacySubnetV4:
			if !have[derivedSubnet] {
				add = append(add, derivedSubnet)
				have[derivedSubnet] = true
			}
		case LegacyGatewayV4 + "/32":
			if !have[derivedGatewayCIDR] {
				add = append(add, derivedGatewayCIDR)
				have[derivedGatewayCIDR] = true
			}
		}
	}
	if len(add) == 0 {
		return cidrs
	}
	return append(append([]string{}, cidrs...), add...)
}

// gatewayOf returns the .1 host address of a /24 CIDR string.
func gatewayOf(subnet string) (string, error) {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	gw := make(net.IP, len(ipnet.IP))
	copy(gw, ipnet.IP)
	gw[len(gw)-1] = 1
	return gw.String(), nil
}

// parseAndMigrate unmarshals a persisted overlay. A file written before IPv6
// support (both v6 fields absent) has them backfilled from the IPv4 subnet;
// migrated reports whether that happened. Any other v6 mismatch is rejected.
func parseAndMigrate(data []byte) (o Overlay, migrated bool, err error) {
	if err := json.Unmarshal(data, &o); err != nil {
		return Overlay{}, false, err
	}
	if o.SubnetV6 == "" && o.GatewayV6 == "" {
		subnetV6, gatewayV6, err := v6FromV4(o.SubnetV4)
		if err != nil {
			return Overlay{}, false, err
		}
		o.SubnetV6, o.GatewayV6 = subnetV6, gatewayV6
		migrated = true
	}
	if err := o.validate(); err != nil {
		return Overlay{}, false, err
	}
	return o, migrated, nil
}

func save(path string, o Overlay) error {
	data, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return fmt.Errorf("overlay: marshal: %w", err)
	}
	return atomic.WriteFile(path, append(data, '\n'), 0640)
}

func (o Overlay) validate() error {
	_, base, err := net.ParseCIDR(Base)
	if err != nil {
		return fmt.Errorf("overlay: base %q does not parse: %w", Base, err)
	}
	ip, ipnet, err := net.ParseCIDR(o.SubnetV4)
	if err != nil {
		return fmt.Errorf("overlay: subnet %q does not parse: %w", o.SubnetV4, err)
	}
	if ones, _ := ipnet.Mask.Size(); ones != 24 {
		return fmt.Errorf("overlay: subnet %q is not a /24", o.SubnetV4)
	}
	if o.SubnetV4 != ipnet.String() {
		return fmt.Errorf("overlay: subnet %q is not canonical", o.SubnetV4)
	}
	if !base.Contains(ip) {
		return fmt.Errorf("overlay: subnet %q is outside %s", o.SubnetV4, Base)
	}
	if want, _ := gatewayOf(o.SubnetV4); o.GatewayV4 != want {
		return fmt.Errorf("overlay: gateway %q is not the .1 of %s", o.GatewayV4, o.SubnetV4)
	}

	wantSubnetV6, wantGatewayV6, err := v6FromV4(o.SubnetV4)
	if err != nil {
		return fmt.Errorf("overlay: derive v6 pairing for %q: %w", o.SubnetV4, err)
	}
	if o.SubnetV6 != wantSubnetV6 {
		return fmt.Errorf("overlay: subnet v6 %q does not match v4 %q (want %q)", o.SubnetV6, o.SubnetV4, wantSubnetV6)
	}
	if o.GatewayV6 != wantGatewayV6 {
		return fmt.Errorf("overlay: gateway v6 %q does not match v4 %q (want %q)", o.GatewayV6, o.SubnetV4, wantGatewayV6)
	}
	return nil
}
