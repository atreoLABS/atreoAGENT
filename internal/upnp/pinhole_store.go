package upnp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atomic"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"github.com/atreoLABS/atreoAGENT/internal/pcp"
)

// loadNonces seeds the PCP nonces from disk so a renewal after restart reuses
// the original nonce (a fresh one is rejected NOT_AUTHORIZED, RFC 6887). Entries
// route by family: IPv6 → pinholes, IPv4 → the mapping nonce. Missing file → no-op.
func (c *Client) loadNonces() {
	if c.statePath == "" {
		return
	}
	data, err := os.ReadFile(c.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logging.Warn("pcp nonce: read %s: %v", c.statePath, err)
			return
		}
		// Migration from the old v6-only filename, so an upgrade keeps nonces.
		legacy := filepath.Join(filepath.Dir(c.statePath), "v6_pinholes.json")
		if data, err = os.ReadFile(legacy); err != nil {
			return
		}
	}
	var stored map[string]string
	if err := json.Unmarshal(data, &stored); err != nil {
		logging.Warn("pcp nonce: parse %s: %v", c.statePath, err)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for ipStr, hexNonce := range stored {
		raw, err := hex.DecodeString(hexNonce)
		if err != nil {
			continue
		}
		var n pcp.Nonce
		if len(raw) != len(n) {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		copy(n[:], raw)
		if ip.To4() != nil {
			c.v4nonce, c.v4nonceSet, c.v4localIP = n, true, ipStr
			continue
		}
		c.v6pinholes[ipStr] = &pinhole{nonce: n, remove: c.pcpDeleteFunc(ip, n)}
	}
}

// pcpDeleteFunc tears down a loaded pinhole, resolving the gateway lazily since
// it's unknown at load time. Best effort, but logs failures so v6 teardown is
// observable (a silent skip looks like it never ran).
func (c *Client) pcpDeleteFunc(ip net.IP, nonce pcp.Nonce) func() {
	return func() {
		gw, err := defaultV6Gateway()
		if err != nil {
			logging.Warn("PCP: cannot remove v6 pinhole for %s: no IPv6 gateway: %v", ip, err)
			return
		}
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pcp.RequestMapping(dctx, gw, ip, ip, pcp.ProtoUDP,
			uint16(c.internalPort), uint16(c.internalPort), 0, nonce); err != nil {
			logging.Warn("PCP: failed to remove v6 pinhole for %s: %v", ip, err)
		} else {
			logging.Info("PCP: v6 pinhole removed for %s", ip)
		}
	}
}

// persistNonces atomically writes the PCP nonces (hex, keyed by internal IP),
// skipping the zero nonce used by UPnP-path pinholes. Caller must NOT hold c.mu.
func (c *Client) persistNonces() {
	if c.statePath == "" {
		return
	}
	c.mu.Lock()
	var zero pcp.Nonce
	stored := make(map[string]string, len(c.v6pinholes)+1)
	if c.v4nonceSet && c.v4localIP != "" && c.v4nonce != zero {
		stored[c.v4localIP] = hex.EncodeToString(c.v4nonce[:])
	}
	for ipStr, p := range c.v6pinholes {
		if p.nonce == zero {
			continue
		}
		stored[ipStr] = hex.EncodeToString(p.nonce[:])
	}
	c.mu.Unlock()

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		logging.Warn("v6 pinhole: marshal: %v", err)
		return
	}
	if err := atomic.WriteFile(c.statePath, data, 0600); err != nil {
		logging.Warn("v6 pinhole: persist: %v", err)
	}
}
