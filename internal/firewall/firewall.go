// Package firewall confines WireGuard peers to the proxy ports via
// iptables. The manager owns two private chains and only inserts/removes
// jumps from INPUT/FORWARD when iif=<wg-iface>; it never edits any other
// rule the host has installed.
package firewall

import (
	"context"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	inputChain   = "ATREOAGENT-WG-INPUT"
	forwardChain = "ATREOAGENT-WG-FORWARD"
)

// The overlay is dual-stack (100.64.0.0/24 + fd00:64::/64) on one wg interface,
// so v6 peer traffic must be confined identically — otherwise network_mode:host
// exposes every ::-bound host service to peers. Each table is driven through the
// same ruleset; only the binary and the ICMP proto name differ.
type fwTable struct {
	bin       string
	icmpProto string
}

var tables = []fwTable{
	{bin: "iptables", icmpProto: "icmp"},
	{bin: "ip6tables", icmpProto: "ipv6-icmp"},
}

type Config struct {
	Iface           string // WG interface name (e.g. "wg-atreo")
	AllowedTCPPorts []int  // ports peers may reach (the proxy HTTP/HTTPS)
}

// PortGrant lets one peer reach a set of raw host ports. SourceIP / SourceIPv6
// are the peer's v4 / v6 overlay addresses; each is emitted only into its own
// table (a v4 literal in ip6tables, or vice versa, is rejected by the binary).
type PortGrant struct {
	SourceIP   string
	SourceIPv6 string
	TCP        []int
	UDP        []int
}

type Manager struct {
	cfg     Config
	mu      sync.Mutex
	enabled bool
	// Re-emitted on every Apply so they survive a watchdog re-apply / flush.
	portGrants []PortGrant
}

func NewManager(c Config) *Manager {
	return &Manager{cfg: c}
}

// Stale state from a previous crash is cleaned up first.
// Fails closed: a missing iptables/ip6tables binary is an error so the caller
// can refuse to bring up the tunnel rather than admit peers unconfined.
func (m *Manager) Apply(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, t := range tables {
		if _, err := exec.LookPath(t.bin); err != nil {
			return fmt.Errorf("firewall: %s not on PATH: %w", t.bin, err)
		}
	}
	if m.cfg.Iface == "" {
		return fmt.Errorf("firewall: empty iface")
	}

	m.teardown(ctx)

	for _, t := range tables {
		if err := m.applyTable(ctx, t); err != nil {
			m.teardown(ctx)
			return err
		}
	}

	m.enabled = true
	logging.Info("firewall: tunnel access on %s restricted to TCP %v + ICMP (IPv4+IPv6)", m.cfg.Iface, m.cfg.AllowedTCPPorts)
	return nil
}

// applyTable installs the confinement ruleset into one address family's table.
func (m *Manager) applyTable(ctx context.Context, t fwTable) error {
	if err := run(ctx, t.bin, "-N", inputChain); err != nil {
		return fmt.Errorf("%s create %s: %w", t.bin, inputChain, err)
	}
	if err := run(ctx, t.bin, "-N", forwardChain); err != nil {
		return fmt.Errorf("%s create %s: %w", t.bin, forwardChain, err)
	}

	// established/related (return traffic) + ICMP (diagnostics).
	if err := run(ctx, t.bin, "-A", inputChain,
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("%s conntrack rule: %w", t.bin, err)
	}
	if err := run(ctx, t.bin, "-A", inputChain, "-p", t.icmpProto, "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("%s icmp rule: %w", t.bin, err)
	}

	for _, port := range m.cfg.AllowedTCPPorts {
		if port <= 0 {
			continue
		}
		if err := run(ctx, t.bin, "-A", inputChain,
			"-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"); err != nil {
			return fmt.Errorf("%s allow tcp/%d: %w", t.bin, port, err)
		}
	}

	// Host-native services: source-scoped ACCEPTs above the terminal DROP.
	v6 := t.bin == "ip6tables"
	for _, args := range portGrantRules(inputChain, m.portGrants, v6) {
		if err := run(ctx, t.bin, args...); err != nil {
			return fmt.Errorf("%s port grant input rule %v: %w", t.bin, args, err)
		}
	}

	if err := run(ctx, t.bin, "-A", inputChain, "-j", "DROP"); err != nil {
		return fmt.Errorf("%s input drop: %w", t.bin, err)
	}

	// Docker publishes container ports via DNAT, so they traverse FORWARD, not
	// INPUT. Return traffic rides Docker's own forward rules.
	for _, args := range portGrantRules(forwardChain, m.portGrants, v6) {
		if err := run(ctx, t.bin, args...); err != nil {
			return fmt.Errorf("%s port grant forward rule %v: %w", t.bin, args, err)
		}
	}

	if err := run(ctx, t.bin, "-A", forwardChain, "-j", "DROP"); err != nil {
		return fmt.Errorf("%s forward drop: %w", t.bin, err)
	}

	// Top of chain wins over permissive default-accept rules.
	if err := run(ctx, t.bin, "-I", "INPUT", "1", "-i", m.cfg.Iface, "-j", inputChain); err != nil {
		return fmt.Errorf("%s install INPUT jump: %w", t.bin, err)
	}
	if err := run(ctx, t.bin, "-I", "FORWARD", "1", "-i", m.cfg.Iface, "-j", forwardChain); err != nil {
		_ = run(ctx, t.bin, "-D", "INPUT", "-i", m.cfg.Iface, "-j", inputChain)
		return fmt.Errorf("%s install FORWARD jump: %w", t.bin, err)
	}
	return nil
}

// SetPortGrants swaps the grants and rebuilds. No-op when unchanged.
func (m *Manager) SetPortGrants(ctx context.Context, grants []PortGrant) error {
	m.mu.Lock()
	if grantsEqual(m.portGrants, grants) {
		m.mu.Unlock()
		return nil
	}
	m.portGrants = grants
	enabled := m.enabled
	m.mu.Unlock()

	// Stored until the first Apply (startup) emits them once the chain exists.
	if !enabled {
		return nil
	}
	return m.Apply(ctx)
}

// portGrantRules expands grants into arg vectors for chain, one per
// (ip, proto, port). v6 selects which family's source address is emitted, so
// each rule lands in the matching table.
func portGrantRules(chain string, grants []PortGrant, v6 bool) [][]string {
	var rules [][]string
	for _, g := range grants {
		src := g.SourceIP
		if v6 {
			src = g.SourceIPv6
		}
		if src == "" {
			continue
		}
		for _, port := range g.TCP {
			if port <= 0 {
				continue
			}
			rules = append(rules, []string{"-A", chain,
				"-s", src, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"})
		}
		for _, port := range g.UDP {
			if port <= 0 {
				continue
			}
			rules = append(rules, []string{"-A", chain,
				"-s", src, "-p", "udp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"})
		}
	}
	return rules
}

func grantsEqual(a, b []PortGrant) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].SourceIP != b[i].SourceIP || a[i].SourceIPv6 != b[i].SourceIPv6 ||
			!intsEqual(a[i].TCP, b[i].TCP) || !intsEqual(a[i].UDP, b[i].UDP) {
			return false
		}
	}
	return true
}

func intsEqual(a, b []int) bool {
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

// Re-applies if the INPUT jump disappears (firewalld reload, `iptables
// -F`, Docker daemon restart, etc).
func (m *Manager) StartWatchdog(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.mu.Lock()
				enabled, iface := m.enabled, m.cfg.Iface
				m.mu.Unlock()
				if !enabled {
					continue
				}
				// -C exits non-zero when the rule is absent, in either table.
				present := true
				for _, t := range tables {
					if err := run(ctx, t.bin, "-C", "INPUT", "-i", iface, "-j", inputChain); err != nil {
						present = false
						break
					}
				}
				if present {
					continue
				}
				logging.Warn("firewall: INPUT jump for %s missing — re-applying ruleset", iface)
				if err := m.Apply(ctx); err != nil {
					logging.Error("firewall: re-apply failed: %v", err)
				}
			}
		}
	}()
}

func (m *Manager) Stop(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return
	}
	m.teardown(ctx)
	m.enabled = false
}

// Errors swallowed — a missing rule is the desired post-state.
func (m *Manager) teardown(ctx context.Context) {
	for _, t := range tables {
		// Drain any accumulated duplicate jumps.
		for i := 0; i < 8; i++ {
			if err := run(ctx, t.bin, "-D", "INPUT", "-i", m.cfg.Iface, "-j", inputChain); err != nil {
				break
			}
		}
		for i := 0; i < 8; i++ {
			if err := run(ctx, t.bin, "-D", "FORWARD", "-i", m.cfg.Iface, "-j", forwardChain); err != nil {
				break
			}
		}
		_ = run(ctx, t.bin, "-F", inputChain)
		_ = run(ctx, t.bin, "-F", forwardChain)
		_ = run(ctx, t.bin, "-X", inputChain)
		_ = run(ctx, t.bin, "-X", forwardChain)
	}
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
