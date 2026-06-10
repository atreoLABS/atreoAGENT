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

type Config struct {
	Iface           string // WG interface name (e.g. "wg-atreo")
	AllowedTCPPorts []int  // ports peers may reach (the proxy HTTP/HTTPS)
}

// PortGrant lets one peer (by tunnel source IP) reach a set of raw host ports.
type PortGrant struct {
	SourceIP string
	TCP      []int
	UDP      []int
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
// Fails closed: a missing iptables binary is an error so the caller can
// refuse to bring up the tunnel rather than admit peers unconfined.
func (m *Manager) Apply(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("firewall: iptables not on PATH: %w", err)
	}
	if m.cfg.Iface == "" {
		return fmt.Errorf("firewall: empty iface")
	}

	m.teardown(ctx)

	if err := run(ctx, "iptables", "-N", inputChain); err != nil {
		return fmt.Errorf("create %s: %w", inputChain, err)
	}
	if err := run(ctx, "iptables", "-N", forwardChain); err != nil {
		_ = run(ctx, "iptables", "-X", inputChain)
		return fmt.Errorf("create %s: %w", forwardChain, err)
	}

	// established/related (return traffic) + ICMP (diagnostics).
	if err := run(ctx, "iptables", "-A", inputChain,
		"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		m.teardown(ctx)
		return fmt.Errorf("conntrack rule: %w", err)
	}
	if err := run(ctx, "iptables", "-A", inputChain, "-p", "icmp", "-j", "ACCEPT"); err != nil {
		m.teardown(ctx)
		return fmt.Errorf("icmp rule: %w", err)
	}

	for _, port := range m.cfg.AllowedTCPPorts {
		if port <= 0 {
			continue
		}
		if err := run(ctx, "iptables", "-A", inputChain,
			"-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"); err != nil {
			m.teardown(ctx)
			return fmt.Errorf("allow tcp/%d: %w", port, err)
		}
	}

	// Host-native services: source-scoped ACCEPTs above the terminal DROP.
	for _, args := range portGrantRules(inputChain, m.portGrants) {
		if err := run(ctx, "iptables", args...); err != nil {
			m.teardown(ctx)
			return fmt.Errorf("port grant input rule %v: %w", args, err)
		}
	}

	if err := run(ctx, "iptables", "-A", inputChain, "-j", "DROP"); err != nil {
		m.teardown(ctx)
		return fmt.Errorf("input drop: %w", err)
	}

	// Docker publishes container ports via DNAT, so they traverse FORWARD, not
	// INPUT. Return traffic rides Docker's own forward rules.
	for _, args := range portGrantRules(forwardChain, m.portGrants) {
		if err := run(ctx, "iptables", args...); err != nil {
			m.teardown(ctx)
			return fmt.Errorf("port grant forward rule %v: %w", args, err)
		}
	}

	if err := run(ctx, "iptables", "-A", forwardChain, "-j", "DROP"); err != nil {
		m.teardown(ctx)
		return fmt.Errorf("forward drop: %w", err)
	}

	// Top of chain wins over permissive default-accept rules.
	if err := run(ctx, "iptables", "-I", "INPUT", "1", "-i", m.cfg.Iface, "-j", inputChain); err != nil {
		m.teardown(ctx)
		return fmt.Errorf("install INPUT jump: %w", err)
	}
	if err := run(ctx, "iptables", "-I", "FORWARD", "1", "-i", m.cfg.Iface, "-j", forwardChain); err != nil {
		_ = run(ctx, "iptables", "-D", "INPUT", "-i", m.cfg.Iface, "-j", inputChain)
		m.teardown(ctx)
		return fmt.Errorf("install FORWARD jump: %w", err)
	}

	m.enabled = true
	logging.Info("firewall: tunnel access on %s restricted to TCP %v + ICMP", m.cfg.Iface, m.cfg.AllowedTCPPorts)
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

// portGrantRules expands grants into iptables arg vectors for chain, one per
// (ip, proto, port).
func portGrantRules(chain string, grants []PortGrant) [][]string {
	var rules [][]string
	for _, g := range grants {
		if g.SourceIP == "" {
			continue
		}
		for _, port := range g.TCP {
			if port <= 0 {
				continue
			}
			rules = append(rules, []string{"-A", chain,
				"-s", g.SourceIP, "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"})
		}
		for _, port := range g.UDP {
			if port <= 0 {
				continue
			}
			rules = append(rules, []string{"-A", chain,
				"-s", g.SourceIP, "-p", "udp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"})
		}
	}
	return rules
}

func grantsEqual(a, b []PortGrant) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].SourceIP != b[i].SourceIP ||
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
				// -C exits non-zero when the rule is absent.
				if err := run(ctx, "iptables", "-C", "INPUT", "-i", iface, "-j", inputChain); err == nil {
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
	// Drain any accumulated duplicate jumps.
	for i := 0; i < 8; i++ {
		if err := run(ctx, "iptables", "-D", "INPUT", "-i", m.cfg.Iface, "-j", inputChain); err != nil {
			break
		}
	}
	for i := 0; i < 8; i++ {
		if err := run(ctx, "iptables", "-D", "FORWARD", "-i", m.cfg.Iface, "-j", forwardChain); err != nil {
			break
		}
	}
	_ = run(ctx, "iptables", "-F", inputChain)
	_ = run(ctx, "iptables", "-F", forwardChain)
	_ = run(ctx, "iptables", "-X", inputChain)
	_ = run(ctx, "iptables", "-X", forwardChain)
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
