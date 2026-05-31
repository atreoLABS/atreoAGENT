package firewall

import (
	"context"
	"os/exec"
	"testing"
)

func TestApply_NoIptables(t *testing.T) {
	// On any test host without iptables on PATH, Apply must degrade
	// gracefully — log a warning and return nil. We can't simulate the
	// missing-binary case portably, so just exercise the early-return
	// branch when iptables isn't available.
	if _, err := exec.LookPath("iptables"); err == nil {
		t.Skip("iptables present; this test only meaningful when missing")
	}
	m := NewManager(Config{Iface: "wg-atreo", AllowedTCPPorts: []int{443}})
	if err := m.Apply(context.Background()); err != nil {
		t.Errorf("Apply with no iptables returned error: %v", err)
	}
	// Stop on a non-applied manager is a no-op.
	m.Stop(context.Background())
}

func TestApply_EmptyIface(t *testing.T) {
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables required for this branch")
	}
	m := NewManager(Config{Iface: "", AllowedTCPPorts: []int{443}})
	if err := m.Apply(context.Background()); err == nil {
		t.Error("Apply with empty iface should error")
	}
}

func TestNewManager_StoresConfig(t *testing.T) {
	cfg := Config{Iface: "wg-atreo", AllowedTCPPorts: []int{80, 443}}
	m := NewManager(cfg)
	if m.cfg.Iface != "wg-atreo" {
		t.Errorf("iface = %q, want wg-atreo", m.cfg.Iface)
	}
	if len(m.cfg.AllowedTCPPorts) != 2 {
		t.Errorf("ports len = %d, want 2", len(m.cfg.AllowedTCPPorts))
	}
	if m.enabled {
		t.Error("manager should not be enabled before Apply")
	}
}
