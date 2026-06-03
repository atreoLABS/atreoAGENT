package firewall

import (
	"context"
	"os/exec"
	"testing"
)

func TestApply_NoIptables(t *testing.T) {
	// Fail closed: without iptables on PATH, Apply must return an error so
	// the agent refuses to admit peers unconfined. Simulate a missing binary
	// by pointing PATH at an empty dir (portable regardless of host setup).
	t.Setenv("PATH", t.TempDir())
	m := NewManager(Config{Iface: "wg-atreo", AllowedTCPPorts: []int{443}})
	if err := m.Apply(context.Background()); err == nil {
		t.Error("Apply with no iptables on PATH should return an error (fail closed)")
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
