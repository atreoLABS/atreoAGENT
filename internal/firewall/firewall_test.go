package firewall

import (
	"context"
	"os/exec"
	"reflect"
	"testing"
)

func TestPortGrantRules(t *testing.T) {
	grants := []PortGrant{
		{SourceIP: "100.64.0.2", TCP: []int{25565}},
		{SourceIP: "100.64.0.3", UDP: []int{19132}},
		{SourceIP: "100.64.0.4", TCP: []int{22, 5432}, UDP: []int{51820}},
		{SourceIP: "", TCP: []int{80}},              // no source: skipped
		{SourceIP: "100.64.0.5", TCP: []int{0, -1}}, // bad ports: skipped
	}
	got := portGrantRules(inputChain, grants)
	want := [][]string{
		{"-A", inputChain, "-s", "100.64.0.2", "-p", "tcp", "--dport", "25565", "-j", "ACCEPT"},
		{"-A", inputChain, "-s", "100.64.0.3", "-p", "udp", "--dport", "19132", "-j", "ACCEPT"},
		{"-A", inputChain, "-s", "100.64.0.4", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
		{"-A", inputChain, "-s", "100.64.0.4", "-p", "tcp", "--dport", "5432", "-j", "ACCEPT"},
		{"-A", inputChain, "-s", "100.64.0.4", "-p", "udp", "--dport", "51820", "-j", "ACCEPT"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("portGrantRules mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestPortGrantRules_ForwardChain(t *testing.T) {
	// Docker-published ports traverse FORWARD; the same grants must emit there.
	grants := []PortGrant{{SourceIP: "100.64.0.2", TCP: []int{9443}}}
	got := portGrantRules(forwardChain, grants)
	want := [][]string{
		{"-A", forwardChain, "-s", "100.64.0.2", "-p", "tcp", "--dport", "9443", "-j", "ACCEPT"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("forward portGrantRules mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestPortGrantRules_Empty(t *testing.T) {
	if rules := portGrantRules(inputChain, nil); len(rules) != 0 {
		t.Errorf("expected no rules for nil grants, got %v", rules)
	}
}

func TestSetPortGrants_NoChainNoApply(t *testing.T) {
	// Grants are stored even before the chain exists, but no Apply runs
	// (enabled=false) — so a missing iptables binary must NOT surface here.
	t.Setenv("PATH", t.TempDir())
	m := NewManager(Config{Iface: "wg-atreo", AllowedTCPPorts: []int{443}})
	g := []PortGrant{{SourceIP: "100.64.0.2", TCP: []int{25565}}}
	if err := m.SetPortGrants(context.Background(), g); err != nil {
		t.Fatalf("SetPortGrants before Apply should not error: %v", err)
	}
	if !grantsEqual(m.portGrants, g) {
		t.Error("grants not stored")
	}
}

func TestGrantsEqual(t *testing.T) {
	a := []PortGrant{{SourceIP: "100.64.0.2", TCP: []int{1, 2}, UDP: []int{3}}}
	b := []PortGrant{{SourceIP: "100.64.0.2", TCP: []int{1, 2}, UDP: []int{3}}}
	if !grantsEqual(a, b) {
		t.Error("identical grants should be equal")
	}
	c := []PortGrant{{SourceIP: "100.64.0.2", TCP: []int{1, 2}, UDP: []int{4}}}
	if grantsEqual(a, c) {
		t.Error("differing UDP ports should not be equal")
	}
	if grantsEqual(a, nil) {
		t.Error("grant vs nil should not be equal")
	}
}

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
