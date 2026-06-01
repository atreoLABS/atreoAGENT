package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvOverride_AllPortFields(t *testing.T) {
	t.Setenv("WG_PORT", "12345")
	t.Setenv("PROXY_AUTH_PORT", "9090")
	t.Setenv("PROXY_HTTP_PORT", "8080")
	t.Setenv("PROXY_HTTPS_PORT", "8443")
	t.Setenv("ENDPOINT_IP", "1.2.3.4")
	t.Setenv("ENDPOINT_PORT", "55555")
	t.Setenv("NOTIFY_PORT", "9999")
	t.Setenv("DATA_DIR", "/tmp/atreoagent-test")

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	if cfg.WireGuard.ListenPort != 12345 {
		t.Errorf("WG_PORT not applied: %d", cfg.WireGuard.ListenPort)
	}
	if cfg.Proxy.AuthPort != 9090 {
		t.Errorf("PROXY_AUTH_PORT not applied: %d", cfg.Proxy.AuthPort)
	}
	if cfg.Proxy.HTTPPort != 8080 {
		t.Errorf("PROXY_HTTP_PORT not applied: %d", cfg.Proxy.HTTPPort)
	}
	if cfg.Proxy.HTTPSPort != 8443 {
		t.Errorf("PROXY_HTTPS_PORT not applied: %d", cfg.Proxy.HTTPSPort)
	}
	if cfg.EndpointIP != "1.2.3.4" {
		t.Errorf("ENDPOINT_IP not applied: %q", cfg.EndpointIP)
	}
	if cfg.EndpointPort != 55555 {
		t.Errorf("ENDPOINT_PORT not applied: %d", cfg.EndpointPort)
	}
	if cfg.Notify.Port != 9999 {
		t.Errorf("NOTIFY_PORT not applied: %d", cfg.Notify.Port)
	}
	if cfg.DataDir != "/tmp/atreoagent-test" {
		t.Errorf("DATA_DIR not applied: %q", cfg.DataDir)
	}
}

func TestEnvOverride_MalformedPortsIgnored(t *testing.T) {
	t.Setenv("WG_PORT", "not-a-number")
	t.Setenv("PROXY_AUTH_PORT", "abc")
	t.Setenv("PROXY_HTTP_PORT", "")
	t.Setenv("ENDPOINT_PORT", "ten")
	t.Setenv("NOTIFY_PORT", "thousands")
	t.Setenv("PROXY_HTTPS_PORT", "12.5")

	cfg := DefaultConfig()
	originalWG := cfg.WireGuard.ListenPort
	originalAuth := cfg.Proxy.AuthPort
	originalNotify := cfg.Notify.Port

	applyEnvOverrides(cfg)

	if cfg.WireGuard.ListenPort != originalWG {
		t.Errorf("WG_PORT mistake: %d, want unchanged %d", cfg.WireGuard.ListenPort, originalWG)
	}
	if cfg.Proxy.AuthPort != originalAuth {
		t.Errorf("PROXY_AUTH_PORT mistake: %d, want unchanged %d", cfg.Proxy.AuthPort, originalAuth)
	}
	if cfg.Notify.Port != originalNotify {
		t.Errorf("NOTIFY_PORT mistake: %d, want unchanged %d", cfg.Notify.Port, originalNotify)
	}
}

// TestLoad_FillsDefaultsFromEmptyYAML exercises applyDefaults through the
// public Load entry point — the path real callers use.
func TestLoad_FillsDefaultsFromEmptyYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("# empty\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.HasPrefix(cfg.AtreoLinkAPIURL, "https://") {
		t.Errorf("AtreoLinkAPIURL=%q", cfg.AtreoLinkAPIURL)
	}
	if cfg.WireGuard.ListenPort == 0 || cfg.WireGuard.TunnelSubnet == "" || cfg.WireGuard.ServerIP == "" {
		t.Errorf("WireGuard defaults missing: %+v", cfg.WireGuard)
	}
	if cfg.Proxy.HTTPPort == 0 || cfg.Proxy.HTTPSPort == 0 || cfg.Proxy.AuthPort == 0 {
		t.Errorf("Proxy defaults missing: %+v", cfg.Proxy)
	}
	if cfg.Notify.Port == 0 {
		t.Errorf("Notify.Port=%d", cfg.Notify.Port)
	}
	if cfg.Proxy.Enabled == nil || !*cfg.Proxy.Enabled {
		t.Error("Proxy.Enabled should default to true")
	}
}

func TestUPnPEnabled_DefaultsTrue(t *testing.T) {
	if cfg := DefaultConfig(); !cfg.WireGuard.UPnPEnabled {
		t.Fatal("UPnPEnabled should default to true")
	}
}

// An explicit `false` in YAML must survive, and WG_UPNP_ENABLED overrides it.
func TestUPnPEnabled_YAMLFalseSurvivesAndEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("wireguard:\n  upnp_enabled: false\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WireGuard.UPnPEnabled {
		t.Error("explicit upnp_enabled:false should survive, got true")
	}

	t.Setenv("WG_UPNP_ENABLED", "true")
	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg2.WireGuard.UPnPEnabled {
		t.Error("WG_UPNP_ENABLED=true should override YAML false, got false")
	}
}

func TestDataDirPaths(t *testing.T) {
	c := &Config{DataDir: "/data"}
	cases := map[string]string{
		c.PinholePath():          "/data/pcp_nonces.json",
		c.CustomDomainPath():     "/data/custom_domain.json",
		c.PortMappingAlertPath(): "/data/port_mapping_alert.cooldown",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}

func TestApplyDefaults_PreservesExisting(t *testing.T) {
	cfg := &Config{
		AtreoLinkAPIURL: "https://custom",
		AppsHostname:    "alice.example.com",
		DataDir:         "/data",
	}
	applyDefaults(cfg)
	if cfg.AtreoLinkAPIURL != "https://custom" {
		t.Errorf("AtreoLinkAPIURL clobbered: %q", cfg.AtreoLinkAPIURL)
	}
	if cfg.AppsHostname != "alice.example.com" {
		t.Errorf("AppsHostname clobbered: %q", cfg.AppsHostname)
	}
}

func TestPCPEnabled_DefaultsTrue(t *testing.T) {
	if cfg := DefaultConfig(); !cfg.WireGuard.PCPEnabled {
		t.Fatal("PCPEnabled should default to true")
	}
}

// An explicit `false` in YAML must survive, and WG_PCP_ENABLED overrides it.
func TestPCPEnabled_YAMLFalseSurvivesAndEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("wireguard:\n  pcp_enabled: false\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WireGuard.PCPEnabled {
		t.Error("explicit pcp_enabled:false should survive, got true")
	}

	t.Setenv("WG_PCP_ENABLED", "true")
	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg2.WireGuard.PCPEnabled {
		t.Error("WG_PCP_ENABLED=true should override YAML false, got false")
	}
}

// Covers the env `false`/`0` disable branches for both new toggles.
func TestNewToggles_EnvDisable(t *testing.T) {
	t.Setenv("WG_PCP_ENABLED", "0")
	t.Setenv("WG_IPV6_PINHOLE_ENABLED", "false")

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	if cfg.WireGuard.PCPEnabled {
		t.Error("WG_PCP_ENABLED=0 should disable PCP")
	}
	if cfg.WireGuard.IPv6PinholeEnabled == nil || *cfg.WireGuard.IPv6PinholeEnabled {
		t.Error("WG_IPV6_PINHOLE_ENABLED=false should disable v6 pinholes")
	}
}

func TestIPv6PinholeEnabled_DefaultsTrue(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.WireGuard.IPv6PinholeEnabled == nil || !*cfg.WireGuard.IPv6PinholeEnabled {
		t.Fatal("IPv6PinholeEnabled should default to true")
	}
	// applyDefaults must fill a nil pointer (config saved before the field existed).
	cfg.WireGuard.IPv6PinholeEnabled = nil
	applyDefaults(cfg)
	if cfg.WireGuard.IPv6PinholeEnabled == nil || !*cfg.WireGuard.IPv6PinholeEnabled {
		t.Fatal("applyDefaults should fill nil IPv6PinholeEnabled to true")
	}
}

// *bool: explicit `false` in YAML survives the default, and the env var
// (tri-state) overrides it back to true.
func TestIPv6PinholeEnabled_YAMLFalseSurvivesAndEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("wireguard:\n  ipv6_pinhole_enabled: false\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WireGuard.IPv6PinholeEnabled == nil || *cfg.WireGuard.IPv6PinholeEnabled {
		t.Error("explicit ipv6_pinhole_enabled:false should survive, got true/nil")
	}

	t.Setenv("WG_IPV6_PINHOLE_ENABLED", "true")
	cfg2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg2.WireGuard.IPv6PinholeEnabled == nil || !*cfg2.WireGuard.IPv6PinholeEnabled {
		t.Error("WG_IPV6_PINHOLE_ENABLED=true should override YAML false")
	}
}
