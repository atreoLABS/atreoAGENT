package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// AppsHostname has no built-in default — it's set from atreoLINK at
	// pair time so the agent uses whatever the operator's deployment
	// is configured for.
	if cfg.AppsHostname != "" {
		t.Errorf("AppsHostname = %q, want empty (populated at pair)", cfg.AppsHostname)
	}
	if cfg.DataDir != "/var/lib/atreoagent" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/var/lib/atreoagent")
	}
	if cfg.WireGuard.ListenPort != 51820 {
		t.Errorf("WG ListenPort = %d, want %d", cfg.WireGuard.ListenPort, 51820)
	}
	// Overlay addressing is fixed (non-configurable) — assert the constants.
	if OverlaySubnetV4 != "100.64.0.0/24" {
		t.Errorf("OverlaySubnetV4 = %q, want %q", OverlaySubnetV4, "100.64.0.0/24")
	}
	if OverlayServerIPv4 != "100.64.0.1" {
		t.Errorf("OverlayServerIPv4 = %q, want %q", OverlayServerIPv4, "100.64.0.1")
	}
	if OverlayServerIPv6 != "fd00:64::1" {
		t.Errorf("OverlayServerIPv6 = %q, want %q", OverlayServerIPv6, "fd00:64::1")
	}
	if cfg.Proxy.HTTPSPort != 443 {
		t.Errorf("Proxy HTTPSPort = %d, want %d", cfg.Proxy.HTTPSPort, 443)
	}
}

// applyDefaults must seed the SMTP allowlist with the LAN/WG default when
// the operator leaves trusted_networks unset — the broad 0.0.0.0 bind relies
// on this allowlist to stay LAN-only.
func TestApplyDefaults_SMTPTrustedNetworks(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	if len(cfg.SMTP.TrustedNetworks) == 0 {
		t.Fatal("SMTP.TrustedNetworks should default to a LAN allowlist, got empty")
	}
	wantContains := map[string]bool{"10.0.0.0/8": false, "192.168.0.0/16": false, "100.64.0.0/24": false}
	for _, c := range cfg.SMTP.TrustedNetworks {
		if _, ok := wantContains[c]; ok {
			wantContains[c] = true
		}
	}
	for cidr, found := range wantContains {
		if !found {
			t.Errorf("default SMTP allowlist missing %s", cidr)
		}
	}

	// An operator-provided list must survive untouched.
	custom := &Config{SMTP: SMTPConfig{TrustedNetworks: []string{"172.20.0.0/16"}}}
	applyDefaults(custom)
	if len(custom.SMTP.TrustedNetworks) != 1 || custom.SMTP.TrustedNetworks[0] != "172.20.0.0/16" {
		t.Errorf("operator allowlist overwritten: %v", custom.SMTP.TrustedNetworks)
	}
}

// SavePairing persists only the three identity fields to pairing.json,
// never touches config.yaml, and Load repopulates them while leaving
// runtime-derived values (endpoint_ip) at their non-frozen defaults.
func TestSavePairingLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.DeviceID = "dev-001"
	cfg.AppsHostname = "mynas.myatreo.com"
	cfg.TunnelHost = "dev-001.atreo.link"

	if err := cfg.SavePairing(); err != nil {
		t.Fatalf("SavePairing: %v", err)
	}

	if _, err := os.Stat(cfg.ConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("config.yaml must not be written by the agent (stat err=%v)", err)
	}

	raw, err := os.ReadFile(cfg.PairingPath())
	if err != nil {
		t.Fatalf("read pairing.json: %v", err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("parse pairing.json: %v", err)
	}
	for _, k := range []string{"device_id", "apps_hostname", "tunnel_host"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("pairing.json missing key %q", k)
		}
	}
	if len(keys) != 3 {
		t.Errorf("pairing.json has %d keys, want exactly 3 (got %v)", len(keys), keys)
	}

	t.Setenv("DATA_DIR", dir)
	loaded, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.DeviceID != cfg.DeviceID {
		t.Errorf("DeviceID = %q, want %q", loaded.DeviceID, cfg.DeviceID)
	}
	if loaded.AppsHostname != cfg.AppsHostname {
		t.Errorf("AppsHostname = %q, want %q", loaded.AppsHostname, cfg.AppsHostname)
	}
	if loaded.TunnelHost != cfg.TunnelHost {
		t.Errorf("TunnelHost = %q, want %q", loaded.TunnelHost, cfg.TunnelHost)
	}
	if loaded.EndpointIP != "" {
		t.Errorf("EndpointIP = %q, want empty — must stay unset so atreoLINK auto-resolution works", loaded.EndpointIP)
	}
}

// pairing.json is authoritative; a hand-authored config.yaml device_id
// survives only as a bridge and loses to pairing.json when both exist.
func TestPairingOverridesConfigYAMLBridge(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\ndevice_id: bridge-dev\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ps := DefaultConfig()
	ps.DataDir = dir
	ps.DeviceID = "paired-dev"
	if err := ps.SavePairing(); err != nil {
		t.Fatalf("SavePairing: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DeviceID != "paired-dev" {
		t.Errorf("DeviceID = %q, want %q (pairing.json wins over config.yaml bridge)", cfg.DeviceID, "paired-dev")
	}
}

// Corrupt pairing.json must fail closed — silently treating it as
// unpaired would trigger a destructive re-pair.
func TestLoadCorruptPairingFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("data_dir: "+dir+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pairing.json"), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("Load should fail on corrupt pairing.json")
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("ATREOLINK_API_URL", "https://env.example.com")
	t.Setenv("ATREOLINK_APP_URL", "https://app.env.example.com")
	t.Setenv("DATA_DIR", "/tmp/atreo-test")
	t.Setenv("WG_PORT", "51821")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.AtreoLinkAPIURL != "https://env.example.com" {
		t.Errorf("AtreoLinkAPIURL = %q, want %q", cfg.AtreoLinkAPIURL, "https://env.example.com")
	}
	if cfg.AtreoLinkAppURL != "https://app.env.example.com" {
		t.Errorf("AtreoLinkAppURL = %q, want %q", cfg.AtreoLinkAppURL, "https://app.env.example.com")
	}
	if cfg.DataDir != "/tmp/atreo-test" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/tmp/atreo-test")
	}
	if cfg.WireGuard.ListenPort != 51821 {
		t.Errorf("WG ListenPort = %d, want %d", cfg.WireGuard.ListenPort, 51821)
	}
}

func TestRelayForceEnv(t *testing.T) {
	t.Setenv("DATA_DIR", "/tmp/atreo-test")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Relay.Force {
		t.Error("Relay.Force should default false")
	}

	t.Setenv("RELAY_FORCE", "true")
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Relay.Force {
		t.Error("RELAY_FORCE=true should set Relay.Force")
	}

	// An explicit RELAY_FORCE=0 must clear a YAML/default-set force.
	forced := &Config{Relay: RelayConfig{Force: true}}
	t.Setenv("RELAY_FORCE", "0")
	applyEnvOverrides(forced)
	if forced.Relay.Force {
		t.Error("RELAY_FORCE=0 should clear Relay.Force")
	}
}

// RELAY_ENABLED is a *bool override: it must be able to both disable a
// default-true config and re-enable a config that was set false.
func TestRelayEnabledEnv(t *testing.T) {
	t.Run("disable", func(t *testing.T) {
		t.Setenv("RELAY_ENABLED", "false")
		cfg := DefaultConfig() // Enabled defaults true
		applyEnvOverrides(cfg)
		if cfg.Relay.Enabled == nil || *cfg.Relay.Enabled {
			t.Errorf("RELAY_ENABLED=false should set Relay.Enabled to false, got %v", cfg.Relay.Enabled)
		}
	})

	t.Run("enable", func(t *testing.T) {
		t.Setenv("RELAY_ENABLED", "1")
		f := false
		cfg := &Config{Relay: RelayConfig{Enabled: &f}}
		applyEnvOverrides(cfg)
		if cfg.Relay.Enabled == nil || !*cfg.Relay.Enabled {
			t.Errorf("RELAY_ENABLED=1 should set Relay.Enabled to true, got %v", cfg.Relay.Enabled)
		}
	})
}

func TestHelperPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataDir = "/data"

	if cfg.ConfigPath() != "/data/config.yaml" {
		t.Errorf("ConfigPath = %q", cfg.ConfigPath())
	}
	if cfg.KeysDir() != "/data/keys" {
		t.Errorf("KeysDir = %q", cfg.KeysDir())
	}
	if cfg.ACLPath() != "/data/acl.json" {
		t.Errorf("ACLPath = %q", cfg.ACLPath())
	}
	if cfg.IPAllocPath() != "/data/ip_alloc.json" {
		t.Errorf("IPAllocPath = %q", cfg.IPAllocPath())
	}
	if cfg.CertsDir() != "/data/certs" {
		t.Errorf("CertsDir = %q", cfg.CertsDir())
	}
}

func TestLoadNonexistentPath(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("Load should not error for nonexistent file: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}
}

// TestProxyEnabledYAMLAbsentDefaultsTrue confirms that a config file with
// no `proxy.enabled` key produces Proxy.Enabled == true after Load.
func TestProxyEnabledYAMLAbsentDefaultsTrue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("apps_hostname: mynas.myatreo.com\n"), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.Enabled == nil || !*cfg.Proxy.Enabled {
		t.Errorf("Proxy.Enabled = %v, want true (default when YAML omits key)", cfg.Proxy.Enabled)
	}
	// Confirm the apps_hostname YAML key parses into the renamed field.
	if cfg.AppsHostname != "mynas.myatreo.com" {
		t.Errorf("AppsHostname = %q, want %q", cfg.AppsHostname, "mynas.myatreo.com")
	}
}

// TestProxyEnabledYAMLFalseHonoured confirms that `proxy: { enabled: false }`
// in YAML survives applyDefaults (which otherwise sets it back to true).
func TestProxyEnabledYAMLFalseHonoured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("proxy:\n  enabled: false\n"), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.Enabled == nil || *cfg.Proxy.Enabled {
		t.Errorf("Proxy.Enabled = %v, want false (YAML explicitly set it)", cfg.Proxy.Enabled)
	}
}

// TestProxyEnabledEnvWinsOverYAML confirms env var overrides YAML.
func TestProxyEnabledEnvWinsOverYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("proxy:\n  enabled: false\n"), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	t.Setenv("PROXY_ENABLED", "true")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Proxy.Enabled == nil || !*cfg.Proxy.Enabled {
		t.Errorf("Proxy.Enabled = %v, want true (env overrides YAML)", cfg.Proxy.Enabled)
	}
}

func TestSavePairingCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()

	cfg := DefaultConfig()
	cfg.DataDir = filepath.Join(dir, "sub", "deep")
	cfg.DeviceID = "dev-x"
	if err := cfg.SavePairing(); err != nil {
		t.Fatalf("SavePairing: %v", err)
	}

	if _, err := os.Stat(cfg.PairingPath()); err != nil {
		t.Fatalf("pairing.json not created: %v", err)
	}
}
