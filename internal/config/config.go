package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/atreoLABS/atreoAGENT/internal/atomic"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

type Config struct {
	// Not YAML-configurable; ATREOLINK_API_URL / ATREOLINK_APP_URL
	// override for development.
	AtreoLinkAPIURL string          `yaml:"-"`
	AtreoLinkAppURL string          `yaml:"-"`
	LogLevel        string          `yaml:"log_level"`
	DeviceID        string          `yaml:"device_id"`
	AppsHostname    string          `yaml:"apps_hostname"` // populated from atreoLINK at pair time
	TunnelHost      string          `yaml:"tunnel_host"`   // per-device DDNS host; bound into the v2 transcript
	DataDir         string          `yaml:"data_dir"`
	EndpointIP      string          `yaml:"endpoint_ip"`   // manual fallback when UPnP fails
	EndpointPort    int             `yaml:"endpoint_port"` // manual fallback when UPnP fails
	WireGuard       WireGuardConfig `yaml:"wireguard"`
	Proxy           ProxyConfig     `yaml:"proxy"`
	Certs           CertsConfig     `yaml:"certs"`
	Notify          NotifyConfig    `yaml:"notify"`
	SMTP            SMTPConfig      `yaml:"smtp"`
}

// LAN-only SMTP-to-push gateway. AUTH (PLAIN/LOGIN, password = notify
// API key) is always required; STARTTLS is opt-in.
type SMTPConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Listen          string `yaml:"listen"`            // default: "0.0.0.0:2525"
	MaxMessageBytes int64  `yaml:"max_message_bytes"` // default: 1 MiB
	RatePerMinute   int    `yaml:"rate_per_minute"`   // default: 5 per source IP
	TLSEnabled      bool   `yaml:"tls_enabled"`       // self-signed; clients must skip cert verification
}

type NotifyConfig struct {
	Port int `yaml:"port"` // default: 9876
}

// FirewallEnabled is *bool so an explicit `false` in YAML survives the
// default. Disabling exposes every host port to every paired peer.
// IPv6PinholeEnabled is *bool so an explicit `false` in YAML survives the
// default; it gates opening IPv6 firewall pinholes (PCP / UPnP IGDv2) for the
// WireGuard port, for operators who prefer a manual router-firewall rule.
type WireGuardConfig struct {
	ListenPort         int    `yaml:"listen_port"`
	TunnelSubnet       string `yaml:"tunnel_subnet"`
	ServerIP           string `yaml:"server_ip"`
	FirewallEnabled    *bool  `yaml:"firewall_enabled,omitempty"`     // default: true
	UPnPEnabled        bool   `yaml:"upnp_enabled"`                   // default: true
	PCPEnabled         bool   `yaml:"pcp_enabled"`                    // default: true; PCP (RFC 6887), both families
	IPv6PinholeEnabled *bool  `yaml:"ipv6_pinhole_enabled,omitempty"` // default: true
}

// Enabled is *bool so an explicit `false` in YAML survives the default.
// TrustedProxies controls X-Forwarded-* handling on the forward-auth
// endpoint; empty means trust only the TCP peer.
type ProxyConfig struct {
	Enabled         *bool    `yaml:"enabled,omitempty"`
	HTTPPort        int      `yaml:"http_port"`
	HTTPSPort       int      `yaml:"https_port"`
	AuthPort        int      `yaml:"auth_port"`
	TrustedNetworks []string `yaml:"trusted_networks"`
	TrustedProxies  []string `yaml:"trusted_proxies"`
}

type CertsConfig struct {
	Email   string `yaml:"email,omitempty"`
	CertDir string `yaml:"cert_dir"`
}

// AppsHostname is left empty so atreoLINK's value at pair time wins.
func DefaultConfig() *Config {
	enabled := true
	return &Config{
		AtreoLinkAPIURL: "https://api.atreolink.com",
		AtreoLinkAppURL: "https://app.atreolink.com",
		LogLevel:        "info",
		DataDir:         "/var/lib/atreoagent",
		WireGuard: WireGuardConfig{
			ListenPort:         51820,
			TunnelSubnet:       "100.64.0.0/24",
			ServerIP:           "100.64.0.1",
			FirewallEnabled:    &enabled,
			UPnPEnabled:        true,
			PCPEnabled:         true,
			IPv6PinholeEnabled: &enabled,
		},
		Proxy: ProxyConfig{
			Enabled:   &enabled,
			HTTPPort:  80,
			HTTPSPort: 443,
			AuthPort:  9091,
		},
		Certs: CertsConfig{
			CertDir: "/var/lib/atreoagent/certs",
		},
	}
}

// Empty path falls back to <dataDir>/config.yaml.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		path = cfg.ConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	applyDefaults(cfg)
	applyEnvOverrides(cfg)
	if err := loadPairing(cfg); err != nil {
		return nil, err
	}
	if err := logging.Init(cfg.LogLevel); err != nil {
		return nil, fmt.Errorf("logging: %w", err)
	}
	return cfg, nil
}

// Handles configs saved before new fields existed.
func applyDefaults(cfg *Config) {
	if cfg.AtreoLinkAPIURL == "" {
		cfg.AtreoLinkAPIURL = "https://api.atreolink.com"
	}
	if cfg.AtreoLinkAppURL == "" {
		cfg.AtreoLinkAppURL = "https://app.atreolink.com"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/var/lib/atreoagent"
	}
	if cfg.WireGuard.ListenPort == 0 {
		cfg.WireGuard.ListenPort = 51820
	}
	if cfg.WireGuard.TunnelSubnet == "" {
		cfg.WireGuard.TunnelSubnet = "100.64.0.0/24"
	}
	if cfg.WireGuard.ServerIP == "" {
		cfg.WireGuard.ServerIP = "100.64.0.1"
	}
	if cfg.WireGuard.FirewallEnabled == nil {
		t := true
		cfg.WireGuard.FirewallEnabled = &t
	}
	if cfg.WireGuard.IPv6PinholeEnabled == nil {
		t := true
		cfg.WireGuard.IPv6PinholeEnabled = &t
	}
	if cfg.Proxy.HTTPPort == 0 {
		cfg.Proxy.HTTPPort = 80
	}
	if cfg.Proxy.HTTPSPort == 0 {
		cfg.Proxy.HTTPSPort = 443
	}
	if cfg.Proxy.AuthPort == 0 {
		cfg.Proxy.AuthPort = 9091
	}
	if cfg.Notify.Port == 0 {
		cfg.Notify.Port = 9876
	}
	if cfg.SMTP.Listen == "" {
		cfg.SMTP.Listen = "0.0.0.0:2525"
	}
	if cfg.SMTP.MaxMessageBytes == 0 {
		cfg.SMTP.MaxMessageBytes = 1 << 20 // 1 MiB
	}
	if cfg.SMTP.RatePerMinute == 0 {
		cfg.SMTP.RatePerMinute = 5
	}
	if cfg.Proxy.Enabled == nil {
		t := true
		cfg.Proxy.Enabled = &t
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("ATREOLINK_API_URL"); v != "" {
		cfg.AtreoLinkAPIURL = v
	}
	if v := os.Getenv("ATREOLINK_APP_URL"); v != "" {
		cfg.AtreoLinkAppURL = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("WG_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.WireGuard.ListenPort = port
		}
	}
	if v := os.Getenv("WG_FIREWALL_ENABLED"); v == "false" || v == "0" {
		f := false
		cfg.WireGuard.FirewallEnabled = &f
	} else if v == "true" || v == "1" {
		t := true
		cfg.WireGuard.FirewallEnabled = &t
	}
	if v := os.Getenv("WG_UPNP_ENABLED"); v == "false" || v == "0" {
		cfg.WireGuard.UPnPEnabled = false
	} else if v == "true" || v == "1" {
		cfg.WireGuard.UPnPEnabled = true
	}
	if v := os.Getenv("WG_PCP_ENABLED"); v == "false" || v == "0" {
		cfg.WireGuard.PCPEnabled = false
	} else if v == "true" || v == "1" {
		cfg.WireGuard.PCPEnabled = true
	}
	if v := os.Getenv("WG_IPV6_PINHOLE_ENABLED"); v == "false" || v == "0" {
		f := false
		cfg.WireGuard.IPv6PinholeEnabled = &f
	} else if v == "true" || v == "1" {
		t := true
		cfg.WireGuard.IPv6PinholeEnabled = &t
	}
	if v := os.Getenv("PROXY_AUTH_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.AuthPort = port
		}
	}
	if v := os.Getenv("PROXY_ENABLED"); v == "false" || v == "0" {
		f := false
		cfg.Proxy.Enabled = &f
	} else if v == "true" || v == "1" {
		t := true
		cfg.Proxy.Enabled = &t
	}
	if v := os.Getenv("PROXY_HTTP_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.HTTPPort = port
		}
	}
	if v := os.Getenv("PROXY_HTTPS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.HTTPSPort = port
		}
	}
	if v := os.Getenv("PROXY_TRUSTED_PROXIES"); v != "" {
		var cidrs []string
		for _, c := range strings.Split(v, ",") {
			if c = strings.TrimSpace(c); c != "" {
				cidrs = append(cidrs, c)
			}
		}
		cfg.Proxy.TrustedProxies = cidrs
	}
	if v := os.Getenv("ENDPOINT_IP"); v != "" {
		cfg.EndpointIP = v
	}
	if v := os.Getenv("ENDPOINT_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.EndpointPort = port
		}
	}
	if v := os.Getenv("NOTIFY_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Notify.Port = port
		}
	}
	if v := os.Getenv("SMTP_ENABLED"); v == "true" || v == "1" {
		cfg.SMTP.Enabled = true
	} else if v == "false" || v == "0" {
		cfg.SMTP.Enabled = false
	}
	if v := os.Getenv("SMTP_LISTEN"); v != "" {
		cfg.SMTP.Listen = v
	}
	if v := os.Getenv("SMTP_MAX_MESSAGE_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.SMTP.MaxMessageBytes = n
		}
	}
	if v := os.Getenv("SMTP_RATE_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.SMTP.RatePerMinute = n
		}
	}
	if v := os.Getenv("SMTP_TLS_ENABLED"); v == "true" || v == "1" {
		cfg.SMTP.TLSEnabled = true
	} else if v == "false" || v == "0" {
		cfg.SMTP.TLSEnabled = false
	}
}

// Agent-owned pairing identity. config.yaml is user-authored only; the
// agent never writes it, so defaults/derived values can't get frozen.
type pairingState struct {
	DeviceID     string `json:"device_id"`
	AppsHostname string `json:"apps_hostname"`
	TunnelHost   string `json:"tunnel_host"`
}

// 0600: DeviceID is sensitive metadata; an attacker who reads it could
// craft signed envelopes targeting the agent.
func (c *Config) SavePairing() error {
	path := c.PairingPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pairingState{
		DeviceID:     c.DeviceID,
		AppsHostname: c.AppsHostname,
		TunnelHost:   c.TunnelHost,
	}, "", "  ")
	if err != nil {
		return err
	}
	return atomic.WriteFile(path, data, 0600)
}

// pairing.json is authoritative for the agent-owned identity; a
// hand-authored config.yaml value survives only as a bridge when the
// file is absent. Missing → unpaired (no-op); corrupt → fail closed,
// since silently re-pairing is destructive.
func loadPairing(c *Config) error {
	data, err := os.ReadFile(c.PairingPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read pairing state: %w", err)
	}
	var ps pairingState
	if err := json.Unmarshal(data, &ps); err != nil {
		return fmt.Errorf("parse pairing state: %w", err)
	}
	if ps.DeviceID != "" {
		c.DeviceID = ps.DeviceID
	}
	if ps.AppsHostname != "" {
		c.AppsHostname = ps.AppsHostname
	}
	if ps.TunnelHost != "" {
		c.TunnelHost = ps.TunnelHost
	}
	return nil
}

func (c *Config) ConfigPath() string {
	return filepath.Join(c.DataDir, "config.yaml")
}

func (c *Config) PairingPath() string {
	return filepath.Join(c.DataDir, "pairing.json")
}

func (c *Config) KeysDir() string {
	return filepath.Join(c.DataDir, "keys")
}

func (c *Config) ACLPath() string {
	return filepath.Join(c.DataDir, "acl.json")
}

func (c *Config) IPAllocPath() string {
	return filepath.Join(c.DataDir, "ip_alloc.json")
}

func (c *Config) CertsDir() string {
	return filepath.Join(c.DataDir, "certs")
}

func (c *Config) CustomDomainPath() string {
	return filepath.Join(c.DataDir, "custom_domain.json")
}

// Marker for the port-mapping alert cooldown; mtime is the gate, the
// file itself is empty.
func (c *Config) PortMappingAlertPath() string {
	return filepath.Join(c.DataDir, "port_mapping_alert.cooldown")
}
