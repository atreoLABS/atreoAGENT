package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

const defaultDockerSock = "/var/run/docker.sock"

// Bounds Docker API calls to ~1 per container per TTL; short enough to pick up a restarted container's new IP.
const resolveTTL = 10 * time.Second

// Lets InternalURL hostnames like http://jellyfin:8096 resolve without
// exposed ports.
type dockerResolver struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]resolveEntry
}

type resolveEntry struct {
	ip      string
	expires time.Time
}

// nil = disabled (no socket).
func newDockerResolver(sockPath string) *dockerResolver {
	if _, err := os.Stat(sockPath); err != nil {
		return nil
	}
	return &dockerResolver{
		client: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
				},
			},
		},
		cache: make(map[string]resolveEntry),
	}
}

// Tries Docker name resolution first for non-IP, non-localhost hostnames.
func (d *dockerResolver) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	if net.ParseIP(host) == nil && host != "localhost" {
		if ip, resolveErr := d.resolve(ctx, host); resolveErr == nil {
			addr = net.JoinHostPort(ip, port)
		}
	}
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

// First IP across any of the container's networks.
func (d *dockerResolver) resolve(ctx context.Context, name string) (string, error) {
	if ip, ok := d.cached(name); ok {
		return ip, nil
	}
	// PathEscape so a hostile container name can't reshape the path.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://localhost/v1.41/containers/"+url.PathEscape(name)+"/json", nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("docker: %s", resp.Status)
	}

	var info struct {
		NetworkSettings struct {
			Networks map[string]struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	for _, n := range info.NetworkSettings.Networks {
		if n.IPAddress != "" {
			d.store(name, n.IPAddress)
			return n.IPAddress, nil
		}
	}
	return "", fmt.Errorf("docker: no IP for container %q", name)
}

// Positive cache only, so a transient Docker failure isn't pinned for the whole TTL.
func (d *dockerResolver) cached(name string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.cache[name]
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.ip, true
}

func (d *dockerResolver) store(name, ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache[name] = resolveEntry{ip: ip, expires: time.Now().Add(resolveTTL)}
}
