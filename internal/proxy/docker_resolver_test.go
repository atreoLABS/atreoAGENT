package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestNewDockerResolver_NoSocket(t *testing.T) {
	r := newDockerResolver("/var/run/no-such-docker.sock")
	if r != nil {
		t.Error("expected nil when socket absent")
	}
}

func TestNewDockerResolver_SocketPresent(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "atreodr")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sockPath := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	if r := newDockerResolver(sockPath); r == nil {
		t.Error("expected non-nil resolver when socket present")
	}
}

// makeFakeDockerAPI starts an HTTP server on a temporary Unix socket and
// returns the socket path plus a cleanup func.
//
// Uses /tmp directly to avoid macOS 104-byte Unix socket path limit — paths
// from t.TempDir() embed the full test name and can exceed the limit.
func makeFakeDockerAPI(t *testing.T, handler http.Handler) (sockPath string, cleanup func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "atreodr")
	if err != nil {
		t.Fatalf("mktemp: %v", err)
	}
	sockPath = filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("listen on unix socket: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(l) //nolint:errcheck
	return sockPath, func() {
		_ = srv.Close()
		_ = os.RemoveAll(dir)
	}
}

func TestDockerResolver_Resolve_OK(t *testing.T) {
	sockPath, cleanup := makeFakeDockerAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"NetworkSettings": map[string]any{
				"Networks": map[string]any{
					"bridge": map[string]any{"IPAddress": "172.17.0.5"},
				},
			},
		})
	}))
	defer cleanup()

	r := newDockerResolver(sockPath)
	if r == nil {
		t.Fatal("expected resolver")
	}
	ip, err := r.resolve(context.Background(), "mycontainer")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ip != "172.17.0.5" {
		t.Errorf("got %q, want 172.17.0.5", ip)
	}
}

func TestDockerResolver_Resolve_NotFound(t *testing.T) {
	sockPath, cleanup := makeFakeDockerAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer cleanup()

	r := newDockerResolver(sockPath)
	if r == nil {
		t.Fatal("expected resolver")
	}
	if _, err := r.resolve(context.Background(), "nosuch"); err == nil {
		t.Error("expected error for 404")
	}
}

func TestDockerResolver_Resolve_NoNetworks(t *testing.T) {
	sockPath, cleanup := makeFakeDockerAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"NetworkSettings": map[string]any{
				"Networks": map[string]any{},
			},
		})
	}))
	defer cleanup()

	r := newDockerResolver(sockPath)
	if r == nil {
		t.Fatal("expected resolver")
	}
	if _, err := r.resolve(context.Background(), "mycontainer"); err == nil {
		t.Error("expected error when no IPs in response")
	}
}

// TestDockerResolver_DialContext_IPPassthrough verifies that plain IP addresses
// bypass the Docker API entirely.
func TestDockerResolver_DialContext_IPPassthrough(t *testing.T) {
	called := false
	sockPath, cleanup := makeFakeDockerAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer cleanup()

	r := newDockerResolver(sockPath)
	if r == nil {
		t.Fatal("expected resolver")
	}
	// Connection will fail (nothing listening), but Docker must not be queried.
	_, _ = r.dialContext(context.Background(), "tcp", "127.0.0.1:19999")
	if called {
		t.Error("Docker API must not be called for bare IP addresses")
	}
}

// TestDockerResolver_DialContext_LocalhostPassthrough verifies localhost bypasses
// Docker resolution.
func TestDockerResolver_DialContext_LocalhostPassthrough(t *testing.T) {
	called := false
	sockPath, cleanup := makeFakeDockerAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer cleanup()

	r := newDockerResolver(sockPath)
	if r == nil {
		t.Fatal("expected resolver")
	}
	_, _ = r.dialContext(context.Background(), "tcp", "localhost:19999")
	if called {
		t.Error("Docker API must not be called for localhost")
	}
}

// TestDockerResolver_DialContext_ContainerName verifies that a container name
// is resolved via Docker and the connection is made to the returned IP.
func TestDockerResolver_DialContext_ContainerName(t *testing.T) {
	// Real TCP listener to act as the "container" backend.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Docker API returns 127.0.0.1 as the container's IP.
	sockPath, cleanup := makeFakeDockerAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"NetworkSettings": map[string]any{
				"Networks": map[string]any{
					"appnet": map[string]any{"IPAddress": "127.0.0.1"},
				},
			},
		})
	}))
	defer cleanup()

	r := newDockerResolver(sockPath)
	if r == nil {
		t.Fatal("expected resolver")
	}
	conn, err := r.dialContext(context.Background(), "tcp", "mycontainer:"+port)
	if err != nil {
		t.Fatalf("dialContext: %v", err)
	}
	_ = conn.Close()
}
