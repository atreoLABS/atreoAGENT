package tunnel

import (
	"testing"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

func TestValidateApp(t *testing.T) {
	tests := []struct {
		name    string
		app     atreolink.App
		wantErr bool
	}{
		{"proxy with valid url", atreolink.App{InternalURL: "http://localhost:8080"}, false},
		{"proxy empty type with https", atreolink.App{Type: "", InternalURL: "https://nas:443"}, false},
		{"proxy bad scheme", atreolink.App{InternalURL: "ftp://nas"}, true},
		{"proxy no host", atreolink.App{InternalURL: "http://"}, true},
		{"port tcp valid, no url required", atreolink.App{Type: "port", Port: 25565, Protocol: "tcp"}, false},
		{"port udp valid", atreolink.App{Type: "port", Port: 19132, Protocol: "udp"}, false},
		{"port http valid", atreolink.App{Type: "port", Port: 8096, Protocol: "http"}, false},
		{"port https valid", atreolink.App{Type: "port", Port: 8443, Protocol: "https"}, false},
		{"port zero", atreolink.App{Type: "port", Port: 0, Protocol: "tcp"}, true},
		{"port too high", atreolink.App{Type: "port", Port: 70000, Protocol: "tcp"}, true},
		{"port bad protocol", atreolink.App{Type: "port", Port: 22, Protocol: "sctp"}, true},
		{"port missing protocol", atreolink.App{Type: "port", Port: 22}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateApp(tt.app)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateApp() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
