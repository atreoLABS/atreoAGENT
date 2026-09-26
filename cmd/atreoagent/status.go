package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"github.com/atreoLABS/atreoAGENT/internal/overlay"
)

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logging.Fatalf("Failed to load config: %v", err)
	}

	fmt.Println("atreoAGENT Status")
	fmt.Println("─────────────────")
	if cfg.DeviceID != "" {
		fmt.Printf("Paired:        yes\n")
		fmt.Printf("Device ID:     %s\n", cfg.DeviceID)
		fmt.Printf("Apps hostname: %s\n", cfg.AppsHostname)
	} else {
		fmt.Printf("Paired:        no\n")
	}
	fmt.Printf("atreoLINK API URL:  %s\n", cfg.AtreoLinkAPIURL)
	fmt.Printf("atreoLINK App URL:  %s\n", cfg.AtreoLinkAppURL)
	fmt.Printf("Data Dir:       %s\n", cfg.DataDir)
	fmt.Printf("WG Port:        %d\n", cfg.WireGuard.ListenPort)

	// Read-only: creating overlay.json here as root would leave the daemon
	// unable to write it if it runs as another user.
	ov, err := overlay.Load(cfg.OverlayPath())
	switch {
	case err == nil:
		fmt.Printf("Overlay IP:     %s\n", ov.GatewayV4)
		fmt.Printf("Overlay subnet: %s\n", ov.SubnetV4)
		fmt.Printf("Overlay IPv6:   %s\n", ov.GatewayV6)
		fmt.Printf("Overlay v6 net: %s\n", ov.SubnetV6)
	case errors.Is(err, os.ErrNotExist):
		fmt.Printf("Overlay:        not yet derived (agent has not booted)\n")
	default:
		fmt.Printf("Overlay:        unavailable (%v)\n", err)
	}
}
