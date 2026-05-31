package main

import (
	"flag"
	"fmt"

	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
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
	fmt.Printf("Data Dir:   %s\n", cfg.DataDir)
	fmt.Printf("WG Port:    %d\n", cfg.WireGuard.ListenPort)
}
