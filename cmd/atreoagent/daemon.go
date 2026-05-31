package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/atreoLABS/atreoAGENT/internal/agent"
	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

func runDaemon(args []string) {
	printBanner()
	logging.Info("atreoAGENT %s (commit %s, built %s)", version, commit, date)

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file (default: <dataDir>/config.yaml)")
	dataDir := fs.String("data-dir", "", "Data directory (default: /var/lib/atreoagent)")
	noUPnP := fs.Bool("no-upnp", false, "Disable automatic UPnP/NAT-PMP port mapping (forward the WireGuard UDP port manually)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logging.Fatalf("Failed to load config: %v", err)
	}

	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}

	// Only when explicitly passed, so it beats env/YAML without an unset
	// flag clobbering them.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "no-upnp" {
			cfg.WireGuard.UPnPEnabled = !*noUPnP
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logging.Info("Shutting down...")
		cancel()
	}()

	a, err := agent.New(cfg)
	if err != nil {
		logging.Fatalf("Failed to create agent: %v", err)
	}

	if err := a.Run(ctx); err != nil && ctx.Err() == nil {
		logging.Fatalf("Agent error: %v", err)
	}
}
