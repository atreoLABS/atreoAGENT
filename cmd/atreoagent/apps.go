package main

import (
	"flag"
	"fmt"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

func runApps(args []string) {
	fs := flag.NewFlagSet("apps", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logging.Fatalf("Failed to load config: %v", err)
	}

	store := acl.NewStore(cfg.ACLPath())
	if err := store.Load(); err != nil {
		logging.Fatalf("Failed to load ACL: %v", err)
	}

	apps := store.AllApps()
	if len(apps) == 0 {
		fmt.Println("No apps registered.")
		return
	}

	fmt.Println("Registered Apps")
	fmt.Println("───────────────")
	for _, app := range apps {
		fmt.Printf("  %s  →  %s\n", app.Name, app.InternalURL)
	}
}
