package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"syscall"

	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"github.com/atreoLABS/atreoAGENT/internal/overlay"
)

// runReroll moves this install to a fresh overlay subnet. It only rewrites
// overlay.json; the running agent picks it up on restart and reallocates
// every peer then.
func runReroll(args []string) {
	fs := flag.NewFlagSet("reroll", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config file")
	yes := fs.Bool("yes", false, "Confirm the re-roll")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logging.Fatalf("Failed to load config: %v", err)
	}
	path := cfg.OverlayPath()

	cur, err := overlay.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		logging.Fatalf("No overlay subnet yet: start atreoAGENT once before re-rolling.")
	}
	if err != nil {
		logging.Fatalf("Failed to read %s: %v", path, err)
	}

	if !*yes {
		fmt.Printf("This server is on %s and %s.\n", cur.SubnetV4, cur.SubnetV6)
		fmt.Println("Re-rolling moves it to a new random subnet. Every client reconnects onto a new")
		fmt.Println("address, and any config naming the current subnet (trusted_networks, reverse-proxy")
		fmt.Println("rules, static routes) must be updated by hand.")
		fmt.Println()
		fmt.Println("Run again with --yes to continue.")
		os.Exit(1)
	}

	info, statErr := os.Stat(path)
	next, err := overlay.Reroll(path)
	if err != nil {
		logging.Fatalf("Re-roll failed: %v", err)
	}
	// The write replaces the file, so under sudo it would come back owned by
	// root and unreadable to an agent running as another user.
	if statErr == nil {
		if st, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
			if err := os.Chown(path, int(st.Uid), int(st.Gid)); err != nil {
				logging.Fatalf("Re-rolled, but failed to restore ownership of %s: %v", path, err)
			}
		}
	}

	fmt.Printf("Re-rolled: %s -> %s\n", cur.SubnetV4, next.SubnetV4)
	fmt.Printf("           %s -> %s\n", cur.SubnetV6, next.SubnetV6)
	fmt.Println("Restart atreoAGENT to apply.")
}
