package main

import (
	"flag"
	"fmt"
	"runtime"
	"runtime/debug"
)

// Optionally injected at release time via
// -ldflags "-X main.version=… -X main.commit=… -X main.date=…".
// When a field is left empty (plain `go build` / `docker build` with no
// args), it is filled from the VCS stamp Go embeds automatically.
var (
	version string
	commit  string
	date    string
)

func init() {
	rev, vcsTime, modified := buildVCS()

	if commit == "" {
		commit = orElse(rev, "unknown")
	}
	if date == "" {
		date = orElse(vcsTime, "unknown")
	}
	if version == "" {
		// No release version injected: identify the build by its commit.
		short := rev
		if len(short) > 12 {
			short = short[:12]
		}
		version = orElse(short, "unknown")
		if modified && short != "" {
			version += "-dirty"
		}
	}
}

// buildVCS returns the revision, commit time, and dirty flag Go records in
// the binary when built from a VCS checkout (revision is empty if unavailable).
func buildVCS() (rev, vcsTime string, modified bool) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", false
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	return rev, vcsTime, modified
}

func orElse(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func runVersion(args []string) {
	fs := flag.NewFlagSet("version", flag.ExitOnError)
	_ = fs.Parse(args)

	fmt.Printf("atreoAGENT %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built:  %s\n", date)
	fmt.Printf("go:     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
