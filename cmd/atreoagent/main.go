package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: atreoagent <command>")
		fmt.Println("Commands: run, pair, status, apps, version")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "run":
		runDaemon(os.Args[2:])
	case "pair":
		runPair(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "apps":
		runApps(os.Args[2:])
	case "version", "--version", "-v":
		runVersion(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
