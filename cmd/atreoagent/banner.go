package main

import (
	_ "embed"
	"fmt"
	"os"
)

//go:embed banner.txt
var banner string

func printBanner() {
	_, _ = fmt.Fprint(os.Stdout, banner)
}
