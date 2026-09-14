//go:build ignore

// Run from the repository root:
//
//	go run examples/with_stdlib_regexp.go
//
// This example scans locally using Go's standard-library regexp engine.
package main

import (
	"fmt"
	"log"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/scan"
)

func main() {
	// Stdlib is already the SDK default; select it explicitly here to show how
	// to choose an engine. Engine selection is global, so do it at startup,
	// before loading rules, constructing scanners, or starting concurrent work.
	regexp.SetEngine(regexp.Stdlib{})

	cfg, err := config.Default()
	if err != nil {
		log.Fatal(err)
	}

	// Eagerly compile scanning rules with the selected engine.
	scanner, err := scan.New(cfg, scan.WithPrecompile())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("regexp engine: %s\n", regexp.Version())
	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	for _, finding := range scanner.ScanString("GITHUB_TOKEN=" + token) {
		fmt.Printf("%s: line %d\n", finding.RuleID, finding.Location.StartLine)
	}
}
