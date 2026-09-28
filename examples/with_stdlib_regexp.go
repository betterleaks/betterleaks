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
	// Stdlib is the SDK default. Select it explicitly for this scanner.
	engine := regexp.Stdlib{}

	cfg, err := config.Default()
	if err != nil {
		log.Fatal(err)
	}

	// Eagerly compile scanning rules with the selected engine.
	scanner, err := scan.New(cfg, scan.WithRegexEngine(engine), scan.WithPrecompile())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("regexp engine: %s\n", engine.Version())
	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	for _, finding := range scanner.ScanString("GITHUB_TOKEN=" + token) {
		fmt.Printf("%s: line %d\n", finding.RuleID, finding.Location.StartLine)
	}
}
