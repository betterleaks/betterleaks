//go:build ignore

// Run from the repository root:
//
//	go run examples/with_re2_regexp.go
package main

import (
	"fmt"
	"log"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp/re2"
	"github.com/betterleaks/betterleaks/v2/scan"
)

func main() {
	cfg, err := config.Default()
	if err != nil {
		log.Fatal(err)
	}

	// Importing this backend explicitly opts into its RE2/Wazero dependency.
	scanner, err := scan.New(cfg, scan.WithRegexEngine(re2.RE2{}))
	if err != nil {
		log.Fatal(err)
	}

	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	for _, finding := range scanner.ScanString("GITHUB_TOKEN=" + token) {
		fmt.Printf("%s: line %d\n", finding.RuleID, finding.Location.StartLine)
	}
}
