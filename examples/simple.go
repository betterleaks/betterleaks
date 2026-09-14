//go:build ignore

package main

import (
	"fmt"
	"log"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/scan"
)

func main() {
	cfg, err := config.Default()
	if err != nil {
		log.Fatal(err)
	}

	scanner, err := scan.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	for _, finding := range scanner.ScanString("GITHUB_TOKEN=" + token) {
		fmt.Printf("%s: line %d\n", finding.RuleID, finding.Location.StartLine)
	}
}
