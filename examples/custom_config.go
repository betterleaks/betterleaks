//go:build ignore

package main

import (
	"fmt"
	"log"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect"
)

const customConfig = `
title = "Example rules"

[[rules]]
id = "example-api-key"
description = "Example API key"
regex = '''example_[0-9a-f]{32}'''
keywords = ["example_"]
`

func main() {
	cfg, err := config.ParseTOMLString(customConfig, "embedded-example.toml")
	if err != nil {
		log.Fatal(err)
	}

	detector, err := detect.NewDetector(cfg)
	if err != nil {
		log.Fatal(err)
	}

	const content = "API_KEY=example_0123456789abcdef0123456789abcdef" // betterleaks:allow
	for _, finding := range detector.DetectString(content) {
		fmt.Printf("%s: %s\n", finding.RuleID, finding.Description)
	}
}
