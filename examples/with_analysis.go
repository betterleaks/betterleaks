//go:build ignore

package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

const mockAnalysisConfig = `
title = "Mock analysis rules"

[[rules]]
id = "mock-api-key"
description = "Mock API key"
regex = '''mock_[0-9a-f]{32}'''
keywords = ["mock_"]
validate = '''
{
  "result": "valid",
  "analysis": {"owner": "example-user"}
}
'''
analyze = '''
{
  "identity": {"username": validation["analysis"]["owner"]},
  "capabilities": analysis.capabilities({"read": true})
}
'''
`

func main() {
	cfg, err := config.ParseTOMLString(mockAnalysisConfig, "mock-analysis.toml")
	if err != nil {
		log.Fatal(err)
	}

	detector, err := detect.NewDetector(cfg, detect.WithAnalysis(detect.ProviderOptions{}))
	if err != nil {
		log.Fatal(err)
	}

	const token = "mock_0123456789abcdef0123456789abcdef" // betterleaks:allow
	source := &sources.Reader{
		Content:    strings.NewReader("API_KEY=" + token),
		ShouldSkip: detector.SkipFunc(),
	}
	summary, err := detector.Scan(context.Background(), source, func(finding report.Finding) error {
		fmt.Printf("%s: validation=%s severity=%s\n",
			finding.RuleID,
			finding.Validation.Status,
			finding.Analysis.Severity,
		)
		if identity := finding.Analysis.Identity; identity != nil {
			fmt.Printf("identity: %s\n", identity.Username)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("findings: %d\n", summary.Findings)
}
