//go:build ignore

// Run with: go run examples/without_analysis.go
// This example scans text using the default rules and streams redacted findings
// as JSONL to stdout. It performs no provider validation or analysis and makes
// no network requests. The scan summary goes to stderr.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Default()
	if err != nil {
		return err
	}

	// Scanner only discovers secrets and applies local filters. Provider
	// expressions in the rules are never executed; no opt-out flag is needed.
	scanner, err := scan.New(cfg)
	if err != nil {
		return err
	}

	skip, err := prefilter.Compile(cfg.Prefilter, prefilter.Options{})
	if err != nil {
		return err
	}

	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	source := &sources.Reader{
		Content: strings.NewReader("GITHUB_TOKEN=" + token + "\n"),
		Attributes: map[string]string{
			sources.AttrPath:     "application.env",
			sources.AttrResource: sources.ResourceFileContent,
		},
		ShouldSkip: skip,
	}

	// For caller-supplied paths or URLs, sources.Auto(ctx, target) returns
	// an enum without constructing a source. Use sources.Files for local paths,
	// sources.Git{URL: target} for remote history, or sources.URL{URL: target}
	// for one HTTP response. Detection and remote sources may use the network.
	// For local staged changes, use sources.Git{RepoPath: ".", Mode: sources.GitStaged}.
	encoder := json.NewEncoder(os.Stdout)
	summary, err := scanner.Scan(context.Background(), source, func(finding report.Finding) error {
		// Findings contain detection details without provider results.
		// Redact a copy before exporting. Returning an error stops the scan.
		return encoder.Encode(finding.RedactedCopy(100))
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stderr, "Scanned %d bytes; found %d secrets\n", summary.BytesInspected, summary.Findings)
	return err
}
