//go:build ignore

// Run with: go run -race examples/concurrent_scanner.go
// This example shares one scanner across 100 concurrent scans, each with its
// own input. It streams redacted findings as JSONL to stdout and prints per-input
// summaries to stderr. Finding order can vary. No network requests are made.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// ex config
	cfg := &config.Config{Rules: []config.Rule{{
		ID:          "example-api-key",
		Description: "Example API key",
		Regex:       `example_[0-9a-f]{32}`,
		Keywords:    []string{"example_"},
	}}}
	// Construct once and share. WithWorkers limits detection workers per scan,
	// so 100 concurrent scans use at most 100 detection workers in total.
	// One single scanner struct
	scanner, err := scan.New(cfg, scan.WithWorkers(5))
	if err != nil {
		return err
	}

	const concurrentScans = 100
	inputs := make([]struct{ path, content string }, concurrentScans)
	for i := range inputs {
		inputs[i].path = fmt.Sprintf("input-%03d.env", i+1)
		inputs[i].content = fmt.Sprintf("API_KEY=example_%032x\n", i+1)
	}
	group, ctx := errgroup.WithContext(context.Background())

	encoder := json.NewEncoder(os.Stdout)
	var outputMu sync.Mutex
	summaries := make([]scan.ScanSummary, len(inputs))
	for i, input := range inputs {
		group.Go(func() error {

			// Sources own their input streams and attributes. Give every scan a
			// fresh source; sharing the scanner does not make readers reusable.
			source := &sources.Reader{
				Content: strings.NewReader(input.content),
				Attributes: map[string]string{
					sources.AttrPath:     input.path,
					sources.AttrResource: sources.ResourceFileContent,
				},
				ShouldSkip: scanner.SkipFunc(),
			}
			summary, err := scanner.Scan(ctx, source, func(finding report.Finding) error {
				redacted := finding.RedactedCopy(100)
				// Handlers are serial within one Scan call, but handlers from
				// different calls can overlap. Protect their shared encoder.
				outputMu.Lock()
				defer outputMu.Unlock()
				return encoder.Encode(redacted)
			})
			if err != nil {
				return fmt.Errorf("scan %s: %w", input.path, err)
			}
			// Each goroutine owns one slot; read results only after Wait.
			summaries[i] = summary
			return nil
		})
	}

	// The first error cancels the other scans. Wait joins all started scans
	// before returning, including any cancellation cleanup.
	if err := group.Wait(); err != nil {
		return err
	}
	for i, summary := range summaries {
		if _, err := fmt.Fprintf(os.Stderr, "%s: scanned %d bytes; found %d secrets\n",
			inputs[i].path, summary.BytesInspected, summary.Findings); err != nil {
			return err
		}
	}
	return nil
}
