//go:build ignore

// Run with: go run examples/with_analysis.go
// This example detects plaintext and Base64 credentials, validates and analyzes
// them with local mock rules, and streams redacted findings as JSONL to stdout.
// It also validates an already-extracted credential through the direct SDK API.
// No network requests are made. Scan summaries and diagnostics go to stderr.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
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
confidence = "high"
validate = '''
{
  "result": "valid",
  "analysis": {"owner": "example-user"}
}
'''
analyze = '''
{
  "identity": {
    "username": validation["analysis"]["owner"],
    "account": {"id": "example-account", "name": "Example organization"}
  },
  "capabilities": analysis.capabilities({"read": true, "write": true}),
  "metadata": {"environment": "demo"}
}
'''
`

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo, // Use LevelDebug for detector diagnostics.
	}))
	cfg, err := config.ParseTOMLString(mockAnalysisConfig, "mock-analysis.toml")
	if err != nil {
		return err
	}

	const token = "mock_0123456789abcdef0123456789abcdef"        // betterleaks:allow
	const encodedToken = "mock_fedcba9876543210fedcba9876543210" // betterleaks:allow
	const fixtureToken = "mock_00000000000000000000000000000000" // betterleaks:allow

	detector, err := detect.NewDetector(cfg,
		detect.WithLogger(logger),
		detect.WithJobs(1), // Detection workers; 0 uses GOMAXPROCS.
		detect.WithMatchContext("10L"),
		detect.WithMaxDecodeDepth(3), // Also find credentials inside encoded text.
		detect.WithMinimumConfidence(detect.ConfidenceHigh),
		detect.WithPrecompile(),               // Report regex/expression compilation errors now.
		detect.WithIgnoreAllowComments(false), // Honor betterleaks:allow comments.
		detect.WithExcludedPaths("archived.env"),
		// Ignore this exact primary secret across all rules and locations,
		// before spending any work on validation or analysis.
		detect.WithIgnoredFingerprints(fingerprint.Sum([]byte(fixtureToken))),
		// WithAnalysis also enables validation. Analysis runs for valid
		// credentials whose rules supply an analyze expression.
		detect.WithAnalysis(detect.ProviderOptions{
			Workers:  4, // Provider workers are separate from detection workers.
			Statuses: []report.ValidationStatus{report.ValidationStatusValid},
			// These request controls apply when rules make provider HTTP calls.
			Timeout:              5 * time.Second,
			MaxRequestsPerTarget: 8,
			RequestsPerSecond:    5,
			RequestsPerSecondByRule: map[string]float64{
				"mock-api-key": 2,
			},
			// Only these environment variables are accessible to rule programs.
			EnvVars: []string{"EXAMPLE_API_BASE_URL"},
		}),
	)
	if err != nil {
		return err
	}

	// The scan deadline covers the entire pipeline, in addition to the
	// per-request provider timeout above. Cancellation stops the scan.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	content := strings.Join([]string{
		"# Example application configuration",
		"API_KEY=" + token,
		"ENCODED_KEY=" + base64.StdEncoding.EncodeToString([]byte(encodedToken)),
		"FIXTURE_KEY=" + fixtureToken,
		"ALLOWED_KEY=mock_11111111111111111111111111111111 # betterleaks:allow",
		"MODE=development",
	}, "\n")

	encoder := json.NewEncoder(os.Stdout)
	// Reuse the compiled detector for sequential scans. Each Reader is fresh
	// because scanning consumes its input. The second path is excluded above.
	for _, path := range []string{"application.env", "archived.env"} {
		source := &sources.Reader{
			Content: strings.NewReader(content),
			Attributes: map[string]string{
				sources.AttrPath:     path,
				sources.AttrResource: sources.ResourceFileContent,
			},
			ShouldSkip: detector.SkipFunc(), // Apply the detector's source prefilter.
		}
		summary, err := detector.Scan(ctx, source, func(finding report.Finding) error {
			// The handler receives resolved validation and analysis, including
			// identity, account, capabilities, and derived severity. Redact a
			// copy before exporting. Returning an error stops the scan.
			redacted := finding.RedactedCopy(100)
			// finding.MatchContext is available for local inspection. Redaction
			// is per credential; context can contain other or encoded secrets,
			// so omit the raw context from this example's exported JSONL.
			redacted.MatchContext = ""
			return encoder.Encode(redacted)
		})
		logger.Info("scan complete", "path", path,
			"bytes", summary.BytesInspected, "findings", summary.Findings,
			"validation_counts", summary.ValidationCounts)
		if err != nil {
			return fmt.Errorf("scan %s: %w", path, err)
		}
	}

	// Already have a credential? No Reader, regex matching, or Scan is needed.
	// This deliberately checks the fixture ignored by scans above: explicit
	// validation bypasses scan filters, fingerprint ignores, and status filters.
	result, err := detector.ValidateCredential(ctx, detect.Credential{
		RuleID: "mock-api-key",
		Secret: fixtureToken,
		Attributes: map[string]string{
			"application": "example-service",
		},
	})
	if err != nil {
		return fmt.Errorf("validate credential: %w", err)
	}
	logger.Info("credential checked", "status", result.Validation.Status,
		"severity", result.Analysis.Severity)
	// Credential reports already sanitize supplied secrets and captures.
	return encoder.Encode(result)
}
