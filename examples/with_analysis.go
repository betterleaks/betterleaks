//go:build ignore

// Run with: go run examples/with_analysis.go
// This example detects plaintext and Base64 credentials, validates and analyzes
// them with local mock rules, and streams redacted findings as JSONL to stdout.
// It also analyzes and validates an already-extracted credential directly.
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

	"github.com/betterleaks/betterleaks/v2/analyze"
	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/credential"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/pipeline"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
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
		Level: slog.LevelInfo, // Use LevelDebug for scanner diagnostics.
	}))
	cfg, err := config.ParseTOMLString(mockAnalysisConfig, "mock-analysis.toml")
	if err != nil {
		return err
	}

	const token = "mock_0123456789abcdef0123456789abcdef"        // betterleaks:allow
	const encodedToken = "mock_fedcba9876543210fedcba9876543210" // betterleaks:allow
	const fixtureToken = "mock_00000000000000000000000000000000" // betterleaks:allow

	scanner, err := scan.New(cfg,
		scan.WithLogger(logger),
		scan.WithWorkers(1), // Detection workers; 0 uses GOMAXPROCS.
		scan.WithMatchContext("10L"),
		scan.WithMaxDecodeDepth(3), // Also find credentials inside encoded text.
		scan.WithMinimumConfidence(scan.ConfidenceHigh),
		scan.WithPrecompile(),               // Report regex/expression compilation errors now.
		scan.WithIgnoreAllowComments(false), // Honor betterleaks:allow comments.
		scan.WithExcludedPaths("archived.env"),
		// Ignore this exact primary secret across all rules and locations,
		// before spending any work on validation or analysis.
		scan.WithIgnoredFingerprints(fingerprint.Sum([]byte(fixtureToken))),
	)
	if err != nil {
		return fmt.Errorf("create scanner: %w", err)
	}

	// Analyzer owns provider programs and request controls. Its workers operate
	// independently of discovery. Each pipeline scan gets fresh caches and limits.
	analyzer, err := analyze.New(cfg,
		analyze.WithLogger(logger),
		analyze.WithWorkers(4),
		analyze.WithTimeout(5*time.Second),
		analyze.WithMaxRequestsPerTarget(8),
		analyze.WithRequestsPerSecond(5),
		analyze.WithRequestsPerSecondByRule(map[string]float64{"mock-api-key": 2}),
		analyze.WithEnvVars("EXAMPLE_API_BASE_URL"),
		analyze.WithPrecompile(),
	)
	if err != nil {
		return fmt.Errorf("create analyzer: %w", err)
	}

	// Output policy belongs to the pipeline. Analyzer always returns its result.
	// Both engines use the same resolved config so their rules and credential
	// requirements agree. Pipeline also accepts compatible subsets of that config.
	p, err := pipeline.New(scanner, analyzer,
		pipeline.WithValidationStatuses(report.ValidationStatusValid),
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
	// Reuse the scanner and analyzer for sequential scans. Each Reader is fresh
	// because scanning consumes its input. The second path is excluded above.
	for _, path := range []string{"application.env", "archived.env"} {
		source := &sources.Reader{
			Content: strings.NewReader(content),
			Attributes: map[string]string{
				sources.AttrPath:     path,
				sources.AttrResource: sources.ResourceFileContent,
			},
			ShouldSkip: scanner.SkipFunc(), // Apply the scanner's source prefilter.
		}
		summary, err := p.Scan(ctx, source, func(finding report.Finding) error {
			// Finding.Analysis contains status, identity, account, capabilities,
			// and derived severity. Match groups the matched text and value;
			// Location contains the source path and coordinates. Redact a
			// copy before exporting. Returning an error stops the scan.
			redacted := finding.RedactedCopy(100)
			// finding.Match.Context is available for local inspection. Redaction
			// is per credential; context can contain other or encoded secrets,
			// so omit the raw context from this example's exported JSONL.
			redacted.Match.Context = ""
			return encoder.Encode(redacted)
		})
		logger.Info("scan complete", "path", path,
			"bytes", summary.BytesInspected, "findings", summary.EmittedFindings,
			"validation_counts", summary.ValidationCounts)
		if err != nil {
			return fmt.Errorf("scan %s: %w", path, err)
		}
	}

	// Already have a credential? No Reader, regex matching, or Scanner is needed.
	// This deliberately checks the fixture ignored by scans above: explicit
	// credential analysis bypasses scan filters, fingerprint ignores, and status filters.
	result, err := analyzer.AnalyzeCredential(ctx, credential.Input{
		RuleID:     "mock-api-key",
		Secret:     fixtureToken,
		Attributes: map[string]string{"application": "example-service"},
	})
	if err != nil {
		return fmt.Errorf("analyze credential: %w", err)
	}
	logger.Info("credential checked", "status", result.Analysis.Status,
		"severity", result.Analysis.Severity)
	// Credential reports already sanitize supplied secrets and captures.
	if err := encoder.Encode(result); err != nil {
		return err
	}

	// Liveness alone never runs the analysis expression, even on an Analyzer
	// already used for permission analysis.
	validation, err := analyzer.ValidateCredential(ctx, credential.Input{
		RuleID: "mock-api-key", Secret: token,
	})
	if err != nil {
		return err
	}
	logger.Info("credential validated", "status", validation.Analysis.Status)

	// Scanner is useful alone: these findings have confidence and locations,
	// with an empty Analysis field.
	logger.Info("local scan complete", "findings", len(scanner.ScanString("API_KEY="+token)))
	return nil
}
