package scan_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
)

func Example() {
	cfg, err := config.Default()
	if err != nil {
		panic(err)
	}
	scanner, err := scan.New(cfg)
	if err != nil {
		panic(err)
	}

	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	for _, finding := range scanner.ScanString("GITHUB_TOKEN=" + token) {
		fmt.Println(finding.RuleID)
	}

	// Output:
	// github-pat
}

func ExampleWithIgnoredFingerprints() {
	policy := fingerprint.Format(fingerprint.Sum([]byte("secret-fixture"))) + "\n"
	hashes, diagnostics, err := fingerprint.Load(strings.NewReader(policy))
	if err != nil || len(diagnostics) != 0 {
		panic("invalid ignore policy")
	}
	cfg := &config.Config{Rules: []config.Rule{{ID: "token", Regex: `secret-[a-z]+`}}}
	scanner, err := scan.New(cfg, scan.WithIgnoredFingerprints(hashes...))
	if err != nil {
		panic(err)
	}
	for _, finding := range scanner.ScanString("secret-fixture secret-live") {
		fmt.Println(finding.Match.Value)
	}
	// Output: secret-live
}

func Example_customConfig() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.LoadFile("./betterleaks.toml", config.WithLogger(logger))
	if err != nil {
		panic(err)
	}
	scanner, err := scan.New(cfg,
		scan.WithLogger(logger),
	)
	if err != nil {
		panic(err)
	}

	skip, err := prefilter.Compile(cfg.Prefilter, prefilter.Options{Logger: logger})
	if err != nil {
		panic(err)
	}

	source := &sources.Reader{
		Content:   os.Stdin,
		Prefilter: skip,
	}
	_, err = scanner.Scan(context.Background(), source, func(finding report.Finding) error {
		fmt.Println(finding.RuleID, finding.Confidence)
		return nil
	})
	if err != nil {
		panic(err)
	}
}
