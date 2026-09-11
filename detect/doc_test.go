package detect_test

import (
	"context"
	"fmt"
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

func Example() {
	cfg, err := config.Default()
	if err != nil {
		panic(err)
	}
	detector, err := detect.NewDetector(cfg)
	if err != nil {
		panic(err)
	}

	const token = "ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5" // betterleaks:allow
	for _, finding := range detector.DetectString("GITHUB_TOKEN=" + token) {
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
	detector, err := detect.NewDetector(cfg, detect.WithIgnoredFingerprints(hashes...))
	if err != nil {
		panic(err)
	}
	for _, finding := range detector.DetectString("secret-fixture secret-live") {
		fmt.Println(finding.Secret)
	}
	// Output: secret-live
}

func ExampleDetector_ValidateCredential() {
	// Mock provider programs keep this example independent of network services.
	cfg := &config.Config{Rules: []config.Rule{{
		ID:           "demo-token",
		Regex:        `demo_(?P<tenant>[a-z]+)_(?P<key>[a-z]+)`,
		SecretGroup:  2,
		ValidateExpr: `finding.captures.tenant == "acme" ? {"result": "valid", "analysis": {"owner": "demo-user"}} : {"result": "invalid"}`,
		AnalyzeExpr:  `{"identity": {"username": validation["analysis"]["owner"]}, "capabilities": ["read"]}`,
	}}}
	detector, err := detect.NewDetector(cfg, detect.WithAnalysis(detect.ProviderOptions{
		Timeout: 5 * time.Second,
	}))
	if err != nil {
		panic(err)
	}
	result, err := detector.ValidateCredential(context.Background(), detect.Credential{
		RuleID: "demo-token",
		Secret: "example",
		// Supply the named inputs the detection regex would otherwise extract.
		Captures: map[string]string{"tenant": "acme"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(result.Validation.Status)
	fmt.Println(result.Analysis.Identity.Username)
	fmt.Println(result.Analysis.Severity)
	// Output:
	// valid
	// demo-user
	// medium
}

func Example_customConfig() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.LoadFile("./betterleaks.toml", config.WithLogger(logger))
	if err != nil {
		panic(err)
	}
	detector, err := detect.NewDetector(cfg,
		detect.WithLogger(logger),
		// Analysis includes validation and only analyzes valid credentials.
		detect.WithAnalysis(detect.ProviderOptions{
			Workers: 10,
			Timeout: 10 * time.Second,
		}),
	)
	if err != nil {
		panic(err)
	}

	source := &sources.Reader{
		Content:    os.Stdin,
		ShouldSkip: detector.SkipFunc(),
	}
	_, err = detector.Scan(context.Background(), source, func(finding report.Finding) error {
		fmt.Printf("%s: validation=%s severity=%s\n",
			finding.RuleID,
			finding.Validation.Status,
			finding.Analysis.Severity,
		)
		return nil
	})
	if err != nil {
		panic(err)
	}
}
