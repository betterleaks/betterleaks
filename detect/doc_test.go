package detect_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/detect"
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
