//go:build ignore

// Run from the repository root:
//
//	go run examples/git.go -repo ../my-repo
//	go run examples/git.go -repo ../my-repo -revision HEAD
//	go run examples/git.go -repo ../my-repo -since 2025-01-01T00:00:00Z -until 2025-01-31T23:59:59Z
//	go run examples/git.go -repo ../my-repo -author '<alice@example[.]com>'
//	go run examples/git.go -repo ../my-repo -since 2025-01-01T00:00:00Z -author '(?i)alice'
//	go run examples/git.go -repo ../my-repo -revision refs/heads/main -committer '(?i)release bot'
//	go run examples/git.go -repo ../my-repo -include commit-messages,notes -exclude merges
//	go run examples/git.go -repo ../my-repo -include commit-messages -exclude history
//
// Defaults to HEAD and all refs, including first-parent merge patches.
// Use -revision to restrict the history to a revision or an A..B range.
// Dates are inclusive bounds on committer time, not author time. Identity filters
// are Go regular expressions over "Name <email>". Supplied filters combine with AND.
// Include adds resources; exclude removes them. To scan only messages, explicitly
// exclude history as above. Keep source settings immutable during a scan.
// Local scanning invokes no Git subprocess or network requests. Findings are
// redacted JSONL on stdout; warnings and the scan summary go to stderr.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources/gogit"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	source := &gogit.Source{
		Workers:         4, // History readers; detector workers are configured below.
		MaxArchiveDepth: 8,
		Logger:          slog.Default(),
	}
	flag.StringVar(&source.RepoPath, "repo", ".", "Local repository path")
	flag.StringVar(&source.Revision, "revision", "", "Revision or A..B range; defaults to HEAD and all refs")
	flag.StringVar(&source.Author, "author", "", "Author name/email regular expression")
	flag.StringVar(&source.Committer, "committer", "", "Committer name/email regular expression")
	since := flag.String("since", "", "Inclusive committer timestamp, RFC3339")
	until := flag.String("until", "", "Inclusive committer timestamp, RFC3339")
	include := flag.String("include", "", "Comma-separated resources to add, e.g. commit-messages,notes")
	exclude := flag.String("exclude", "", "Comma-separated resources to remove, e.g. merges or history")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments; use -repo PATH")
	}
	if *since != "" {
		date, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			return fmt.Errorf("since: %w", err)
		}
		source.Since = &date
	}
	if *until != "" {
		date, err := time.Parse(time.RFC3339, *until)
		if err != nil {
			return fmt.Errorf("until: %w", err)
		}
		source.Until = &date
	}
	if *include != "" {
		source.Include = strings.Split(*include, ",")
	}
	if *exclude != "" {
		source.Exclude = strings.Split(*exclude, ",")
	}
	if err := source.Validate(); err != nil {
		return err
	}

	cfg, err := config.Default()
	if err != nil {
		return err
	}
	// Sources apply prefilters; constructing a scanner alone does not apply them.
	source.Prefilter, err = prefilter.Compile(cfg.PrefilterExpr, prefilter.Options{})
	if err != nil {
		return err
	}
	scanner, err := scan.New(cfg, scan.WithWorkers(8))
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	output := json.NewEncoder(os.Stdout)
	// Scan detects secrets and applies local filters without validation or analysis.
	summary, scanErr := scanner.Scan(ctx, source, func(finding report.Finding) error {
		return output.Encode(finding.RedactedCopy(100))
	})
	state := "complete"
	if scanErr != nil {
		state = "incomplete"
	}
	_, outputErr := fmt.Fprintf(os.Stderr, "%s: scanned %d bytes; found %d secrets\n",
		state, summary.BytesInspected, summary.Findings)
	return errors.Join(scanErr, outputErr)
}
