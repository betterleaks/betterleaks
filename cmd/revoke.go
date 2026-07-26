package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/internal/validate"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

func init() {
	rootCmd.AddCommand(revokeCmd)
	revokeCmd.Flags().String("fingerprint", "", "only revoke the finding with this exact fingerprint (default: consider every finding in the report)")
	revokeCmd.Flags().Bool("yes", false, "revoke without an interactive per-finding confirmation prompt")
	revokeCmd.Flags().Bool("dry-run", false, "print what would be revoked without calling any provider")
	revokeCmd.Flags().Bool("continue-on-error", false, "keep going after a revocation fails or errors, instead of stopping")
	revokeCmd.Flags().String("output", "", "write an updated copy of the report (with revoked findings marked) to this path")
}

var revokeCmd = &cobra.Command{
	Use:   "revoke <report-file>",
	Short: "revoke a live secret at its provider, using a scan report as input",
	Long: `revoke calls a rule's 'revoke' expression to deactivate a secret at its provider
(e.g. deleting a Buildkite access token via its DELETE /access-token endpoint).

This is a destructive, irreversible action against a real, live credential.
It is never run automatically during a scan - it only runs here, against
findings you already have in a report file, and only for rules whose config
defines a 'revoke' expression. Findings for rules with no 'revoke' expression
are skipped and reported as unsupported.

By default you are asked to confirm each revocation individually. Use --yes
to skip the prompt in a non-interactive context (e.g. CI), and --dry-run to
see what would happen without revoking anything.`,
	Args: cobra.ExactArgs(1),
	Run:  runRevoke,
}

// revocationOutcome classifies the result of attempting to revoke a single finding.
type revocationOutcome string

const (
	outcomeRevoked     revocationOutcome = "revoked"
	outcomeUnsupported revocationOutcome = "unsupported" // rule has no revoke expression
	outcomeSkipped     revocationOutcome = "skipped"     // user declined confirmation
	outcomeDryRun      revocationOutcome = "dry-run"
	outcomeFailed      revocationOutcome = "failed" // eval error, compile error, or non-"revoked" result
)

// revocationAttempt is the pure result of evaluating one finding's revoke
// expression - no I/O, no process exit, so it's directly unit-testable.
type revocationAttempt struct {
	Outcome revocationOutcome
	Reason  string
	Err     error
}

// revokeOne evaluates a single finding's rule-level revoke expression and
// reports what happened. It does not prompt, print, or exit - callers
// (the CLI command, or a test) decide what to do with the result.
//
// If the rule has no RevokeExpr, the outcome is outcomeUnsupported.
// The compiled program is cached on the rule (via SetRevocationProgram) so
// repeated calls for the same rule ID only compile once.
func revokeOne(ctx context.Context, cfg *config.Config, runtime *exprruntime.Runtime, f *report.Finding) revocationAttempt {
	rule, ok := cfg.Rules[f.RuleID]
	if !ok || rule.RevokeExpr == "" {
		return revocationAttempt{Outcome: outcomeUnsupported}
	}

	prg := rule.RevocationProgram()
	if prg == nil {
		var err error
		prg, err = runtime.CompileValidation(rule.RevokeExpr)
		if err != nil {
			return revocationAttempt{Outcome: outcomeFailed, Err: fmt.Errorf("compiling revoke expression for rule %s: %w", f.RuleID, err)}
		}
		rule.SetRevocationProgram(prg)
		cfg.Rules[f.RuleID] = rule
	}

	result, evalErr := runtime.EvalValidation(ctx, prg, f.ToExprMap(), f.CaptureGroups, f.Attributes, exprruntime.EvalOptions{})
	if evalErr != nil {
		return revocationAttempt{Outcome: outcomeFailed, Err: fmt.Errorf("evaluating revoke expression: %w", evalErr)}
	}

	parsed := validate.ParseResult(result.Value)
	if parsed.Status == report.ValidationStatusRevoked {
		return revocationAttempt{Outcome: outcomeRevoked, Reason: parsed.Reason}
	}
	reason := parsed.Reason
	if reason == "" {
		reason = fmt.Sprintf("revoke expression returned status %q instead of \"revoked\"", parsed.Status)
	}
	return revocationAttempt{Outcome: outcomeFailed, Reason: reason}
}

func runRevoke(cmd *cobra.Command, args []string) {
	reportPath := args[0]
	fingerprint := mustGetStringFlag(cmd, "fingerprint")
	skipConfirm := mustGetBoolFlag(cmd, "yes")
	dryRun := mustGetBoolFlag(cmd, "dry-run")
	continueOnError := mustGetBoolFlag(cmd, "continue-on-error")
	outputPath := mustGetStringFlag(cmd, "output")

	source := "."
	initConfig(source)
	cfg := Config(cmd)

	allFindings, err := loadFindingsReport(reportPath)
	if err != nil {
		logging.Fatal().Err(err).Str("path", reportPath).Msg("failed to load report")
	}
	if len(allFindings) == 0 {
		logging.Info().Msg("report contains no findings, nothing to revoke")
		return
	}

	// targets is the subset of allFindings to actually attempt revocation
	// against. allFindings itself is never filtered down - --output must
	// always write back the complete original set (with only the attempted
	// findings' statuses updated), otherwise every finding excluded by
	// --fingerprint would silently disappear from the written report and
	// from downstream baseline processing.
	var targets []*report.Finding
	if fingerprint != "" {
		for i := range allFindings {
			if allFindings[i].Fingerprint == fingerprint {
				targets = append(targets, &allFindings[i])
			}
		}
		if len(targets) == 0 {
			logging.Fatal().Str("fingerprint", fingerprint).Msg("no finding in the report matches this fingerprint")
		}
	} else {
		for i := range allFindings {
			targets = append(targets, &allFindings[i])
		}
	}

	runtime, err := cfg.CompileRevocation()
	if err != nil {
		logging.Fatal().Err(err).Msg("failed to compile revocation expressions")
	}

	reader := bufio.NewReader(os.Stdin)
	counts := map[revocationOutcome]int{}

	writeOutput := func() {
		if outputPath == "" || dryRun {
			return
		}
		out, err := json.MarshalIndent(allFindings, "", " ")
		if err != nil {
			logging.Fatal().Err(err).Msg("failed to marshal updated report")
		}
		// 0o600: this file can contain revoked/skipped/failed secrets in
		// plaintext, so it must not be group- or world-readable.
		if err := os.WriteFile(outputPath, out, 0o600); err != nil {
			logging.Fatal().Err(err).Str("path", outputPath).Msg("failed to write updated report")
		}
		logging.Info().Str("path", outputPath).Msg("wrote updated report")
	}

	for _, f := range targets {

		rule, ok := cfg.Rules[f.RuleID]
		if !ok || rule.RevokeExpr == "" {
			fmt.Printf("[skip] %s: rule %q has no 'revoke' expression configured\n", shortFingerprint(f.Fingerprint), f.RuleID)
			counts[outcomeUnsupported]++
			continue
		}

		fmt.Printf("\nRuleID:      %s\n", f.RuleID)
		fmt.Printf("Path:        %s\n", f.Attributes[sources.AttrPath])
		fmt.Printf("Fingerprint: %s\n", f.Fingerprint)

		if dryRun {
			fmt.Println("[dry-run] would attempt revocation here")
			counts[outcomeDryRun]++
			continue
		}

		if !skipConfirm {
			fmt.Print("Revoke this secret now? This cannot be undone. [y/N]: ")
			line, _ := reader.ReadString('\n')
			answer := strings.ToLower(strings.TrimSpace(line))
			if answer != "y" && answer != "yes" {
				fmt.Println("[skip] not confirmed")
				counts[outcomeSkipped]++
				continue
			}
		}

		attempt := revokeOne(context.Background(), cfg, runtime, f)
		counts[attempt.Outcome]++

		switch attempt.Outcome {
		case outcomeRevoked:
			fmt.Printf("[revoked] %s\n", nonEmptyOr(attempt.Reason, "provider confirmed revocation"))
			f.ValidationStatus = report.ValidationStatusRevoked
			f.ValidationReason = attempt.Reason
		case outcomeFailed:
			if attempt.Err != nil {
				fmt.Printf("[error] %v\n", attempt.Err)
			} else {
				fmt.Printf("[failed] %s\n", attempt.Reason)
			}
			if !continueOnError {
				fmt.Printf("\nrevoked=%d unsupported=%d skipped=%d failed=%d\n",
					counts[outcomeRevoked], counts[outcomeUnsupported], counts[outcomeSkipped], counts[outcomeFailed])
				// Write back whatever was already revoked before stopping -
				// otherwise a real, successful, irreversible revocation would
				// go unrecorded in the report just because a later finding failed.
				writeOutput()
				os.Exit(1)
			}
		}
	}

	fmt.Printf("\nrevoked=%d unsupported=%d skipped=%d failed=%d\n",
		counts[outcomeRevoked], counts[outcomeUnsupported], counts[outcomeSkipped], counts[outcomeFailed])

	writeOutput()
}

// loadFindingsReport reads a JSON report (as produced by --report-format json)
// into a slice of findings, mirroring detect.LoadBaseline's approach to
// reading a prior report back in.
func loadFindingsReport(path string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading report file: %w", err)
	}
	var findings []report.Finding
	if err := json.Unmarshal(bytes, &findings); err != nil {
		return nil, fmt.Errorf("parsing report file as JSON findings: %w", err)
	}
	return findings, nil
}

func shortFingerprint(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12] + "…"
}

func nonEmptyOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
