package cmd

import (
	"fmt"
	"strconv"
	"time"

	"github.com/alecthomas/kong"

	"github.com/betterleaks/betterleaks/internal/confidence"
)

// ScanFlags are shared by commands that detect findings from a source.
type ScanFlags struct {
	ExitCode            int        `name:"exit-code" default:"1" help:"Exit code when leaks have been encountered."`
	Silent              bool       `short:"s" help:"Suppress findings and banner."`
	JSONL               bool       `name:"jsonl" help:"Print findings as JSONL."`
	Output              string     `name:"output" short:"o" placeholder:"PATH" help:"Write findings to PATH (.json or .jsonl; use '-' for stdout)."`
	Confidence          string     `help:"Minimum confidence to include (low, medium, high)."`
	MaxTargetMegabytes  int        `name:"max-target-megabytes" help:"Files larger than this will be skipped."`
	Jobs                int        `name:"jobs" short:"j" help:"Parallel scan jobs; CPU-bound stages cap at available processors (0 = automatic)."`
	IgnoreFile          string     `name:"ignore-file" placeholder:"PATH" help:"Read secret fingerprints from PATH."`
	IgnoreAllowComments bool       `name:"ignore-allow-comments" help:"Ignore allow comments."`
	Redact              redactFlag `placeholder:"PERCENT" help:"Redact secrets from logs and stdout. With no value, redact 100%; otherwise specify 0..100."`
	NoBanner            bool       `name:"no-banner" help:"Suppress banner."`
	DisableRule         []string   `name:"disable-rule" help:"Disable specific rules by id (repeatable; shorthand: -dr)."`
	IsolateRule         []string   `name:"isolate-rule" help:"Only enable specific rules by id (repeatable; shorthand: -ir)."`
	MatchContext        string     `name:"match-context" help:"Context around match: L (lines), C (columns/characters), e.g. 10L, 100C, -2C,+4C."`
	MaxDecodeDepth      int        `name:"max-decode-depth" default:"5" help:"Allow recursive decoding up to this depth."`
	MaxArchiveDepth     int        `name:"max-archive-depth" default:"8" help:"Allow scanning into nested archives up to this depth."`

	Validation           bool   `help:"Enable validation of findings against live APIs."`
	Analysis             bool   `help:"Validate findings and analyze valid credentials for identity and capabilities."`
	ValidationStatus     string `name:"validation-status" help:"Comma-separated validation statuses to include: valid, needs_validation, invalid, revoked, error, unknown, none."`
	ProviderWorkers      int    `name:"provider-workers" default:"10" help:"Number of concurrent provider workers."`
	ProviderDebug        bool   `name:"provider-debug" help:"Include provider HTTP debug metadata in output."`
	ProviderRuntimeFlags `embed:""`

	Diagnostics    string `help:"Enable diagnostics: http or a comma-separated list of cpu,mem,trace,rules,rules-csv."`
	DiagnosticsDir string `name:"diagnostics-dir" help:"Directory for diagnostics output (default: ./diagnostics)."`
}

func (f ScanFlags) Validate() error {
	if f.Jobs < 0 {
		return fmt.Errorf("--jobs must be non-negative")
	}
	if _, err := confidence.Parse(f.Confidence); err != nil {
		return err
	}
	return f.ProviderRuntimeFlags.Validate()
}

// ProviderRuntimeFlags bound active requests made by validation and analysis.
// The validation-* aliases remain accepted for v1 CLI compatibility.
type ProviderRuntimeFlags struct {
	ProviderTimeout        time.Duration `name:"provider-timeout" default:"10s" help:"Per-request timeout for provider checks."`
	ProviderMaxRequests    int           `name:"provider-max-requests" help:"Maximum requests sent to each provider target (0 = unlimited)."`
	ProviderRPS            float64       `name:"provider-rps" help:"Global provider requests per second (0 = unlimited)."`
	ProviderRPSRule        []string      `name:"provider-rps-rule" help:"Rule-specific provider request rate as RULE=RPS (repeatable)."`
	ValidationExtractEmpty bool          `name:"validation-extract-empty" help:"Include empty values from extractors in output."`
	ProviderEnvVars        []string      `name:"provider-env-vars" help:"Environment variable names provider Expr programs may read (repeatable)."`
}

func (f ProviderRuntimeFlags) Validate() error {
	if f.ProviderTimeout < 0 {
		return fmt.Errorf("--provider-timeout must be non-negative")
	}
	if f.ProviderMaxRequests < 0 {
		return fmt.Errorf("--provider-max-requests must be non-negative")
	}
	if err := validateProviderRPS(f.ProviderRPS); err != nil {
		return fmt.Errorf("--provider-rps: %w", err)
	}
	if _, err := parseProviderRuleRPS(f.ProviderRPSRule); err != nil {
		return fmt.Errorf("--provider-rps-rule: %w", err)
	}
	return nil
}

// redactFlag behaves like a boolean flag when no value is supplied, while
// still accepting --redact=PERCENT.
type redactFlag uint

func (r *redactFlag) Decode(ctx *kong.DecodeContext) error {
	if ctx.Scan.Peek().Type != kong.FlagValueToken {
		*r = 100
		return nil
	}
	token := ctx.Scan.Pop()
	value, ok := token.Value.(string)
	if !ok {
		return fmt.Errorf("expected redaction percentage, got %T", token.Value)
	}
	percent, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid redaction percentage %q: %w", value, err)
	}
	*r = redactFlag(percent)
	return nil
}

func (*redactFlag) IsBool() bool { return true }
