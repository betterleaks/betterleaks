package cmd

import (
	"fmt"
	"strconv"
	"time"

	"github.com/alecthomas/kong"

	"github.com/betterleaks/betterleaks/v2/internal/confidence"
)

// ScanFlags are shared by commands that detect findings from a source.
type ScanFlags struct {
	Jobs                int      `group:"scanning" name:"jobs" short:"j" help:"Source and detection concurrency; detection caps at GOMAXPROCS, sources may apply tighter limits (0 = defaults)."`
	MaxTargetMegabytes  int      `group:"scanning" name:"max-target-megabytes" help:"Files larger than this will be skipped."`
	MaxDecodeDepth      int      `group:"scanning" name:"max-decode-depth" default:"5" help:"Allow recursive decoding up to this depth."`
	MaxArchiveDepth     int      `group:"scanning" name:"max-archive-depth" default:"8" help:"Allow scanning into nested archives up to this depth."`
	DisableRule         []string `group:"scanning" name:"disable-rule" help:"Disable specific rules by id (repeatable; shorthand: -dr)."`
	IsolateRule         []string `group:"scanning" name:"isolate-rule" help:"Only enable specific rules by id (repeatable; shorthand: -ir)."`
	IgnoreFile          string   `group:"scanning" name:"ignore-file" placeholder:"PATH" help:"Read secret fingerprints from PATH."`
	IgnoreAllowComments bool     `group:"scanning" name:"no-allow-comments" help:"Ignore allow comments."`

	Output       string     `group:"output" name:"output" short:"o" placeholder:"PATH" help:"Write findings to PATH (.json or .jsonl; use '-' for stdout)."`
	JSONL        bool       `group:"output" name:"jsonl" help:"Print findings as JSONL."`
	Silent       bool       `group:"output" short:"s" help:"Suppress findings and banner."`
	NoBanner     bool       `group:"output" name:"no-banner" help:"Suppress banner."`
	Confidence   string     `group:"output" help:"Minimum confidence to include (low, medium, high)."`
	Redact       redactFlag `group:"output" placeholder:"PERCENT" help:"Redact secrets from logs and stdout. With no value, redact 100%; otherwise specify 0..100."`
	MatchContext string     `group:"output" name:"match-context" help:"Context around match: L (lines), C (columns/characters), e.g. 10L, 100C, -2C,+4C."`
	ExitCode     int        `group:"output" name:"exit-code" default:"1" help:"Exit code when leaks have been encountered."`

	NoAnalysis           bool   `group:"validation" name:"no-analysis" help:"Disable credential analysis while retaining validation."`
	Offline              bool   `group:"validation" help:"Disable validation and analysis provider requests; source fetching may still use the network."`
	ValidationStatus     string `group:"validation" name:"status" help:"Comma-separated validation statuses to include: valid, needs_validation, invalid, revoked, error, unknown, none."`
	ProviderWorkers      int    `group:"validation" name:"provider-workers" default:"${analyze_workers}" help:"Concurrent credential validation/analysis workers, independent of --jobs (0 = default)."`
	ProviderRuntimeFlags `embed:""`

	Diagnostics    string `group:"diagnostics" help:"Enable diagnostics: http or a comma-separated list of cpu,mem,trace,rules."`
	DiagnosticsDir string `group:"diagnostics" name:"diagnostics-dir" help:"Directory for diagnostics output (default: ./diagnostics)."`
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

func (f ScanFlags) validationEnabled() bool {
	return !f.Offline
}

func (f ScanFlags) analysisEnabled() bool {
	return f.validationEnabled() && !f.NoAnalysis
}

// ProviderRuntimeFlags configure requests made by validation, analysis, and revocation.
type ProviderRuntimeFlags struct {
	ProviderDebug       bool          `group:"validation" name:"provider-debug" help:"Include provider HTTP debug metadata in output."`
	ProviderTimeout     time.Duration `group:"validation" name:"provider-timeout" default:"10s" help:"Per-request timeout for provider checks."`
	ProviderMaxRequests int           `group:"validation" name:"provider-max-requests" help:"Maximum requests sent to each provider target (0 = unlimited)."`
	ProviderRPS         float64       `group:"validation" name:"provider-rps" help:"Global provider requests per second (0 = unlimited)."`
	ProviderRPSRule     []string      `group:"validation" name:"provider-rps-rule" help:"Rule-specific provider request rate as RULE=RPS (repeatable)."`
	ProviderEnvVars     []string      `group:"validation" name:"provider-env-vars" help:"Environment variable names provider Expr programs may read (repeatable)."`
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
