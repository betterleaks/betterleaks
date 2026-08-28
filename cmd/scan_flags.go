package cmd

import (
	"time"

	"github.com/spf13/cobra"
)

// scanFlags adds the options shared by commands that detect findings from a
// source. Each command owns its flags, so scan state is never shared between
// commands.
func scanFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.Int("exit-code", 1, "exit code when leaks have been encountered")
	flags.BoolP("silent", "s", false, "suppress findings and banner")
	flags.Bool("jsonl", false, "print findings as JSONL")
	flags.StringP("report", "r", "", "output findings in report format to file (use \"-\" for stdout)")
	flags.String("confidence", "", "minimum confidence to include (low, medium, high)")
	flags.Int("max-target-megabytes", 0, "files larger than this will be skipped")
	flags.Int("source-workers", 0, "number of concurrent source workers (0 = source default)")
	flags.Int("detect-workers", 0, "number of concurrent detection workers (0 = GOMAXPROCS)")
	flags.Bool("ignore-allow-comments", false, "ignore allow comments")
	flags.Uint("redact", 0, "redact secrets from logs and stdout. To redact only parts of the secret just apply a percent value from 0..100. For example --redact=20 (default 100%)")
	flags.Lookup("redact").NoOptDefVal = "100"
	flags.Bool("no-banner", false, "suppress banner")
	flags.StringSlice("disable-rule", nil, "disable specific rules by id (repeatable; shorthand: -dr)")
	flags.StringSlice("isolate-rule", nil, "only enable specific rules by id (repeatable; shorthand: -ir)")
	flags.String("match-context", "", "context around match (this gets reported): L (lines), C (columns/characters). e.g. 10L, 100C, -2C,+4C")
	flags.Int("max-decode-depth", 5, "allow recursive decoding up to this depth")
	flags.Int("max-archive-depth", 8, "allow scanning into nested archives up to this depth")

	flags.Bool("validation", false, "enable validation of findings against live APIs")
	flags.String("validation-status", "", "comma-separated list of validation statuses to include: valid, needs_validation, invalid, revoked, error, unknown, none (none = rules without validation)")
	flags.Int("validation-workers", 10, "number of concurrent validation workers")
	flags.Bool("validation-debug", false, "include validation HTTP debug metadata in output")
	validationRuntimeFlags(cmd)

	flags.String("diagnostics", "", "enable diagnostics (http OR comma-separated list: cpu,mem,trace,rules,rules-csv). cpu=CPU prof, mem=memory prof, trace=exec tracing, rules=rule timings text, rules-csv=rule timings CSV, http=serve via net/http/pprof")
	flags.String("diagnostics-dir", "", "directory to store diagnostics output files when not using http mode (defaults to ./diagnostics)")
}

// validationRuntimeFlags adds controls shared by scanning validation and the
// direct validate command.
func validationRuntimeFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.Duration("validation-timeout", 10*time.Second, "per-request timeout for validation")
	flags.Int("validation-max-requests", 0, "maximum validation requests sent to each provider target (0 = unlimited)")
	flags.Float64("validation-rps", 0, "global validation requests per second (0 = unlimited)")
	flags.StringSlice("validation-rps-rule", nil, "rule-specific validation request rate as RULE=RPS (repeatable)")
	flags.Bool("validation-extract-empty", false, "include empty values from extractors in output")
	flags.StringSlice("validation-env-vars", nil, "comma-separated env var names the validation env.get(...) binding may read (repeat flag to add more); unset means env access is disabled")
}
