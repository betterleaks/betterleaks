package report

import (
	"strconv"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/logging"
)

// FilterProvider is the interface Replay requires for compiled filter programs.
// Satisfied by detect.FilterSet.
type FilterProvider interface {
	Global() (exprruntime.Program, bool, error)
	ForRule(r config.Rule) (exprruntime.Program, bool, error)
}

// SuppressionProvider is the interface Replay requires for ignore/baseline checks.
// Satisfied by detect.Suppression.
type SuppressionProvider interface {
	Suppressed(f Finding) bool
}

// ReplayOptions controls the behaviour of Replay.
type ReplayOptions struct {
	Config      *config.Config
	ExprRuntime *exprruntime.Runtime
	FilterSet   FilterProvider      // nil skips filter evaluation
	Suppression SuppressionProvider // nil skips ignore/baseline suppression
}

// nonPersistableBindings are filter expression references that evaluate to
// empty string / zero on replay because the underlying data is not in the report.
var nonPersistableBindings = []string{
	"finding.context",
	"finding.fragment_raw",
	"finding.match_start_idx",
	"finding.match_end_idx",
	"finding.match_line_start_idx",
	"finding.match_line_end_idx",
}

// warnedExprs ensures the non-persistable-binding warning fires once per unique expression.
var warnedExprs sync.Map

// warnNonPersistable logs once if expr references bindings unavailable on replay.
func warnNonPersistable(expr string) {
	for _, binding := range nonPersistableBindings {
		// This just does a substring check, not a full parse of the expression.
		// It could produce false positives, but that's very unlikely and is simpler
		// than parsing the expression to an AST and checking for identifiers.
		if strings.Contains(expr, binding) {
			if _, loaded := warnedExprs.LoadOrStore(expr, struct{}{}); !loaded {
				logging.Warn().
					Str("expression", expr).
					Msg("filter references non-persistable bindings; they evaluate to empty/zero on replay — results may differ from scan time")
			}
			return
		}
	}
}

// Replay re-evaluates the config's prefilter + global filter + per-rule filters
// against each input finding, applies Suppression if provided, and returns the
// findings that pass. Findings whose RuleID is absent from the config are kept
// and a debug message is emitted. Individual expression errors are warned, not fatal.
func Replay(findings []Finding, opts ReplayOptions) ([]Finding, error) {
	cfg := opts.Config
	rt := opts.ExprRuntime
	prefilterPrg := cfg.PrefilterProgram()

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		// 1. Backfill deprecated source fields so filters using path/commit/etc. work
		//    even when the report was produced by an older betterleaks version.
		f.SyncDeprecatedSourceFields()

		// 2. Suppression: ignore file + baseline (applied before expressions).
		if opts.Suppression != nil && opts.Suppression.Suppressed(f) {
			continue
		}

		// 3. Prefilter (attributes only).
		if prefilterPrg != nil {
			skip, err := rt.EvalPrefilter(prefilterPrg, f.Attributes)
			if err != nil {
				logging.Warn().Err(err).Str("rule_id", f.RuleID).Msg("prefilter eval error on replay")
			} else if skip {
				continue
			}
		}

		// 4. Determine which filters apply and build findingMap when needed.
		rule, ruleOK := cfg.Rules[f.RuleID]
		hasGlobalFilter := opts.FilterSet != nil && (cfg.Filter != "" || cfg.FilterProgram() != nil)
		hasRuleFilter := opts.FilterSet != nil && ruleOK && (rule.Filter != "" || rule.FilterProgram() != nil)

		var findingMap map[string]any
		if hasGlobalFilter || hasRuleFilter {
			if f.Attributes == nil {
				f.Attributes = make(map[string]string)
			}
			findingMap = make(map[string]any, 12)
			for key, value := range f.ToExprMap() {
				findingMap[key] = value
			}
			// Convert entropy from float32 to string, the format needed for filter expressions.
			findingMap["entropy"] = strconv.FormatFloat(float64(f.Entropy), 'g', -1, 64)
			// Non-persistable bindings are set to their zero values (same as
			// emptyFilterFinding in exprruntime) so expressions compile but see empties.
			findingMap["fragment_raw"] = ""
			findingMap["match_start_idx"] = 0
			findingMap["match_end_idx"] = 0
			findingMap["match_line_start_idx"] = 0
			findingMap["match_line_end_idx"] = 0
		}

		// 5. Global filter.
		if hasGlobalFilter {
			warnNonPersistable(cfg.Filter)
			prg, ok, err := opts.FilterSet.Global()
			if err != nil {
				logging.Warn().Err(err).Msg("global filter compile error on replay")
			} else if ok {
				skip, err := rt.EvalFilter(prg, findingMap, f.Attributes)
				if err != nil {
					logging.Warn().Err(err).Msg("global filter eval error on replay")
				} else if skip {
					continue
				}
			}
		}

		// 6. Per-rule filter.
		if opts.FilterSet != nil {
			if !ruleOK {
				logging.Debug().Str("rule_id", f.RuleID).Msg("rule not in config on replay; keeping finding")
			} else if hasRuleFilter {
				warnNonPersistable(rule.Filter)
				prg, ok, err := opts.FilterSet.ForRule(rule)
				if err != nil {
					logging.Warn().Err(err).Str("rule_id", f.RuleID).Msg("rule filter compile error on replay")
				} else if ok {
					skip, err := rt.EvalFilter(prg, findingMap, f.Attributes)
					if err != nil {
						logging.Warn().Err(err).Str("rule_id", f.RuleID).Msg("rule filter eval error on replay")
					} else if skip {
						continue
					}
				}
			}
		}

		out = append(out, f)
	}
	return out, nil
}
