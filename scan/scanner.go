package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/ahocorasick"
	"github.com/betterleaks/betterleaks/v2/internal/contextwindow"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/internal/limits"
	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
)

var allowSignatures = [...]string{"betterleaks:allow", "gitleaks:allow"}

var errStopIteration = errors.New("pipeline: stop iteration")

var discardLogger = slog.New(slog.DiscardHandler)

const (
	levelTrace = slog.LevelDebug - 4

	// maxComponentSets caps the Cartesian product of component-finding combinations
	// to prevent excessive memory use with large multi-part rules.
	maxComponentSets = limits.ComponentSets
)

func logTrace(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), levelTrace, msg, args...)
}

func loggerOrDiscard(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return discardLogger
	}
	return logger
}

type ruleCandidates struct {
	// Indexes match rulesBySpecificity, preserving rule order without building
	// a map and sorted slice for every fragment and decode pass.
	marked []bool
}

// Scanner is an immutable rule engine with thread-safe lazy compilation. A
// Scanner may be reused concurrently with independent sources. Each scan
// owns its execution state.
type Scanner struct {
	ignoredFingerprints map[fingerprint.Hash]struct{}
	maxDecodeDepth      int
	matchContext        contextwindow.Spec
	minimumConfidence   string
	ignoreAllowComments bool
	jobs                int
	logger              *slog.Logger

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter        *ahocorasick.Matcher
	prefilterProgram exprruntime.Program
	globalFilterExpr string
	excludedPaths    []string

	tokenCounter     *tokenizer.Counter
	tokenCounterOnce sync.Once

	exprRuntime *exprruntime.LocalRuntime

	globalFilter lazyFilter

	// rulesBySpecificity contains an immutable snapshot of every configured rule in descending
	// specificity order. Its positions are the shared index space used by the
	// candidate slices below, so it must not change after scanner construction.
	rulesBySpecificity []compiledRule
	ruleIndexByID      map[string]int

	// keywordRuleIndexes maps each Aho-Corasick pattern ID to the positions in
	// rulesBySpecificity of rules that use that keyword. Precomputing this avoids
	// keyword strings and map lookups while scanning each fragment.
	keywordRuleIndexes [][]int

	// noKeywordIndexes contains positions in rulesBySpecificity for rules with no
	// keyword prefilter. These rules are candidates on every scan and decode pass.
	noKeywordIndexes []int

	// candidatePool reuses bitmaps across scanner workers and repeated scans. A
	// set bit means the rule at the same rulesBySpecificity position should run.
	// Bitmaps must be cleared before they are returned.
	candidatePool sync.Pool
}

// New creates a Scanner from cfg. The source prefilter compiles during
// construction; rule regexes and finding filters stay
// lazy unless [WithPrecompile] is supplied. Construction never starts scan or
// provider workers.
func New(cfg *config.Config, options ...Option) (*Scanner, error) {
	if cfg == nil {
		return nil, errors.New("config is required to create scanner")
	}
	settings := scannerOptions{logger: discardLogger}
	for _, option := range options {
		if option.apply == nil {
			return nil, errors.New("scanner option is invalid")
		}
		if err := option.apply(&settings); err != nil {
			return nil, err
		}
	}
	rulesBySpecificity, ruleIndexByID, snapshotErr := snapshotRules(cfg)
	if snapshotErr != nil {
		return nil, fmt.Errorf("invalid config: %w", snapshotErr)
	}

	exprRuntime := exprruntime.NewLocal()

	keywordToRuleIndexes := make(map[string][]int)
	noKeywordIndexes := make([]int, 0)
	for ruleIndex, rule := range rulesBySpecificity {
		if len(rule.rule.Keywords) == 0 {
			noKeywordIndexes = append(noKeywordIndexes, ruleIndex)
			continue
		}
		for _, keyword := range rule.rule.Keywords {
			keyword = strings.ToLower(keyword)
			indexes := keywordToRuleIndexes[keyword]
			// A rule may repeat a keyword with different casing. Dispatch it once.
			if len(indexes) == 0 || indexes[len(indexes)-1] != ruleIndex {
				keywordToRuleIndexes[keyword] = append(indexes, ruleIndex)
			}
		}
	}
	keywords := make([]string, 0, len(keywordToRuleIndexes))
	for keyword := range keywordToRuleIndexes {
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	keywordRuleIndexes := make([][]int, len(keywords))
	for patternID, keyword := range keywords {
		keywordRuleIndexes[patternID] = keywordToRuleIndexes[keyword]
	}
	d := &Scanner{
		maxDecodeDepth:      settings.maxDecodeDepth,
		matchContext:        settings.matchContext,
		minimumConfidence:   settings.minimumConfidence,
		ignoreAllowComments: settings.ignoreAllowComments,
		excludedPaths:       slices.Clone(settings.excludedPaths),
		jobs:                settings.jobs,
		logger:              settings.logger,
		globalFilterExpr:    cfg.Filter,
		prefilter:           ahocorasick.Compile(keywords, true),
		exprRuntime:         exprRuntime,
		rulesBySpecificity:  rulesBySpecificity,
		ruleIndexByID:       ruleIndexByID,
		keywordRuleIndexes:  keywordRuleIndexes,
		noKeywordIndexes:    noKeywordIndexes,
	}
	if len(settings.ignoredFingerprints) > 0 {
		d.ignoredFingerprints = make(map[fingerprint.Hash]struct{}, len(settings.ignoredFingerprints))
		for _, hash := range settings.ignoredFingerprints {
			d.ignoredFingerprints[hash] = struct{}{}
		}
	}
	d.candidatePool.New = func() any {
		return &ruleCandidates{marked: make([]bool, len(d.rulesBySpecificity))}
	}
	exprRuntime.SetTokenCounterProvider(d.tokenCounterInstance)

	// Compile only the global prefilter so sources can use it before scanning.
	// Finding filters and per-rule expressions compile lazily on first candidate.
	if cfg.Prefilter != "" {
		program, compileErr := exprRuntime.CompilePrefilter(cfg.Prefilter)
		if compileErr != nil {
			return nil, fmt.Errorf("compile global prefilter: %w", compileErr)
		}
		d.prefilterProgram = program
	}

	if settings.precompile {
		if err := d.compileAll(); err != nil {
			return nil, err
		}
	}

	return d, nil
}

func (d *Scanner) compileAll() error {
	if _, _, err := d.globalFilterProgram(); err != nil {
		return err
	}
	for i := range d.rulesBySpecificity {
		rule := &d.rulesBySpecificity[i]
		if rule.regex != nil {
			if err := rule.regex.Compile(); err != nil {
				return fmt.Errorf("compile rule %q regex: %w", rule.rule.ID, err)
			}
		}
		if rule.path != nil {
			if err := rule.path.Compile(); err != nil {
				return fmt.Errorf("compile rule %q path regex: %w", rule.rule.ID, err)
			}
		}
		if _, _, err := d.ruleFilterProgram(rule); err != nil {
			return err
		}
	}
	return nil
}
