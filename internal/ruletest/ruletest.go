// Package ruletest executes rule test fixtures through the scanner.
package ruletest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Runner isolates each rule with its required and optional components, so
// unrelated specificity/overlap cannot hide failures. Global policy still
// applies. Provider operations are never executed.
type Runner struct {
	cfg       *config.Config
	engine    regexp.Engine
	local     *exprruntime.LocalRuntime
	prefilter exprruntime.Program
	scanners  map[scannerKey]*ruleScanner
}

type scannerKey struct {
	rule  string
	match bool
}

type ruleScanner struct {
	scanner     *scan.Scanner
	diagnostics *bytes.Buffer
}

// Failure describes one failing test of a rule.
type Failure struct {
	Test string
	Err  error
}

// New prepares a runner for rules in cfg. cfg must already be validated.
func New(cfg *config.Config, engine regexp.Engine) (*Runner, error) {
	r := &Runner{
		cfg:      cfg,
		engine:   engine,
		local:    exprruntime.NewLocal(engine),
		scanners: make(map[scannerKey]*ruleScanner),
	}
	if cfg.PrefilterExpr != "" {
		prefilter, err := r.local.CompilePrefilter(cfg.PrefilterExpr)
		if err != nil {
			return nil, err
		}
		r.prefilter = prefilter
	}
	return r, nil
}

// Run executes every test of rule and reports the failing ones. err reports
// setup problems and cancellation, not assertion failures.
func (r *Runner) Run(ctx context.Context, rule config.Rule) ([]Failure, error) {
	var failures []Failure
	for _, test := range rule.Tests {
		if err := ctx.Err(); err != nil {
			return failures, err
		}
		if _, err := r.scanner(rule, test.Mode == "match"); err != nil {
			return failures, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		actual, err := r.Findings(ctx, rule, test)
		if err == nil {
			err = compare(rule.ID, test.Expect, actual)
		} else if ctxErr := ctx.Err(); ctxErr != nil {
			return failures, ctxErr
		}
		if err != nil {
			failures = append(failures, Failure{Test: test.Name, Err: err})
		}
	}
	return failures, nil
}

// Findings scans test.Input as Run would and returns rule's findings. Rule is
// set on each result. Filter diagnostics are errors, so a filter that fails
// open cannot make a test pass.
func (r *Runner) Findings(ctx context.Context, rule config.Rule, test config.RuleTest) ([]config.ExpectedFinding, error) {
	s, err := r.scanner(rule, test.Mode == "match")
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", rule.ID, err)
	}
	s.diagnostics.Reset()
	if r.prefilter != nil {
		skip, err := r.local.EvalPrefilter(r.prefilter, test.Attributes)
		if err != nil || skip {
			return nil, err
		}
	}
	var actual []config.ExpectedFinding
	_, err = s.scanner.Scan(ctx, source{test}, func(f report.Finding) error {
		if f.RuleID != rule.ID {
			return nil
		}
		if f.ComponentSetsTruncated {
			return errors.New("component combinations were truncated")
		}
		value := config.ExpectedFinding{Rule: f.RuleID, Secret: f.Match.Value, Captures: f.Match.Captures}
		for _, set := range f.ComponentSets {
			components := make(map[string]string, len(set.Components))
			for _, component := range set.Components {
				components[component.RuleID] = component.Match.Value
			}
			value.ComponentSets = append(value.ComponentSets, components)
		}
		actual = append(actual, value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if s.diagnostics.Len() > 0 {
		// Scans keep findings on filter evaluation errors. A test must not
		// silently pass just because its filter failed open.
		return nil, fmt.Errorf("scanner diagnostics: %s", strings.TrimSpace(s.diagnostics.String()))
	}
	return actual, nil
}

func (r *Runner) scanner(rule config.Rule, match bool) (*ruleScanner, error) {
	key := scannerKey{rule.ID, match}
	if s := r.scanners[key]; s != nil {
		return s, nil
	}
	probe := *r.cfg
	owner := rule
	owner.Tests = nil
	if match {
		owner.SkipReport = false
	}
	probe.Rules = []config.Rule{owner}
	for _, component := range owner.Components {
		dependency, _ := r.cfg.Rule(component.RuleID) // cfg.Validate checked references.
		dependency.Tests = nil
		probe.Rules = append(probe.Rules, dependency)
	}
	diagnostics := new(bytes.Buffer)
	logger := slog.New(slog.NewTextHandler(diagnostics, &slog.HandlerOptions{Level: slog.LevelWarn}))
	scanner, err := scan.New(&probe, scan.WithRegexEngine(r.engine),
		scan.WithPrecompile(), scan.WithWorkers(1), scan.WithLogger(logger))
	if err != nil {
		return nil, err
	}
	s := &ruleScanner{scanner: scanner, diagnostics: diagnostics}
	r.scanners[key] = s
	return s, nil
}

func compare(ruleID string, expect, actual []config.ExpectedFinding) error {
	want := make([]string, 0, len(expect))
	for _, value := range expect {
		value.Rule = ruleID
		want = append(want, canonical(value))
	}
	got := make([]string, 0, len(actual))
	for _, value := range actual {
		got = append(got, canonical(value))
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return fmt.Errorf("findings differ\n  want: %v\n   got: %v", want, got)
	}
	return nil
}

func canonical(value config.ExpectedFinding) string {
	sets := make([]string, 0, len(value.ComponentSets))
	for _, set := range value.ComponentSets {
		data, _ := json.Marshal(set)
		sets = append(sets, string(data))
	}
	slices.Sort(sets)
	if len(value.Captures) == 0 {
		value.Captures = nil
	}
	data, _ := json.Marshal(struct {
		Rule     string
		Secret   string
		Captures map[string]string
		Sets     []string
	}{value.Rule, value.Secret, value.Captures, sets})
	return string(data)
}

// Yield empty content too, so path-only rules can be tested without file I/O.
type source struct{ test config.RuleTest }

func (s source) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return yield(sources.Fragment{Raw: s.test.Input, Attributes: s.test.Attributes, StartLine: 1}, nil)
}
