package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	ahocorasick "github.com/rrethy/ahocorasick"

	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

type resolvedConfig struct {
	cfg    *configpkg.Config
	source string
}

type ConfigCmd struct {
	Check ConfigCheckCmd `cmd:"" help:"Validate configs and run embedded rule tests."`
	Show  ConfigShowCmd  `cmd:"" help:"Print the resolved betterleaks config."`
	Path  ConfigPathCmd  `cmd:"" help:"Print the selected config source."`
	Hash  ConfigHashCmd  `cmd:"" help:"Print the hash of the resolved config or one rule."`
}

type ConfigHashCmd struct {
	Rule string `help:"Hash this rule and its component definitions instead of the whole config."`
	Path string `arg:"" optional:"" name:"config-path" help:"Config file to hash."`
}

func (cmd *ConfigHashCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(runtime, cli.Config, cmd.Path)
	if err != nil {
		return err
	}
	var hash string
	if cmd.Rule == "" {
		hash = resolved.cfg.Hash()
	} else {
		hash, err = resolved.cfg.RuleHash(cmd.Rule)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(runtime.stdout, hash)
	return err
}

type ConfigCheckCmd struct {
	Path string `arg:"" optional:"" name:"config-path" help:"Config file or directory of TOML files to validate and test."`
}

func (cmd *ConfigCheckCmd) Run(cli *CLI, runtime *commandRuntime) error {
	path := cmd.Path
	if path == "" {
		path = cli.Config
	}
	if path == "" {
		path = os.Getenv("BETTERLEAKS_CONFIG")
	}
	paths := []string{path}
	directory := false
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			directory = true
			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			paths = nil
			for _, entry := range entries {
				if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".toml") {
					paths = append(paths, filepath.Join(path, entry.Name()))
				}
			}
			if len(paths) == 0 {
				return fmt.Errorf("no TOML config files in %q", path)
			}
		}
	}

	var failures []error
	total, failed := 0, 0
	for _, path := range paths {
		if err := runtime.logContext().Err(); err != nil {
			return err
		}
		resolved, err := resolveConfig(runtime, cli.Config, path)
		if err == nil {
			err = validateConfig(resolved.cfg, runtime.regexEngine())
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("config %q: %w", path, err))
			continue
		}
		run, bad, err := runConfigRuleTests(runtime, resolved)
		total += run
		failed += bad
		if err != nil {
			return err
		}
		if bad != 0 {
			continue
		}
		withValidation, withoutValidation := countValidationRules(resolved.cfg)
		prefix := ""
		if directory {
			prefix = resolved.source + ": "
		}
		if _, err := fmt.Fprintf(runtime.stdout, "%sOK: %d rules (%d with validation, %d without validation); %d rule tests passed\n",
			prefix, len(resolved.cfg.Rules), withValidation, withoutValidation, run); err != nil {
			return err
		}
	}
	if failed > 0 {
		failures = append(failures, fmt.Errorf("%d of %d rule tests failed", failed, total))
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	if directory {
		_, err := fmt.Fprintf(runtime.stdout, "OK: %d rule tests passed across %d config files\n", total, len(paths))
		return err
	}
	return nil
}

// Rule fixtures isolate their owner and its required/optional components. This
// keeps unrelated specificity/overlap from hiding failures in a provider rule.
// Global policy still applies. Provider operations are compiled by validateConfig
// but are never executed by this detection-only runner.
func runConfigRuleTests(runtime *commandRuntime, resolved *resolvedConfig) (total, failed int, err error) {
	cfg := resolved.cfg
	local := exprruntime.NewLocal(runtime.regexEngine())
	var prefilter exprruntime.Program
	if cfg.PrefilterExpr != "" {
		prefilter, err = local.CompilePrefilter(cfg.PrefilterExpr)
		if err != nil {
			return total, failed, err
		}
	}
	for _, rule := range cfg.Rules {
		if len(rule.Tests) == 0 {
			continue
		}
		var diagnostics bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&diagnostics, &slog.HandlerOptions{Level: slog.LevelWarn}))
		scanners := make(map[bool]*scan.Scanner, 2)
		for _, test := range rule.Tests {
			if err := runtime.logContext().Err(); err != nil {
				return total, failed, err
			}
			total++
			diagnostics.Reset()
			match := test.Mode == "match"
			scanner := scanners[match]
			if scanner == nil {
				probe := *cfg
				owner := rule
				owner.Tests = nil
				if match {
					owner.SkipReport = false
				}
				probe.Rules = []configpkg.Rule{owner}
				for _, component := range owner.Components {
					dependency, _ := cfg.Rule(component.RuleID) // cfg.Validate checked references.
					dependency.Tests = nil
					probe.Rules = append(probe.Rules, dependency)
				}
				scanner, err = scan.New(&probe, scan.WithRegexEngine(runtime.regexEngine()),
					scan.WithPrecompile(), scan.WithWorkers(1), scan.WithLogger(logger))
				if err != nil {
					return total, failed, fmt.Errorf("%s: rule %q: %w", resolved.source, rule.ID, err)
				}
				scanners[match] = scanner
			}
			var skip bool
			var testErr error
			if prefilter != nil {
				skip, testErr = local.EvalPrefilter(prefilter, test.Attributes)
			}
			var actual []string
			if testErr == nil && !skip {
				_, testErr = scanner.Scan(runtime.logContext(), ruleTestSource{test}, func(f report.Finding) error {
					if f.RuleID != rule.ID {
						return nil
					}
					if f.ComponentSetsTruncated {
						return errors.New("component combinations were truncated")
					}
					value := configpkg.ExpectedFinding{Rule: f.RuleID, Secret: f.Match.Value, Captures: f.Match.Captures}
					for _, set := range f.ComponentSets {
						components := make(map[string]string, len(set.Components))
						for _, component := range set.Components {
							components[component.RuleID] = component.Match.Value
						}
						value.ComponentSets = append(value.ComponentSets, components)
					}
					actual = append(actual, canonicalTestFinding(value))
					return nil
				})
			}
			if testErr == nil && diagnostics.Len() > 0 {
				// Scans keep findings on filter evaluation errors. A test must not
				// silently pass just because its filter failed open.
				testErr = fmt.Errorf("scanner diagnostics: %s", strings.TrimSpace(diagnostics.String()))
			}
			if testErr == nil {
				expected := make([]string, 0, len(test.Expect))
				for _, value := range test.Expect {
					value.Rule = rule.ID
					expected = append(expected, canonicalTestFinding(value))
				}
				slices.Sort(expected)
				slices.Sort(actual)
				if !slices.Equal(expected, actual) {
					testErr = fmt.Errorf("findings differ\n  want: %v\n   got: %v", expected, actual)
				}
			}
			if testErr != nil {
				if err := runtime.logContext().Err(); err != nil {
					return total, failed, err
				}
				failed++
				if _, err := fmt.Fprintf(runtime.stderr, "FAIL: %s: rule %q test %q: %v\n", resolved.source, rule.ID, test.Name, testErr); err != nil {
					return total, failed, err
				}
			}
		}
	}
	return total, failed, nil
}

// Yield empty content too, so path-only rules can be tested without file I/O.
type ruleTestSource struct{ test configpkg.RuleTest }

func (s ruleTestSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return yield(sources.Fragment{Raw: s.test.Input, Attributes: s.test.Attributes, StartLine: 1}, nil)
}

func canonicalTestFinding(value configpkg.ExpectedFinding) string {
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

type ConfigShowCmd struct {
	TOML ConfigShowTOMLCmd `cmd:"" name:"toml" default:"withargs" help:"Print the resolved config as TOML (toml may be omitted before a path)."`
	IDs  ConfigShowIDsCmd  `cmd:"" name:"ids" help:"List rule IDs from the resolved config."`
}

type ConfigShowTOMLCmd struct {
	Path string `arg:"" optional:"" name:"config-path" help:"Config file to render."`
}

func (cmd *ConfigShowTOMLCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(runtime, cli.Config, cmd.Path)
	if err != nil {
		return err
	}
	if err := validateConfig(resolved.cfg, runtime.regexEngine()); err != nil {
		return err
	}
	_, _ = runtime.stdout.Write([]byte(renderConfigTOML(renderConfig(resolved.cfg))))
	return nil
}

type ConfigPathCmd struct{}

func (*ConfigPathCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(runtime, cli.Config, "")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(runtime.stdout, resolved.source)
	return nil
}

func resolveConfig(runtime *commandRuntime, configPath, argumentPath string) (*resolvedConfig, error) {
	loadOption := configpkg.WithLogger(runtime.Logger())
	if argumentPath != "" {
		return loadConfigFile(argumentPath, loadOption)
	}

	if configPath != "" {
		return loadConfigFile(configPath, loadOption)
	}
	if envPath := os.Getenv("BETTERLEAKS_CONFIG"); envPath != "" {
		resolved, err := loadConfigFile(envPath, loadOption)
		if err != nil {
			return nil, err
		}
		resolved.source = "env:BETTERLEAKS_CONFIG:" + envPath
		return resolved, nil
	}
	if content := os.Getenv("BETTERLEAKS_CONFIG_TOML"); content != "" {
		cfg, err := configpkg.ParseTOMLString(content, "", loadOption)
		if err != nil {
			return nil, err
		}
		return &resolvedConfig{cfg: cfg, source: "env:BETTERLEAKS_CONFIG_TOML"}, nil
	}
	cfg, err := configpkg.Default(loadOption)
	if err != nil {
		return nil, err
	}
	return &resolvedConfig{cfg: cfg, source: "default"}, nil
}

func loadConfigFile(path string, options ...configpkg.LoadOption) (*resolvedConfig, error) {
	cfg, err := configpkg.LoadFile(path, options...)
	if err != nil {
		return nil, err
	}
	return &resolvedConfig{cfg: cfg, source: path}, nil
}

func validateConfig(cfg *configpkg.Config, engine regexp.Engine) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	compileKeywordTrie(cfg)
	if err := compileRuleRegexps(cfg, engine); err != nil {
		return err
	}
	rt, err := exprruntime.NewWithRegexEngine(nil, engine)
	if err != nil {
		return err
	}
	if cfg.PrefilterExpr != "" {
		_, err := rt.CompilePrefilter(cfg.PrefilterExpr)
		if err != nil {
			return fmt.Errorf("compiling global prefilter: %w", err)
		}
	}
	if cfg.FilterExpr != "" {
		_, err := rt.CompileFilter(cfg.FilterExpr, nil)
		if err != nil {
			return fmt.Errorf("compiling global filter: %w", err)
		}
	}
	for _, rule := range cfg.Rules {
		id := rule.ID
		if rule.FilterExpr != "" {
			_, err := rt.CompileFilter(rule.FilterExpr, nil)
			if err != nil {
				return fmt.Errorf("compiling rule %s filter: %w", id, err)
			}
		}
		if rule.ValidateExpr != "" {
			if _, err := rt.CompileValidation(rule.ValidateExpr); err != nil {
				return fmt.Errorf("compiling rule %s validation: %w", id, err)
			}
		}
		if rule.AnalyzeExpr != "" {
			if _, err := rt.CompileAnalysis(rule.AnalyzeExpr); err != nil {
				return fmt.Errorf("compiling rule %s analysis: %w", id, err)
			}
		}
		if rule.RevokeExpr != "" {
			if _, err := rt.CompileRevocation(rule.RevokeExpr); err != nil {
				return fmt.Errorf("compiling rule %s revocation: %w", id, err)
			}
		}
	}
	return nil
}

func countValidationRules(cfg *configpkg.Config) (int, int) {
	withValidation := 0
	for _, rule := range cfg.Rules {
		if rule.ValidateExpr != "" {
			withValidation++
		}
	}
	return withValidation, len(cfg.Rules) - withValidation
}

func compileKeywordTrie(cfg *configpkg.Config) {
	unique := make(map[string]struct{})
	for _, rule := range cfg.Rules {
		for _, keyword := range rule.Keywords {
			unique[strings.ToLower(keyword)] = struct{}{}
		}
	}
	keywords := make([]string, 0, len(unique))
	for keyword := range unique {
		keywords = append(keywords, keyword)
	}
	_ = ahocorasick.CompileStrings(keywords)
}

func compileRuleRegexps(cfg *configpkg.Config, engine regexp.Engine) error {
	for _, rule := range cfg.Rules {
		for _, entry := range []struct{ kind, pattern string }{{"regex", rule.Regex}, {"path regex", rule.Path}} {
			if entry.pattern == "" {
				continue
			}
			re, err := regexp.CompileWithEngine(entry.pattern, engine)
			if err == nil {
				err = re.Compile()
			}
			if err != nil {
				return fmt.Errorf("compiling rule %s %s: %w", rule.ID, entry.kind, err)
			}
		}
	}
	return nil
}

type configView struct {
	Title       string     `toml:"title,omitempty"`
	Provider    string     `toml:"provider,omitempty"`
	Description string     `toml:"description,omitempty"`
	MinVersion  string     `toml:"minVersion,omitempty"`
	Prefilter   string     `toml:"prefilter,omitempty"`
	Filter      string     `toml:"filter,omitempty"`
	Rules       []ruleView `toml:"rules"`
}

type ruleView struct {
	ID          string               `toml:"id"`
	Description string               `toml:"description,omitempty"`
	Path        string               `toml:"path,omitempty"`
	Regex       string               `toml:"regex,omitempty"`
	ValueGroup  int                  `toml:"valueGroup,omitempty"`
	Keywords    []string             `toml:"keywords,omitempty"`
	Tags        []string             `toml:"tags,omitempty"`
	Specificity int                  `toml:"specificity,omitempty"`
	Confidence  string               `toml:"confidence,omitempty"`
	Components  []componentView      `toml:"components,omitempty"`
	Validate    string               `toml:"validate,omitempty"`
	Analyze     string               `toml:"analyze,omitempty"`
	Revoke      string               `toml:"revoke,omitempty"`
	SkipReport  bool                 `toml:"skipReport,omitempty"`
	Filter      string               `toml:"filter,omitempty"`
	Tests       []configpkg.RuleTest `toml:"tests,omitempty"`
}

type componentView struct {
	ID       string `toml:"id"`
	Optional bool   `toml:"optional,omitempty"`
	Within   string `toml:"within,omitempty"`
}

func renderConfig(cfg *configpkg.Config) configView {
	view := configView{
		Title:       cfg.Title,
		Provider:    cfg.Provider,
		Description: cfg.Description,
		MinVersion:  cfg.MinVersion,
		Prefilter:   cfg.PrefilterExpr,
		Filter:      cfg.FilterExpr,
	}
	for _, rule := range cfg.Rules {
		rv := ruleView{
			ID:          rule.ID,
			Description: rule.Description,
			Path:        rule.Path,
			Regex:       rule.Regex,
			ValueGroup:  rule.ValueGroup,
			Keywords:    rule.Keywords,
			Tags:        rule.Tags,
			Specificity: rule.Specificity,
			Confidence:  rule.Confidence,
			Validate:    rule.ValidateExpr,
			Analyze:     rule.AnalyzeExpr,
			Revoke:      rule.RevokeExpr,
			SkipReport:  rule.SkipReport,
			Filter:      rule.FilterExpr,
			Tests:       rule.Tests,
		}
		for _, component := range rule.Components {
			rv.Components = append(rv.Components, componentView{
				ID:       component.RuleID,
				Optional: component.Optional,
				Within:   component.Within,
			})
		}
		view.Rules = append(view.Rules, rv)
	}
	return view
}

func renderConfigTOML(view configView) string {
	var b strings.Builder

	writeString(&b, "title", view.Title)
	writeString(&b, "provider", view.Provider)
	writeString(&b, "description", view.Description)
	writeString(&b, "minVersion", view.MinVersion)
	writeString(&b, "prefilter", view.Prefilter)
	writeString(&b, "filter", view.Filter)

	for _, rule := range view.Rules {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("[[rules]]\n")
		writeString(&b, "id", rule.ID)
		writeString(&b, "description", rule.Description)
		writeString(&b, "path", rule.Path)
		writeString(&b, "regex", rule.Regex)
		writeInt(&b, "valueGroup", rule.ValueGroup)
		writeStrings(&b, "keywords", rule.Keywords)
		writeStrings(&b, "tags", rule.Tags)
		writeInt(&b, "specificity", rule.Specificity)
		writeString(&b, "confidence", rule.Confidence)
		writeString(&b, "validate", rule.Validate)
		writeString(&b, "analyze", rule.Analyze)
		writeString(&b, "revoke", rule.Revoke)
		writeBool(&b, "skipReport", rule.SkipReport)
		writeString(&b, "filter", rule.Filter)
		writeComponents(&b, rule.Components)
		writeRuleTests(&b, rule.Tests)
	}

	return b.String()
}

func writeRuleTests(b *strings.Builder, tests []configpkg.RuleTest) {
	for _, test := range tests {
		b.WriteString("\n[[rules.tests]]\n")
		writeString(b, "name", test.Name)
		writeString(b, "mode", test.Mode)
		// Empty input and empty expectations are meaningful, so always emit them.
		fmt.Fprintf(b, "input = %s\n", tomlString(test.Input))
		if len(test.Attributes) > 0 {
			fmt.Fprintf(b, "attributes = %s\n", tomlStringMap(test.Attributes))
		}
		b.WriteString("expect = [")
		for i, expected := range test.Expect {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(b, "{ secret = %s", tomlString(expected.Secret))
			if expected.Rule != "" {
				fmt.Fprintf(b, ", rule = %s", tomlString(expected.Rule))
			}
			if len(expected.Captures) > 0 {
				fmt.Fprintf(b, ", captures = %s", tomlStringMap(expected.Captures))
			}
			if len(expected.ComponentSets) > 0 {
				b.WriteString(", componentSets = [")
				for j, set := range expected.ComponentSets {
					if j > 0 {
						b.WriteString(", ")
					}
					b.WriteString(tomlStringMap(set))
				}
				b.WriteString("]")
			}
			b.WriteString(" }")
		}
		b.WriteString("]\n")
	}
}

func tomlStringMap(values map[string]string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fields := make([]string, 0, len(keys))
	for _, key := range keys {
		fields = append(fields, tomlString(key)+" = "+tomlString(values[key]))
	}
	return "{ " + strings.Join(fields, ", ") + " }"
}

func writeComponents(b *strings.Builder, components []componentView) {
	if len(components) == 0 {
		return
	}
	b.WriteString("components = [\n")
	for _, component := range components {
		b.WriteString("  { id = ")
		b.WriteString(tomlString(component.ID))
		if component.Optional {
			b.WriteString(", optional = true")
		}
		if component.Within != "" {
			b.WriteString(", within = ")
			b.WriteString(tomlString(component.Within))
		}
		b.WriteString(" },\n")
	}
	b.WriteString("]\n")
}

func writeString(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	b.WriteString(key)
	b.WriteString(" = ")
	b.WriteString(tomlString(value))
	b.WriteByte('\n')
}

func writeStrings(b *strings.Builder, key string, values []string) {
	if len(values) == 0 {
		return
	}
	b.WriteString(key)
	b.WriteString(" = [")
	for i, value := range values {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(tomlString(value))
	}
	b.WriteString("]\n")
}

func writeInt(b *strings.Builder, key string, value int) {
	if value == 0 {
		return
	}
	b.WriteString(key)
	b.WriteString(" = ")
	_, _ = fmt.Fprint(b, value)
	b.WriteByte('\n')
}

func writeBool(b *strings.Builder, key string, value bool) {
	if !value {
		return
	}
	b.WriteString(key)
	b.WriteString(" = true\n")
}

func tomlString(s string) string {
	if strings.Contains(s, "\n") && !strings.Contains(s, "'''") {
		return "'''\n" + s + "'''"
	}
	if strings.ContainsAny(s, `'\`) && !strings.Contains(s, "'''") && !hasControlChar(s) {
		return "'''" + s + "'''"
	}
	if !strings.Contains(s, "'") && !hasControlChar(s) {
		return "'" + s + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if r < 0x20 || r == 0x7f {
				_, _ = fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
