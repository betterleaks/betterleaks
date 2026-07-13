package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"

	ahocorasick "github.com/rrethy/ahocorasick"
	"github.com/spf13/cobra"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/regexp"
)

type resolvedConfig struct {
	cfg    *configpkg.Config
	source string
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configCheckCmd, configShowCmd, configPathCmd)
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "validate and inspect betterleaks configs",
}

var configCheckCmd = &cobra.Command{
	Use:          "check [config-path]",
	Short:        "validate a betterleaks config",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		resolved, err := resolveConfig(cmd, args)
		if err != nil {
			return err
		}
		if err := validateConfig(resolved.cfg); err != nil {
			return err
		}
		withValidation, withoutValidation := countValidationRules(resolved.cfg)
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK: %d rules (%d with validation, %d without validation)\n",
			len(resolved.cfg.Rules), withValidation, withoutValidation)
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:          "show [config-path]",
	Short:        "print the resolved betterleaks config",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		resolved, err := resolveConfig(cmd, args)
		if err != nil {
			return err
		}
		if err := validateConfig(resolved.cfg); err != nil {
			return err
		}
		_, _ = cmd.OutOrStdout().Write([]byte(renderConfigTOML(renderConfig(resolved.cfg))))
		return nil
	},
}

var configPathCmd = &cobra.Command{
	Use:          "path",
	Short:        "print the selected config source",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		resolved, err := resolveConfig(cmd, args)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), resolved.source)
		return nil
	},
}

func resolveConfig(cmd *cobra.Command, args []string) (*resolvedConfig, error) {
	if len(args) > 0 {
		return loadConfigFile(args[0])
	}

	if cfgPath := getConfigFlag(cmd); cfgPath != "" {
		return loadConfigFile(cfgPath)
	}
	if envPath, name := getEnvWithName("BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"); envPath != "" {
		resolved, err := loadConfigFile(envPath)
		if err != nil {
			return nil, err
		}
		resolved.source = "env:" + name + ":" + envPath
		return resolved, nil
	}
	if content, name := getEnvWithName("BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"); content != "" {
		cfg, err := configpkg.ParseTOMLString(content, "")
		if err != nil {
			return nil, err
		}
		return &resolvedConfig{cfg: cfg, source: "env:" + name}, nil
	}
	if path := findConfigFile("."); path != "" {
		return loadConfigFile(path)
	}
	cfg, err := configpkg.Default()
	if err != nil {
		return nil, err
	}
	return &resolvedConfig{cfg: cfg, source: "default"}, nil
}

func loadConfigFile(path string) (*resolvedConfig, error) {
	cfg, err := configpkg.LoadFile(path)
	if err != nil {
		return nil, err
	}
	return &resolvedConfig{cfg: cfg, source: path}, nil
}

func getConfigFlag(cmd *cobra.Command) string {
	if cfgPath, err := cmd.Flags().GetString("config"); err == nil {
		return cfgPath
	}
	if cfgPath, err := cmd.InheritedFlags().GetString("config"); err == nil {
		return cfgPath
	}
	if cmd.Root() != nil {
		if cfgPath, err := cmd.Root().PersistentFlags().GetString("config"); err == nil {
			return cfgPath
		}
	}
	return ""
}

func getEnvWithName(primary, fallback string) (string, string) {
	if val := os.Getenv(primary); val != "" {
		return val, primary
	}
	if val := os.Getenv(fallback); val != "" {
		return val, fallback
	}
	return "", ""
}

func validateConfig(cfg *configpkg.Config) error {
	compileKeywordTrie(cfg)
	if err := compileRuleRegexps(cfg); err != nil {
		return err
	}
	if err := cfg.CompileFilters(nil); err != nil {
		return err
	}
	rt, err := exprruntime.New(nil)
	if err != nil {
		return err
	}
	if prg := cfg.PrefilterProgram(); prg != nil {
		if _, err := rt.EvalPrefilter(prg, fakeAttributes()); err != nil {
			return fmt.Errorf("evaluating global prefilter: %w", err)
		}
	}
	if cfg.Filter != "" {
		prg, err := rt.CompileFilter(cfg.Filter, nil)
		if err != nil {
			return fmt.Errorf("compiling global filter: %w", err)
		}
		if _, err := rt.EvalFilter(prg, fakeFinding(), fakeAttributes()); err != nil {
			return fmt.Errorf("evaluating global filter: %w", err)
		}
	}
	validationRT, err := cfg.CompileValidation()
	if err != nil {
		return err
	}
	for _, id := range sortedRuleIDs(cfg) {
		rule := cfg.Rules[id]
		if rule.Filter != "" {
			prg, err := rt.CompileFilter(rule.Filter, nil)
			if err != nil {
				return fmt.Errorf("compiling rule %s filter: %w", id, err)
			}
			if _, err := rt.EvalFilter(prg, fakeFinding(), fakeAttributes()); err != nil {
				return fmt.Errorf("evaluating rule %s filter: %w", id, err)
			}
		}
		if validationRT != nil && rule.ValidateExpr != "" {
			if _, err := validationRT.CompileValidation(rule.ValidateExpr); err != nil {
				return fmt.Errorf("compiling rule %s validation: %w", id, err)
			}
		}
	}
	return nil
}

func fakeFinding() map[string]any {
	raw := "betterleaks-check-line"
	return map[string]any{
		"secret":          "betterleaks-check-secret",
		"match":           "betterleaks-check-match",
		"line":            raw,
		"ruleID":          "betterleaks-check-rule",
		"description":     "betterleaks check rule",
		"fragment_raw":    raw,
		"raw_match_start": 0,
		"raw_match_end":   len(raw),
		"raw_line_start":  0,
		"raw_line_end":    len(raw),
	}
}

func fakeAttributes() map[string]string {
	return map[string]string{
		"path":       "betterleaks/check.txt",
		"file":       "betterleaks/check.txt",
		"commit":     "0000000000000000000000000000000000000000",
		"git.sha":    "0000000000000000000000000000000000000000",
		"author":     "betterleaks",
		"email":      "betterleaks@example.com",
		"repository": "betterleaks",
	}
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
	keywords := make([]string, 0, len(cfg.Keywords))
	for keyword := range cfg.Keywords {
		keywords = append(keywords, keyword)
	}
	_ = ahocorasick.CompileStrings(keywords)
}

func compileRuleRegexps(cfg *configpkg.Config) error {
	for _, id := range sortedRuleIDs(cfg) {
		rule := cfg.Rules[id]
		if rule.Regex != nil {
			if err := rule.Regex.Compile(); err != nil {
				return fmt.Errorf("compiling rule %s regex: %w", id, err)
			}
		}
		if rule.Path != nil {
			if err := rule.Path.Compile(); err != nil {
				return fmt.Errorf("compiling rule %s path regex: %w", id, err)
			}
		}
	}
	return nil
}

func sortedRuleIDs(cfg *configpkg.Config) []string {
	ids := make([]string, 0, len(cfg.Rules))
	seen := make(map[string]struct{}, len(cfg.Rules))
	for _, id := range cfg.OrderedRules {
		if _, ok := cfg.Rules[id]; ok {
			ids = append(ids, id)
			seen[id] = struct{}{}
		}
	}
	var rest []string
	for id := range cfg.Rules {
		if _, ok := seen[id]; !ok {
			rest = append(rest, id)
		}
	}
	sort.Strings(rest)
	return append(ids, rest...)
}

type configView struct {
	Title                 string     `toml:"title,omitempty"`
	Description           string     `toml:"description,omitempty"`
	MinVersion            string     `toml:"minVersion,omitempty"`
	BetterleaksMinVersion string     `toml:"betterleaksMinVersion,omitempty"`
	Prefilter             string     `toml:"prefilter,omitempty"`
	Filter                string     `toml:"filter,omitempty"`
	Rules                 []ruleView `toml:"rules"`
}

type ruleView struct {
	ID          string         `toml:"id"`
	Description string         `toml:"description,omitempty"`
	Path        string         `toml:"path,omitempty"`
	Regex       string         `toml:"regex,omitempty"`
	SecretGroup int            `toml:"secretGroup,omitempty"`
	Keywords    []string       `toml:"keywords,omitempty"`
	Tags        []string       `toml:"tags,omitempty"`
	Specificity int            `toml:"specificity,omitempty"`
	Required    []requiredView `toml:"required,omitempty"`
	Validate    string         `toml:"validate,omitempty"`
	SkipReport  bool           `toml:"skipReport,omitempty"`
	Filter      string         `toml:"filter,omitempty"`
}

type requiredView struct {
	ID            string `toml:"id"`
	WithinLines   *int   `toml:"withinLines,omitempty"`
	WithinColumns *int   `toml:"withinColumns,omitempty"`
}

func renderConfig(cfg *configpkg.Config) configView {
	view := configView{
		Title:                 cfg.Title,
		Description:           cfg.Description,
		MinVersion:            cfg.MinVersion,
		BetterleaksMinVersion: cfg.BetterleaksMinVersion,
		Prefilter:             cfg.Prefilter,
		Filter:                cfg.Filter,
	}
	for _, id := range sortedRuleIDs(cfg) {
		rule := cfg.Rules[id]
		rv := ruleView{
			ID:          rule.RuleID,
			Description: rule.Description,
			Path:        regexString(rule.Path),
			Regex:       regexString(rule.Regex),
			SecretGroup: rule.SecretGroup,
			Keywords:    rule.Keywords,
			Tags:        rule.Tags,
			Specificity: renderedSpecificity(rule.Specificity),
			Validate:    rule.ValidateExpr,
			SkipReport:  rule.SkipReport,
			Filter:      rule.Filter,
		}
		for _, required := range rule.RequiredRules {
			rv.Required = append(rv.Required, requiredView{
				ID:            required.RuleID,
				WithinLines:   required.WithinLines,
				WithinColumns: required.WithinColumns,
			})
		}
		view.Rules = append(view.Rules, rv)
	}
	return view
}

func renderConfigTOML(view configView) string {
	var b strings.Builder

	writeString(&b, "title", view.Title)
	writeString(&b, "description", view.Description)
	writeString(&b, "minVersion", view.MinVersion)
	writeString(&b, "betterleaksMinVersion", view.BetterleaksMinVersion)
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
		writeInt(&b, "secretGroup", rule.SecretGroup)
		writeStrings(&b, "keywords", rule.Keywords)
		writeStrings(&b, "tags", rule.Tags)
		writeInt(&b, "specificity", rule.Specificity)
		writeString(&b, "validate", rule.Validate)
		writeBool(&b, "skipReport", rule.SkipReport)
		writeString(&b, "filter", rule.Filter)
		for _, required := range rule.Required {
			b.WriteString("\n[[rules.required]]\n")
			writeString(&b, "id", required.ID)
			writeIntPtr(&b, "withinLines", required.WithinLines)
			writeIntPtr(&b, "withinColumns", required.WithinColumns)
		}
	}

	return b.String()
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

func writeIntPtr(b *strings.Builder, key string, value *int) {
	if value == nil {
		return
	}
	b.WriteString(key)
	b.WriteString(" = ")
	_, _ = fmt.Fprint(b, *value)
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

func regexString(re *regexp.Regexp) string {
	if re == nil {
		return ""
	}
	return re.String()
}

func renderedSpecificity(specificity int) int {
	if specificity == configpkg.DefaultRuleSpecificity {
		return 0
	}
	return specificity
}
