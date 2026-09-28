package cmd

import (
	"fmt"
	"os"
	"strings"

	ahocorasick "github.com/rrethy/ahocorasick"

	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

type resolvedConfig struct {
	cfg    *configpkg.Config
	source string
}

type ConfigCmd struct {
	Check ConfigCheckCmd `cmd:"" help:"Validate a betterleaks config."`
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
	Path string `arg:"" optional:"" name:"config-path" help:"Config file to validate."`
}

func (cmd *ConfigCheckCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(runtime, cli.Config, cmd.Path)
	if err != nil {
		return err
	}
	if err := validateConfig(resolved.cfg, runtime.regexEngine()); err != nil {
		return err
	}
	withValidation, withoutValidation := countValidationRules(resolved.cfg)
	_, _ = fmt.Fprintf(runtime.stdout, "OK: %d rules (%d with validation, %d without validation)\n",
		len(resolved.cfg.Rules), withValidation, withoutValidation)
	return nil
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
	if cfg.Prefilter != "" {
		prg, err := rt.CompilePrefilter(cfg.Prefilter)
		if err != nil {
			return fmt.Errorf("compiling global prefilter: %w", err)
		}
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
	for _, rule := range cfg.Rules {
		id := rule.ID
		if rule.FilterExpr != "" {
			prg, err := rt.CompileFilter(rule.FilterExpr, nil)
			if err != nil {
				return fmt.Errorf("compiling rule %s filter: %w", id, err)
			}
			if _, err := rt.EvalFilter(prg, fakeFinding(), fakeAttributes()); err != nil {
				return fmt.Errorf("evaluating rule %s filter: %w", id, err)
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

func fakeFinding() map[string]any {
	raw := "betterleaks-check-line"
	return map[string]any{
		"secret":               "betterleaks-check-secret",
		"match":                "betterleaks-check-match",
		"line":                 raw,
		"rule_id":              "betterleaks-check-rule",
		"description":          "betterleaks check rule",
		"fragment_raw":         raw,
		"match_start_idx":      0,
		"match_end_idx":        len(raw),
		"match_line_start_idx": 0,
		"match_line_end_idx":   len(raw),
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
	Description string     `toml:"description,omitempty"`
	MinVersion  string     `toml:"minVersion,omitempty"`
	Prefilter   string     `toml:"prefilter,omitempty"`
	Filter      string     `toml:"filter,omitempty"`
	Rules       []ruleView `toml:"rules"`
}

type ruleView struct {
	ID          string          `toml:"id"`
	Description string          `toml:"description,omitempty"`
	Path        string          `toml:"path,omitempty"`
	Regex       string          `toml:"regex,omitempty"`
	ValueGroup  int             `toml:"valueGroup,omitempty"`
	Keywords    []string        `toml:"keywords,omitempty"`
	Tags        []string        `toml:"tags,omitempty"`
	Specificity int             `toml:"specificity,omitempty"`
	Confidence  string          `toml:"confidence,omitempty"`
	Components  []componentView `toml:"components,omitempty"`
	Validate    string          `toml:"validate,omitempty"`
	Analyze     string          `toml:"analyze,omitempty"`
	Revoke      string          `toml:"revoke,omitempty"`
	SkipReport  bool            `toml:"skipReport,omitempty"`
	Filter      string          `toml:"filter,omitempty"`
}

type componentView struct {
	ID       string `toml:"id"`
	Optional bool   `toml:"optional,omitempty"`
	Within   string `toml:"within,omitempty"`
}

func renderConfig(cfg *configpkg.Config) configView {
	view := configView{
		Title:       cfg.Title,
		Description: cfg.Description,
		MinVersion:  cfg.MinVersion,
		Prefilter:   cfg.Prefilter,
		Filter:      cfg.Filter,
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
	}

	return b.String()
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
