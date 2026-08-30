package cmd

import (
	"fmt"
	"os"
	"strings"

	ahocorasick "github.com/rrethy/ahocorasick"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/regexp"
)

type resolvedConfig struct {
	cfg    *configpkg.Config
	source string
}

type ConfigCmd struct {
	Check ConfigCheckCmd `cmd:"" help:"Validate a betterleaks config."`
	Show  ConfigShowCmd  `cmd:"" help:"Print the resolved betterleaks config."`
	Path  ConfigPathCmd  `cmd:"" help:"Print the selected config source."`
}

type ConfigCheckCmd struct {
	Path string `arg:"" optional:"" name:"config-path" help:"Config file to validate."`
}

func (cmd *ConfigCheckCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(cli.Config, cmd.Path)
	if err != nil {
		return err
	}
	if err := validateConfig(resolved.cfg); err != nil {
		return err
	}
	withValidation, withoutValidation := countValidationRules(resolved.cfg)
	_, _ = fmt.Fprintf(runtime.stdout, "OK: %d rules (%d with validation, %d without validation)\n",
		len(resolved.cfg.Rules), withValidation, withoutValidation)
	return nil
}

type ConfigShowCmd struct {
	Path string `arg:"" optional:"" name:"config-path" help:"Config file to render."`
}

func (cmd *ConfigShowCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(cli.Config, cmd.Path)
	if err != nil {
		return err
	}
	if err := validateConfig(resolved.cfg); err != nil {
		return err
	}
	_, _ = runtime.stdout.Write([]byte(renderConfigTOML(renderConfig(resolved.cfg))))
	return nil
}

type ConfigPathCmd struct{}

func (*ConfigPathCmd) Run(cli *CLI, runtime *commandRuntime) error {
	resolved, err := resolveConfig(cli.Config, "")
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(runtime.stdout, resolved.source)
	return nil
}

func resolveConfig(configPath, argumentPath string) (*resolvedConfig, error) {
	if argumentPath != "" {
		return loadConfigFile(argumentPath)
	}

	if configPath != "" {
		return loadConfigFile(configPath)
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
	if err := cfg.Validate(); err != nil {
		return err
	}
	compileKeywordTrie(cfg)
	if err := compileRuleRegexps(cfg); err != nil {
		return err
	}
	rt, err := exprruntime.New(nil)
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
		id := rule.RuleID
		if rule.Filter != "" {
			prg, err := rt.CompileFilter(rule.Filter, nil)
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
	}
	return nil
}

func fakeFinding() map[string]any {
	raw := "betterleaks-check-line"
	return map[string]any{
		"secret":               "betterleaks-check-secret",
		"match":                "betterleaks-check-match",
		"line":                 raw,
		"ruleID":               "betterleaks-check-rule",
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

func compileRuleRegexps(cfg *configpkg.Config) error {
	for _, rule := range cfg.Rules {
		id := rule.RuleID
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
	SecretGroup int             `toml:"secretGroup,omitempty"`
	Keywords    []string        `toml:"keywords,omitempty"`
	Tags        []string        `toml:"tags,omitempty"`
	Specificity int             `toml:"specificity,omitempty"`
	Confidence  string          `toml:"confidence,omitempty"`
	Components  []componentView `toml:"components,omitempty"`
	Validate    string          `toml:"validate,omitempty"`
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
			ID:          rule.RuleID,
			Description: rule.Description,
			Path:        regexString(rule.Path),
			Regex:       regexString(rule.Regex),
			SecretGroup: rule.SecretGroup,
			Keywords:    rule.Keywords,
			Tags:        rule.Tags,
			Specificity: renderedSpecificity(rule.Specificity),
			Confidence:  rule.Confidence,
			Validate:    rule.ValidateExpr,
			SkipReport:  rule.SkipReport,
			Filter:      rule.Filter,
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
		writeInt(&b, "secretGroup", rule.SecretGroup)
		writeStrings(&b, "keywords", rule.Keywords)
		writeStrings(&b, "tags", rule.Tags)
		writeInt(&b, "specificity", rule.Specificity)
		writeString(&b, "confidence", rule.Confidence)
		writeString(&b, "validate", rule.Validate)
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
