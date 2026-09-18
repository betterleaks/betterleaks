package config

import (
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"

	gv "github.com/hashicorp/go-version"
	"github.com/pelletier/go-toml/v2"

	"github.com/betterleaks/betterleaks/v2/version"
)

var (
	//go:embed betterleaks.toml
	defaultConfig string
	discardLogger = slog.New(slog.DiscardHandler)
)

const maxExtendDepth = 2
const DefaultRuleSpecificity = 100

type rawConfig struct {
	Title       string       `toml:"title"`
	Description string       `toml:"description"`
	Extend      extendConfig `toml:"extend"`
	Rules       []rawRule    `toml:"rules"`

	MinVersion string `toml:"minVersion"`

	// Global filter expressions.
	Prefilter string `toml:"prefilter"`
	Filter    string `toml:"filter"`

	path   string
	logger *slog.Logger
}

type rawRule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Path        string   `toml:"path"`
	Regex       string   `toml:"regex"`
	SecretGroup int      `toml:"secretGroup"`
	Keywords    []string `toml:"keywords"`
	Tags        []string `toml:"tags"`
	Specificity *int     `toml:"specificity"`
	Confidence  string   `toml:"confidence"`

	Components []rawComponent `toml:"components"`

	// Required exists only to reject the removed [[rules.required]] syntax.
	Required []struct{} `toml:"required"`

	Validate   string `toml:"validate"`
	Analyze    string `toml:"analyze"`
	Revoke     string `toml:"revoke"`
	SkipReport bool   `toml:"skipReport"`
	Filter     string `toml:"filter"`
}

type rawComponent struct {
	ID       string `toml:"id"`
	Optional bool   `toml:"optional"`
	Within   string `toml:"within"`
}

// Config is a configuration struct that contains detection rules and filters.
type Config struct {
	Title       string
	Path        string
	Description string
	// Rules is the resolved rule set in deterministic configuration order.
	// Scanner construction derives all lookup and dispatch indexes from it.
	Rules []Rule

	MinVersion string

	// Prefilter is a global expression (attributes only) evaluated before any
	// per-match work. Returns true = skip this fragment entirely; false = keep.
	Prefilter string
	// Filter is a global expression (attributes + finding) evaluated per match.
	// Returns true = skip (discard) this finding; false = keep.
	Filter string
}

// LoadOption configures a config loading operation.
type LoadOption func(*loadOptions)

type loadOptions struct {
	logger *slog.Logger
}

// WithLogger sends config loading diagnostics to logger. A nil logger discards
// diagnostics, which is also the default for library callers.
func WithLogger(logger *slog.Logger) LoadOption {
	return func(options *loadOptions) {
		if logger == nil {
			logger = discardLogger
		}
		options.logger = logger
	}
}

func resolveLoadOptions(options []LoadOption) loadOptions {
	resolved := loadOptions{logger: discardLogger}
	for _, option := range options {
		if option != nil {
			option(&resolved)
		}
	}
	return resolved
}

// extendConfig describes the unresolved config extension requested by TOML.
type extendConfig struct {
	Path          string   `toml:"path"`
	URL           string   `toml:"url"`
	UseDefault    bool     `toml:"useDefault"`
	DisabledRules []string `toml:"disabledRules"`
}

func ParseTOML(data []byte, path string, options ...LoadOption) (*Config, error) {
	loadOptions := resolveLoadOptions(options)
	var rc rawConfig
	if err := toml.Unmarshal(data, &rc); err != nil {
		return nil, err
	}
	rc.path = path
	rc.logger = loadOptions.logger
	if err := rc.resolve(0); err != nil {
		return nil, err
	}
	cfg := rc.translate()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func ParseTOMLString(content, path string, options ...LoadOption) (*Config, error) {
	return ParseTOML([]byte(content), path, options...)
}

func LoadFile(path string, options ...LoadOption) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTOML(data, path, options...)
}

func Default(options ...LoadOption) (*Config, error) {
	return ParseTOMLString(defaultConfig, "", options...)
}

func (rc *rawConfig) translate() *Config {
	c := &Config{
		Title:       rc.Title,
		Path:        rc.path,
		Description: rc.Description,
		Rules:       make([]Rule, 0, len(rc.Rules)),
		MinVersion:  rc.MinVersion,
		Prefilter:   rc.Prefilter,
		Filter:      rc.Filter,
	}
	for _, raw := range rc.Rules {
		rule := Rule{
			ID:           raw.ID,
			Description:  raw.Description,
			Regex:        raw.Regex,
			Path:         raw.Path,
			SecretGroup:  raw.SecretGroup,
			Specificity:  DefaultRuleSpecificity,
			Confidence:   raw.Confidence,
			SkipReport:   raw.SkipReport,
			ValidateExpr: raw.Validate,
			AnalyzeExpr:  raw.Analyze,
			RevokeExpr:   raw.Revoke,
			Filter:       raw.Filter,
			Keywords:     raw.Keywords,
			Tags:         raw.Tags,
		}
		if raw.Specificity != nil {
			rule.Specificity = *raw.Specificity
		}
		if rule.Keywords == nil {
			rule.Keywords = []string{}
		}
		for i, keyword := range rule.Keywords {
			rule.Keywords[i] = strings.ToLower(keyword)
		}
		if rule.Tags == nil {
			rule.Tags = []string{}
		}
		for _, component := range raw.Components {
			rule.Components = append(rule.Components, Component{
				RuleID:   component.ID,
				Optional: component.Optional,
				Within:   component.Within,
			})
		}
		c.Rules = append(c.Rules, rule)
	}
	return c
}

func validateMinVersion(logger *slog.Logger, minVersion, configPath string) error {
	if logger == nil {
		logger = discardLogger
	}
	if minVersion == "" {
		logger.Debug("no minVersion specified in config; consider adding minVersion to ensure compatibility", "config_path", configPath)
		return nil
	}

	minimum, err := gv.NewSemver(minVersion)
	if err != nil {
		return fmt.Errorf("invalid minVersion %q: %w", minVersion, err)
	}
	if version.Version == version.DefaultMsg {
		logger.Debug("dev build, skipping minVersion comparison", "required", minVersion)
		return nil
	}
	current, err := gv.NewSemver(version.Version)
	if err != nil {
		return fmt.Errorf("unable to parse current betterleaks version: %w", err)
	}
	if current.LessThan(minimum) {
		logger.Warn("config requires a newer betterleaks version",
			"required", minVersion,
			"current", version.Version,
			"config_path", configPath,
		)
	}
	return nil
}

// Rule returns the rule with the requested ID.
func (c *Config) Rule(id string) (Rule, bool) {
	if c == nil {
		return Rule{}, false
	}
	for _, rule := range c.Rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}

// Validate checks the resolved declarative configuration without mutating it.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is required")
	}
	ruleIDs := make(map[string]Rule, len(c.Rules))
	for i := range c.Rules {
		rule := c.Rules[i]
		if err := rule.Validate(); err != nil {
			return err
		}
		if _, exists := ruleIDs[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		ruleIDs[rule.ID] = rule
	}
	for _, rule := range c.Rules {
		for _, component := range rule.Components {
			componentRule, ok := ruleIDs[component.RuleID]
			if !ok {
				return fmt.Errorf("%s: component rule ID %q does not exist", rule.ID, component.RuleID)
			}
			if len(componentRule.Components) != 0 {
				return fmt.Errorf("%s: component rule %q must not itself have components", rule.ID, component.RuleID)
			}
			if componentRule.Regex == "" {
				return fmt.Errorf("%s: path-only rule %q cannot be a credential component", rule.ID, component.RuleID)
			}
		}
	}
	return nil
}

func (rc *rawConfig) resolve(depth int) error {
	if err := validateMinVersion(rc.logger, rc.MinVersion, rc.path); err != nil {
		return err
	}
	// Duplicate IDs and removed syntax are errors even in overridden rules.
	ids := make(map[string]struct{}, len(rc.Rules))
	for _, rule := range rc.Rules {
		if _, exists := ids[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if rule.Required != nil {
			return fmt.Errorf("%s: [[rules.required]] is not supported; use rules.components", rule.ID)
		}
	}
	if depth == maxExtendDepth {
		return nil
	}
	if rc.Extend.Path != "" && rc.Extend.UseDefault {
		return errors.New("unable to load config due to extend.path and extend.useDefault being set")
	}

	var data []byte
	name := rc.Extend.Path
	switch {
	case rc.Extend.UseDefault:
		name = "default"
		data = []byte(defaultConfig)
	case rc.Extend.Path != "":
		var err error
		data, err = os.ReadFile(rc.Extend.Path)
		if err != nil {
			return fmt.Errorf("load extended config %q: %w", name, err)
		}
	default:
		return nil
	}
	base := rawConfig{path: rc.Extend.Path, logger: rc.logger}
	if err := toml.Unmarshal(data, &base); err != nil {
		return fmt.Errorf("load extended config %q: %w", name, err)
	}
	rc.logger.Debug("extending config", "path", name)
	if err := base.resolve(depth + 1); err != nil {
		return fmt.Errorf("load extended config %q: %w", name, err)
	}
	rc.merge(&base)
	return nil
}

func (rc *rawConfig) merge(base *rawConfig) {
	extend := rc.Extend
	var configName string
	if extend.Path != "" {
		configName = extend.Path
	} else {
		configName = "default"
	}
	disabledRuleIDs := map[string]struct{}{}
	baseRules := make(map[string]struct{}, len(base.Rules))
	for _, rule := range base.Rules {
		baseRules[rule.ID] = struct{}{}
	}
	for _, id := range extend.DisabledRules {
		if _, ok := baseRules[id]; !ok {
			rc.logger.Warn("Disabled rule doesn't exist in extended config.", "rule_id", id, "config", configName)
		}
		disabledRuleIDs[id] = struct{}{}
	}

	currentRuleIDs := make(map[string]struct{}, len(rc.Rules))
	for _, rule := range rc.Rules {
		currentRuleIDs[rule.ID] = struct{}{}
	}
	for _, baseRule := range base.Rules {
		ruleID := baseRule.ID
		if _, ok := disabledRuleIDs[ruleID]; ok {
			rc.logger.Debug("Ignoring rule from extended config.", "rule_id", ruleID, "config", configName)
			continue
		}

		if _, replaced := currentRuleIDs[ruleID]; !replaced {
			rc.Rules = append(rc.Rules, baseRule)
		}
	}

	// Global filters are skip predicates, so extension is additive: either
	// config may suppress the input. Keep each Expr program intact and compose
	// them only at their boolean boundary.
	rc.Prefilter = extendGlobalExpr(base.Prefilter, rc.Prefilter)
	rc.Filter = extendGlobalExpr(base.Filter, rc.Filter)

	// Extended configs retain their existing ID order.
	sort.Slice(rc.Rules, func(i, j int) bool {
		return rc.Rules[i].ID < rc.Rules[j].ID
	})
}

func extendGlobalExpr(base, current string) string {
	switch {
	case base == "":
		return current
	case current == "":
		return base
	default:
		return "(\n" + strings.TrimSpace(base) + "\n) || (\n" + strings.TrimSpace(current) + "\n)"
	}
}
