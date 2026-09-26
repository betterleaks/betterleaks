package config

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
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
	ValueGroup  int      `toml:"valueGroup"`
	Keywords    []string `toml:"keywords"`
	Tags        []string `toml:"tags"`
	Specificity *int     `toml:"specificity"`
	Confidence  string   `toml:"confidence"`

	Components []rawComponent `toml:"components"`

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
	UseDefault    bool     `toml:"useDefault"`
	DisabledRules []string `toml:"disabledRules"`
}

func ParseTOML(data []byte, path string, options ...LoadOption) (*Config, error) {
	loadOptions := resolveLoadOptions(options)
	rc := rawConfig{path: path, logger: loadOptions.logger}
	if err := rc.decode(data); err != nil {
		return nil, err
	}
	if err := rc.resolve(0); err != nil {
		return nil, err
	}
	cfg := rc.translate()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (rc *rawConfig) decode(data []byte) error {
	err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(rc)
	var unknown *toml.StrictMissingError
	if errors.As(err, &unknown) {
		fields := make([]string, 0, len(unknown.Errors))
		for _, field := range unknown.Errors {
			line, column := field.Position()
			fields = append(fields, fmt.Sprintf("%s (line %d, column %d)", strings.Join(field.Key(), "."), line, column))
		}
		err = fmt.Errorf("unknown configuration fields: %s: %w", strings.Join(fields, ", "), err)
	}
	if err != nil && rc.path != "" {
		return fmt.Errorf("config %q: %w", rc.path, err)
	}
	return err
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
			ValueGroup:   raw.ValueGroup,
			Specificity:  DefaultRuleSpecificity,
			Confidence:   raw.Confidence,
			SkipReport:   raw.SkipReport,
			ValidateExpr: raw.Validate,
			AnalyzeExpr:  raw.Analyze,
			RevokeExpr:   raw.Revoke,
			FilterExpr:   raw.Filter,
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
		return fmt.Errorf("config %q requires Betterleaks %s or newer; running %s", configPath, minVersion, version.Version)
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

// Hash identifies the resolved configuration, including rule order, finding
// metadata, global filters, and validate, analyze, and revoke expressions. Config
// title, description, path, and minimum version are excluded.
//
// The hash describes the current configuration; it is not cached or validated.
// Compute it after customization, from the same state used to construct the
// scanner and source filters. A nil Config returns an empty string.
//
// This is one cache-key input, not an identity for scan results: callers must
// also account for input, source and scanner options, implementation versions,
// and output policy. The result is a lowercase SHA-256 hex string.
func (c *Config) Hash() string {
	if c == nil {
		return ""
	}
	data := appendHashString(nil, c.Prefilter)
	data = appendHashString(data, c.Filter)
	data = binary.AppendUvarint(data, uint64(len(c.Rules)))
	for _, rule := range c.Rules {
		// Every component definition is already present in the resolved rules.
		data = appendHashRule(data, rule)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// RuleHash identifies a rule and its required and optional component definitions,
// including finding metadata and validate, analyze, and revoke expressions.
// Global filters are excluded. The resolved configuration must
// pass Validate, and ruleID must exist. No provider expressions are compiled.
//
// An unchanged hash does not guarantee unchanged final findings: global filters
// and competing rules can still affect them. Use Hash for the complete
// configuration. Like Hash, this describes current config data rather
// than an existing scanner's snapshot. The result is a lowercase SHA-256 hex string.
func (c *Config) RuleHash(ruleID string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	rule, ok := c.Rule(ruleID)
	if !ok {
		return "", fmt.Errorf("rule %q not found in config", ruleID)
	}
	return c.ruleHash(rule), nil
}

// RuleHashes returns the component-aware hash of every rule,
// keyed by rule ID. It validates the configuration once. The returned map belongs
// to the caller and does not change when Config is modified.
func (c *Config) RuleHashes() (map[string]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	hashes := make(map[string]string, len(c.Rules))
	for _, rule := range c.Rules {
		hashes[rule.ID] = c.ruleHash(rule)
	}
	return hashes, nil
}

func (c *Config) ruleHash(rule Rule) string {
	data := appendHashRule(nil, rule)
	for _, component := range rule.Components {
		// Validate ensures references exist and components have no components.
		componentRule, _ := c.Rule(component.RuleID)
		data = appendHashRule(data, componentRule)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// Length prefixes preserve field boundaries and arbitrary string bytes. Keep
// this explicit field order stable to avoid invalidating unchanged configs.
// Nil and empty slices intentionally share an encoding.
func appendHashRule(data []byte, rule Rule) []byte {
	data = appendHashString(data, rule.ID)
	data = appendHashString(data, rule.Description)
	data = appendHashString(data, rule.Regex)
	data = appendHashString(data, rule.Path)
	data = binary.AppendVarint(data, int64(rule.ValueGroup))
	data = appendHashStrings(data, rule.Keywords)
	data = appendHashStrings(data, rule.Tags)
	data = binary.AppendVarint(data, int64(rule.Specificity))
	data = appendHashString(data, rule.Confidence)
	data = appendHashString(data, rule.FilterExpr)
	if rule.SkipReport {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}
	data = binary.AppendUvarint(data, uint64(len(rule.Components)))
	for _, component := range rule.Components {
		data = appendHashString(data, component.RuleID)
		data = appendHashString(data, component.Within)
		if component.Optional {
			data = append(data, 1)
		} else {
			data = append(data, 0)
		}
	}
	data = appendHashString(data, rule.ValidateExpr)
	data = appendHashString(data, rule.AnalyzeExpr)
	data = appendHashString(data, rule.RevokeExpr)
	return data
}

func appendHashString(data []byte, value string) []byte {
	data = binary.AppendUvarint(data, uint64(len(value)))
	return append(data, value...)
}

func appendHashStrings(data []byte, values []string) []byte {
	data = binary.AppendUvarint(data, uint64(len(values)))
	for _, value := range values {
		data = appendHashString(data, value)
	}
	return data
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
	// Duplicate IDs are errors even in overridden rules.
	ids := make(map[string]struct{}, len(rc.Rules))
	for _, rule := range rc.Rules {
		if _, exists := ids[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
	}
	if rc.Extend.Path != "" && rc.Extend.UseDefault {
		return errors.New("unable to load config due to extend.path and extend.useDefault being set")
	}

	if rc.Extend.Path == "" && !rc.Extend.UseDefault {
		return nil
	}
	if depth >= maxExtendDepth {
		return fmt.Errorf("config extension exceeds maximum depth of %d", maxExtendDepth)
	}

	var data []byte
	name := rc.Extend.Path
	if rc.Extend.UseDefault {
		name = "default"
		data = []byte(defaultConfig)
	} else {
		var err error
		data, err = os.ReadFile(rc.Extend.Path)
		if err != nil {
			return fmt.Errorf("load extended config %q: %w", name, err)
		}
	}
	base := rawConfig{path: rc.Extend.Path, logger: rc.logger}
	if err := base.decode(data); err != nil {
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

	// Sort after merging so the resolved order does not depend on extension order.
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
