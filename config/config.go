package config

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	gv "github.com/hashicorp/go-version"
	"github.com/pelletier/go-toml/v2"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/version"
)

var (
	//go:embed betterleaks.toml
	defaultConfig string
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

	path string
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

	// Components is a pointer so config extension can distinguish omission
	// from an explicit empty list.
	Components *[]*rawComponent `toml:"components"`

	// Required exists only to reject the removed [[rules.required]] syntax
	// explicitly instead of silently weakening a rule.
	Required []struct{} `toml:"required"`

	Validate   string `toml:"validate"`
	Analyze    string `toml:"analyze"`
	SkipReport bool   `toml:"skipReport"`

	// Filter is an Expr expression evaluated per match (attributes + finding).
	// Returns true = skip (discard this finding); false = keep.
	Filter string `toml:"filter"`
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
	// Detector construction derives all lookup and dispatch indexes from it.
	Rules []Rule

	MinVersion string

	// Prefilter is a global expression (attributes only) evaluated before any
	// per-match work. Returns true = skip this fragment entirely; false = keep.
	Prefilter string
	// Filter is a global expression (attributes + finding) evaluated per match.
	// Returns true = skip (discard) this finding; false = keep.
	Filter string
}

// extendConfig describes the unresolved config extension requested by TOML.
type extendConfig struct {
	Path          string   `toml:"path"`
	URL           string   `toml:"url"`
	UseDefault    bool     `toml:"useDefault"`
	DisabledRules []string `toml:"disabledRules"`
}

func ParseTOML(data []byte, path string) (*Config, error) {
	var rc rawConfig
	if err := toml.Unmarshal(data, &rc); err != nil {
		return nil, err
	}
	rc.path = path
	return rc.translate(0)
}

func ParseTOMLString(content, path string) (*Config, error) {
	return ParseTOML([]byte(content), path)
}

func LoadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTOML(data, path)
}

func Default() (*Config, error) {
	return ParseTOMLString(defaultConfig, "")
}

func (rc *rawConfig) translate(depth int) (*Config, error) {
	var (
		rules         = make([]Rule, 0, len(rc.Rules))
		ruleIndexes   = make(map[string]int, len(rc.Rules))
		componentsSet = make(map[string]struct{})
	)

	// Validate individual rules.
	for _, vr := range rc.Rules {
		var (
			pathPat  *regexp.Regexp
			regexPat *regexp.Regexp
		)
		if vr.Path != "" {
			pat, err := regexp.Compile(vr.Path)
			if err != nil {
				return nil, fmt.Errorf("%s: invalid path regex %q: %w", vr.ID, vr.Path, err)
			}
			pathPat = pat
		}
		if vr.Regex != "" {
			pat, err := regexp.Compile(vr.Regex)
			if err != nil {
				return nil, fmt.Errorf("%s: invalid regex %q: %w", vr.ID, vr.Regex, err)
			}
			regexPat = pat
		}
		if vr.Keywords == nil {
			vr.Keywords = []string{}
		} else {
			for i, k := range vr.Keywords {
				keyword := strings.ToLower(k)
				vr.Keywords[i] = keyword
			}
		}
		if vr.Tags == nil {
			vr.Tags = []string{}
		}
		specificity := DefaultRuleSpecificity
		if vr.Specificity != nil {
			specificity = *vr.Specificity
		}
		cr := Rule{
			RuleID:      vr.ID,
			Description: vr.Description,
			Regex:       regexPat,
			SecretGroup: vr.SecretGroup,
			Path:        pathPat,
			Keywords:    vr.Keywords,
			Tags:        vr.Tags,
			Specificity: specificity,
			Confidence:  vr.Confidence,
			SkipReport:  vr.SkipReport,
		}
		if vr.Required != nil {
			return nil, fmt.Errorf("%s: [[rules.required]] is not supported; use rules.components", cr.RuleID)
		}

		if vr.Components != nil {
			componentsSet[cr.RuleID] = struct{}{}
			for _, component := range *vr.Components {
				if component == nil {
					component = &rawComponent{}
				}
				cr.Components = append(cr.Components, &Component{
					RuleID:   component.ID,
					Optional: component.Optional,
					Within:   component.Within,
				})
			}
		}

		cr.ValidateExpr = vr.Validate
		cr.AnalyzeExpr = vr.Analyze
		cr.Filter = vr.Filter

		if index, exists := ruleIndexes[cr.RuleID]; exists {
			// TOML configs historically used last-rule-wins semantics because
			// rules were loaded into a map. Preserve that compatibility while
			// keeping the resolved Config rule set canonical and unique.
			rules[index] = cr
			if vr.Components == nil {
				delete(componentsSet, cr.RuleID)
			}
			continue
		}
		ruleIndexes[cr.RuleID] = len(rules)
		rules = append(rules, cr)
	}

	// Assemble the config.
	c := &Config{
		Title:       rc.Title,
		Description: rc.Description,
		Rules:       rules,
		MinVersion:  rc.MinVersion,
		Prefilter:   rc.Prefilter,
		Filter:      rc.Filter,
	}

	c.Path = rc.path

	if err := validateMinVersion(c.MinVersion, c.Path); err != nil {
		return nil, err
	}

	if maxExtendDepth != depth {
		// disallow both usedefault and path from being set
		if rc.Extend.Path != "" && rc.Extend.UseDefault {
			return nil, errors.New("unable to load config due to extend.path and extend.useDefault being set")
		}
		if rc.Extend.UseDefault {
			if err := c.extendDefault(depth, rc.Extend, componentsSet); err != nil {
				return nil, err
			}
		} else if rc.Extend.Path != "" {
			if err := c.extendPath(depth, rc.Extend, componentsSet); err != nil {
				return nil, err
			}
		}
	}

	// Validate the rules after everything has been assembled (including extended configs).
	if depth == 0 {
		if err := c.Validate(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func validateMinVersion(minVersion, configPath string) error {
	if minVersion == "" {
		logging.Debug().Str("config path", configPath).
			Msg("no minVersion specified in config... consider adding minVersion to ensure compatibility.")
		return nil
	}

	minimum, err := gv.NewSemver(minVersion)
	if err != nil {
		return fmt.Errorf("invalid minVersion %q: %w", minVersion, err)
	}
	if version.Version == version.DefaultMsg {
		logging.Debug().
			Str("required", minVersion).
			Msg("dev build, skipping minVersion comparison")
		return nil
	}
	current, err := gv.NewSemver(version.Version)
	if err != nil {
		return fmt.Errorf("unable to parse current betterleaks version: %w", err)
	}
	if current.LessThan(minimum) {
		logging.Warn().
			Str("required", minVersion).
			Str("current", version.Version).
			Str("config path", configPath).
			Msg("config requires a newer betterleaks version")
	}
	return nil
}

// Rule returns the rule with the requested ID.
func (c *Config) Rule(id string) (Rule, bool) {
	if c == nil {
		return Rule{}, false
	}
	for _, rule := range c.Rules {
		if rule.RuleID == id {
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
	ruleIDs := make(map[string]struct{}, len(c.Rules))
	for i := range c.Rules {
		rule := c.Rules[i]
		if err := rule.Validate(); err != nil {
			return err
		}
		if _, exists := ruleIDs[rule.RuleID]; exists {
			return fmt.Errorf("duplicate rule ID %q", rule.RuleID)
		}
		ruleIDs[rule.RuleID] = struct{}{}
	}
	for _, rule := range c.Rules {
		for _, component := range rule.Components {
			if component == nil {
				continue // Rule.Validate reports this with rule context.
			}
			if _, ok := ruleIDs[component.RuleID]; !ok {
				return fmt.Errorf("%s: component rule ID %q does not exist", rule.RuleID, component.RuleID)
			}
		}
	}
	return nil
}

func (c *Config) extendDefault(depth int, extend extendConfig, componentsSet map[string]struct{}) error {
	var defaultRawConfig rawConfig
	if err := toml.Unmarshal([]byte(defaultConfig), &defaultRawConfig); err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)
	}
	cfg, err := defaultRawConfig.translate(depth + 1)
	if err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)

	}
	logging.Debug().Msg("extending config with default config")
	c.extend(cfg, extend, componentsSet)
	return nil
}

func (c *Config) extendPath(depth int, extend extendConfig, componentsSet map[string]struct{}) error {
	data, err := os.ReadFile(extend.Path)
	if err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	var extensionRawConfig rawConfig
	if err := toml.Unmarshal(data, &extensionRawConfig); err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	extensionRawConfig.path = extend.Path
	logging.Debug().Msgf("extending config with %s", extend.Path)
	cfg, err := extensionRawConfig.translate(depth + 1)
	if err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	c.extend(cfg, extend, componentsSet)
	return nil
}

func (c *Config) extend(extensionConfig *Config, extend extendConfig, componentsSet map[string]struct{}) {
	// Get config name for helpful log messages.
	var configName string
	if extend.Path != "" {
		configName = extend.Path
	} else {
		configName = "default"
	}
	// Convert |Config.DisabledRules| into a map for ease of access.
	disabledRuleIDs := map[string]struct{}{}
	baseRules := make(map[string]Rule, len(extensionConfig.Rules))
	for _, rule := range extensionConfig.Rules {
		baseRules[rule.RuleID] = rule
	}
	for _, id := range extend.DisabledRules {
		if _, ok := baseRules[id]; !ok {
			logging.Warn().
				Str("rule-id", id).
				Str("config", configName).
				Msg("Disabled rule doesn't exist in extended config.")
		}
		disabledRuleIDs[id] = struct{}{}
	}

	currentRuleIndexes := make(map[string]int, len(c.Rules))
	for i, rule := range c.Rules {
		currentRuleIndexes[rule.RuleID] = i
	}
	for _, baseRule := range extensionConfig.Rules {
		ruleID := baseRule.RuleID
		// Skip the rule.
		if _, ok := disabledRuleIDs[ruleID]; ok {
			logging.Debug().
				Str("rule-id", ruleID).
				Str("config", configName).
				Msg("Ignoring rule from extended config.")
			continue
		}

		currentIndex, ok := currentRuleIndexes[ruleID]
		if !ok {
			// Rule doesn't exist, add it to the config.
			c.Rules = append(c.Rules, baseRule)
			currentRuleIndexes[ruleID] = len(c.Rules) - 1
		} else {
			currentRule := c.Rules[currentIndex]
			// Rule exists, merge our changes into the base.
			if currentRule.Description != "" {
				baseRule.Description = currentRule.Description
			}
			if currentRule.SecretGroup != 0 {
				baseRule.SecretGroup = currentRule.SecretGroup
			}
			if currentRule.Regex != nil {
				baseRule.Regex = currentRule.Regex
			}
			if currentRule.Path != nil {
				baseRule.Path = currentRule.Path
			}
			if currentRule.ValidateExpr != "" {
				baseRule.ValidateExpr = currentRule.ValidateExpr
			}
			if currentRule.AnalyzeExpr != "" {
				baseRule.AnalyzeExpr = currentRule.AnalyzeExpr
			}
			if currentRule.Confidence != "" {
				baseRule.Confidence = currentRule.Confidence
			}
			// Current rule's Filter replaces the extending one if set.
			if currentRule.Filter != "" {
				baseRule.Filter = currentRule.Filter
			}
			baseRule.Tags = append(baseRule.Tags, currentRule.Tags...)
			baseRule.Keywords = append(baseRule.Keywords, currentRule.Keywords...)
			if _, set := componentsSet[ruleID]; set {
				baseRule.Components = currentRule.Components
			}
			c.Rules[currentIndex] = baseRule
		}
	}

	// Global filters are skip predicates, so extension is additive: either
	// config may suppress the input. Keep each Expr program intact and compose
	// them only at their boolean boundary.
	c.Prefilter = extendGlobalExpr(extensionConfig.Prefilter, c.Prefilter)
	c.Filter = extendGlobalExpr(extensionConfig.Filter, c.Filter)

	// Preserve the existing deterministic extended-config ordering without a
	// second order index on Config.
	sort.Slice(c.Rules, func(i, j int) bool {
		return c.Rules[i].RuleID < c.Rules[j].RuleID
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
