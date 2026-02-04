package config

import (
	_ "embed"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	gv "github.com/hashicorp/go-version"
	"github.com/spf13/viper"
)

var (
	//go:embed gitleaks.toml
	DefaultConfig string

	// use to keep track of how many configs we can extend
	// yea I know, globals bad
	extendDepth int
)

const maxExtendDepth = 2

// ViperConfig is the config struct used by the Viper config package
// to parse the config file. This struct does not include regular expressions.
// It is used as an intermediary to convert the Viper config to the Config struct.
type ViperConfig struct {
	Title       string
	Description string
	Extend      Extend
	Rules       []struct {
		ID          string
		Description string
		Path        string
		Regex       string
		SecretGroup int
		Entropy     float64
		Keywords    []string
		Tags        []string

		// Deprecated: this is a shim for backwards-compatibility.
		// TODO: Remove this in 9.x.
		AllowList *viperRuleAllowlist

		Allowlists []*viperRuleAllowlist
		Required   []*viperRequired
		SkipReport bool
	}
	// Deprecated: this is a shim for backwards-compatibility.
	// TODO: Remove this in 9.x.
	AllowList *viperGlobalAllowlist

	Allowlists []*viperGlobalAllowlist

	MinVersion     string
	currentVersion string

	configPath string
}

type viperRequired struct {
	ID            string
	WithinLines   *int `mapstructure:"withinLines"`
	WithinColumns *int `mapstructure:"withinColumns"`
}

type viperRuleAllowlist struct {
	Description string
	Condition   string
	Commits     []string
	Paths       []string
	RegexTarget string
	Regexes     []string
	StopWords   []string
	Resources   []string
}

type viperGlobalAllowlist struct {
	TargetRules        []string
	viperRuleAllowlist `mapstructure:",squash"`
}

// Config is a configuration struct that contains rules and an allowlist if present.
type Config struct {
	Title       string
	Extend      Extend
	Path        string
	Description string
	Rules       map[string]Rule
	Keywords    map[string]struct{}
	// KeywordToRules maps each keyword to the rule IDs that use it
	KeywordToRules map[string][]string
	// NoKeywordRules contains rule IDs for rules that have no keywords (must always be checked)
	NoKeywordRules []string
	// used to keep sarif results consistent
	OrderedRules []string
	Allowlists   []*Allowlist
	MinVersion   string

	currentVersion string
}

// Extend is a struct that allows users to define how they want their
// configuration extended by other configuration files.
type Extend struct {
	Path          string
	URL           string
	UseDefault    bool
	DisabledRules []string
}

func (vc *ViperConfig) SetCurrentVersion(currentVersion string) {
	vc.currentVersion = currentVersion
}

func (vc *ViperConfig) Translate() (Config, error) {
	var (
		keywords       = make(map[string]struct{})
		keywordToRules = make(map[string][]string)
		noKeywordRules []string
		orderedRules   []string
		rulesMap       = make(map[string]Rule)
		ruleAllowlists = make(map[string][]*Allowlist)
	)

	// Validate individual rules.
	for _, vr := range vc.Rules {
		var (
			pathPat  *regexp.Regexp
			regexPat *regexp.Regexp
		)
		if vr.Path != "" {
			pathPat = regexp.MustCompile(vr.Path)
		}
		if vr.Regex != "" {
			regexPat = regexp.MustCompile(vr.Regex)
		}
		if vr.Keywords == nil {
			vr.Keywords = []string{}
			noKeywordRules = append(noKeywordRules, vr.ID)
		} else if len(vr.Keywords) == 0 {
			noKeywordRules = append(noKeywordRules, vr.ID)
		} else {
			for i, k := range vr.Keywords {
				keyword := strings.ToLower(k)
				keywords[keyword] = struct{}{}
				keywordToRules[keyword] = append(keywordToRules[keyword], vr.ID)
				vr.Keywords[i] = keyword
			}
		}
		if vr.Tags == nil {
			vr.Tags = []string{}
		}
		cr := Rule{
			RuleID:      vr.ID,
			Description: vr.Description,
			Regex:       regexPat,
			SecretGroup: vr.SecretGroup,
			Entropy:     vr.Entropy,
			Path:        pathPat,
			Keywords:    vr.Keywords,
			Tags:        vr.Tags,
			SkipReport:  vr.SkipReport,
		}

		// Parse the rule allowlists, including the older format for backwards compatibility.
		if vr.AllowList != nil {
			// TODO: Remove this in v9.
			if len(vr.Allowlists) > 0 {
				return Config{}, fmt.Errorf("%s: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]", cr.RuleID)
			}
			vr.Allowlists = append(vr.Allowlists, vr.AllowList)
		}
		for _, a := range vr.Allowlists {
			allowlist, err := vc.parseAllowlist(a)
			if err != nil {
				return Config{}, fmt.Errorf("%s: [[rules.allowlists]] %w", cr.RuleID, err)
			}
			cr.Allowlists = append(cr.Allowlists, allowlist)
		}

		for _, r := range vr.Required {
			if r.ID == "" {
				return Config{}, fmt.Errorf("%s: [[rules.required]] rule ID is empty", cr.RuleID)
			}
			requiredRule := Required{
				RuleID:        r.ID,
				WithinLines:   r.WithinLines,
				WithinColumns: r.WithinColumns,
				// Distance: r.Distance,
			}
			cr.RequiredRules = append(cr.RequiredRules, &requiredRule)
		}

		orderedRules = append(orderedRules, cr.RuleID)
		rulesMap[cr.RuleID] = cr
	}

	// after all the rules have been processed, let's ensure the required rules
	// actually exist.
	for _, r := range rulesMap {
		for _, rr := range r.RequiredRules {
			if _, ok := rulesMap[rr.RuleID]; !ok {
				return Config{}, fmt.Errorf("%s: [[rules.required]] rule ID '%s' does not exist", r.RuleID, rr.RuleID)
			}
		}
	}

	// Assemble the config.
	c := Config{
		Title:          vc.Title,
		Description:    vc.Description,
		Extend:         vc.Extend,
		Rules:          rulesMap,
		Keywords:       keywords,
		KeywordToRules: keywordToRules,
		NoKeywordRules: noKeywordRules,
		OrderedRules:   orderedRules,
		MinVersion:     vc.MinVersion,
		currentVersion: vc.currentVersion,
	}

	if extendDepth > 0 {
		// annoying hack to set the current config with the extended path
		// since if extendDepth > 0 we are operating an extended config.
		c.Path = vc.configPath
	} else {
		// I don't love this
		c.Path = viper.ConfigFileUsed()
	}

	if err := validateMinVersion(c.MinVersion, c.currentVersion, c.Path); err != nil {
		return Config{}, err
	}

	// Parse the config allowlists, including the older format for backwards compatibility.
	if vc.AllowList != nil {
		// TODO: Remove this in v9.
		if len(vc.Allowlists) > 0 {
			return Config{}, errors.New("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]")
		}
		vc.Allowlists = append(vc.Allowlists, vc.AllowList)
	}
	for _, a := range vc.Allowlists {
		allowlist, err := vc.parseAllowlist(&a.viperRuleAllowlist)
		if err != nil {
			return Config{}, fmt.Errorf("[[allowlists]] %w", err)
		}
		// Allowlists with |targetRules| aren't added to the global list.
		if len(a.TargetRules) > 0 {
			for _, ruleID := range a.TargetRules {
				// It's not possible to validate |ruleID| until after extend.
				ruleAllowlists[ruleID] = append(ruleAllowlists[ruleID], allowlist)
			}
		} else {
			c.Allowlists = append(c.Allowlists, allowlist)
		}
	}

	currentExtendDepth := extendDepth
	if maxExtendDepth != currentExtendDepth {
		// disallow both usedefault and path from being set
		if c.Extend.Path != "" && c.Extend.UseDefault {
			return Config{}, errors.New("unable to load config due to extend.path and extend.useDefault being set")
		}
		if c.Extend.UseDefault {
			if err := c.extendDefault(vc); err != nil {
				return Config{}, err
			}
		} else if c.Extend.Path != "" {
			if err := c.extendPath(vc); err != nil {
				return Config{}, err
			}
		}
	}

	// Validate the rules after everything has been assembled (including extended configs).
	if currentExtendDepth == 0 {
		for _, rule := range c.Rules {
			if err := rule.Validate(); err != nil {
				return Config{}, err
			}
		}

		// Populate targeted configs.
		for ruleID, allowlists := range ruleAllowlists {
			rule, ok := c.Rules[ruleID]
			if !ok {
				return Config{}, fmt.Errorf("[[allowlists]] target rule ID '%s' does not exist", ruleID)
			}
			rule.Allowlists = append(rule.Allowlists, allowlists...)
			c.Rules[ruleID] = rule
		}
	}

	return c, nil
}

func validateMinVersion(minVer, currentVer, configPath string) error {
	if minVer == "" {
		logging.Debug().Str("config path", configPath).
			Msg("no minVersion specified in config... consider adding minVersion to ensure compatibility.")
		return nil
	}

	if currentVer == "" && minVer != "" {
		logging.Warn().
			Str("required", minVer).
			Msg("current version not set, skipping config version check.")
		return nil
	}

	minSemVer, err := gv.NewSemver(minVer)
	if err != nil {
		return fmt.Errorf("invalid minVersion '%s': %w", minVer, err)
	}

	currentSemVer, err := gv.NewSemver(currentVer)
	if err != nil {
		return fmt.Errorf("unable to parse current version: %w", err)
	}

	if currentSemVer.LessThan(minSemVer) {
		logging.Warn().
			Str("required", minVer).
			Str("current", currentVer).
			Str("config path", configPath).
			Msg("config requires a newer Gitleaks version...")
	}

	return nil
}

func (vc *ViperConfig) parseAllowlist(a *viperRuleAllowlist) (*Allowlist, error) {
	var matchCondition AllowlistMatchCondition
	switch strings.ToUpper(a.Condition) {
	case "AND", "&&":
		matchCondition = AllowlistMatchAnd
	case "", "OR", "||":
		matchCondition = AllowlistMatchOr
	default:
		return nil, fmt.Errorf("unknown allowlist |condition| '%s' (expected 'and', 'or')", a.Condition)
	}

	// Validate the target.
	regexTarget := a.RegexTarget
	if regexTarget != "" {
		switch regexTarget {
		case "secret":
			regexTarget = ""
		case "match", "line":
			// do nothing
		default:
			return nil, fmt.Errorf("unknown allowlist |regexTarget| '%s' (expected 'match', 'line')", regexTarget)
		}
	}
	var allowlistRegexes []*regexp.Regexp
	for _, a := range a.Regexes {
		allowlistRegexes = append(allowlistRegexes, regexp.MustCompile(a))
	}
	var allowlistPaths []*regexp.Regexp
	for _, a := range a.Paths {
		allowlistPaths = append(allowlistPaths, regexp.MustCompile(a))
	}

	var resourceMatchers []*ResourceMatcher
	for _, r := range a.Resources {
		rm, err := ParseResourceMatcher(r)
		if err != nil {
			return nil, err
		}
		resourceMatchers = append(resourceMatchers, rm)
	}

	allowlist := &Allowlist{
		Description:    a.Description,
		MatchCondition: matchCondition,
		Commits:        a.Commits,
		Paths:          allowlistPaths,
		RegexTarget:    regexTarget,
		Regexes:        allowlistRegexes,
		StopWords:      a.StopWords,
		Resources:      resourceMatchers,
	}
	if err := allowlist.Validate(); err != nil {
		return nil, err
	}
	return allowlist, nil
}

func (c *Config) GetOrderedRules() []Rule {
	var orderedRules []Rule
	for _, id := range c.OrderedRules {
		if _, ok := c.Rules[id]; ok {
			orderedRules = append(orderedRules, c.Rules[id])
		}
	}
	return orderedRules
}

func (c *Config) extendDefault(parent *ViperConfig) error {
	extendDepth++
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(DefaultConfig)); err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)
	}
	defaultViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&defaultViperConfig); err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)
	}
	defaultViperConfig.SetCurrentVersion(c.currentVersion)
	cfg, err := defaultViperConfig.Translate()
	if err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)

	}
	logging.Debug().Msg("extending config with default config")
	c.extend(cfg)
	return nil
}

func (c *Config) extendPath(parent *ViperConfig) error {
	extendDepth++
	viper.SetConfigFile(c.Extend.Path)
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	extensionViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&extensionViperConfig); err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}

	extensionViperConfig.configPath = c.Extend.Path
	logging.Debug().Msgf("extending config with %s", c.Extend.Path)
	extensionViperConfig.SetCurrentVersion(c.currentVersion)
	cfg, err := extensionViperConfig.Translate()
	if err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	c.extend(cfg)
	return nil
}

func (c *Config) extendURL() {
	// TODO
}

func (c *Config) extend(extensionConfig Config) {
	// Get config name for helpful log messages.
	var configName string
	if c.Extend.Path != "" {
		configName = c.Extend.Path
	} else {
		configName = "default"
	}
	// Convert |Config.DisabledRules| into a map for ease of access.
	disabledRuleIDs := map[string]struct{}{}
	for _, id := range c.Extend.DisabledRules {
		if _, ok := extensionConfig.Rules[id]; !ok {
			logging.Warn().
				Str("rule-id", id).
				Str("config", configName).
				Msg("Disabled rule doesn't exist in extended config.")
		}
		disabledRuleIDs[id] = struct{}{}
	}

	for ruleID, baseRule := range extensionConfig.Rules {
		// Skip the rule.
		if _, ok := disabledRuleIDs[ruleID]; ok {
			logging.Debug().
				Str("rule-id", ruleID).
				Str("config", configName).
				Msg("Ignoring rule from extended config.")
			continue
		}

		currentRule, ok := c.Rules[ruleID]
		if !ok {
			// Rule doesn't exist, add it to the config.
			c.Rules[ruleID] = baseRule
			if len(baseRule.Keywords) == 0 {
				c.NoKeywordRules = append(c.NoKeywordRules, ruleID)
			} else {
				for _, k := range baseRule.Keywords {
					c.Keywords[k] = struct{}{}
					c.KeywordToRules[k] = append(c.KeywordToRules[k], ruleID)
				}
			}
			c.OrderedRules = append(c.OrderedRules, ruleID)
		} else {
			// Rule exists, merge our changes into the base.
			if currentRule.Description != "" {
				baseRule.Description = currentRule.Description
			}
			if currentRule.Entropy != 0 {
				baseRule.Entropy = currentRule.Entropy
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
			baseRule.Tags = append(baseRule.Tags, currentRule.Tags...)
			baseRule.Keywords = append(baseRule.Keywords, currentRule.Keywords...)
			baseRule.Allowlists = append(baseRule.Allowlists, currentRule.Allowlists...)
			// The keywords from the base rule and the extended rule must be merged into the global keywords list
			for _, k := range baseRule.Keywords {
				c.Keywords[k] = struct{}{}
				// Only add to KeywordToRules if not already present for this rule
				if !slices.Contains(c.KeywordToRules[k], ruleID) {
					c.KeywordToRules[k] = append(c.KeywordToRules[k], ruleID)
				}
			}
			c.Rules[ruleID] = baseRule
		}
	}

	// append allowlists, not attempting to merge
	c.Allowlists = append(c.Allowlists, extensionConfig.Allowlists...)

	// sort to keep extended rules in order
	sort.Strings(c.OrderedRules)
}
