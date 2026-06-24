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
	tiktoken "github.com/pkoukk/tiktoken-go"

	"github.com/betterleaks/betterleaks/internal/exprruntime"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/version"
)

var (
	//go:embed betterleaks.toml
	DefaultConfig string
)

const maxExtendDepth = 2

type rawConfig struct {
	Title       string    `toml:"title"`
	Description string    `toml:"description"`
	Extend      Extend    `toml:"extend"`
	Rules       []rawRule `toml:"rules"`

	// Deprecated: this is a shim for backwards-compatibility.
	// TODO: Remove this in 9.x.
	AllowList *rawGlobalAllowlist `toml:"allowlist"`

	Allowlists []*rawGlobalAllowlist `toml:"allowlists"`

	MinVersion            string `toml:"minVersion"`
	BetterleaksMinVersion string `toml:"betterleaksMinVersion"`

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
	Entropy     float64  `toml:"entropy"`
	Keywords    []string `toml:"keywords"`
	Tags        []string `toml:"tags"`

	// Deprecated: this is a shim for backwards-compatibility.
	// TODO: Remove this in 9.x.
	AllowList *rawRuleAllowlist `toml:"allowlist"`

	Allowlists      []*rawRuleAllowlist `toml:"allowlists"`
	Required        []*rawRequired      `toml:"required"`
	Validate        string              `toml:"validate"`
	SkipReport      bool                `toml:"skipReport"`
	TokenEfficiency bool                `toml:"tokenEfficiency"`

	// Filter is an Expr expression evaluated per match (attributes + finding).
	// Returns true = skip (discard this finding); false = keep.
	Filter string `toml:"filter"`
}

type rawRequired struct {
	ID            string `toml:"id"`
	WithinLines   *int   `toml:"withinLines"`
	WithinColumns *int   `toml:"withinColumns"`
}

type rawRuleAllowlist struct {
	Description string   `toml:"description"`
	Condition   string   `toml:"condition"`
	Commits     []string `toml:"commits"`
	Paths       []string `toml:"paths"`
	RegexTarget string   `toml:"regexTarget"`
	Regexes     []string `toml:"regexes"`
	StopWords   []string `toml:"stopwords"`
}

type rawGlobalAllowlist struct {
	TargetRules      []string `toml:"targetRules"`
	rawRuleAllowlist `toml:",inline"`
}

// Config is a configuration struct that contains rules and an allowlist if present.
type Config struct {
	Title       string
	Extend      Extend
	Path        string
	Description string
	Rules       map[string]Rule
	Keywords    map[string]struct{}
	// KeywordToRules maps each lowercase keyword to the rule IDs that use it.
	// This allows O(1) lookup from Aho-Corasick keyword matches to the rules
	// that need to be checked, instead of iterating all rules.
	KeywordToRules map[string][]string
	// NoKeywordRules contains rule IDs that have no keywords and must always be checked.
	NoKeywordRules []string
	// used to keep sarif results consistent
	OrderedRules []string

	// Deprecated: use filter/prefilter Expr expressions instead. This is a shim for backwards-compatibility.
	Allowlists []*Allowlist

	MinVersion            string
	BetterleaksMinVersion string

	// Prefilter is a global expression (attributes only) evaluated before any
	// per-match work. Returns true = skip this fragment entirely; false = keep.
	// Translated from global Allowlists path/commit checks.
	Prefilter string
	// Filter is a global expression (attributes + finding) evaluated per match.
	// Returns true = skip (discard) this finding; false = keep.
	// Translated from global Allowlists regex/stopword checks.
	Filter string

	// prefilterProgram and filterProgram hold programs compiled by
	// CompileFilters. Validation compilation is handled separately by
	// CompileValidation.
	prefilterProgram exprruntime.Program
	filterProgram    exprruntime.Program
}

// Extend is a struct that allows users to define how they want their
// configuration extended by other configuration files.
type Extend struct {
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
	return ParseTOMLString(DefaultConfig, "")
}

func (rc *rawConfig) translate(depth int) (*Config, error) {
	var (
		keywords       = make(map[string]struct{})
		orderedRules   []string
		rulesMap       = make(map[string]Rule)
		ruleAllowlists = make(map[string][]*Allowlist)
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
				keywords[keyword] = struct{}{}
				vr.Keywords[i] = keyword
			}
		}
		if vr.Tags == nil {
			vr.Tags = []string{}
		}
		cr := Rule{
			RuleID:          vr.ID,
			Description:     vr.Description,
			Regex:           regexPat,
			SecretGroup:     vr.SecretGroup,
			Entropy:         vr.Entropy,
			Path:            pathPat,
			Keywords:        vr.Keywords,
			Tags:            vr.Tags,
			SkipReport:      vr.SkipReport,
			TokenEfficiency: vr.TokenEfficiency,
		}

		// Parse the rule allowlists, including the older format for backwards compatibility.
		if vr.AllowList != nil {
			// TODO: Remove this in v9.
			if len(vr.Allowlists) > 0 {
				return nil, fmt.Errorf("%s: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]", cr.RuleID)
			}
			vr.Allowlists = append(vr.Allowlists, vr.AllowList)
		}
		for _, a := range vr.Allowlists {
			if a == nil {
				a = &rawRuleAllowlist{}
			}
			allowlist, err := rc.parseAllowlist(a)
			if err != nil {
				return nil, fmt.Errorf("%s: [[rules.allowlists]] %w", cr.RuleID, err)
			}
			cr.Allowlists = append(cr.Allowlists, allowlist)
		}

		for _, r := range vr.Required {
			if r.ID == "" {
				return nil, fmt.Errorf("%s: [[rules.required]] rule ID is empty", cr.RuleID)
			}
			requiredRule := Required{
				RuleID:        r.ID,
				WithinLines:   r.WithinLines,
				WithinColumns: r.WithinColumns,
				// Distance: r.Distance,
			}
			cr.RequiredRules = append(cr.RequiredRules, &requiredRule)
		}

		cr.ValidateExpr = vr.Validate
		cr.Filter = vr.Filter

		orderedRules = append(orderedRules, cr.RuleID)
		rulesMap[cr.RuleID] = cr
	}

	// after all the rules have been processed, let's ensure the required rules
	// actually exist.
	for _, r := range rulesMap {
		for _, rr := range r.RequiredRules {
			if _, ok := rulesMap[rr.RuleID]; !ok {
				return nil, fmt.Errorf("%s: [[rules.required]] rule ID '%s' does not exist", r.RuleID, rr.RuleID)
			}
		}
	}

	// Assemble the config.
	c := &Config{
		Title:                 rc.Title,
		Description:           rc.Description,
		Extend:                rc.Extend,
		Rules:                 rulesMap,
		Keywords:              keywords,
		OrderedRules:          orderedRules,
		MinVersion:            rc.MinVersion,
		BetterleaksMinVersion: rc.BetterleaksMinVersion,
		Prefilter:             rc.Prefilter,
		Filter:                rc.Filter,
	}

	c.Path = rc.path

	if err := validateMinVersion(c.MinVersion, c.BetterleaksMinVersion, c.Path); err != nil {
		return nil, err
	}

	// Parse the config allowlists, including the older format for backwards compatibility.
	if rc.AllowList != nil {
		// TODO: Remove this in v9.
		if len(rc.Allowlists) > 0 {
			return nil, errors.New("[allowlist] is deprecated, it cannot be used alongside [[allowlists]]")
		}
		rc.Allowlists = append(rc.Allowlists, rc.AllowList)
	}
	for _, a := range rc.Allowlists {
		if a == nil {
			a = &rawGlobalAllowlist{}
		}
		allowlist, err := rc.parseAllowlist(&a.rawRuleAllowlist)
		if err != nil {
			return nil, fmt.Errorf("[[allowlists]] %w", err)
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

	if maxExtendDepth != depth {
		// disallow both usedefault and path from being set
		if c.Extend.Path != "" && c.Extend.UseDefault {
			return nil, errors.New("unable to load config due to extend.path and extend.useDefault being set")
		}
		if c.Extend.UseDefault {
			if err := c.extendDefault(depth); err != nil {
				return nil, err
			}
		} else if c.Extend.Path != "" {
			if err := c.extendPath(depth); err != nil {
				return nil, err
			}
		}
	}

	// Validate the rules after everything has been assembled (including extended configs).
	if depth == 0 {
		for _, rule := range c.Rules {
			if err := rule.Validate(); err != nil {
				return nil, err
			}
		}

		// Populate targeted configs.
		for ruleID, allowlists := range ruleAllowlists {
			rule, ok := c.Rules[ruleID]
			if !ok {
				return nil, fmt.Errorf("[[allowlists]] target rule ID '%s' does not exist", ruleID)
			}
			rule.Allowlists = append(rule.Allowlists, allowlists...)
			c.Rules[ruleID] = rule
		}

	}

	// Build keyword-to-rules lookup for efficient rule dispatch.
	// This must be done after extends are resolved so all rules are present.
	c.KeywordToRules = make(map[string][]string)
	c.NoKeywordRules = nil
	for ruleID, rule := range c.Rules {
		if len(rule.Keywords) == 0 {
			c.NoKeywordRules = append(c.NoKeywordRules, ruleID)
		} else {
			for _, k := range rule.Keywords {
				c.KeywordToRules[k] = append(c.KeywordToRules[k], ruleID)
			}
		}
	}

	// Translate legacy allowlists / entropy / token-efficiency into CEL strings.
	// Must run after all extends and targeted allowlist population are complete.
	if depth == 0 {
		if err := c.translateLegacyFilters(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func validateMinVersion(gitleaksMinVer, betterleaksMinVer, configPath string) error {
	isDev := version.Version == version.DefaultMsg

	// Check gitleaks config format compatibility (minVersion field).
	if gitleaksMinVer != "" {
		if isDev {
			logging.Debug().
				Str("required", gitleaksMinVer).
				Msg("dev build, skipping gitleaks minVersion check.")
		} else {
			minSemVer, err := gv.NewSemver(gitleaksMinVer)
			if err != nil {
				return fmt.Errorf("invalid minVersion '%s': %w", gitleaksMinVer, err)
			}
			compatSemVer, err := gv.NewSemver(version.GitleaksCompat)
			if err != nil {
				return fmt.Errorf("unable to parse gitleaks compat version: %w", err)
			}
			if compatSemVer.LessThan(minSemVer) {
				logging.Warn().
					Str("required", gitleaksMinVer).
					Str("current", version.GitleaksCompat).
					Str("config path", configPath).
					Msg("config minVersion exceeds this build's gitleaks compatibility level")
			}
		}
	}

	// Check betterleaks version compatibility (betterleaksMinVersion field).
	if betterleaksMinVer != "" {
		if isDev {
			logging.Debug().
				Str("required", betterleaksMinVer).
				Msg("dev build, skipping betterleaksMinVersion check.")
		} else {
			minSemVer, err := gv.NewSemver(betterleaksMinVer)
			if err != nil {
				return fmt.Errorf("invalid betterleaksMinVersion '%s': %w", betterleaksMinVer, err)
			}
			currentSemVer, err := gv.NewSemver(version.Version)
			if err != nil {
				return fmt.Errorf("unable to parse current version: %w", err)
			}
			if currentSemVer.LessThan(minSemVer) {
				logging.Warn().
					Str("required", betterleaksMinVer).
					Str("current", version.Version).
					Str("config path", configPath).
					Msg("config requires a newer betterleaks version")
			}
		}
	}

	if gitleaksMinVer == "" && betterleaksMinVer == "" {
		logging.Debug().Str("config path", configPath).
			Msg("no minVersion specified in config... consider adding minVersion to ensure compatibility.")
	}

	return nil
}

func (rc *rawConfig) parseAllowlist(a *rawRuleAllowlist) (*Allowlist, error) {
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
		pat, err := regexp.Compile(a)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", a, err)
		}
		allowlistRegexes = append(allowlistRegexes, pat)
	}
	var allowlistPaths []*regexp.Regexp
	for _, a := range a.Paths {
		pat, err := regexp.Compile(a)
		if err != nil {
			return nil, fmt.Errorf("invalid path regex %q: %w", a, err)
		}
		allowlistPaths = append(allowlistPaths, pat)
	}

	allowlist := &Allowlist{
		Description:    a.Description,
		MatchCondition: matchCondition,
		Commits:        a.Commits,
		Paths:          allowlistPaths,
		RegexTarget:    regexTarget,
		Regexes:        allowlistRegexes,
		StopWords:      a.StopWords,
	}
	if err := allowlist.Validate(); err != nil {
		return nil, err
	}
	return allowlist, nil
}

// PrefilterProgram returns the compiled global prefilter program, or nil if not set.
func (c *Config) PrefilterProgram() exprruntime.Program { return c.prefilterProgram }

// SetPrefilterProgram stores a compiled global prefilter program.
func (c *Config) SetPrefilterProgram(p exprruntime.Program) { c.prefilterProgram = p }

// FilterProgram returns the compiled global filter program, or nil if not set.
func (c *Config) FilterProgram() exprruntime.Program { return c.filterProgram }

// SetFilterProgram stores a compiled global filter program.
func (c *Config) SetFilterProgram(p exprruntime.Program) { c.filterProgram = p }

// CompileFilters compiles the global prefilter, global filter, and per-rule
// filter expressions into executable programs. This is idempotent.
func (c *Config) CompileFilters(tokenizer *tiktoken.Tiktoken) error {
	runtime, err := exprruntime.New(nil)
	if err != nil {
		return fmt.Errorf("creating expr runtime: %w", err)
	}

	if c.Prefilter != "" {
		prg, compileErr := runtime.CompilePrefilter(c.Prefilter)
		if compileErr != nil {
			return fmt.Errorf("compiling global prefilter: %w", compileErr)
		}
		c.prefilterProgram = prg
	}
	if c.Filter != "" {
		prg, compileErr := runtime.CompileFilter(c.Filter, tokenizer)
		if compileErr != nil {
			return fmt.Errorf("compiling global filter: %w", compileErr)
		}
		c.filterProgram = prg
	}

	for ruleID, r := range c.Rules {
		if r.Filter != "" {
			prg, compileErr := runtime.CompileFilter(r.Filter, tokenizer)
			if compileErr != nil {
				return fmt.Errorf("compiling rule %s filter: %w", ruleID, compileErr)
			}
			r.SetFilterProgram(prg)
			c.Rules[ruleID] = r
		}
	}

	return nil
}

// CompileValidation compiles per-rule validation expressions.
// It creates its own exprruntime.Runtime.
// and returns it so the caller can store it for runtime use by the validation pool.
// Returns (nil, nil) when no rules have validation expressions.
func (c *Config) CompileValidation() (*exprruntime.Runtime, error) {
	// Quick check: skip environment creation if nothing to compile.
	hasValidation := false
	for _, r := range c.Rules {
		if r.ValidateExpr != "" {
			hasValidation = true
			break
		}
	}
	if !hasValidation {
		return nil, nil
	}

	runtime, err := exprruntime.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating validation env: %w", err)
	}

	for ruleID, r := range c.Rules {
		if r.ValidateExpr == "" {
			continue
		}
		prg, compileErr := runtime.CompileValidation(r.ValidateExpr)
		if compileErr != nil {
			return nil, fmt.Errorf("compiling rule %s validation: %w", ruleID, compileErr)
		}
		r.SetValidationProgram(prg)
		c.Rules[ruleID] = r
	}

	return runtime, nil
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

func (c *Config) extendDefault(depth int) error {
	var defaultRawConfig rawConfig
	if err := toml.Unmarshal([]byte(DefaultConfig), &defaultRawConfig); err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)
	}
	cfg, err := defaultRawConfig.translate(depth + 1)
	if err != nil {
		return fmt.Errorf("failed to load extended default config, err: %w", err)

	}
	logging.Debug().Msg("extending config with default config")
	c.extend(cfg)
	return nil
}

func (c *Config) extendPath(depth int) error {
	data, err := os.ReadFile(c.Extend.Path)
	if err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	var extensionRawConfig rawConfig
	if err := toml.Unmarshal(data, &extensionRawConfig); err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	extensionRawConfig.path = c.Extend.Path
	logging.Debug().Msgf("extending config with %s", c.Extend.Path)
	cfg, err := extensionRawConfig.translate(depth + 1)
	if err != nil {
		return fmt.Errorf("failed to load extended config, err: %w", err)
	}
	c.extend(cfg)
	return nil
}

func (c *Config) extend(extensionConfig *Config) {
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
			for _, k := range baseRule.Keywords {
				c.Keywords[k] = struct{}{}
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
			if currentRule.ValidateExpr != "" {
				baseRule.ValidateExpr = currentRule.ValidateExpr
			}
			// Current rule's Filter replaces the extending one if set.
			if currentRule.Filter != "" {
				baseRule.Filter = currentRule.Filter
			}
			baseRule.Tags = append(baseRule.Tags, currentRule.Tags...)
			baseRule.Keywords = append(baseRule.Keywords, currentRule.Keywords...)
			baseRule.Allowlists = append(baseRule.Allowlists, currentRule.Allowlists...)
			// The keywords from the base rule and the extended rule must be merged into the global keywords list
			for _, k := range baseRule.Keywords {
				c.Keywords[k] = struct{}{}
			}
			c.Rules[ruleID] = baseRule
		}
	}

	// append allowlists, not attempting to merge
	c.Allowlists = append(c.Allowlists, extensionConfig.Allowlists...)

	// Current config's global Prefilter/Filter wins over extension's if set.
	if c.Prefilter == "" {
		c.Prefilter = extensionConfig.Prefilter
	}
	if c.Filter == "" {
		c.Filter = extensionConfig.Filter
	}

	// sort to keep extended rules in order
	sort.Strings(c.OrderedRules)
}
