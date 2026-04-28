package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/regexp"
	"github.com/google/cel-go/cel"
)

// Rules contain information that define details on how to detect secrets
type Rule struct {
	// RuleID is a unique identifier for this rule
	RuleID string

	// Description is the description of the rule.
	Description string

	// Entropy is a float representing the minimum shannon
	// entropy a regex group must have to be considered a secret.
	Entropy float64

	// SecretGroup is an int used to extract secret from regex
	// match and used as the group that will have its entropy
	// checked if `entropy` is set.
	SecretGroup int

	// Regex is a golang regular expression used to detect secrets.
	Regex *regexp.Regexp

	// Path is a golang regular expression used to
	// filter secrets by path
	Path *regexp.Regexp

	// Tags is an array of strings used for metadata
	// and reporting purposes.
	Tags []string

	// Keywords are used for pre-regex check filtering. Rules that contain
	// keywords will perform a quick string compare check to make sure the
	// keyword(s) are in the content being scanned.
	Keywords []string

	// Allowlists allows a rule to be ignored for specific commits, paths, regexes, and/or stopwords.
	Allowlists []*Allowlist

	// validated is an internal flag to track whether `Validate()` has been called.
	validated bool

	// If a rule has RequiredRules, it makes the rule dependent on the RequiredRules.
	// In otherwords, this rule is now a composite rule.
	RequiredRules []*Required

	SkipReport bool

	// TokenEfficiency enables the Token Efficiency filter for this rule.
	// When enabled, candidate secrets are evaluated using BPE tokenization
	// to measure how "rare" or non-natural-language a string is. Strings that
	// tokenize efficiently (i.e., common words/phrases) are filtered out.
	TokenEfficiency bool

	// ValidateCEL is the raw CEL expression used for secret validation.
	ValidateCEL string

	// celProgram is the compiled CEL program, set at config load time.
	celProgram cel.Program

	// Filter is a CEL expression evaluated against attributes + finding per regex match.
	// Returns true = skip (discard this finding); false = keep.
	// Deprecated legacy Allowlists, Entropy, and TokenEfficiency are translated into this field.
	Filter string

	// filterProgram is the compiled FilterEnv program, set at startup.
	filterProgram cel.Program
}

type Required struct {
	RuleID        string
	WithinLines   *int
	WithinColumns *int
}

// Validate guards against common misconfigurations.
func (r *Rule) Validate() error {
	if r.validated {
		return nil
	}

	// Ensure |id| is present.
	if strings.TrimSpace(r.RuleID) == "" {
		// Try to provide helpful context, since |id| is empty.
		var sb strings.Builder
		if r.Description != "" {
			sb.WriteString(", description: " + r.Description)
		}
		if r.Regex != nil {
			sb.WriteString(", regex: " + r.Regex.String())
		}
		if r.Path != nil {
			sb.WriteString(", path: " + r.Path.String())
		}
		return errors.New("rule |id| is missing or empty" + sb.String())
	}

	// Ensure the rule actually matches something.
	if r.Regex == nil && r.Path == nil {
		return errors.New(r.RuleID + ": both |regex| and |path| are empty, this rule will have no effect")
	}

	// Ensure |secretGroup| works.
	if r.Regex != nil && r.SecretGroup > r.Regex.NumSubexp() {
		return fmt.Errorf("%s: invalid regex secret group %d, max regex secret group %d", r.RuleID, r.SecretGroup, r.Regex.NumSubexp())
	}

	for _, allowlist := range r.Allowlists {
		// This will probably never happen.
		if allowlist == nil {
			continue
		}
		if err := allowlist.Validate(); err != nil {
			return fmt.Errorf("%s: %w", r.RuleID, err)
		}
	}

	r.validated = true
	return nil
}

// CelProgram returns the compiled CEL program for this rule, or nil.
func (r *Rule) CelProgram() cel.Program {
	return r.celProgram
}

// SetCelProgram stores a compiled CEL program on the rule.
func (r *Rule) SetCelProgram(p cel.Program) {
	r.celProgram = p
}

// FilterProgram returns the compiled filter program for this rule, or nil.
func (r *Rule) FilterProgram() cel.Program { return r.filterProgram }

// SetFilterProgram stores a compiled filter program on the rule.
func (r *Rule) SetFilterProgram(p cel.Program) { r.filterProgram = p }
