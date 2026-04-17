package config

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
)

// translateLegacyFilters converts deprecated Allowlists, Entropy, and TokenEfficiency
// fields into CEL prefilter/filter string expressions on the Config and its Rules.
//
// Called once, at the end of Translate(), after all extends and targeted allowlist
// population are complete (extendDepth == 0). Logs translated expressions at debug level
// so users can copy them and migrate away from the deprecated fields.
//
// Return convention: prefilter/filter expressions return true = keep, false = skip.
// Allowlists suppress (true = skip), so each translated allowlist expression is
// wrapped in !(…) before being AND-ed into the final expression.
// TranslateLegacyFilters converts deprecated Allowlists, Entropy, and TokenEfficiency
// fields into CEL prefilter/filter expressions. Exported for use by the config generator.
func (c *Config) TranslateLegacyFilters() error {
	return c.translateLegacyFilters()
}

func (c *Config) translateLegacyFilters() error {
	// ── global allowlists ──────────────────────────────────────────────────────
	globalPre, globalFil, err := translateAllowlistSlice(c.Allowlists)
	if err != nil {
		return fmt.Errorf("global allowlists: %w", err)
	}

	c.Prefilter = composeFilters(globalPre, nil, c.Prefilter)
	c.Filter = composeFilters(globalFil, nil, c.Filter)

	if c.Prefilter != "" {
		logging.Debug().Str("prefilter", c.Prefilter).Msg("translated global prefilter CEL expression")
	}
	if c.Filter != "" {
		logging.Debug().Str("filter", c.Filter).Msg("translated global filter CEL expression")
	}

	// ── per-rule fields ────────────────────────────────────────────────────────
	for ruleID, r := range c.Rules {
		rulePre, ruleSuppressFil, err := translateAllowlistSlice(r.Allowlists)
		if err != nil {
			return fmt.Errorf("rule %s allowlists: %w", ruleID, err)
		}

		// Entropy and TokenEfficiency are "keep" conditions (true = keep, no !() needed).
		var ruleKeepFil []string
		if r.Entropy != 0 {
			threshold := fmt.Sprintf("%g", r.Entropy)
			if !strings.ContainsAny(threshold, ".e") {
				threshold += ".0"
			}
			ruleKeepFil = append(ruleKeepFil, fmt.Sprintf(`entropy(finding["secret"]) > %s`, threshold))
		}
		if r.TokenEfficiency {
			ruleKeepFil = append(ruleKeepFil, `tokenEfficiencyOK(finding["secret"])`)
		}

		r.Prefilter = composeFilters(rulePre, nil, r.Prefilter)
		r.Filter = composeFilters(ruleSuppressFil, ruleKeepFil, r.Filter)

		if r.Prefilter != "" {
			logging.Debug().Str("rule", ruleID).Str("prefilter", r.Prefilter).
				Msg("translated rule prefilter CEL expression")
		}
		if r.Filter != "" {
			logging.Debug().Str("rule", ruleID).Str("filter", r.Filter).
				Msg("translated rule filter CEL expression")
		}

		c.Rules[ruleID] = r
	}

	return nil
}

// translateAllowlistSlice translates a slice of Allowlists into two lists of CEL
// sub-expressions: prefilterParts (for attributes-only prefilter) and filterParts
// (for per-match filter). Each sub-expression, when true, means "suppress this item",
// so callers must wrap them in !(…).
func translateAllowlistSlice(allowlists []*Allowlist) (prefilterParts, filterParts []string, err error) {
	for _, a := range allowlists {
		pre, fil := translateAllowlist(a)
		prefilterParts = append(prefilterParts, pre...)
		filterParts = append(filterParts, fil...)
	}
	return prefilterParts, filterParts, nil
}

// translateAllowlist translates one Allowlist into "suppress-when-true" CEL sub-expressions.
//
// For OR allowlists: paths/commits land in prefilter, regexes/stopwords in filter.
// For AND allowlists: prefilter gets path as an over-approximation (fast bail-out),
// filter gets the full AND expression including all conditions.
//
// Each returned string, when true, means "this fragment/finding should be suppressed".
func translateAllowlist(a *Allowlist) (prefilterParts, filterParts []string) {
	var pathParts, commitParts, regexParts, stopParts []string

	// Collect path expressions (prefilter-level).
	if len(a.Paths) > 0 {
		patterns := make([]string, len(a.Paths))
		for i, p := range a.Paths {
			patterns[i] = p.String()
		}
		pathParts = append(pathParts, fmt.Sprintf(`matchesAny(attributes["path"], %s)`, celStringList(patterns)))
	}

	// Collect commit expressions (prefilter-level).
	if len(a.Commits) > 0 {
		commitParts = append(commitParts, fmt.Sprintf(`attributes["git.sha"] in %s`, celStringList(a.Commits)))
	}

	// Collect regex expressions (filter-level).
	if len(a.Regexes) > 0 {
		patterns := make([]string, len(a.Regexes))
		for i, re := range a.Regexes {
			patterns[i] = re.String()
		}
		target := "secret"
		if a.RegexTarget != "" {
			target = a.RegexTarget
		}
		regexParts = append(regexParts, fmt.Sprintf(`matchesAny(finding[%s], %s)`, celStringLit(target), celStringList(patterns)))
	}

	// Collect stopword expressions (filter-level).
	if len(a.StopWords) > 0 {
		stopParts = append(stopParts, fmt.Sprintf(`containsAny(finding["secret"], %s)`, celStringList(a.StopWords)))
	}

	if a.MatchCondition == AllowlistMatchAnd {
		// AND allowlist:
		// • Prefilter receives the path fragment as an over-approximation for fast bail-out.
		//   The full AND check in the filter preserves exact semantics for non-path-matched items.
		// • Filter receives the complete AND expression (all applicable conditions).
		for _, p := range pathParts {
			prefilterParts = append(prefilterParts, p)
		}
		allParts := concat(pathParts, commitParts, regexParts, stopParts)
		if len(allParts) > 0 {
			filterParts = append(filterParts, joinAnd(allParts))
		}
	} else {
		// OR allowlist:
		// • Prefilter receives path and commit checks.
		// • Filter receives regex and stopword checks.
		if len(pathParts) > 0 || len(commitParts) > 0 {
			prefilterParts = append(prefilterParts, joinOr(concat(pathParts, commitParts)))
		}
		if len(regexParts) > 0 || len(stopParts) > 0 {
			filterParts = append(filterParts, joinOr(concat(regexParts, stopParts)))
		}
	}

	return prefilterParts, filterParts
}

// composeFilters builds a final CEL expression. The result is true (= skip) when:
//   - any suppressPart (suppress-when-true) matches — added directly without !(…)
//   - any keepPart (keep-when-true) is NOT satisfied — wrapped in !(…)
//   - the user-specified expression (if any) is true
//
// Parts are OR-ed: skip if any condition fires.
// If all inputs are empty, returns "".
func composeFilters(suppressParts, keepParts []string, userExpr string) string {
	var parts []string
	for _, sp := range suppressParts {
		parts = append(parts, "("+sp+")")
	}
	for _, kp := range keepParts {
		parts = append(parts, "!("+kp+")")
	}
	if userExpr != "" {
		parts = append(parts, "("+userExpr+")")
	}
	if len(parts) <= 1 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts, "\n|| ")
}

// ── CEL string encoding helpers ───────────────────────────────────────────────

// celStringLit returns a CEL string literal. Strings containing backslashes
// (typically regex patterns) use CEL raw string syntax r"""...""" to avoid
// double-escaping. Other strings use regular double-quoted literals.
func celStringLit(s string) string {
	if strings.ContainsRune(s, '\\') {
		return `r"""` + s + `"""`
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// celStringList returns a CEL list literal from a slice of Go strings.
// Lists with multiple elements are formatted with one entry per line for readability.
func celStringList(ss []string) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = celStringLit(s)
	}
	if len(parts) <= 1 {
		return "[" + strings.Join(parts, ", ") + "]"
	}
	var b strings.Builder
	b.WriteString("[\n")
	for i, p := range parts {
		b.WriteString("  " + p)
		if i < len(parts)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteByte(']')
	return b.String()
}

// ── join helpers ──────────────────────────────────────────────────────────────

func joinOr(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " || ") + ")"
}

func joinAnd(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " && ") + ")"
}

func concat(slices ...[]string) []string {
	var out []string
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
