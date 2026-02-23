package validate

import (
	"regexp"
	"sort"

	"github.com/betterleaks/betterleaks/logging"
)

// maxCombos is the upper bound on cartesian product expansions to prevent
// fan-out explosion when multiple placeholders each have many captured secrets.
const maxCombos = 100

// placeholderRe matches {{ some.rule-id }} (with optional inner whitespace).
var placeholderRe = regexp.MustCompile(`\{\{\s*([\w.\-]+)\s*\}\}`)

// PlaceholderIDs returns all unique rule IDs referenced in tmpl.
func PlaceholderIDs(tmpl string) []string {
	seen := make(map[string]struct{})
	var ids []string
	for _, m := range placeholderRe.FindAllStringSubmatch(tmpl, -1) {
		id := m[1]
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

// Render replaces all {{ rule-id }} placeholders with values[ruleID].
// Placeholders whose ruleID is not in values are left unchanged.
func Render(tmpl string, values map[string]string) string {
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		sub := placeholderRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		if val, ok := values[sub[1]]; ok {
			return val
		}
		return match
	})
}

// Expand generates all cartesian-product combinations of a template
// given a map of ruleID → []possibleSecrets.
// Returns one rendered string per combination.
func Expand(tmpl string, secrets map[string][]string) []string {
	ids := PlaceholderIDs(tmpl)
	if len(ids) == 0 {
		return []string{tmpl}
	}

	// Filter to IDs that actually have secrets, sort for deterministic output.
	var activeIDs []string
	for _, id := range ids {
		if vals, ok := secrets[id]; ok && len(vals) > 0 {
			activeIDs = append(activeIDs, id)
		}
	}
	sort.Strings(activeIDs)

	if len(activeIDs) == 0 {
		return []string{tmpl}
	}

	combos := cartesian(activeIDs, secrets)
	results := make([]string, 0, len(combos))
	for _, combo := range combos {
		results = append(results, Render(tmpl, combo))
	}
	return results
}

// cartesian produces the cartesian product of secrets for each ID.
func cartesian(ids []string, secrets map[string][]string) []map[string]string {
	if len(ids) == 0 {
		return []map[string]string{{}}
	}

	first := ids[0]
	rest := cartesian(ids[1:], secrets)

	var result []map[string]string
	for _, val := range secrets[first] {
		for _, combo := range rest {
			m := make(map[string]string, len(combo)+1)
			for k, v := range combo {
				m[k] = v
			}
			m[first] = val
			result = append(result, m)
		}
	}
	return result
}

// Combos generates the cartesian-product combo maps for the given placeholder IDs
// and secrets. Each returned map assigns one concrete value to each ID.
// IDs not present in secrets are omitted (callers should check for missing IDs first).
func Combos(ids []string, secrets map[string][]string) []map[string]string {
	var activeIDs []string
	for _, id := range ids {
		if vals, ok := secrets[id]; ok && len(vals) > 0 {
			activeIDs = append(activeIDs, id)
		}
	}
	sort.Strings(activeIDs)

	if len(activeIDs) == 0 {
		return []map[string]string{{}}
	}
	combos := cartesian(activeIDs, secrets)
	if len(combos) > maxCombos {
		logging.Warn().
			Int("total", len(combos)).
			Int("max", maxCombos).
			Msg("validation combo count exceeds limit, truncating")
		combos = combos[:maxCombos]
	}
	return combos
}

// RenderMap applies Render to every string value in a map.
func RenderMap(m map[string]string, values map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = Render(v, values)
	}
	return out
}
