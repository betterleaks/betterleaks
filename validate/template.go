package validate

import (
	"regexp"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
)

// maxCombos is the upper bound on cartesian product expansions to prevent
// fan-out explosion when multiple placeholders each have many captured secrets.
const maxCombos = 100

// exprRe matches the full contents of a {{ ... }} expression (including filters).
var exprRe = regexp.MustCompile(`\{\{(.*?)\}\}`)

// identRe matches a bare identifier (not a quoted string literal).
var identRe = regexp.MustCompile(`^[\w][\w.\-]*$`)

// PlaceholderIDs returns all unique variable IDs referenced in tmpl,
// including variables used as filter arguments (e.g. `append: secret`).
// String literals (quoted values) are ignored.
// This is used to determine which secret variables a template needs before
// rendering (e.g. to detect missing placeholders). Rendering itself is
// handled by [TemplateEngine].
func PlaceholderIDs(tmpl string) []string {
	seen := make(map[string]struct{})
	var ids []string
	addID := func(id string) {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}

	for _, m := range exprRe.FindAllStringSubmatch(tmpl, -1) {
		inner := strings.TrimSpace(m[1])
		parts := strings.Split(inner, "|")

		// First segment is the primary value (variable or string literal).
		primary := strings.TrimSpace(parts[0])
		if identRe.MatchString(primary) {
			addID(primary)
		}

		// Remaining segments are filters. Extract bare identifiers used
		// as arguments (skip quoted strings and numeric literals).
		for _, part := range parts[1:] {
			seg := strings.TrimSpace(part)
			if colonIdx := strings.Index(seg, ":"); colonIdx >= 0 {
				for _, arg := range strings.Split(seg[colonIdx+1:], ",") {
					arg = strings.TrimSpace(arg)
					if identRe.MatchString(arg) {
						addID(arg)
					}
				}
			}
		}
	}
	return ids
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
