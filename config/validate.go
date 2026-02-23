package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/tidwall/gjson"
)

// Probably want to warn rule authors not to hit APIs that change state
var validMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"PATCH":   {},
	"HEAD":    {},
	"OPTIONS": {},
}

type ValidationType string

const (
	ValidationTypeHTTP ValidationType = "http"
	// TODO Add more in the future (aws, postgres, etc)
)

// Validation describes a request to fire against a live API and a list of
// match clauses to evaluate the response, determining a finding's status.
type Validation struct {
	Type    ValidationType
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	Match   []MatchClause
}

// MatchClause is one branch in a first-match-wins decision list.
// All specified fields must be satisfied for the clause to match.
// The first matching clause determines the finding's ValidationStatus.
type MatchClause struct {
	Status        *int     // if set, response status code must equal this
	Words         []string // if set, body must contain these words (any by default)
	WordsAll      bool     // if true, ALL words must be present
	NegativeWords []string // if set, body must NOT contain any of these
	Result        string   // required: "confirmed", "invalid", "revoked", "error"
	Extract       []string // optional: JSON field names to extract into finding metadata
}

var validResults = map[string]struct{}{
	"confirmed": {},
	"invalid":   {},
	"revoked":   {},
	"error":     {},
	"unknown":   {},
}

// Check verifies that the Validation block has all required fields.
func (v *Validation) Check() error {
	switch v.Type {
	case ValidationTypeHTTP:
	default:
		return fmt.Errorf("validate: unknown type %q", v.Type)
	}
	if v.Method == "" {
		return errors.New("validate: method is required")
	}
	if _, ok := validMethods[strings.ToUpper(v.Method)]; !ok {
		return fmt.Errorf("validate: unsupported method %q", v.Method)
	}
	if v.URL == "" {
		return errors.New("validate: url is required")
	}
	if u, err := url.Parse(v.URL); err != nil || u.Scheme == "" || u.Host == "" {
		// URLs may contain {{ placeholders }}, so only reject obviously malformed ones
		// where the scheme or host is missing even after ignoring template syntax.
		if !strings.Contains(v.URL, "{{") {
			return fmt.Errorf("validate: url %q must have a scheme and host", v.URL)
		}
	}
	if len(v.Match) == 0 {
		return errors.New("validate: at least one match clause is required")
	}
	for i, c := range v.Match {
		if _, ok := validResults[c.Result]; !ok {
			return fmt.Errorf("validate: match[%d]: result %q is invalid (expected confirmed, invalid, revoked, unknown, or error)", i, c.Result)
		}
	}

	// Warn if the last match clause isn't a catch-all. Without one, unexpected
	// responses silently become ERROR status which can be confusing to debug.
	last := v.Match[len(v.Match)-1]
	if last.Status != nil || len(last.Words) > 0 || len(last.NegativeWords) > 0 {
		logging.Warn().
			Str("url", v.URL).
			Msg("validate: last match clause is not a catch-all (has status/words conditions); unmatched responses will default to error")
	}

	return nil
}

// EvalMatch evaluates match clauses against an HTTP response.
// Returns the result string of the first matching clause, extracted metadata,
// and a reason. If no clause matches, returns "error" with a reason explaining
// the miss.
func (v *Validation) EvalMatch(statusCode int, body []byte) (result string, meta map[string]string, reason string) {
	for i, c := range v.Match {
		if !clauseMatches(c, statusCode, body) {
			continue
		}
		var extracted map[string]string
		if len(c.Extract) > 0 {
			extracted = extractJSON(body, c.Extract)
		}
		return c.Result, extracted, fmt.Sprintf("match[%d] (%s)", i, c.Result)
	}
	return "unknown", nil, fmt.Sprintf("no match clause satisfied (status=%d)", statusCode)
}

func clauseMatches(c MatchClause, statusCode int, body []byte) bool {
	if c.Status != nil && statusCode != *c.Status {
		return false
	}

	lowerBody := bytes.ToLower(body)

	if len(c.Words) > 0 {
		if c.WordsAll {
			for _, w := range c.Words {
				if !bytes.Contains(lowerBody, bytes.ToLower([]byte(w))) {
					return false
				}
			}
		} else {
			found := false
			for _, w := range c.Words {
				if bytes.Contains(lowerBody, bytes.ToLower([]byte(w))) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	for _, w := range c.NegativeWords {
		if bytes.Contains(lowerBody, bytes.ToLower([]byte(w))) {
			return false
		}
	}

	return true
}

// extractJSON extracts JSON values using GJSON path expressions, stringifying them.
// Simple field names (e.g. "login") work as top-level lookups for backward
// compatibility. GJSON paths enable nested access ("user.name"), array
// indexing ("repos.0.name"), wildcards ("repos.#.name"), and more.
// See https://github.com/tidwall/gjson/blob/master/SYNTAX.md
func extractJSON(body []byte, fields []string) map[string]string {
	if !gjson.ValidBytes(body) {
		return nil
	}
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		result := gjson.GetBytes(body, f)
		if !result.Exists() {
			continue
		}
		if result.IsArray() {
			parts := make([]string, 0)
			result.ForEach(func(_, v gjson.Result) bool {
				parts = append(parts, v.String())
				return true
			})
			out[f] = strings.Join(parts, ",")
		} else {
			out[f] = result.String()
		}
	}
	return out
}
