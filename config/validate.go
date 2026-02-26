package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/osteele/liquid"
	"github.com/tidwall/gjson"
)

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
	// Extract is the default extractor map. Used when a matching clause has no
	// extract of its own. Keys are output names, values are source-prefixed
	// expressions (e.g. "json:login", "header:X-OAuth-Scopes").
	Extract map[string]string
}

// MatchClause is one branch in a first-match-wins decision list.
// All specified fields must be satisfied for the clause to match.
// The first matching clause determines the finding's ValidationStatus.
type MatchClause struct {
	StatusCodes   []int             // if set, response status code must be one of these
	Words         []string          // if set, body must contain these words (any by default)
	WordsAll      bool              // if true, ALL words must be present
	NegativeWords []string          // if set, body must NOT contain any of these
	JSON          map[string]any    // GJSON path assertions; all must match
	Headers       map[string]string // response header assertions (case-insensitive substring)
	Result        string            // required: "confirmed", "invalid", "revoked", "error", "unknown"
	Extract       map[string]string // per-clause extract overrides Validation.Extract
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

	last := v.Match[len(v.Match)-1]
	if len(last.StatusCodes) > 0 || len(last.Words) > 0 || len(last.NegativeWords) > 0 || len(last.JSON) > 0 || len(last.Headers) > 0 {
		logging.Warn().
			Str("url", v.URL).
			Msg("validate: last match clause is not a catch-all (has conditions); unmatched responses will default to error")
	}

	// Validate Liquid template syntax at config time so broken templates
	// fail loudly rather than silently at runtime.
	if err := v.checkTemplates(); err != nil {
		return err
	}

	return nil
}

func (v *Validation) checkTemplates() error {
	engine := liquid.NewEngine()
	templates := []struct {
		name, tmpl string
	}{
		{"url", v.URL},
		{"body", v.Body},
	}
	for _, h := range v.Headers {
		templates = append(templates, struct{ name, tmpl string }{"header value", h})
	}
	for _, t := range templates {
		if t.tmpl == "" {
			continue
		}
		if _, err := engine.ParseString(t.tmpl); err != nil {
			return fmt.Errorf("validate: template error in %s %q: %w", t.name, t.tmpl, err)
		}
	}
	return nil
}

// EvalMatch evaluates match clauses against an HTTP response.
// Returns the result string of the first matching clause, extracted metadata,
// and a reason. If no clause matches, returns "unknown" with a reason.
func (v *Validation) EvalMatch(statusCode int, body []byte, headers http.Header) (result string, meta map[string]string, reason string) {
	for i, c := range v.Match {
		if !clauseMatches(c, statusCode, body, headers) {
			continue
		}
		extractMap := v.Extract
		if len(c.Extract) > 0 {
			extractMap = c.Extract
		}
		extracted := extractValues(body, headers, extractMap)
		return c.Result, extracted, fmt.Sprintf("match[%d] (%s)", i, c.Result)
	}
	return "unknown", nil, fmt.Sprintf("no match clause satisfied (status=%d)", statusCode)
}

func clauseMatches(c MatchClause, statusCode int, body []byte, headers http.Header) bool {
	if len(c.StatusCodes) > 0 {
		found := false
		for _, code := range c.StatusCodes {
			if statusCode == code {
				found = true
				break
			}
		}
		if !found {
			return false
		}
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

	// JSON path assertions
	if len(c.JSON) > 0 {
		if !gjson.ValidBytes(body) {
			return false
		}
		for path, expected := range c.JSON {
			result := gjson.GetBytes(body, path)
			if !matchJSONAssertion(result, expected) {
				return false
			}
		}
	}

	// Response header assertions
	for name, expected := range c.Headers {
		actual := headers.Get(name)
		if !strings.Contains(strings.ToLower(actual), strings.ToLower(expected)) {
			return false
		}
	}

	return true
}

// matchJSONAssertion checks a GJSON result against an expected value:
//   - "!empty": path must exist and be non-empty
//   - []any: actual value must match one of the list entries
//   - scalar: exact match via string comparison
func matchJSONAssertion(result gjson.Result, expected any) bool {
	switch v := expected.(type) {
	case string:
		if v == "!empty" {
			return result.Exists() && result.String() != ""
		}
		return result.Exists() && result.String() == v
	case []any:
		if !result.Exists() {
			return false
		}
		actual := result.Value()
		for _, want := range v {
			if fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", want) {
				return true
			}
		}
		return false
	case bool:
		return result.Exists() && result.Bool() == v
	case float64:
		return result.Exists() && result.Float() == v
	case int:
		return result.Exists() && result.Int() == int64(v)
	case int64:
		return result.Exists() && result.Int() == v
	default:
		return result.Exists() && fmt.Sprintf("%v", result.Value()) == fmt.Sprintf("%v", expected)
	}
}

// extractValues extracts data from an HTTP response using source-prefixed expressions.
// Supported prefixes: "json:" (GJSON path on body), "header:" (response header value),
// "xpath:" (stub for future XML support).
func extractValues(body []byte, headers http.Header, extract map[string]string) map[string]string {
	if len(extract) == 0 {
		return nil
	}
	out := make(map[string]string, len(extract))
	for name, expr := range extract {
		prefix, path, _ := strings.Cut(expr, ":")
		var val string
		switch prefix {
		case "json":
			if gjson.ValidBytes(body) {
				r := gjson.GetBytes(body, path)
				if r.Exists() {
					if r.IsArray() {
						parts := make([]string, 0)
						r.ForEach(func(_, v gjson.Result) bool {
							parts = append(parts, v.String())
							return true
						})
						val = strings.Join(parts, ",")
					} else {
						val = r.String()
					}
				}
			}
		case "header":
			val = headers.Get(path)
		case "xpath":
			// Stub — implement when needed
		}
		if val != "" {
			out[name] = val
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
