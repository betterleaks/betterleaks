package config

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Check() tests ---

func TestValidation_Check(t *testing.T) {
	tests := []struct {
		name    string
		v       *Validation
		wantErr string
	}{
		{
			name:    "missing method",
			v:       &Validation{Type: ValidationTypeHTTP, URL: "http://x", Match: []MatchClause{{Result: "valid"}}},
			wantErr: "method is required",
		},
		{
			name:    "missing url",
			v:       &Validation{Type: ValidationTypeHTTP, Method: "GET", Match: []MatchClause{{Result: "valid"}}},
			wantErr: "url is required",
		},
		{
			name:    "no match clauses",
			v:       &Validation{Type: ValidationTypeHTTP, Method: "GET", URL: "http://x"},
			wantErr: "at least one match clause",
		},
		{
			name: "invalid result string",
			v: &Validation{
				Type:   ValidationTypeHTTP,
				Method: "GET",
				URL:    "http://x",
				Match:  []MatchClause{{Result: "maybe"}},
			},
			wantErr: `result "maybe" is invalid`,
		},
		{
			name: "unknown type",
			v: &Validation{
				Type:   "ftp",
				Method: "GET",
				URL:    "http://x",
				Match:  []MatchClause{{Result: "valid"}},
			},
			wantErr: `unknown type "ftp"`,
		},
		{
			name: "valid result",
			v: &Validation{
				Type:   ValidationTypeHTTP,
				Method: "GET",
				URL:    "http://x",
				Match:  []MatchClause{{StatusCodes: []int{200}, Result: "valid"}},
			},
		},
		{
			name: "valid all result strings",
			v: &Validation{
				Type:   ValidationTypeHTTP,
				Method: "GET",
				URL:    "http://x",
				Match: []MatchClause{
					{StatusCodes: []int{200}, Result: "valid"},
					{StatusCodes: []int{401}, Result: "invalid"},
					{StatusCodes: []int{403}, Result: "revoked"},
					{Result: "error"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.v.Check()
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- EvalMatch() tests ---

var emptyHeaders = http.Header{}

func slackValidation() *Validation {
	return &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://slack.com/api/auth.test",
		Extract: map[string]string{
			"user": "json:user",
			"team": "json:team",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Words: []string{`"ok":true`}, Result: "valid"},
			{StatusCodes: []int{200}, Words: []string{"token_revoked"}, Result: "revoked"},
			{StatusCodes: []int{200}, Words: []string{"invalid_auth"}, Result: "invalid"},
		},
	}
}

func TestEvalMatch_FirstMatchWins(t *testing.T) {
	v := slackValidation()

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true,"user":"bob","team":"acme"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"token_revoked"}`), emptyHeaders, false)
	assert.Equal(t, "revoked", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"invalid_auth"}`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_StatusOnly(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
			{StatusCodes: []int{401}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte("anything"), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(401, []byte("anything"), emptyHeaders, false)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(500, []byte("anything"), emptyHeaders, false)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_StatusList(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200, 201}, Result: "valid"},
			{StatusCodes: []int{500, 502, 503}, Result: "error"},
		},
	}

	result, _, _ := v.EvalMatch(201, []byte("anything"), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(502, []byte("anything"), emptyHeaders, false)
	assert.Equal(t, "error", result)
}

func TestEvalMatch_WordsAny(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Words: []string{"access_token", "bearer"}, Result: "valid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"bearer": true}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"access_token": "abc"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`nothing here`), emptyHeaders, false)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_WordsAll(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Words: []string{"access_token", "bearer"}, WordsAll: true, Result: "valid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"access_token":"abc","bearer":true}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"access_token":"abc"}`), emptyHeaders, false)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_NegativeWords(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, NegativeWords: []string{"error", "revoked"}, Result: "valid"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"token_revoked"}`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_NoMatch(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
		},
	}

	result, meta, reason := v.EvalMatch(500, []byte("server error"), emptyHeaders, false)
	assert.Equal(t, "unknown", result)
	assert.Nil(t, meta)
	assert.Contains(t, reason, "HTTP 500")
}

func TestEvalMatch_Extract(t *testing.T) {
	v := slackValidation()

	result, meta, _ := v.EvalMatch(200, []byte(`{"ok":true,"user":"alice","team":"eng"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)
	require.NotNil(t, meta)
	assert.Equal(t, "alice", meta["user"])
	assert.Equal(t, "eng", meta["team"])
}

func TestEvalMatch_ExtractStringifiesArrays(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Extract: map[string]string{
			"scopes": "json:scopes",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`{"scopes":["read","write","admin"]}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)
	require.NotNil(t, meta)
	assert.Equal(t, "read,write,admin", meta["scopes"])
}

func TestEvalMatch_PerClauseExtractOverridesDefault(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Extract: map[string]string{
			"user": "json:user",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid", Extract: map[string]string{"error": "json:error"}},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`{"user":"alice","error":"none"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)
	require.NotNil(t, meta)
	assert.Equal(t, "none", meta["error"])
	_, hasUser := meta["user"]
	assert.False(t, hasUser, "per-clause extract should override default, not merge")
}

func TestEvalMatch_HeaderExtract(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Extract: map[string]string{
			"scopes": "header:X-OAuth-Scopes",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
		},
	}

	headers := http.Header{}
	headers.Set("X-OAuth-Scopes", "repo, user")

	result, meta, _ := v.EvalMatch(200, []byte(`{}`), headers, false)
	assert.Equal(t, "valid", result)
	require.NotNil(t, meta)
	assert.Equal(t, "repo, user", meta["scopes"])
}

// --- Case-insensitivity tests ---

func TestEvalMatch_WordsCaseInsensitive(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Words: []string{"access_token"}, Result: "valid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ACCESS_TOKEN": "abc"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"Access_Token": "abc"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)
}

func TestEvalMatch_NegativeWordsCaseInsensitive(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, NegativeWords: []string{"error"}, Result: "valid"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ERROR": "something broke"}`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"status": "ok"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)
}

// --- JSON assertion tests ---

func TestEvalMatch_JSONAssertion_Scalar(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"ok": true}, Result: "valid"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false}`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_JSONAssertion_List(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"error": []any{"account_inactive", "token_revoked"}}, Result: "revoked"},
			{StatusCodes: []int{200}, Result: "unknown"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"error":"token_revoked"}`), emptyHeaders, false)
	assert.Equal(t, "revoked", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"error":"account_inactive"}`), emptyHeaders, false)
	assert.Equal(t, "revoked", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"error":"other"}`), emptyHeaders, false)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_JSONAssertion_NotEmpty(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"user": "!empty"}, Result: "valid"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"user":"alice"}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"user":""}`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"other":"x"}`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_JSONAssertion_NonJSON(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"ok": true}, Result: "valid"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`not json`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)
}

// --- Response header matching tests ---

func TestEvalMatch_ResponseHeaderMatch(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, Headers: map[string]string{"Content-Type": "json"}, Result: "valid"},
			{StatusCodes: []int{200}, Result: "unknown"},
		},
	}

	headers := http.Header{}
	headers.Set("Content-Type", "application/json; charset=utf-8")
	result, _, _ := v.EvalMatch(200, []byte(`{}`), headers, false)
	assert.Equal(t, "valid", result)

	headers2 := http.Header{}
	headers2.Set("Content-Type", "text/html")
	result, _, _ = v.EvalMatch(200, []byte(`{}`), headers2, false)
	assert.Equal(t, "unknown", result)
}

// --- GJSON path extraction tests (now via extractValues) ---

func TestEvalMatch_ExtractNestedPath(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Extract: map[string]string{
			"email": "json:user.profile.email",
			"name":  "json:user.name",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
		},
	}

	body := []byte(`{"user":{"name":"alice","profile":{"email":"alice@example.com","bio":"dev"}}}`)
	result, meta, _ := v.EvalMatch(200, body, emptyHeaders, false)
	assert.Equal(t, "valid", result)
	require.NotNil(t, meta)
	assert.Equal(t, "alice@example.com", meta["email"])
	assert.Equal(t, "alice", meta["name"])
}

func TestEvalMatch_ExtractArrayWildcard(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Extract: map[string]string{
			"names": "json:repos.#.name",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
		},
	}

	body := []byte(`{"repos":[{"name":"alpha","stars":10},{"name":"beta","stars":50}]}`)
	result, meta, _ := v.EvalMatch(200, body, emptyHeaders, false)
	assert.Equal(t, "valid", result)
	require.NotNil(t, meta)
	assert.Equal(t, "alpha,beta", meta["names"])
}

func TestEvalMatch_ExtractNonJSONBody(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Extract: map[string]string{
			"field": "json:field",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`not json at all`), emptyHeaders, false)
	assert.Equal(t, "valid", result)
	assert.Nil(t, meta)
}

func TestEvalMatch_ExtractEmpty(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Extract: map[string]string{
			"present": "json:name",
			"missing": "json:nope",
			"blank":   "header:X-Missing",
		},
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "valid"},
		},
	}
	body := []byte(`{"name":"alice"}`)

	// Without extract-empty: only non-empty values appear
	_, meta, _ := v.EvalMatch(200, body, emptyHeaders, false)
	require.NotNil(t, meta)
	assert.Equal(t, "alice", meta["present"])
	_, hasMissing := meta["missing"]
	assert.False(t, hasMissing)
	_, hasBlank := meta["blank"]
	assert.False(t, hasBlank)

	// With extract-empty: all keys appear, empty ones have ""
	_, meta, _ = v.EvalMatch(200, body, emptyHeaders, true)
	require.NotNil(t, meta)
	assert.Equal(t, "alice", meta["present"])
	assert.Equal(t, "", meta["missing"])
	assert.Equal(t, "", meta["blank"])
}

// --- Check() validation tests for method and URL ---

func TestValidation_Check_UnsupportedMethod(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GTE",
		URL:    "https://example.com",
		Match:  []MatchClause{{Result: "valid"}},
	}
	err := v.Check()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported method "GTE"`)
}

func TestValidation_Check_MalformedURL(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "not a url",
		Match:  []MatchClause{{Result: "valid"}},
	}
	err := v.Check()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must have a scheme and host")
}

func TestValidation_Check_TemplatedURL_Allowed(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "{{ base-url }}/api/check",
		Match:  []MatchClause{{Result: "valid"}},
	}
	err := v.Check()
	require.NoError(t, err)
}

// --- parseHTTPValidation round-trip test ---

func TestParseHTTPValidation_RoundTrip(t *testing.T) {
	vv := &viperValidation{
		Type:   "HTTP",
		Method: "post",
		URL:    "https://api.example.com/check",
		Headers: map[string]string{
			"Authorization": "Bearer {{ test.rule }}",
		},
		Body: "token={{ test.rule }}",
		Extract: map[string]string{
			"user": "json:user",
		},
		Match: []viperMatchClause{
			{Status: 200, Words: []string{"ok"}, WordsAll: false, Result: "valid"},
			{Status: 401, Result: "invalid"},
			{Result: "error"},
		},
	}

	v, err := parseHTTPValidation(vv)
	require.NoError(t, err)

	assert.Equal(t, ValidationTypeHTTP, v.Type)
	assert.Equal(t, "POST", v.Method, "method should be uppercased")
	assert.Equal(t, "https://api.example.com/check", v.URL)
	assert.Equal(t, "Bearer {{ test.rule }}", v.Headers["Authorization"])
	assert.Equal(t, "token={{ test.rule }}", v.Body)
	require.Len(t, v.Match, 3)
	assert.Equal(t, "valid", v.Match[0].Result)
	assert.Equal(t, []int{200}, v.Match[0].StatusCodes)
	assert.Equal(t, "invalid", v.Match[1].Result)
	assert.Equal(t, "error", v.Match[2].Result)
	assert.Equal(t, map[string]string{"user": "json:user"}, v.Extract)
}

func TestParseHTTPValidation_StatusList(t *testing.T) {
	vv := &viperValidation{
		Type:   "http",
		Method: "GET",
		URL:    "https://example.com",
		Match: []viperMatchClause{
			{Status: []any{float64(500), float64(502), float64(503)}, Result: "error"},
			{Result: "unknown"},
		},
	}

	v, err := parseHTTPValidation(vv)
	require.NoError(t, err)
	assert.Equal(t, []int{500, 502, 503}, v.Match[0].StatusCodes)
}

func TestParseHTTPValidation_StatusAsList(t *testing.T) {
	vv := &viperValidation{
		Type:   "http",
		Method: "GET",
		URL:    "https://example.com",
		Match: []viperMatchClause{
			{Status: []any{float64(401), float64(403)}, Result: "invalid"},
			{Result: "unknown"},
		},
	}

	v, err := parseHTTPValidation(vv)
	require.NoError(t, err)
	assert.Equal(t, []int{401, 403}, v.Match[0].StatusCodes)
}

func TestParseHTTPValidation_EmptyResult_Errors(t *testing.T) {
	vv := &viperValidation{
		Type:   "http",
		Method: "GET",
		URL:    "https://example.com",
		Match: []viperMatchClause{
			{Status: 200, Result: ""},
		},
	}

	_, err := parseHTTPValidation(vv)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "result is required")
}

// Google Maps example: status-based differentiation
func TestEvalMatch_GoogleMaps(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://maps.googleapis.com/maps/api/geocode/json",
		Match: []MatchClause{
			{StatusCodes: []int{200}, Words: []string{`"status":"OK"`}, Result: "valid"},
			{StatusCodes: []int{200}, Words: []string{`"REQUEST_DENIED"`}, Result: "invalid"},
			{Result: "error"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"status":"OK","results":[]}`), emptyHeaders, false)
	assert.Equal(t, "valid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"status":"REQUEST_DENIED"}`), emptyHeaders, false)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(503, []byte(`service unavailable`), emptyHeaders, false)
	assert.Equal(t, "error", result)
}
