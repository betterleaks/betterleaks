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
			v:       &Validation{Type: ValidationTypeHTTP, URL: "http://x", Match: []MatchClause{{Result: "confirmed"}}},
			wantErr: "method is required",
		},
		{
			name:    "missing url",
			v:       &Validation{Type: ValidationTypeHTTP, Method: "GET", Match: []MatchClause{{Result: "confirmed"}}},
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
				Match:  []MatchClause{{Result: "confirmed"}},
			},
			wantErr: `unknown type "ftp"`,
		},
		{
			name: "valid confirmed",
			v: &Validation{
				Type:   ValidationTypeHTTP,
				Method: "GET",
				URL:    "http://x",
				Match:  []MatchClause{{StatusCodes: []int{200}, Result: "confirmed"}},
			},
		},
		{
			name: "valid all result strings",
			v: &Validation{
				Type:   ValidationTypeHTTP,
				Method: "GET",
				URL:    "http://x",
				Match: []MatchClause{
					{StatusCodes: []int{200}, Result: "confirmed"},
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
			{StatusCodes: []int{200}, Words: []string{`"ok":true`}, Result: "confirmed"},
			{StatusCodes: []int{200}, Words: []string{"token_revoked"}, Result: "revoked"},
			{StatusCodes: []int{200}, Words: []string{"invalid_auth"}, Result: "invalid"},
		},
	}
}

func TestEvalMatch_FirstMatchWins(t *testing.T) {
	v := slackValidation()

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true,"user":"bob","team":"acme"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"token_revoked"}`), emptyHeaders)
	assert.Equal(t, "revoked", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"invalid_auth"}`), emptyHeaders)
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_StatusOnly(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "confirmed"},
			{StatusCodes: []int{401}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte("anything"), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(401, []byte("anything"), emptyHeaders)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(500, []byte("anything"), emptyHeaders)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_StatusList(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200, 201}, Result: "confirmed"},
			{StatusCodes: []int{500, 502, 503}, Result: "error"},
		},
	}

	result, _, _ := v.EvalMatch(201, []byte("anything"), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(502, []byte("anything"), emptyHeaders)
	assert.Equal(t, "error", result)
}

func TestEvalMatch_WordsAny(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Words: []string{"access_token", "bearer"}, Result: "confirmed"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"bearer": true}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"access_token": "abc"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`nothing here`), emptyHeaders)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_WordsAll(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Words: []string{"access_token", "bearer"}, WordsAll: true, Result: "confirmed"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"access_token":"abc","bearer":true}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"access_token":"abc"}`), emptyHeaders)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_NegativeWords(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, NegativeWords: []string{"error", "revoked"}, Result: "confirmed"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"token_revoked"}`), emptyHeaders)
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_NoMatch(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, Result: "confirmed"},
		},
	}

	result, meta, reason := v.EvalMatch(500, []byte("server error"), emptyHeaders)
	assert.Equal(t, "unknown", result)
	assert.Nil(t, meta)
	assert.Contains(t, reason, "status=500")
}

func TestEvalMatch_Extract(t *testing.T) {
	v := slackValidation()

	result, meta, _ := v.EvalMatch(200, []byte(`{"ok":true,"user":"alice","team":"eng"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)
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
			{StatusCodes: []int{200}, Result: "confirmed"},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`{"scopes":["read","write","admin"]}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)
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
			{StatusCodes: []int{200}, Result: "confirmed", Extract: map[string]string{"error": "json:error"}},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`{"user":"alice","error":"none"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)
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
			{StatusCodes: []int{200}, Result: "confirmed"},
		},
	}

	headers := http.Header{}
	headers.Set("X-OAuth-Scopes", "repo, user")

	result, meta, _ := v.EvalMatch(200, []byte(`{}`), headers)
	assert.Equal(t, "confirmed", result)
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
			{Words: []string{"access_token"}, Result: "confirmed"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ACCESS_TOKEN": "abc"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"Access_Token": "abc"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)
}

func TestEvalMatch_NegativeWordsCaseInsensitive(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, NegativeWords: []string{"error"}, Result: "confirmed"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ERROR": "something broke"}`), emptyHeaders)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"status": "ok"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)
}

// --- JSON assertion tests ---

func TestEvalMatch_JSONAssertion_Scalar(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"ok": true}, Result: "confirmed"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false}`), emptyHeaders)
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

	result, _, _ := v.EvalMatch(200, []byte(`{"error":"token_revoked"}`), emptyHeaders)
	assert.Equal(t, "revoked", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"error":"account_inactive"}`), emptyHeaders)
	assert.Equal(t, "revoked", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"error":"other"}`), emptyHeaders)
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_JSONAssertion_NotEmpty(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"user": "!empty"}, Result: "confirmed"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"user":"alice"}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"user":""}`), emptyHeaders)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"other":"x"}`), emptyHeaders)
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_JSONAssertion_NonJSON(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, JSON: map[string]any{"ok": true}, Result: "confirmed"},
			{StatusCodes: []int{200}, Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`not json`), emptyHeaders)
	assert.Equal(t, "invalid", result)
}

// --- Response header matching tests ---

func TestEvalMatch_ResponseHeaderMatch(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{StatusCodes: []int{200}, Headers: map[string]string{"Content-Type": "json"}, Result: "confirmed"},
			{StatusCodes: []int{200}, Result: "unknown"},
		},
	}

	headers := http.Header{}
	headers.Set("Content-Type", "application/json; charset=utf-8")
	result, _, _ := v.EvalMatch(200, []byte(`{}`), headers)
	assert.Equal(t, "confirmed", result)

	headers2 := http.Header{}
	headers2.Set("Content-Type", "text/html")
	result, _, _ = v.EvalMatch(200, []byte(`{}`), headers2)
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
			{StatusCodes: []int{200}, Result: "confirmed"},
		},
	}

	body := []byte(`{"user":{"name":"alice","profile":{"email":"alice@example.com","bio":"dev"}}}`)
	result, meta, _ := v.EvalMatch(200, body, emptyHeaders)
	assert.Equal(t, "confirmed", result)
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
			{StatusCodes: []int{200}, Result: "confirmed"},
		},
	}

	body := []byte(`{"repos":[{"name":"alpha","stars":10},{"name":"beta","stars":50}]}`)
	result, meta, _ := v.EvalMatch(200, body, emptyHeaders)
	assert.Equal(t, "confirmed", result)
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
			{StatusCodes: []int{200}, Result: "confirmed"},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`not json at all`), emptyHeaders)
	assert.Equal(t, "confirmed", result)
	assert.Nil(t, meta)
}

// --- Check() validation tests for method and URL ---

func TestValidation_Check_UnsupportedMethod(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GTE",
		URL:    "https://example.com",
		Match:  []MatchClause{{Result: "confirmed"}},
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
		Match:  []MatchClause{{Result: "confirmed"}},
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
		Match:  []MatchClause{{Result: "confirmed"}},
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
			{Status: 200, Words: []string{"ok"}, WordsAll: false, Result: "confirmed"},
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
	assert.Equal(t, "confirmed", v.Match[0].Result)
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
			{StatusCodes: []int{200}, Words: []string{`"status":"OK"`}, Result: "confirmed"},
			{StatusCodes: []int{200}, Words: []string{`"REQUEST_DENIED"`}, Result: "invalid"},
			{Result: "error"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"status":"OK","results":[]}`), emptyHeaders)
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"status":"REQUEST_DENIED"}`), emptyHeaders)
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(503, []byte(`service unavailable`), emptyHeaders)
	assert.Equal(t, "error", result)
}
