package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intPtr(i int) *int { return &i }

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
				Match:  []MatchClause{{Status: intPtr(200), Result: "confirmed"}},
			},
		},
		{
			name: "valid all result strings",
			v: &Validation{
				Type:   ValidationTypeHTTP,
				Method: "GET",
				URL:    "http://x",
				Match: []MatchClause{
					{Status: intPtr(200), Result: "confirmed"},
					{Status: intPtr(401), Result: "invalid"},
					{Status: intPtr(403), Result: "revoked"},
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

func slackValidation() *Validation {
	return &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "https://slack.com/api/auth.test",
		Match: []MatchClause{
			{Status: intPtr(200), Words: []string{`"ok":true`}, Result: "confirmed", Extract: []string{"user", "team"}},
			{Status: intPtr(200), Words: []string{"token_revoked"}, Result: "revoked"},
			{Status: intPtr(200), Words: []string{"invalid_auth"}, Result: "invalid"},
		},
	}
}

func TestEvalMatch_FirstMatchWins(t *testing.T) {
	v := slackValidation()

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true,"user":"bob","team":"acme"}`))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"token_revoked"}`))
	assert.Equal(t, "revoked", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"invalid_auth"}`))
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_StatusOnly(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed"},
			{Status: intPtr(401), Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte("anything"))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(401, []byte("anything"))
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(500, []byte("anything"))
	assert.Equal(t, "unknown", result)
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

	result, _, _ := v.EvalMatch(200, []byte(`{"bearer": true}`))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"access_token": "abc"}`))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`nothing here`))
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

	result, _, _ := v.EvalMatch(200, []byte(`{"access_token":"abc","bearer":true}`))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"access_token":"abc"}`))
	assert.Equal(t, "unknown", result)
}

func TestEvalMatch_NegativeWords(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), NegativeWords: []string{"error", "revoked"}, Result: "confirmed"},
			{Status: intPtr(200), Result: "invalid"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"ok":true}`))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"ok":false,"error":"token_revoked"}`))
	assert.Equal(t, "invalid", result)
}

func TestEvalMatch_NoMatch(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed"},
		},
	}

	result, meta, reason := v.EvalMatch(500, []byte("server error"))
	assert.Equal(t, "unknown", result)
	assert.Nil(t, meta)
	assert.Contains(t, reason, "status=500")
}

func TestEvalMatch_Extract(t *testing.T) {
	v := slackValidation()

	result, meta, _ := v.EvalMatch(200, []byte(`{"ok":true,"user":"alice","team":"eng"}`))
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
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed", Extract: []string{"scopes"}},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`{"scopes":["read","write","admin"]}`))
	assert.Equal(t, "confirmed", result)
	require.NotNil(t, meta)
	assert.Equal(t, "read,write,admin", meta["scopes"])
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

	result, _, _ := v.EvalMatch(200, []byte(`{"ACCESS_TOKEN": "abc"}`))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"Access_Token": "abc"}`))
	assert.Equal(t, "confirmed", result)
}

func TestEvalMatch_NegativeWordsCaseInsensitive(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), NegativeWords: []string{"error"}, Result: "confirmed"},
			{Status: intPtr(200), Result: "invalid"},
		},
	}

	// "ERROR" should still be caught by negative_words = ["error"]
	result, _, _ := v.EvalMatch(200, []byte(`{"ERROR": "something broke"}`))
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"status": "ok"}`))
	assert.Equal(t, "confirmed", result)
}

// --- GJSON path extraction tests ---

func TestEvalMatch_ExtractNestedPath(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed", Extract: []string{"user.profile.email", "user.name"}},
		},
	}

	body := []byte(`{"user":{"name":"alice","profile":{"email":"alice@example.com","bio":"dev"}}}`)
	result, meta, _ := v.EvalMatch(200, body)
	assert.Equal(t, "confirmed", result)
	require.NotNil(t, meta)
	assert.Equal(t, "alice@example.com", meta["user.profile.email"])
	assert.Equal(t, "alice", meta["user.name"])
}

func TestEvalMatch_ExtractArrayWildcard(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed", Extract: []string{"repos.#.name"}},
		},
	}

	body := []byte(`{"repos":[{"name":"alpha","stars":10},{"name":"beta","stars":50}]}`)
	result, meta, _ := v.EvalMatch(200, body)
	assert.Equal(t, "confirmed", result)
	require.NotNil(t, meta)
	assert.Equal(t, "alpha,beta", meta["repos.#.name"])
}

func TestEvalMatch_ExtractArrayCount(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed", Extract: []string{"repos.#"}},
		},
	}

	body := []byte(`{"repos":[{"name":"a"},{"name":"b"},{"name":"c"}]}`)
	result, meta, _ := v.EvalMatch(200, body)
	assert.Equal(t, "confirmed", result)
	require.NotNil(t, meta)
	assert.Equal(t, "3", meta["repos.#"])
}

func TestEvalMatch_ExtractArrayIndex(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed", Extract: []string{"repos.0.name", "repos.1.name"}},
		},
	}

	body := []byte(`{"repos":[{"name":"first"},{"name":"second"}]}`)
	result, meta, _ := v.EvalMatch(200, body)
	assert.Equal(t, "confirmed", result)
	require.NotNil(t, meta)
	assert.Equal(t, "first", meta["repos.0.name"])
	assert.Equal(t, "second", meta["repos.1.name"])
}

func TestEvalMatch_ExtractMissingNestedPath(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed", Extract: []string{"user.nonexistent.deep", "exists"}},
		},
	}

	body := []byte(`{"exists":"yes","user":{"name":"alice"}}`)
	result, meta, _ := v.EvalMatch(200, body)
	assert.Equal(t, "confirmed", result)
	require.NotNil(t, meta)
	assert.Equal(t, "yes", meta["exists"])
	_, hasMissing := meta["user.nonexistent.deep"]
	assert.False(t, hasMissing)
}

func TestEvalMatch_ExtractNonJSONBody(t *testing.T) {
	v := &Validation{
		Type:   ValidationTypeHTTP,
		Method: "GET",
		URL:    "http://x",
		Match: []MatchClause{
			{Status: intPtr(200), Result: "confirmed", Extract: []string{"field"}},
		},
	}

	result, meta, _ := v.EvalMatch(200, []byte(`not json at all`))
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
	// Should not error — URL contains placeholders so we can't validate it statically.
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
		Match: []viperMatchClause{
			{Status: intPtr(200), Words: []string{"ok"}, WordsAll: false, Result: "confirmed", Extract: []string{"user"}},
			{Status: intPtr(401), Result: "invalid"},
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
	assert.Equal(t, []string{"user"}, v.Match[0].Extract)
	assert.Equal(t, "invalid", v.Match[1].Result)
	assert.Equal(t, "error", v.Match[2].Result)
}

func TestParseHTTPValidation_EmptyResult_Errors(t *testing.T) {
	vv := &viperValidation{
		Type:   "http",
		Method: "GET",
		URL:    "https://example.com",
		Match: []viperMatchClause{
			{Status: intPtr(200), Result: ""},
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
			{Status: intPtr(200), Words: []string{`"status":"OK"`}, Result: "confirmed"},
			{Status: intPtr(200), Words: []string{`"REQUEST_DENIED"`}, Result: "invalid"},
			{Result: "error"},
		},
	}

	result, _, _ := v.EvalMatch(200, []byte(`{"status":"OK","results":[]}`))
	assert.Equal(t, "confirmed", result)

	result, _, _ = v.EvalMatch(200, []byte(`{"status":"REQUEST_DENIED"}`))
	assert.Equal(t, "invalid", result)

	result, _, _ = v.EvalMatch(503, []byte(`service unavailable`))
	assert.Equal(t, "error", result)
}
