package exprruntime

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseValidationEnvAllowlist(t *testing.T) {
	got := ParseValidationEnvAllowlist([]string{" A ", "B,C", "", "D"})
	require.Equal(t, map[string]struct{}{
		"A": {}, "B": {}, "C": {}, "D": {},
	}, got)
}

func TestEnvironmentBindings(t *testing.T) {
	const present = "BETTERLEAKS_TEST_ENV_PRESENT"
	const absent = "BETTERLEAKS_TEST_ENV_ABSENT"
	t.Setenv(present, "override")
	t.Setenv(absent, "") // Restore any original value after exercising an unset variable.
	require.NoError(t, os.Unsetenv(absent))
	env, err := New(nil)
	require.NoError(t, err)
	get, err := env.CompileValidation(`env.get(finding.secret)`)
	require.NoError(t, err)
	fallback, err := env.CompileValidation(`env.getOrDefault(finding.secret, "fallback")`)
	require.NoError(t, err)
	for _, tc := range []struct {
		name                             string
		allowlist                        map[string]struct{}
		key, want, wantFallback, wantErr string
	}{
		{"nil allowlist", nil, present, "", "fallback", "provider env allowlist"},
		{"empty allowlist", map[string]struct{}{}, present, "", "fallback", "provider env allowlist"},
		{"not allowed", map[string]struct{}{"OTHER": {}}, present, "", "fallback", "not in provider env allowlist"},
		{"allowed set", map[string]struct{}{present: {}}, present, "override", "override", ""},
		{"allowed unset", map[string]struct{}{absent: {}}, absent, "", "fallback", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Reuse programs to prove access policy is read at evaluation time.
			env.AllowedEnv = tc.allowlist
			finding := map[string]string{"secret": tc.key}
			got, err := env.Eval(get, finding, nil)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
			got, err = env.Eval(fallback, finding, nil)
			require.NoError(t, err)
			require.Equal(t, tc.wantFallback, got)
		})
	}
}

func TestEnvBinding_httpGetAuthorizationHeader(t *testing.T) {
	const tok = "tok-xyz-123"
	t.Setenv("CELENV_TEST_AUTH", tok)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+tok {
			http.Error(w, "bad auth: "+got, 500)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(ts.Close)

	env, err := New(ts.Client())
	require.NoError(t, err)
	env.AllowedEnv = map[string]struct{}{"CELENV_TEST_AUTH": {}}

	expr := fmt.Sprintf(
		`http.get(%s, {"Authorization": "Bearer " + env.get("CELENV_TEST_AUTH")}).status`,
		strconv.Quote(ts.URL),
	)
	prg, err := env.CompileValidation(expr)
	require.NoError(t, err)
	got, err := env.Eval(prg, nil, nil)
	require.NoError(t, err)
	require.Equal(t, int64(http.StatusOK), got)
}

func TestValidation_envAndFindingHttpPostCompose(t *testing.T) {
	t.Setenv("CELENV_HDR_VAL", "alpha")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if string(b) != "key=sec1|hdr=alpha" {
			http.Error(w, "body "+string(b), 500)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	env, err := New(ts.Client())
	require.NoError(t, err)
	env.AllowedEnv = map[string]struct{}{"CELENV_HDR_VAL": {}}

	expr := fmt.Sprintf(
		`http.post(%s, {"Content-Type": "text/plain"}, "key="+finding["secret"]+"|hdr="+env.get("CELENV_HDR_VAL")).status`,
		strconv.Quote(ts.URL),
	)
	prg, err := env.CompileValidation(expr)
	require.NoError(t, err)
	got, err := env.Eval(prg, map[string]string{"secret": "sec1"}, nil)
	require.NoError(t, err)
	require.Equal(t, int64(http.StatusOK), got)
}
