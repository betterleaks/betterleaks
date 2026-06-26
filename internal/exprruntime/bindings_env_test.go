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

func TestEnvBinding_allowlistedSet(t *testing.T) {
	t.Setenv("FOO", "bar")
	env, err := New(nil)
	require.NoError(t, err)
	env.AllowedEnv = map[string]struct{}{"FOO": {}}

	prg, err := env.CompileValidation(`env("FOO")`)
	require.NoError(t, err)
	got, err := env.Eval(prg, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "bar", got)
}

func TestEnvBinding_allowlistedUnset(t *testing.T) {
	const name = "BETTERLEAKS_TEST_ENV_UNSET_XYZ"
	_ = os.Unsetenv(name)
	env, err := New(nil)
	require.NoError(t, err)
	env.AllowedEnv = map[string]struct{}{name: {}}

	prg, err := env.CompileValidation(`env("` + name + `") == ""`)
	require.NoError(t, err)
	got, err := env.Eval(prg, nil, nil)
	require.NoError(t, err)
	require.Equal(t, true, got)
}

func TestEnvBinding_notAllowlisted(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	env.AllowedEnv = map[string]struct{}{"ONLY": {}}

	prg, err := env.CompileValidation(`env("OPENAI_API_KEY")`)
	require.NoError(t, err)
	_, err = env.Eval(prg, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not in validation env allowlist")
}

func TestEnvBinding_nilAllowlistDisables(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	prg, err := env.CompileValidation(`env("ANYTHING")`)
	require.NoError(t, err)
	_, err = env.Eval(prg, nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "validation env allowlist")
}

func TestEnvBinding_emptyAllowlistDisables(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	env.AllowedEnv = map[string]struct{}{}

	prg, err := env.CompileValidation(`env("X")`)
	require.NoError(t, err)
	_, err = env.Eval(prg, nil, nil)
	require.Error(t, err)
}

func TestEnvGetOrDefault(t *testing.T) {
	t.Setenv("CELENV_DEFAULT_TEST", "override")
	env, err := New(nil)
	require.NoError(t, err)

	prg, err := env.CompileValidation(`env.getOrDefault("CELENV_DEFAULT_TEST", "fallback")`)
	require.NoError(t, err)
	got, err := env.Eval(prg, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "fallback", got)

	env.AllowedEnv = map[string]struct{}{"CELENV_DEFAULT_TEST": {}}
	got, err = env.Eval(prg, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "override", got)
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
		`http.get(%s, {"Authorization": "Bearer " + env("CELENV_TEST_AUTH")}).status`,
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
		`http.post(%s, {"Content-Type": "text/plain"}, "key="+finding["secret"]+"|hdr="+env("CELENV_HDR_VAL")).status`,
		strconv.Quote(ts.URL),
	)
	prg, err := env.CompileValidation(expr)
	require.NoError(t, err)
	got, err := env.Eval(prg, map[string]string{"secret": "sec1"}, nil)
	require.NoError(t, err)
	require.Equal(t, int64(http.StatusOK), got)
}
