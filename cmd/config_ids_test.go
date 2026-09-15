package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigShowIDs(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()
	configPath := writeValidateTestConfig(t, fmt.Sprintf(`
[[rules]]
id = "z-local"
regex = '''(unused-regex)'''

[[rules]]
id = "b-validation"
regex = '''(unused-regex)'''
validate = '''let response = http.get(%q, {}); {"result": "valid"}'''

[[rules]]
id = "a-analysis"
regex = '''(unused-regex)'''
validate = '''let response = http.get(%q, {}); {"result": "valid"}'''
analyze = '''let response = http.get(%q, {}); {"capabilities": ["read"]}'''
`, server.URL, server.URL, server.URL))
	for _, test := range []struct {
		name  string
		flags []string
		want  string
	}{
		{name: "all", want: "a-analysis\nb-validation\nz-local\n"},
		{name: "validation", flags: []string{"--validation"}, want: "a-analysis\nb-validation\n"},
		{name: "analysis", flags: []string{"--analysis"}, want: "a-analysis\n"},
		{name: "both", flags: []string{"--validation", "--analysis"}, want: "a-analysis\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, stdout := newValidateTestRoot(t)
			args := []string{"config", "show", "ids", "--config", configPath}
			root.SetArgs(append(args, test.flags...))
			require.NoError(t, root.Execute())
			require.Equal(t, test.want, stdout.String())
		})
	}
	require.Zero(t, requests.Load(), "listing IDs must not execute provider expressions")

	t.Run("positional config overrides global flag", func(t *testing.T) {
		root, stdout := newValidateTestRoot(t)
		root.SetArgs([]string{"config", "show", "ids", "--config", "missing-config.toml", "--analysis", configPath})
		require.NoError(t, root.Execute())
		require.Equal(t, "a-analysis\n", stdout.String())
	})
	t.Run("config environment", func(t *testing.T) {
		t.Setenv("BETTERLEAKS_CONFIG", configPath)
		root, stdout := newValidateTestRoot(t)
		root.SetArgs([]string{"config", "show", "ids", "--analysis"})
		require.NoError(t, root.Execute())
		require.Equal(t, "a-analysis\n", stdout.String())
	})
}

func TestConfigShowIDsWithNoMatches(t *testing.T) {
	configPath := writeValidateTestConfig(t, `[[rules]]
id = "local-only"
regex = '''(unused-regex)'''
`)
	root, stdout := newValidateTestRoot(t)
	root.SetArgs([]string{"config", "show", "ids", "--analysis", configPath})
	require.NoError(t, root.Execute())
	require.Empty(t, stdout.String())
}

func TestConfigShowIDsPropagatesWriteError(t *testing.T) {
	configPath := writeValidateTestConfig(t, credentialRequirementsConfig)
	root, _ := newValidateTestRoot(t)
	want := errors.New("output failed")
	root.runtime.stdout = configIDsErrorWriter{err: want}
	root.SetArgs([]string{"config", "show", "ids", configPath})
	require.ErrorIs(t, root.Execute(), want)
}

type configIDsErrorWriter struct{ err error }

func (w configIDsErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestConfigShowPreservesTOMLForms(t *testing.T) {
	configPath := writeValidateTestConfig(t, credentialRequirementsConfig)
	for _, args := range [][]string{
		{"config", "show", "--config", configPath},
		{"config", "show", configPath},
		{"config", "show", "toml", configPath},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			root, stdout := newValidateTestRoot(t)
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			require.Contains(t, stdout.String(), "[[rules]]")
			require.Contains(t, stdout.String(), "id = 'analysis-token'")
		})
	}
}
