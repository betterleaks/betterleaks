package exprruntime

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectFunctionNamesFollowConvention(t *testing.T) {
	validName := regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-zA-Z0-9]*)?$`)

	for _, env := range []struct {
		name       string
		fns        map[string]struct{}
		current    []string
		deprecated []string
	}{
		{
			name: "validation",
			fns:  functionNames((&Runtime{}).validationBindings(nil, nil, nil, nil)),
			current: []string{
				"http.get", "http.post", "env.get", "env.getOrDefault", "strings.obfuscate",
				"strings.urlQueryEscape", "validate.unknown", "json.string",
				"crypto.md5", "crypto.sha1", "crypto.hmacSha1",
				"crypto.hmacSha256", "hex.encode", "time.nowUnix",
				"time.nowRFC3339", "aws.validate", "gcp.validate",
				"base64.encode", "base64.decode",
			},
			deprecated: []string{"obfuscate", "unknown", "crypto.hmac_sha256", "time.now_unix"},
		},
		{
			name: "filter",
			fns:  functionNames(filterBindings(nil, emptyStringMap, emptyStringMap)),
			current: []string{
				"filter.matchesAny", "filter.containsAny", "filter.entropy",
				"filter.failsTokenEfficiency",
			},
			deprecated: []string{"matchesAny", "containsAny", "entropy", "failsTokenEfficiency"},
		},
		{
			name: "prefilter",
			fns:  functionNames(prefilterBindings(emptyStringMap)),
			current: []string{
				"filter.matchesAny", "filter.containsAny", "filter.entropy",
				"filter.failsTokenEfficiency",
			},
			deprecated: []string{"matchesAny", "containsAny", "entropy", "failsTokenEfficiency"},
		},
	} {
		for _, name := range env.current {
			require.Contains(t, env.fns, name, "%s missing function %q", env.name, name)
			require.Truef(t, validName.MatchString(name), "%s function %q does not follow convention", env.name, name)
		}
		for _, name := range env.deprecated {
			require.Contains(t, env.fns, name, "%s missing deprecated alias %q", env.name, name)
		}
	}
}

func TestFilterScopes(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	_, err = env.CompileFilter(`http.get("https://example.com")`, nil)
	require.Error(t, err)
	_, err = env.CompileFilter(`entropy(finding["secret"]) > 0`, nil)
	require.NoError(t, err)

	_, err = env.CompilePrefilter(`finding["secret"] == ""`)
	require.Error(t, err)
	_, err = env.CompilePrefilter(`matchesAny(get(attributes, "path", ""), [".go"])`)
	require.NoError(t, err)
}

func TestFilterEntropy(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompileFilter(`entropy(finding["secret"]) <= 1.0`, nil)
	require.NoError(t, err)

	skip, err := env.EvalFilter(prg, map[string]string{
		"secret": "aaaaaaaa",
	}, nil)
	require.NoError(t, err)
	require.True(t, skip)
}

func functionNames(env map[string]any) map[string]struct{} {
	out := make(map[string]struct{})
	for name, value := range env {
		if nested, ok := value.(map[string]any); ok {
			for child := range nested {
				out[name+"."+child] = struct{}{}
			}
			continue
		}
		out[name] = struct{}{}
	}
	return out
}
