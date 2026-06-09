package celenv

import (
	"regexp"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/require"
)

func TestProjectFunctionNamesFollowConvention(t *testing.T) {
	validationEnv, err := NewEnvironment(nil)
	require.NoError(t, err)

	filterEnv, err := NewFilterEnv(nil)
	require.NoError(t, err)

	prefilterEnv, err := NewPrefilterEnv()
	require.NoError(t, err)

	validName := regexp.MustCompile(`^[a-z]+(\.[a-z][a-zA-Z0-9]*)?$`)

	for _, env := range []struct {
		name       string
		fns        map[string]struct{}
		current    []string
		deprecated []string
	}{
		{
			name: "validation",
			fns:  functionNames(validationEnv.env),
			current: []string{
				"http.get", "http.post", "env.get", "strings.obfuscate",
				"strings.urlQueryEscape", "validate.unknown", "json.string",
				"crypto.md5", "crypto.sha1", "crypto.hmacSha1",
				"crypto.hmacSha256", "hex.encode", "time.nowUnix",
				"time.nowRFC3339", "aws.validate",
			},
			deprecated: []string{"env", "obfuscate", "unknown", "crypto.hmac_sha256", "time.now_unix"},
		},
		{
			name: "filter",
			fns:  functionNames(filterEnv.env),
			current: []string{
				"filter.matchesAny", "filter.containsAny", "filter.entropy",
				"filter.failsTokenEfficiency",
			},
			deprecated: []string{"matchesAny", "containsAny", "entropy", "failsTokenEfficiency"},
		},
		{
			name: "prefilter",
			fns:  functionNames(prefilterEnv.env),
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

func functionNames(env *cel.Env) map[string]struct{} {
	out := make(map[string]struct{}, len(env.Functions()))
	for name := range env.Functions() {
		out[name] = struct{}{}
	}
	return out
}
