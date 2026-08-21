package exprruntime

import (
	"fmt"
	"regexp"
	"testing"

	tiktoken "github.com/pkoukk/tiktoken-go"
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
			fns:  functionNames((&Runtime{}).validationBindings(nil, nil, nil, nil, nil, nil)),
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
			fns:  functionNames(filterBindings(nil, emptyFilterFinding, emptyStringMap)),
			current: []string{
				"filter.matchesAny", "filter.findMatch", "filter.containsAny", "filter.entropy",
				"filter.failsTokenEfficiency", "filter.tokenRatio", "filter.setConfidence",
			},
			deprecated: []string{"matchesAny", "containsAny", "entropy", "failsTokenEfficiency"},
		},
		{
			name: "prefilter",
			fns:  functionNames(prefilterBindings(emptyStringMap)),
			current: []string{
				"filter.matchesAny", "filter.findMatch", "filter.containsAny", "filter.entropy",
				"filter.failsTokenEfficiency", "filter.tokenRatio",
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
	_, err = env.CompilePrefilter(`matchesAny(attributes["path"], [".go"])`)
	require.NoError(t, err)
}

func TestAttributeMapAccessIsSafeWhenKeyIsMissing(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	prg, err := env.CompilePrefilter(`attributes["path"] == ""`)
	require.NoError(t, err)

	got, err := env.EvalPrefilter(prg, nil)
	require.NoError(t, err)
	require.True(t, got)
}

func TestPathPrefilterUsesReusableAttributes(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompilePrefilter(`matchesAny(attributes["path"], ["\\.go$"])`)
	require.NoError(t, err)

	skip, err := env.EvalPathPrefilter(prg, "internal/runtime.go")
	require.NoError(t, err)
	require.True(t, skip)

	skip, err = env.EvalPathPrefilter(prg, "README.md")
	require.NoError(t, err)
	require.False(t, skip)
}

func TestPathPrefilterKeepsGeneralExprSemantics(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	namespaced, err := env.CompilePrefilter(`filter.matchesAny(attributes["path"], ["\\.go$"])`)
	require.NoError(t, err)
	got, err := env.EvalPathPrefilter(namespaced, "runtime.go")
	require.NoError(t, err)
	require.True(t, got)

	compound, err := env.CompilePrefilter(`matchesAny(attributes["path"], ["\\.go$"]) || attributes["generated"] == "true"`)
	require.NoError(t, err)
	got, err = env.EvalPathPrefilter(compound, "README.md")
	require.NoError(t, err)
	require.False(t, got)

	dynamic, err := env.CompilePrefilter(`let patterns = ["\\.go$"]; matchesAny(attributes["path"], patterns)`)
	require.NoError(t, err)
	got, err = env.EvalPathPrefilter(dynamic, "runtime.go")
	require.NoError(t, err)
	require.True(t, got)
}

func TestFilterEntropy(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompileFilter(`entropy(finding["secret"]) <= 1.0`, nil)
	require.NoError(t, err)

	skip, err := env.EvalFilter(prg, map[string]any{
		"secret": "aaaaaaaa",
	}, nil)
	require.NoError(t, err)
	require.True(t, skip)
}

func TestFilterTracksFragmentRawUsage(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	plain, err := env.CompileFilter(`finding["secret"] == "value"`, nil)
	require.NoError(t, err)
	require.False(t, plain.NeedsFragmentRaw())

	withRaw, err := env.CompileFilter(`finding["fragment_raw"] contains finding["secret"]`, nil)
	require.NoError(t, err)
	require.True(t, withRaw.NeedsFragmentRaw())
}

func TestFilterTracksContextUsage(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	plain, err := env.CompileFilter(`finding["line"] == "value"`, nil)
	require.NoError(t, err)
	require.False(t, plain.NeedsContext())
	require.True(t, plain.NeedsFinding("line"))
	require.False(t, plain.NeedsFinding("secret"))

	withContext, err := env.CompileFilter(`finding["context"] contains finding["secret"]`, nil)
	require.NoError(t, err)
	require.True(t, withContext.NeedsContext())

	namedContext, err := env.CompileFilter(`let providerMatchContext = finding["line"]; providerMatchContext == "value"`, nil)
	require.NoError(t, err)
	require.False(t, namedContext.NeedsContext())

	commentContext, err := env.CompileFilter("// use nearby context\nfinding[\"line\"] == \"value\"", nil)
	require.NoError(t, err)
	require.False(t, commentContext.NeedsContext())

	dynamic, err := env.CompileFilter(`let key = "context"; finding[key] == "value"`, nil)
	require.NoError(t, err)
	require.True(t, dynamic.NeedsContext())
	require.True(t, dynamic.NeedsFragmentRaw())
	require.True(t, dynamic.NeedsFinding("secret"))
	require.True(t, dynamic.NeedsFinding("not_a_known_field"))

	alias, err := env.CompileFilter(`let candidate = finding; candidate["context"] == "value"`, nil)
	require.NoError(t, err)
	require.True(t, alias.NeedsContext())
	require.True(t, alias.NeedsFragmentRaw())
}

func TestFilterTracksBoundedMatchViews(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	localLine, err := env.CompileFilter(`finding["local_line"][finding["local_line_match_start_idx"]:] == "value"`, nil)
	require.NoError(t, err)
	require.True(t, localLine.NeedsLocalLine())
	require.False(t, localLine.NeedsLine())
	require.False(t, localLine.NeedsMatchWindow())
	require.False(t, localLine.NeedsFragmentRaw())

	window, err := env.CompileFilter(`finding["match_prefix"] + finding["match_suffix"] == "value"`, nil)
	require.NoError(t, err)
	require.True(t, window.NeedsMatchWindow())
	require.False(t, window.NeedsLocalLine())
	require.False(t, window.NeedsFragmentRaw())

	nearby, err := env.CompileFilter(`finding["nearby_context"] + finding["line_prefix"] == "value"`, nil)
	require.NoError(t, err)
	require.True(t, nearby.NeedsNearbyContext())
	require.False(t, nearby.NeedsMatchWindow())
	require.False(t, nearby.NeedsFragmentRaw())

	line, err := env.CompileFilter(`finding["line"] == "value"`, nil)
	require.NoError(t, err)
	require.True(t, line.NeedsLine())
	require.False(t, line.NeedsLocalLine())
}

func TestFilterSetConfidence(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompileFilter(`let _ = filter.setConfidence("high"); false`, nil)
	require.NoError(t, err)

	attributes := map[string]string{}
	_, err = env.EvalFilter(prg, nil, attributes)
	require.NoError(t, err)
	require.Equal(t, "high", attributes["confidence"])
}

func TestFilterEvalUsesPerCallBindings(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompileFilter(`finding["secret"] == attributes["expected"]`, nil)
	require.NoError(t, err)

	skip, err := env.EvalFilter(prg, map[string]any{"secret": "one"}, map[string]string{"expected": "one"})
	require.NoError(t, err)
	require.True(t, skip)

	skip, err = env.EvalFilter(prg, map[string]any{"secret": "two"}, map[string]string{"expected": "one"})
	require.NoError(t, err)
	require.False(t, skip)
}

func TestFilterConcurrentEvalUsesIsolatedBindings(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompileFilter(
		`let _ = filter.setConfidence(finding["confidence"]); filter.matchesAny(finding["secret"], ["^secret-"]) && finding["secret"] == attributes["expected"]`,
		nil,
	)
	require.NoError(t, err)

	for worker := 0; worker < 32; worker++ {
		worker := worker
		t.Run(fmt.Sprintf("worker-%d", worker), func(t *testing.T) {
			t.Parallel()
			for iteration := 0; iteration < 100; iteration++ {
				secret := fmt.Sprintf("secret-%d-%d", worker, iteration)
				confidence := "low"
				if worker%2 == 0 {
					confidence = "high"
				}
				attributes := map[string]string{"expected": secret}
				skip, err := env.EvalFilter(prg, map[string]any{
					"secret":     secret,
					"confidence": confidence,
				}, attributes)
				require.NoError(t, err)
				require.True(t, skip)
				require.Equal(t, confidence, attributes["confidence"])
			}
		})
	}
}

func TestFilterCacheIncludesTokenizer(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	tokA := &tiktoken.Tiktoken{}
	tokB := &tiktoken.Tiktoken{}
	expr := `finding["secret"] == "x"`

	prgA1, err := env.CompileFilter(expr, tokA)
	require.NoError(t, err)
	prgA2, err := env.CompileFilter(expr, tokA)
	require.NoError(t, err)
	prgB, err := env.CompileFilter(expr, tokB)
	require.NoError(t, err)

	require.Same(t, prgA1, prgA2)
	require.NotSame(t, prgA1, prgB)
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
