package exprruntime

import (
	"regexp"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/tokenizer"
	"github.com/stretchr/testify/require"
)

func TestProjectFunctionNamesFollowConvention(t *testing.T) {
	validName := regexp.MustCompile(`^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)?$`)
	runtime := &Runtime{}
	analysisBindings, _ := runtime.compileBindings(modeAnalysis, nil)

	for _, env := range []struct {
		name    string
		fns     map[string]struct{}
		current []string
	}{
		{
			name: "validation",
			fns:  functionNames(runtime.validationBindings(nil, nil, nil, nil, nil, nil)),
			current: []string{
				"http.get", "http.post", "env.get", "env.getOrDefault", "strings.obfuscate",
				"strings.splitTrim", "strings.urlQueryEscape", "validate.unknown",
				"crypto.md5", "crypto.sha1", "crypto.sha256", "crypto.hmacSha1",
				"crypto.hmacSha256", "hex.encode", "time.nowUnix",
				"time.nowRFC3339", "aws.validate", "gcp.validate",
				"base64.encode", "base64.decode", "matchesAny",
				"containsAny", "startsWithAny", "intersects",
			},
		},
		{
			name: "analysis",
			fns:  functionNames(analysisBindings),
			current: []string{
				"analysis.capabilities", "strings.splitTrim",
				"matchesAny", "containsAny", "startsWithAny", "intersects",
			},
		},
		{
			name: "filter",
			fns:  functionNames(filterBindings(nil, emptyFilterFinding, emptyStringMap)),
			current: []string{
				"crypto.sha256",
				"matchesAny", "findMatch", "containsAny", "startsWithAny", "entropy",
				"intersects", "failsTokenEfficiency", "tokenRatio", "setConfidence",
			},
		},
		{
			name: "prefilter",
			fns:  functionNames(prefilterBindings(emptyStringMap)),
			current: []string{
				"matchesAny", "findMatch", "containsAny", "startsWithAny", "entropy",
				"intersects", "failsTokenEfficiency", "tokenRatio",
			},
		},
	} {
		for _, name := range env.current {
			require.Contains(t, env.fns, name, "%s missing function %q", env.name, name)
			require.Truef(t, validName.MatchString(name), "%s function %q does not follow convention", env.name, name)
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
	_, err = env.CompileFilter(`finding.captures.username == "example"`, nil)
	require.NoError(t, err)
	for _, expression := range []string{
		`components["part"].secret == "fixture"`,
		`validation.status == "valid"`,
		`captures["username"] == "example"`,
	} {
		_, err = env.CompileFilter(expression, nil)
		require.Error(t, err, "filter must not expose provider-stage bindings: %s", expression)
	}

	_, err = env.CompilePrefilter(`finding["secret"] == ""`)
	require.Error(t, err)
	_, err = env.CompilePrefilter(`finding.captures.username == "example"`)
	require.Error(t, err)
	_, err = env.CompilePrefilter(`matchesAny(attributes["path"], [".go"])`)
	require.NoError(t, err)
}

func TestCELBindIsRejected(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	_, err = env.CompileValidation(`cel.bind(secret, finding["secret"], secret)`)
	require.Error(t, err)
}

func TestCredentialBindingsRejectLegacyAliases(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, stage := range []struct {
		name    string
		compile func(string) (Program, error)
	}{
		{"validation", env.CompileValidation},
		{"analysis", env.CompileAnalysis},
	} {
		t.Run(stage.name, func(t *testing.T) {
			for _, expression := range []string{
				`secret`,
				`captures["username"]`,
				`captures["account-id"]`,
				`captures["account-id:region"]`,
				`captures?.username ?? ""`,
			} {
				_, err := stage.compile(expression)
				require.ErrorContains(t, err, "unknown name", expression)
			}
			for _, expression := range []string{
				`finding.secret`,
				`finding["secret"]`,
				`finding.captures["username"]`,
				`components["account-id"].secret`,
				`components["account-id"]?.captures?.region ?? ""`,
				// Local variables are valid Expr, not injected legacy bindings.
				`let secret = finding.secret; secret`,
			} {
				_, err := stage.compile(expression)
				require.NoError(t, err, expression)
			}
		})
	}
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

func TestFilterEntropy(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, expression := range []string{
		`entropy(finding["secret"]) <= 1.0`,
		`entropy(finding["secret"]) <= 1.0`,
	} {
		prg, err := env.CompileFilter(expression, nil)
		require.NoError(t, err)

		skip, err := env.EvalFilter(prg, map[string]any{
			"secret": "aaaaaaaa",
		}, nil)
		require.NoError(t, err)
		require.True(t, skip)
	}
}

func TestFilterSHA256(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompileFilter("crypto.sha256(finding[\"secret\"]) in [\"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"]", nil)
	require.NoError(t, err)

	for secret, want := range map[string]bool{"abc": true, "ABC": false, "abc\n": false, "abc ": false} {
		skip, err := env.EvalFilter(prg, map[string]any{"secret": secret}, nil)
		require.NoError(t, err)
		require.Equal(t, want, skip)
	}
}

func TestFilterSetConfidence(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	prg, err := env.CompileFilter(`let _ = setConfidence("high"); false`, nil)
	require.NoError(t, err)

	attributes := map[string]string{}
	_, err = env.EvalFilter(prg, nil, attributes)
	require.NoError(t, err)
	require.Equal(t, "high", attributes["confidence"])

	_, err = env.CompilePrefilter(`setConfidence("high") == "high"`)
	require.Error(t, err)
	_, err = env.CompileValidation(`setConfidence("high")`)
	require.Error(t, err)
	_, err = env.CompileAnalysis(`setConfidence("high")`)
	require.Error(t, err)

	prg, err = env.CompileFilter(`let _ = setConfidence(finding.confidence); false`, nil)
	require.NoError(t, err)
	for _, level := range []string{"low", "medium", "high"} {
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			for range 100 {
				attrs := map[string]string{}
				skip, err := env.EvalFilter(prg, map[string]any{"confidence": level}, attrs)
				require.NoError(t, err)
				require.False(t, skip)
				require.Equal(t, level, attrs["confidence"])
			}
		})
	}
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

func TestFilterCacheIncludesTokenCounter(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)

	tokA := &tokenizer.Counter{}
	tokB := &tokenizer.Counter{}
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
