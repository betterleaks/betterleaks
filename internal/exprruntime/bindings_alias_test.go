package exprruntime

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBindingsRejectAliases(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, stage := range []struct {
		name    string
		compile func(string) (Program, error)
	}{
		{"prefilter", env.CompilePrefilter},
		{"filter", func(s string) (Program, error) { return env.CompileFilter(s, nil) }},
		{"validation", env.CompileValidation},
		{"analysis", env.CompileAnalysis},
	} {
		t.Run(stage.name, func(t *testing.T) {
			for _, expression := range []string{
				`env_get("X") == ""`,
				`filter.matchesAny("x", ["x"])`,
				`filter.findMatch("x", "x") == "x"`,
				`filter.containsAny("x", ["x"])`,
				`filter.startsWithAny("x", ["x"])`,
				`filter.entropy("x") == 0`,
				`filter.intersects(["x"], ["x"])`,
				`filter.failsTokenEfficiency("x")`,
				`filter.tokenRatio("x") == 0`,
				`filter.setConfidence("high") == "high"`,
				`fingerprint.sha256("x") == "x"`,
				`unknown({"status": 429}).result == "unknown"`,
				`obfuscate("x") == "x"`,
				`crypto.hmac_sha256(bytes("k"), bytes("x")) == nil`,
				`strings.url_query_escape("x") == "x"`, `time.now_unix() == ""`,
				`size([]) == 0`, `substring("abc", 1) == "bc"`,
				`json.string("x") == "x"`, `sha256("x") == "x"`,
				`get({}, "missing", "fallback") == "fallback"`,
			} {
				_, err := stage.compile(expression)
				require.Error(t, err, expression)
			}
		})
	}
}

func TestGeneralHelpersAcrossStages(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, mode := range []compileMode{modePrefilter, modeFilter, modeValidation, modeAnalysis} {
		for _, expression := range []string{
			`matchesAny("example", ["exam"])`,
			`containsAny("example", ["EXAM"])`,
			`startsWithAny("example", ["exam"])`,
			`entropy("aaaa") == 0`,
			`findMatch("example", "exam") == "exam"`,
			`intersects(["read", "write"], ["write"])`,
			`filter([1, 2, 3], { # > 1 }) == [2, 3]`,
			`filter(["read_api", "write_api"], { startsWithAny(#, ["read"]) }) == ["read_api"]`,
		} {
			t.Run(string(mode)+"/"+expression, func(t *testing.T) {
				program, err := env.compile(mode, expression, nil)
				require.NoError(t, err)
				var got any
				switch mode {
				case modePrefilter:
					got, err = env.EvalPrefilter(program, nil)
				case modeFilter:
					got, err = env.EvalFilter(program, nil, nil)
				case modeValidation:
					got, err = env.Eval(program, nil, nil)
				case modeAnalysis:
					result, evalErr := env.EvalAnalysisWithComponents(t.Context(), program, nil, nil, nil, nil, nil, EvalOptions{})
					got, err = result.Value, evalErr
				}
				require.NoError(t, err)
				require.Equal(t, true, got)
			})
		}
	}
}

func TestCryptoFingerprintProviderStages(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, mode := range []compileMode{modeValidation, modeAnalysis} {
		t.Run(string(mode), func(t *testing.T) {
			program, err := env.compile(mode, `crypto.sha256("abc")`, nil)
			require.NoError(t, err)
			var got any
			if mode == modeValidation {
				got, err = env.Eval(program, nil, nil)
			} else {
				result, evalErr := env.EvalAnalysisWithComponents(t.Context(), program, nil, nil, nil, nil, nil, EvalOptions{})
				got, err = result.Value, evalErr
			}
			require.NoError(t, err)
			require.Equal(t, "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", got)
		})
	}
}

func TestNativeExprHelpers(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, expression := range []string{
		`(get({}, "missing") ?? "fallback") == "fallback"`,
		`(get({"zero": 0}, "zero") ?? 42) == 0`,
		`(get({"empty": ""}, "empty") ?? "fallback") == ""`,
		`(get({"value": nil}, "value") ?? "fallback") == "fallback"`,
		`len([1, 2]) == 2 && len({"x": 1}) == 1`,
		`len("é") == 1 && len(bytes("é")) == 2`,
		`replace("aaa", "a", "b") == "bbb"`,
		`replace("aaa", "a", "b", 1) == "baa"`,
		`lastIndexOf("key-us1", "-") == 3`,
		`let s = "key-us1"; s[lastIndexOf(s, "-") + 1:] == "us1"`,
		`let s = "key"; s[lastIndexOf(s, "-") + 1:] == "key"`,
		`"abc"[max(0, -1):] == "abc" && "abc"[99:] == ""`,
		`toJSON("a\"b\n") == "\"a\\\"b\\n\""`,
		`hex.encode(crypto.hmacSha256(bytes("key"), bytes("hello"))) == "9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b"`,
	} {
		t.Run(expression, func(t *testing.T) {
			program, err := env.CompileValidation(expression)
			require.NoError(t, err)
			got, err := env.Eval(program, nil, nil)
			require.NoError(t, err)
			require.Equal(t, true, got)
		})
	}
}
