package exprruntime

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBindings(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, expression string
		want             any
		wantErr          string
	}{
		{"md5", `hex.encode(crypto.md5(bytes("hello")))`, "5d41402abc4b2a76b9719d911017c592", ""},
		{"md5 empty", `hex.encode(crypto.md5(bytes("")))`, "d41d8cd98f00b204e9800998ecf8427e", ""},
		{"md5 finding", `hex.encode(crypto.md5(bytes(finding.secret)))`, "cc03e747a6afbbcbf8be7668acfebee5", ""},
		{"sha1", `hex.encode(crypto.sha1(bytes("hello")))`, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", ""},
		{"hmac sha256", `hex.encode(crypto.hmacSha256(bytes("key"), bytes("hello")))`, "9307b3b915efb5171ff14d8cb55fbcc798c6c0ef1456d66ded1a6aa723a58b7b", ""},
		{"hmac sha1", `hex.encode(crypto.hmacSha1(bytes("key"), bytes("hello")))`, "b34ceac4516ff23a143e61d79d0fa7a4fbe5f266", ""},
		{"query escape", `strings.urlQueryEscape("a b+/:")`, "a+b%2B%2F%3A", ""},
		{"split empty", `strings.splitTrim("", ",")`, []string{}, ""},
		{"split comma", `strings.splitTrim(" repo, read:org, repo, ", ",")`, []string{"repo", "read:org", "repo"}, ""},
		{"split separator", `strings.splitTrim("read | write | ", "|")`, []string{"read", "write"}, ""},
		{"split invalid separator", `strings.splitTrim("read,write", "")`, nil, "separator must not be empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := env.CompileValidation(tc.expression)
			require.NoError(t, err)
			got, err := env.Eval(program, map[string]string{"secret": "test123"}, nil)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
	for _, expression := range []string{`time.nowUnix()`, `time.nowRFC3339()`} {
		t.Run(expression, func(t *testing.T) {
			program, err := env.CompileValidation(expression)
			require.NoError(t, err)
			value, err := env.Eval(program, nil, nil)
			require.NoError(t, err)
			got, ok := value.(string)
			require.True(t, ok)
			if expression == `time.nowUnix()` {
				_, err = strconv.ParseInt(got, 10, 64)
				require.GreaterOrEqual(t, len(got), 10)
			} else {
				_, err = time.Parse(time.RFC3339, got)
			}
			require.NoError(t, err)
		})
	}
}

func TestProviderBindingsExcludeOccurrence(t *testing.T) {
	env, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, expression := range []string{`attributes["path"]`, `finding.line`, `finding.context`, `finding.match`, `finding.confidence`, `finding.description`} {
		for _, compile := range []func(string) (Program, error){env.CompileValidation, env.CompileAnalysis} {
			if _, err := compile(expression); err == nil {
				t.Errorf("accepted occurrence input %s", expression)
			}
		}
	}
}

func TestEvalValidationDebugMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Figma-Token") != "figma-secret" {
			t.Fatalf("x-figma-token header = %q", r.Header.Get("X-Figma-Token"))
		}
		w.Header().Set("X-Debug", "present")
		w.Header().Set("DD-API-KEY", "datadog-secret")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	env, err := New(srv.Client())
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}
	prg, err := env.CompileValidation(`http.post("` + srv.URL + `", {"Authorization": "Bearer secret", "X-Figma-Token": "figma-secret"}, "payload").status`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	withoutDebug, err := env.EvalValidation(nil, prg, nil, nil, nil, EvalOptions{})
	if err != nil {
		t.Fatalf("eval without debug: %v", err)
	}
	if withoutDebug.Value != int64(http.StatusCreated) {
		t.Fatalf("value without debug = %v, want %d", withoutDebug.Value, http.StatusCreated)
	}
	if len(withoutDebug.Debug) != 0 {
		t.Fatalf("debug without debug option = %#v, want empty", withoutDebug.Debug)
	}

	withDebug, err := env.EvalValidation(nil, prg, nil, nil, nil, EvalOptions{Debug: true})
	if err != nil {
		t.Fatalf("eval with debug: %v", err)
	}
	if withDebug.Value != int64(http.StatusCreated) {
		t.Fatalf("value with debug = %v, want %d", withDebug.Value, http.StatusCreated)
	}
	if withDebug.Debug["req_method"] != http.MethodPost {
		t.Fatalf("req_method = %v", withDebug.Debug["req_method"])
	}
	if withDebug.Debug["req_url"] != srv.URL {
		t.Fatalf("req_url = %v, want %s", withDebug.Debug["req_url"], srv.URL)
	}
	if withDebug.Debug["req_body"] != "payload" {
		t.Fatalf("req_body = %v", withDebug.Debug["req_body"])
	}
	if withDebug.Debug["req_header_authorization"] != "[redacted]" {
		t.Fatalf("authorization debug header = %v", withDebug.Debug["req_header_authorization"])
	}
	if withDebug.Debug["req_header_x-figma-token"] != "[redacted]" {
		t.Fatalf("x-figma-token debug header = %v", withDebug.Debug["req_header_x-figma-token"])
	}
	if withDebug.Debug["resp_status"] != int64(http.StatusCreated) {
		t.Fatalf("resp_status = %v", withDebug.Debug["resp_status"])
	}
	if withDebug.Debug["resp_header_x-debug"] != "present" {
		t.Fatalf("resp_header_x-debug = %v", withDebug.Debug["resp_header_x-debug"])
	}
	if withDebug.Debug["resp_header_dd-api-key"] != "[redacted]" {
		t.Fatalf("resp_header_dd-api-key = %v", withDebug.Debug["resp_header_dd-api-key"])
	}
	body, ok := withDebug.Debug["resp_body"].(string)
	if !ok || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("resp_body = %#v", withDebug.Debug["resp_body"])
	}
}

func TestOptionalComponentAccess(t *testing.T) {
	runtime, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	program, err := runtime.CompileValidation(`components["tenant-id"]?.secret ?? "missing"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	got, err := runtime.EvalWithComponents(program, nil, nil, map[string]any{
		"tenant-id": map[string]any{"secret": "tenant-secret"},
	})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if got != "tenant-secret" {
		t.Fatalf("component secret = %#v, want tenant-secret", got)
	}

	got, err = runtime.EvalWithComponents(program, nil, nil, map[string]any{})
	if err != nil {
		t.Fatalf("eval missing component: %v", err)
	}
	if got != "missing" {
		t.Fatalf("missing component secret = %#v, want missing", got)
	}
}

func TestGeneralHelpersAcrossStages(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	for _, mode := range []compileMode{modePrefilter, modeFilter, modeValidation, modeAnalysis} {
		expressions := []string{
			`matchesAny("example", ["exam"])`,
			`containsAny("example", ["EXAM"])`,
			`startsWithAny("example", ["exam"])`,
			`filter([1, 2, 3], { # > 1 }) == [2, 3]`,
			`filter(["read_api", "write_api"], { startsWithAny(#, ["read"]) }) == ["read_api"]`,
		}
		if mode != modePrefilter {
			expressions = append(expressions,
				`entropy("aaaa") == 0`,
				`findMatch("example", "exam") == "exam"`,
				`intersects(["read", "write"], ["write"])`,
			)
		}
		for _, expression := range expressions {
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
			require.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", got)
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
