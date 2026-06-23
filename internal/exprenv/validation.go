package exprenv

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	tiktoken "github.com/pkoukk/tiktoken-go"
)

// Program is the compiled expression representation used by validation,
// filters, and prefilters.
type Program = *compiledProgram

type compiledProgram struct {
	vm        *vm.Program
	tokenizer *tiktoken.Tiktoken
}

var (
	mapStringStringType = reflect.TypeFor[map[string]string]()
	mapAnyType          = reflect.TypeFor[map[string]any]()
)

var emptyStringMap = map[string]string{}

// maxResponseBody is the maximum number of bytes read from an HTTP response body.
const maxResponseBody = 1 << 20 // 1 MB

// ValidationEnvironment holds compiled Expr programs and validation services.
type ValidationEnvironment struct {
	client *http.Client

	mu    sync.RWMutex
	cache map[string]Program

	DebugResponse bool
	debugMu       sync.Mutex
	debugMeta     map[string]any

	STSEndpoint      string
	GCPTokenEndpoint string
	AllowedEnv       map[string]struct{}
}

type evalEnv = map[string]any

// DefaultHTTPClient returns an HTTP client with reasonable timeouts.
func DefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

func (e *ValidationEnvironment) SetHTTPClient(c *http.Client) { e.client = c }

func NewValidationEnv(httpClient *http.Client) (*ValidationEnvironment, error) {
	return NewEnvironment(httpClient)
}

func NewEnvironment(httpClient *http.Client) (*ValidationEnvironment, error) {
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}
	return &ValidationEnvironment{
		client: httpClient,
		cache:  make(map[string]Program),
	}, nil
}

func (e *ValidationEnvironment) Compile(expression string) (Program, error) {
	rewritten, err := RewriteCELCompat(expression)
	if err != nil {
		return nil, err
	}

	e.mu.RLock()
	if prg, ok := e.cache[rewritten]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	env := e.validationEnv(context.Background(), nil, nil, nil)
	vmPrg, err := expr.Compile(rewritten, expr.Env(env), expr.WithContext("ctx"))
	if err != nil {
		if rewritten != expression {
			return nil, fmt.Errorf("expr compile error: %w\noriginal expression:\n%s\nrewritten expression:\n%s", err, expression, rewritten)
		}
		return nil, fmt.Errorf("expr compile error: %w", err)
	}
	prg := &compiledProgram{vm: vmPrg}

	e.mu.Lock()
	e.cache[rewritten] = prg
	e.mu.Unlock()
	return prg, nil
}

func (e *ValidationEnvironment) Eval(prg Program, finding, captures map[string]string) (any, error) {
	return e.EvalWithContext(context.Background(), prg, finding, captures, nil)
}

func (e *ValidationEnvironment) EvalWithAttributes(prg Program, finding, captures, attributes map[string]string) (any, error) {
	return e.EvalWithContext(context.Background(), prg, finding, captures, attributes)
}

func (e *ValidationEnvironment) EvalWithContext(ctx context.Context, prg Program, finding, captures, attributes map[string]string) (any, error) {
	if e.DebugResponse {
		e.debugMu.Lock()
		defer e.debugMu.Unlock()
		e.debugMeta = make(map[string]any)
	}
	env := e.validationEnv(ctx, finding, captures, attributes)
	return expr.Run(prg.vm, env)
}

func (e *ValidationEnvironment) DebugMeta() map[string]any { return e.debugMeta }

func (e *ValidationEnvironment) validationEnv(ctx context.Context, finding, captures, attributes map[string]string) evalEnv {
	if finding == nil {
		finding = emptyStringMap
	}
	if captures == nil {
		captures = emptyStringMap
	}
	if attributes == nil {
		attributes = emptyStringMap
	}
	findingAny := stringMapToAny(finding)
	attrsAny := stringMapToAny(attributes)
	return baseEnv(&runtimeBindings{
		validation: e,
		ctx:        ctx,
		tokenizer:  nil,
		finding:    findingAny,
		attrs:      attrsAny,
		captures:   stringMapToAny(captures),
	})
}

type runtimeBindings struct {
	validation *ValidationEnvironment
	ctx        context.Context
	tokenizer  *tiktoken.Tiktoken
	finding    map[string]any
	attrs      map[string]any
	captures   map[string]any
}

func baseEnv(rt *runtimeBindings) evalEnv {
	if rt.ctx == nil {
		rt.ctx = context.Background()
	}
	if rt.finding == nil {
		rt.finding = map[string]any{}
	}
	if rt.attrs == nil {
		rt.attrs = map[string]any{}
	}
	if rt.captures == nil {
		rt.captures = map[string]any{}
	}

	env := evalEnv{
		"ctx":         rt.ctx,
		"finding":     rt.finding,
		"attributes":  rt.attrs,
		"captures":    rt.captures,
		"secret":      stringValue(rt.finding["secret"]),
		"bytes":       func(s string) []byte { return []byte(s) },
		"size":        size,
		"get":         getDefault,
		"getPath":     getPathDefault,
		"substring":   substring,
		"lastIndexOf": strings.LastIndex,
		"replace":     strings.ReplaceAll,
		"http": map[string]any{
			"get":  rt.httpGet,
			"post": rt.httpPost,
		},
		"env": map[string]any{
			"get":          rt.envGet,
			"getOrDefault": rt.envGetOrDefault,
		},
		"strings": map[string]any{
			"obfuscate":        func(s string) (string, error) { return obfuscate(s), nil },
			"urlQueryEscape":   urlQueryEscape,
			"url_query_escape": urlQueryEscape,
		},
		"validate": map[string]any{
			"unknown": unknownResult,
		},
		"json": map[string]any{
			"string": jsonString,
		},
		"crypto": map[string]any{
			"md5":         md5Bytes,
			"sha1":        sha1Bytes,
			"hmacSha1":    hmacSha1Bytes,
			"hmacSha256":  hmacSha256Bytes,
			"hmac_sha256": hmacSha256Bytes,
		},
		"hex": map[string]any{
			"encode": hexEncode,
		},
		"base64": map[string]any{
			"encode": base64Encode,
			"decode": base64Decode,
		},
		"time": map[string]any{
			"nowUnix":    timeNowUnix,
			"now_unix":   timeNowUnix,
			"nowRFC3339": timeNowRFC3339,
		},
		"aws": map[string]any{
			"validate": rt.awsValidate,
		},
		"gcp": map[string]any{
			"validate": rt.gcpValidate,
		},
		"filter": map[string]any{
			"matchesAny":           matchesAny,
			"containsAny":          containsAny,
			"entropy":              celShannonEntropy,
			"failsTokenEfficiency": rt.failsTokenEfficiency,
		},
		"matchesAny":           matchesAny,
		"containsAny":          containsAny,
		"entropy":              celShannonEntropy,
		"failsTokenEfficiency": rt.failsTokenEfficiency,
		"unknown":              unknownResult,
		"obfuscate":            func(s string) (string, error) { return obfuscate(s), nil },
	}
	env["env"] = map[string]any{
		"get":          rt.envGet,
		"getOrDefault": rt.envGetOrDefault,
	}
	env["env_get"] = rt.envGet
	return env
}

func size(v any) int {
	switch x := v.(type) {
	case string:
		return len(x)
	case []any:
		return len(x)
	case []string:
		return len(x)
	case []byte:
		return len(x)
	case map[string]any:
		return len(x)
	case map[string]string:
		return len(x)
	default:
		return 0
	}
}

func substring(s string, start int) string {
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return ""
	}
	return s[start:]
}

func stringMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func getDefault(container any, key string, fallback any) any {
	if v, ok := lookup(container, key); ok && v != nil {
		return v
	}
	return fallback
}

func getPathDefault(container any, path string, fallback any) any {
	cur := container
	for _, part := range strings.Split(path, ".") {
		next, ok := lookup(cur, part)
		if !ok || next == nil {
			return fallback
		}
		cur = next
	}
	return cur
}

func lookup(container any, key string) (any, bool) {
	switch m := container.(type) {
	case map[string]any:
		v, ok := m[key]
		return v, ok
	case map[string]string:
		v, ok := m[key]
		return v, ok
	case []any:
		i, err := strconv.Atoi(key)
		if err != nil || i < 0 || i >= len(m) {
			return nil, false
		}
		return m[i], true
	default:
		rv := reflect.ValueOf(container)
		if rv.Kind() == reflect.Map && rv.Type().Key().Kind() == reflect.String {
			v := rv.MapIndex(reflect.ValueOf(key))
			if v.IsValid() {
				return v.Interface(), true
			}
		}
	}
	return nil, false
}

func (rt *runtimeBindings) envGet(name string) (string, error) {
	e := rt.validation
	if e == nil {
		return "", fmt.Errorf("env: validation environment unavailable")
	}
	if len(e.AllowedEnv) == 0 {
		return "", fmt.Errorf("env: no validation env allowlist configured (use --validation-env-vars)")
	}
	if _, ok := e.AllowedEnv[name]; !ok {
		return "", fmt.Errorf("env: %q not in validation env allowlist", name)
	}
	return os.Getenv(name), nil
}

func (rt *runtimeBindings) envGetOrDefault(name, fallback string) string {
	e := rt.validation
	if e == nil || len(e.AllowedEnv) == 0 {
		return fallback
	}
	if _, ok := e.AllowedEnv[name]; !ok {
		return fallback
	}
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}
