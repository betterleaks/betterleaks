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

type compileMode string

const (
	modeFilter     compileMode = "filter"
	modePrefilter  compileMode = "prefilter"
	modeValidation compileMode = "validation"
)

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

// Env holds compiled Expr programs and validation services.
type Env struct {
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

func (e *Env) SetHTTPClient(c *http.Client) { e.client = c }

func New(httpClient *http.Client) (*Env, error) {
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}
	return &Env{
		client: httpClient,
		cache:  make(map[string]Program),
	}, nil
}

func (e *Env) CompileFilter(expression string, tokenizer *tiktoken.Tiktoken) (Program, error) {
	return e.compile(modeFilter, expression, tokenizer)
}

func (e *Env) CompilePrefilter(expression string) (Program, error) {
	return e.compile(modePrefilter, expression, nil)
}

func (e *Env) CompileValidation(expression string) (Program, error) {
	return e.compile(modeValidation, expression, nil)
}

func (e *Env) compile(mode compileMode, expression string, tokenizer *tiktoken.Tiktoken) (Program, error) {
	exprText := expression
	if NeedsCELCompat(expression) {
		var err error
		exprText, err = RewriteCELCompat(expression)
		if err != nil {
			return nil, err
		}
	}

	// One Env compiles all expression types. The mode is part of the cache key
	// because filter, prefilter, and validation expose different bindings.
	cacheKey := string(mode) + "\x00" + exprText
	e.mu.RLock()
	if prg, ok := e.cache[cacheKey]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	env, options := e.compileEnv(mode, tokenizer)
	vmPrg, err := expr.Compile(exprText, append([]expr.Option{expr.Env(env)}, options...)...)
	if err != nil {
		if exprText != expression {
			return nil, fmt.Errorf("%s expr compile error: %w\noriginal expression:\n%s\ncompat expression:\n%s", mode, err, expression, exprText)
		}
		return nil, fmt.Errorf("%s expr compile error: %w", mode, err)
	}
	prg := &compiledProgram{vm: vmPrg, tokenizer: tokenizer}

	e.mu.Lock()
	e.cache[cacheKey] = prg
	e.mu.Unlock()
	return prg, nil
}

func (e *Env) compileEnv(mode compileMode, tokenizer *tiktoken.Tiktoken) (evalEnv, []expr.Option) {
	switch mode {
	case modeFilter:
		return filterEvalEnv(tokenizer, emptyStringMap, emptyStringMap), []expr.Option{expr.AsBool()}
	case modePrefilter:
		return prefilterEvalEnv(emptyStringMap), []expr.Option{expr.AsBool()}
	default:
		env := e.validationEnv(context.Background(), nil, nil, nil)
		setCompileMaps(env)
		return env, []expr.Option{expr.WithContext("ctx")}
	}
}

// Runtime envs intentionally mirror the compile envs. That keeps Expr's static
// checks honest: prefilters cannot see findings, filters cannot call validators.
func (e *Env) EvalFilter(prg Program, finding, attributes map[string]string) (bool, error) {
	env := filterEvalEnv(prg.tokenizer, nonNilStringMap(finding), nonNilStringMap(attributes))
	return runBool(prg, env, "filter")
}

func (e *Env) EvalPrefilter(prg Program, attributes map[string]string) (bool, error) {
	return runBool(prg, prefilterEvalEnv(nonNilStringMap(attributes)), "prefilter")
}

func runBool(prg Program, env evalEnv, name string) (bool, error) {
	val, err := expr.Run(prg.vm, env)
	if err != nil {
		return false, err
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("%s returned non-bool: %T", name, val)
	}
	return b, nil
}

func (e *Env) Eval(prg Program, finding, captures map[string]string) (any, error) {
	return e.EvalWithContext(context.Background(), prg, finding, captures, nil)
}

func (e *Env) EvalWithAttributes(prg Program, finding, captures, attributes map[string]string) (any, error) {
	return e.EvalWithContext(context.Background(), prg, finding, captures, attributes)
}

func (e *Env) EvalWithContext(ctx context.Context, prg Program, finding, captures, attributes map[string]string) (any, error) {
	if e.DebugResponse {
		e.debugMu.Lock()
		defer e.debugMu.Unlock()
		e.debugMeta = make(map[string]any)
	}
	env := e.validationEnv(ctx, finding, captures, attributes)
	return expr.Run(prg.vm, env)
}

func (e *Env) DebugMeta() map[string]any { return e.debugMeta }

func (e *Env) validationEnv(ctx context.Context, finding, captures, attributes map[string]string) evalEnv {
	if finding == nil {
		finding = emptyStringMap
	}
	if captures == nil {
		captures = emptyStringMap
	}
	if attributes == nil {
		attributes = emptyStringMap
	}
	rt := &runtimeBindings{
		validation: e,
		ctx:        ctx,
		tokenizer:  nil,
		finding:    finding,
		attrs:      attributes,
		captures:   captures,
	}
	env := baseEnv(rt)
	env["ctx"] = rt.ctx
	env["finding"] = rt.finding
	env["captures"] = rt.captures
	env["secret"] = lookupString(rt.finding, "secret")
	env["bytes"] = func(s string) []byte { return []byte(s) }
	env["size"] = size
	env["substring"] = substring
	env["lastIndexOf"] = strings.LastIndex
	env["replace"] = strings.ReplaceAll
	env["http"] = httpNamespace(rt)
	env["env"] = envNamespace(rt)
	env["env_get"] = rt.envGet
	env["strings"] = stringsNamespace()
	env["validate"] = validateNamespace()
	env["json"] = jsonNamespace()
	env["crypto"] = cryptoNamespace()
	env["hex"] = hexNamespace()
	env["base64"] = base64Namespace()
	env["time"] = timeNamespace()
	env["aws"] = awsNamespace(rt)
	env["gcp"] = gcpNamespace(rt)
	env["unknown"] = unknownResult
	env["obfuscate"] = func(s string) (string, error) { return obfuscate(s), nil }
	return env
}

type runtimeBindings struct {
	validation *Env
	ctx        context.Context
	tokenizer  *tiktoken.Tiktoken
	finding    any
	attrs      any
	captures   any
}

func baseEnv(rt *runtimeBindings) evalEnv {
	if rt.ctx == nil {
		rt.ctx = context.Background()
	}
	if rt.attrs == nil {
		rt.attrs = map[string]any{}
	}

	return evalEnv{
		"attributes":           rt.attrs,
		"get":                  getDefault,
		"getPath":              getPathDefault,
		"filter":               filterNamespace(rt),
		"matchesAny":           matchesAny,
		"containsAny":          containsAny,
		"entropy":              shannonEntropy,
		"failsTokenEfficiency": rt.failsTokenEfficiency,
	}
}

func setCompileMaps(env evalEnv) {
	env["finding"] = map[string]any{}
	env["attributes"] = map[string]any{}
	env["captures"] = map[string]any{}
	env["secret"] = ""
}

func nonNilStringMap(m map[string]string) map[string]string {
	if m == nil {
		return emptyStringMap
	}
	return m
}

func filterEvalEnv(tokenizer *tiktoken.Tiktoken, finding, attributes map[string]string) evalEnv {
	env := baseEnv(&runtimeBindings{tokenizer: tokenizer, attrs: attributes})
	env["finding"] = finding
	return env
}

func prefilterEvalEnv(attributes map[string]string) evalEnv {
	return baseEnv(&runtimeBindings{attrs: attributes})
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

func lookupString(container any, key string) string {
	if v, ok := lookup(container, key); ok {
		s, ok := v.(string)
		if ok {
			return s
		}
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
	for part := range strings.SplitSeq(path, ".") {
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
