package exprruntime

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
	vm                *vm.Program
	mode              compileMode
	tokenizer         *tiktoken.Tiktoken
	tokenizerProvider func() *tiktoken.Tiktoken
	bindings          bindings
}

var emptyStringMap = map[string]string{}

type EvalOptions struct {
	Debug bool
}

type EvalResult struct {
	Value any
	Debug map[string]any
}

type evalState struct {
	debug bool
	meta  map[string]any
}

func (s *evalState) addDebug(name string, value any) {
	if s == nil || !s.debug {
		return
	}
	if s.meta == nil {
		s.meta = make(map[string]any)
	}
	s.meta[name] = value
}

// maxResponseBody is the maximum number of bytes read from an HTTP response body.
const maxResponseBody = 1 << 20 // 1 MB

// Runtime holds compiled Expr programs and validation services (if needed).
type Runtime struct {
	client *http.Client

	mu    sync.RWMutex
	cache map[string]Program

	// These endpoints are used for tests, not for real scans.
	STSEndpoint             string
	GCPTokenEndpoint        string
	AzureTokenEndpoint      string
	AzureStorageEndpoint    string
	AzureAppConfigEndpoint  string
	AzureServiceBusEndpoint string
	AllowedEnv              map[string]struct{}

	tokenizerProvider func() *tiktoken.Tiktoken
}

type bindings = map[string]any

// DefaultHTTPClient returns an HTTP client with reasonable timeouts.
func DefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

func (e *Runtime) SetHTTPClient(c *http.Client) { e.client = c }

func (e *Runtime) SetTokenizerProvider(provider func() *tiktoken.Tiktoken) {
	e.tokenizerProvider = provider
}

func New(httpClient *http.Client) (*Runtime, error) {
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}
	return &Runtime{
		client: httpClient,
		cache:  make(map[string]Program),
	}, nil
}

func (e *Runtime) CompileFilter(expression string, tokenizer *tiktoken.Tiktoken) (Program, error) {
	return e.compile(modeFilter, expression, tokenizer)
}

func (e *Runtime) CompilePrefilter(expression string) (Program, error) {
	return e.compile(modePrefilter, expression, nil)
}

func (e *Runtime) CompileValidation(expression string) (Program, error) {
	return e.compile(modeValidation, expression, nil)
}

func (e *Runtime) compile(mode compileMode, expression string, tokenizer *tiktoken.Tiktoken) (Program, error) {
	exprText := expression
	if NeedsCELCompat(expression) {
		var err error
		exprText, err = RewriteCELCompat(expression)
		if err != nil {
			return nil, err
		}
	}

	// One Runtime compiles all expression types. The mode is part of the cache key
	// because filter, prefilter, and validation expose different bindings.
	cacheKey := compileCacheKey(mode, exprText, tokenizer)
	e.mu.RLock()
	if prg, ok := e.cache[cacheKey]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	b, options := e.compileBindings(mode, tokenizer)
	vmPrg, err := expr.Compile(exprText, append([]expr.Option{expr.Env(b)}, options...)...)
	if err != nil {
		if exprText != expression {
			return nil, fmt.Errorf("%s expr compile error: %w\noriginal expression:\n%s\ncompat expression:\n%s", mode, err, expression, exprText)
		}
		return nil, fmt.Errorf("%s expr compile error: %w", mode, err)
	}
	prg := &compiledProgram{
		vm:                vmPrg,
		mode:              mode,
		tokenizer:         tokenizer,
		tokenizerProvider: e.tokenizerProvider,
		bindings:          programBindings(mode, b),
	}

	e.mu.Lock()
	e.cache[cacheKey] = prg
	e.mu.Unlock()
	return prg, nil
}

func compileCacheKey(mode compileMode, exprText string, tokenizer *tiktoken.Tiktoken) string {
	key := string(mode) + "\x00" + exprText
	if mode == modeFilter {
		key += fmt.Sprintf("\x00%p", tokenizer)
	}
	return key
}

func programBindings(mode compileMode, b bindings) bindings {
	switch mode {
	case modeFilter, modePrefilter:
		return cloneBindings(b)
	default:
		return nil
	}
}

func (e *Runtime) compileBindings(mode compileMode, tokenizer *tiktoken.Tiktoken) (bindings, []expr.Option) {
	switch mode {
	case modeFilter:
		return filterBindings(tokenizer, emptyStringMap, emptyStringMap), []expr.Option{expr.AsBool()}
	case modePrefilter:
		return prefilterBindings(emptyStringMap), []expr.Option{expr.AsBool()}
	default:
		b := e.validationBindings(context.Background(), nil, nil, nil, nil)
		setCompileMaps(b)
		return b, []expr.Option{expr.WithContext("ctx")}
	}
}

// Compile and runtime bindings expose the same names. Dynamic values are layered
// onto a shallow copy so compiled programs can share static function bindings.
func (e *Runtime) EvalFilter(prg Program, finding, attributes map[string]string) (bool, error) {
	b := prg.evalBindings()
	b["finding"] = nonNilStringMap(finding)
	b["attributes"] = nonNilStringMap(attributes)
	return runBool(prg, b, "filter")
}

func (e *Runtime) EvalPrefilter(prg Program, attributes map[string]string) (bool, error) {
	b := prg.evalBindings()
	b["attributes"] = nonNilStringMap(attributes)
	return runBool(prg, b, "prefilter")
}

func (prg Program) evalBindings() bindings {
	if prg.bindings != nil {
		b := cloneBindings(prg.bindings)
		if rt, ok := b["__runtime"].(*runtimeBindings); ok {
			rt.tokenizer = prg.tokenizer
			rt.tokenizerProvider = prg.tokenizerProvider
		}
		return b
	}
	return bindings{}
}

func cloneBindings(src bindings) bindings {
	dst := make(bindings, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func runBool(prg Program, b bindings, name string) (bool, error) {
	val, err := expr.Run(prg.vm, b)
	if err != nil {
		return false, err
	}
	result, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("%s returned non-bool: %T", name, val)
	}
	return result, nil
}

func (e *Runtime) Eval(prg Program, finding, captures map[string]string) (any, error) {
	return e.EvalWithContext(context.Background(), prg, finding, captures, nil)
}

func (e *Runtime) EvalWithAttributes(prg Program, finding, captures, attributes map[string]string) (any, error) {
	return e.EvalWithContext(context.Background(), prg, finding, captures, attributes)
}

func (e *Runtime) EvalWithContext(ctx context.Context, prg Program, finding, captures, attributes map[string]string) (any, error) {
	result, err := e.EvalValidation(ctx, prg, finding, captures, attributes, EvalOptions{})
	return result.Value, err
}

func (e *Runtime) EvalValidation(ctx context.Context, prg Program, finding, captures, attributes map[string]string, opts EvalOptions) (EvalResult, error) {
	state := &evalState{debug: opts.Debug}
	b := e.validationBindings(ctx, finding, captures, attributes, state)
	val, err := expr.Run(prg.vm, b)
	return EvalResult{Value: val, Debug: state.meta}, err
}

func (e *Runtime) validationBindings(ctx context.Context, finding, captures, attributes map[string]string, state *evalState) bindings {
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
		debug:      state,
	}
	b := baseBindings(rt)
	b["ctx"] = rt.ctx
	b["finding"] = rt.finding
	b["captures"] = rt.captures
	b["secret"] = lookupString(rt.finding, "secret")
	b["bytes"] = func(s string) []byte { return []byte(s) }
	b["size"] = size
	b["substring"] = substring
	b["lastIndexOf"] = strings.LastIndex
	b["replace"] = strings.ReplaceAll
	b["http"] = httpNamespace(rt)
	b["env"] = envNamespace(rt)
	b["env_get"] = rt.envGet
	b["strings"] = stringsNamespace()
	b["validate"] = validateNamespace()
	b["json"] = jsonNamespace()
	b["crypto"] = cryptoNamespace()
	b["hex"] = hexNamespace()
	b["base64"] = base64Namespace()
	b["time"] = timeNamespace()
	b["aws"] = awsNamespace(rt)
	b["gcp"] = gcpNamespace(rt)
	b["azure"] = azureNamespace(rt)
	b["unknown"] = unknownResult
	b["obfuscate"] = func(s string) (string, error) { return obfuscate(s), nil }
	return b
}

type runtimeBindings struct {
	validation        *Runtime
	ctx               context.Context
	tokenizer         *tiktoken.Tiktoken
	tokenizerProvider func() *tiktoken.Tiktoken
	finding           any
	attrs             any
	captures          any
	debug             *evalState
}

func baseBindings(rt *runtimeBindings) bindings {
	if rt.ctx == nil {
		rt.ctx = context.Background()
	}
	if rt.attrs == nil {
		rt.attrs = map[string]any{}
	}

	rtb := bindings{
		"attributes":           rt.attrs,
		"get":                  getDefault,
		"getPath":              getPathDefault,
		"filter":               filterNamespace(rt),
		"matchesAny":           matchesAny,
		"containsAny":          containsAny,
		"entropy":              shannonEntropy,
		"failsTokenEfficiency": rt.failsTokenEfficiency,
	}
	rtb["__runtime"] = rt
	return rtb
}

func setCompileMaps(b bindings) {
	b["finding"] = map[string]any{}
	b["attributes"] = map[string]any{}
	b["captures"] = map[string]any{}
	b["secret"] = ""
}

func nonNilStringMap(m map[string]string) map[string]string {
	if m == nil {
		return emptyStringMap
	}
	return m
}

func filterBindings(tokenizer *tiktoken.Tiktoken, finding, attributes map[string]string) bindings {
	b := baseBindings(&runtimeBindings{tokenizer: tokenizer, attrs: attributes})
	b["finding"] = finding
	return b
}

func prefilterBindings(attributes map[string]string) bindings {
	return baseBindings(&runtimeBindings{attrs: attributes})
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
