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

// Program is the compiled representation used by filter, validation, and
// analysis expressions.
type Program = *compiledProgram

type compileMode string

const (
	modeFilter     compileMode = "filter"
	modePrefilter  compileMode = "prefilter"
	modeValidation compileMode = "validation"
	modeAnalysis   compileMode = "analysis"
)

type compiledProgram struct {
	vm                *vm.Program
	mode              compileMode
	tokenizer         *tiktoken.Tiktoken
	tokenizerProvider func() *tiktoken.Tiktoken
	bindings          bindings
}

var emptyStringMap = map[string]string{}
var emptyFilterFinding = map[string]any{
	"secret":               "",
	"match":                "",
	"line":                 "",
	"rule_id":              "",
	"description":          "",
	"context":              "",
	"entropy":              "",
	"fragment_raw":         "",
	"match_start_idx":      0,
	"match_end_idx":        0,
	"match_line_start_idx": 0,
	"match_line_end_idx":   0,
}

type EvalOptions struct {
	Debug bool
}

type EvalResult struct {
	Value           any
	Debug           map[string]any
	RequestLimitHit *ValidationRequestLimitHit
}

type evalState struct {
	debug bool
	meta  map[string]any

	limitMu  sync.Mutex
	limitHit *ValidationRequestLimitHit
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

func (s *evalState) recordValidationLimitHit(hit ValidationRequestLimitHit) {
	if s == nil {
		return
	}
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if s.limitHit == nil {
		s.limitHit = &hit
	}
}

func (s *evalState) validationLimitHit() *ValidationRequestLimitHit {
	if s == nil {
		return nil
	}
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if s.limitHit == nil {
		return nil
	}
	hit := *s.limitHit
	return &hit
}

// maxResponseBody is the maximum number of bytes read from an HTTP response body.
const maxResponseBody = 1 << 20 // 1 MB

// Runtime holds compiled Expr programs and the provider services used by
// validation and analysis.
type Runtime struct {
	client *http.Client
	// validationLimiter is applied to every request made through client,
	// including generic HTTP and typed cloud validation bindings.
	validationLimiter *validationRequestLimiter

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

func (e *Runtime) SetHTTPClient(c *http.Client) {
	e.client = wrapValidationLimitClient(c, e.validationLimiter)
}

// SetValidationRequestLimits applies request-level validation limits to the
// Runtime's shared HTTP client.
func (e *Runtime) SetValidationRequestLimits(cfg ValidationRequestLimits) error {
	limiter, err := newValidationRequestLimiter(cfg)
	if err != nil {
		return err
	}
	e.validationLimiter = limiter
	e.client = wrapValidationLimitClient(e.client, limiter)
	return nil
}

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

func (e *Runtime) CompileAnalysis(expression string) (Program, error) {
	return e.compile(modeAnalysis, expression, nil)
}

func (e *Runtime) compile(mode compileMode, expression string, tokenizer *tiktoken.Tiktoken) (Program, error) {
	// One Runtime compiles all expression types. The mode is part of the cache key
	// because each expression kind exposes a different binding contract.
	cacheKey := compileCacheKey(mode, expression, tokenizer)
	e.mu.RLock()
	if prg, ok := e.cache[cacheKey]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	b, options := e.compileBindings(mode, tokenizer)
	vmPrg, err := expr.Compile(expression, append([]expr.Option{expr.Env(b)}, options...)...)
	if err != nil {
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
		return filterBindings(tokenizer, emptyFilterFinding, emptyStringMap), []expr.Option{expr.AsBool()}
	case modePrefilter:
		return prefilterBindings(emptyStringMap), []expr.Option{expr.AsBool()}
	case modeValidation:
		b := e.validationBindings(context.Background(), nil, nil, nil, nil, nil)
		setCompileMaps(b)
		return b, []expr.Option{expr.WithContext("ctx")}
	case modeAnalysis:
		b := e.validationBindings(context.Background(), nil, nil, nil, nil, nil)
		setCompileMaps(b)
		b["validation"] = emptyValidationMap()
		return b, []expr.Option{expr.WithContext("ctx")}
	default:
		panic(fmt.Sprintf("unsupported expression mode %q", mode))
	}
}

// Compile and runtime bindings expose the same names. Dynamic values are layered
// onto a shallow copy so compiled programs can share static function bindings.
func (e *Runtime) EvalFilter(prg Program, finding map[string]any, attributes map[string]string) (bool, error) {
	b := prg.evalBindings()
	if finding == nil {
		finding = emptyFilterFinding
	}
	if attributes == nil {
		attributes = make(map[string]string)
	}
	b["finding"] = finding
	b["attributes"] = attributes
	if rt, ok := b["__runtime"].(*runtimeBindings); ok {
		rt.attrs = attributes
		filter := filterNamespace(rt)
		filter["setConfidence"] = rt.setConfidence
		b["filter"] = filter
	}
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
			rtCopy := *rt
			rt = &rtCopy
			rt.tokenizer = prg.tokenizer
			rt.tokenizerProvider = prg.tokenizerProvider
			b["__runtime"] = rt
			b["filter"] = filterNamespace(rt)
			b["failsTokenEfficiency"] = rt.failsTokenEfficiency
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

// EvalWithComponents evaluates a validation program with primary named regex
// captures and structured component findings.
func (e *Runtime) EvalWithComponents(prg Program, finding, captures map[string]string, components map[string]any) (any, error) {
	result, err := e.EvalValidationWithComponents(context.Background(), prg, finding, captures, components, nil, EvalOptions{})
	return result.Value, err
}

func (e *Runtime) EvalWithAttributes(prg Program, finding, captures, attributes map[string]string) (any, error) {
	return e.EvalWithContext(context.Background(), prg, finding, captures, attributes)
}

func (e *Runtime) EvalWithContext(ctx context.Context, prg Program, finding, captures, attributes map[string]string) (any, error) {
	result, err := e.EvalValidation(ctx, prg, finding, captures, attributes, EvalOptions{})
	return result.Value, err
}

func (e *Runtime) EvalValidation(ctx context.Context, prg Program, finding, captures, attributes map[string]string, opts EvalOptions) (EvalResult, error) {
	return e.EvalValidationWithComponents(ctx, prg, finding, captures, nil, attributes, opts)
}

// EvalValidationWithComponents evaluates a validation program with structured
// component findings isolated from the primary rule's named capture groups.
func (e *Runtime) EvalValidationWithComponents(ctx context.Context, prg Program, finding, captures map[string]string, components map[string]any, attributes map[string]string, opts EvalOptions) (EvalResult, error) {
	return e.evalProviderProgram(ctx, prg, finding, captures, components, attributes, nil, opts)
}

// EvalAnalysisWithComponents evaluates an analysis program with the successful
// validation result that authorized the analysis stage.
func (e *Runtime) EvalAnalysisWithComponents(ctx context.Context, prg Program, finding, captures map[string]string, components map[string]any, attributes map[string]string, validation map[string]any, opts EvalOptions) (EvalResult, error) {
	if validation == nil {
		validation = emptyValidationMap()
	}
	return e.evalProviderProgram(ctx, prg, finding, captures, components, attributes, validation, opts)
}

func (e *Runtime) evalProviderProgram(ctx context.Context, prg Program, finding, captures map[string]string, components map[string]any, attributes map[string]string, validation map[string]any, opts EvalOptions) (EvalResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	state := &evalState{debug: opts.Debug}
	ctx = context.WithValue(ctx, validationRequestContextKey{}, &validationRequestContext{
		ruleID: lookupString(finding, "rule_id"),
		state:  state,
	})
	b := e.validationBindings(ctx, finding, captures, components, attributes, state)
	if validation != nil {
		b["validation"] = validation
	}
	val, err := expr.Run(prg.vm, b)
	return EvalResult{
		Value:           val,
		Debug:           state.meta,
		RequestLimitHit: state.validationLimitHit(),
	}, err
}

func emptyValidationMap() map[string]any {
	return map[string]any{
		"status":   "",
		"reason":   "",
		"metadata": map[string]any{},
	}
}

func (e *Runtime) validationBindings(ctx context.Context, finding, captures map[string]string, components map[string]any, attributes map[string]string, state *evalState) bindings {
	if finding == nil {
		finding = emptyStringMap
	}
	if captures == nil {
		captures = emptyStringMap
	}
	if components == nil {
		components = map[string]any{}
	}
	if attributes == nil {
		attributes = emptyStringMap
	}
	findingWithCaptures := make(map[string]any, len(finding)+1)
	for key, value := range finding {
		findingWithCaptures[key] = value
	}
	findingWithCaptures["captures"] = captures
	legacyCaptures := legacyValidationCaptures(captures, components)
	rt := &runtimeBindings{
		validation: e,
		ctx:        ctx,
		tokenizer:  nil,
		finding:    findingWithCaptures,
		attrs:      attributes,
		captures:   legacyCaptures,
		components: components,
		debug:      state,
	}
	b := baseBindings(rt)
	b["ctx"] = rt.ctx
	b["finding"] = rt.finding
	b["captures"] = rt.captures
	b["components"] = rt.components
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

// legacyValidationCaptures preserves the v1 composite-validation contract at
// the top-level captures binding. New expressions should use finding["captures"]
// for primary named groups and components for component data. The overloaded
// binding can be removed in a future breaking release.
func legacyValidationCaptures(primary map[string]string, components map[string]any) map[string]string {
	if len(components) == 0 {
		return primary
	}

	legacy := make(map[string]string, len(primary)+len(components)*2)
	for name, value := range primary {
		legacy[name] = value
	}
	for ruleID, raw := range components {
		component, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if secret, ok := component["secret"].(string); ok {
			legacy[ruleID] = secret
		}
		switch captures := component["captures"].(type) {
		case map[string]string:
			for name, value := range captures {
				legacy[ruleID+":"+name] = value
			}
		case map[string]any:
			for name, rawValue := range captures {
				if value, ok := rawValue.(string); ok {
					legacy[ruleID+":"+name] = value
				}
			}
		}
	}
	return legacy
}

type runtimeBindings struct {
	validation        *Runtime
	ctx               context.Context
	tokenizer         *tiktoken.Tiktoken
	tokenizerProvider func() *tiktoken.Tiktoken
	finding           any
	attrs             any
	captures          any
	components        any
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
		"filter":               filterNamespace(rt),
		"matchesAny":           matchesAny,
		"containsAny":          containsAny,
		"startsWithAny":        startsWithAny,
		"entropy":              shannonEntropy,
		"failsTokenEfficiency": rt.failsTokenEfficiency,
	}
	rtb["__runtime"] = rt
	return rtb
}

func setCompileMaps(b bindings) {
	b["finding"] = map[string]any{"captures": map[string]any{}}
	b["attributes"] = map[string]any{}
	b["captures"] = map[string]any{}
	b["components"] = map[string]any{}
	b["secret"] = ""
}

func nonNilStringMap(m map[string]string) map[string]string {
	if m == nil {
		return emptyStringMap
	}
	return m
}

func filterBindings(tokenizer *tiktoken.Tiktoken, finding map[string]any, attributes map[string]string) bindings {
	rt := &runtimeBindings{tokenizer: tokenizer, attrs: attributes}
	b := baseBindings(rt)
	b["filter"].(map[string]any)["setConfidence"] = rt.setConfidence
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
		return "", fmt.Errorf("env: provider environment unavailable")
	}
	if len(e.AllowedEnv) == 0 {
		return "", fmt.Errorf("env: no provider env allowlist configured (use --provider-env-vars)")
	}
	if _, ok := e.AllowedEnv[name]; !ok {
		return "", fmt.Errorf("env: %q not in provider env allowlist", name)
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
