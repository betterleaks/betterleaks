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
	"github.com/expr-lang/expr/ast"
	"github.com/expr-lang/expr/parser"
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
	vm                 *vm.Program
	mode               compileMode
	tokenizer          *tiktoken.Tiktoken
	tokenizerProvider  func() *tiktoken.Tiktoken
	bindings           bindings
	evalPool           sync.Pool
	needsFragmentRaw   bool
	needsContext       bool
	needsLine          bool
	needsLocalLine     bool
	needsMatchWindow   bool
	needsNearbyContext bool
	findingUsage       findingUsage
}

var emptyStringMap = map[string]string{}
var emptyFilterFinding = map[string]any{
	"secret":                     "",
	"match":                      "",
	"line":                       "",
	"rule_id":                    "",
	"description":                "",
	"context":                    "",
	"entropy":                    "",
	"fragment_raw":               "",
	"match_start_idx":            0,
	"match_end_idx":              0,
	"match_line_start_idx":       0,
	"match_line_end_idx":         0,
	"local_line":                 "",
	"local_line_match_start_idx": 0,
	"local_line_match_end_idx":   0,
	"match_prefix":               "",
	"match_suffix":               "",
	"nearby_context":             "",
	"line_prefix":                "",
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

// Runtime holds compiled Expr programs and validation services (if needed).
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

// evaluationBindings owns the mutable environment for one expression run.
// Programs are evaluated concurrently, so each active run needs isolated maps
// and runtime state. Inactive environments are pooled to avoid rebuilding the
// same maps and bound-method values for every file and rule candidate.
type evaluationBindings struct {
	values            bindings
	runtime           *runtimeBindings
	scratchAttributes map[string]string
	machine           vm.VM
}

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
	inspectionTree, inspectionErr := parser.Parse(exprText)
	var inspectionNode ast.Node
	if inspectionErr == nil {
		inspectionNode = inspectionTree.Node
	}
	usage := inspectFindingUsageNode(inspectionNode)
	prg := &compiledProgram{
		vm:                vmPrg,
		mode:              mode,
		tokenizer:         tokenizer,
		tokenizerProvider: e.tokenizerProvider,
		bindings:          programBindings(mode, b),
		needsFragmentRaw:  mode == modeFilter && usage.needs("fragment_raw"),
		needsContext:      mode == modeFilter && usage.needs("context"),
		needsLine:         mode == modeFilter && usage.needs("line"),
		needsLocalLine: mode == modeFilter && (usage.needs("local_line") ||
			usage.needs("local_line_match_start_idx") || usage.needs("local_line_match_end_idx")),
		needsMatchWindow:   mode == modeFilter && (usage.needs("match_prefix") || usage.needs("match_suffix")),
		needsNearbyContext: mode == modeFilter && (usage.needs("nearby_context") || usage.needs("line_prefix")),
		findingUsage:       usage,
	}
	e.mu.Lock()
	e.cache[cacheKey] = prg
	e.mu.Unlock()
	return prg, nil
}

// NeedsFragmentRaw reports whether a filter expression references the complete
// fragment text. Byte-oriented scans use this to avoid materializing a string
// for the overwhelmingly common filters that only inspect finding fields.
func (prg Program) NeedsFragmentRaw() bool {
	return prg != nil && prg.needsFragmentRaw
}

// NeedsContext reports whether a filter expression references the bounded
// finding context. Detectors use this to avoid building context for candidates
// whose filters only inspect the match, secret, line, or attributes.
func (prg Program) NeedsContext() bool {
	return prg != nil && prg.needsContext
}

// NeedsLine reports whether a filter reads finding["line"].
func (prg Program) NeedsLine() bool {
	return prg != nil && prg.needsLine
}

// NeedsLocalLine reports whether a filter uses the current match line and its
// line-relative byte offsets.
func (prg Program) NeedsLocalLine() bool {
	return prg != nil && prg.needsLocalLine
}

// NeedsMatchWindow reports whether a filter uses the bounded 8 KiB prefix or
// suffix adjacent to the current match.
func (prg Program) NeedsMatchWindow() bool {
	return prg != nil && prg.needsMatchWindow
}

// NeedsNearbyContext reports whether a filter uses the match-excluded nearby
// line context or the prefix of the current line.
func (prg Program) NeedsNearbyContext() bool {
	return prg != nil && prg.needsNearbyContext
}

// NeedsFinding reports whether a filter reads a particular finding field.
// Detectors use it to avoid boxing and inserting unused values into the Expr
// map for every candidate. Dynamic access conservatively reports every field.
func (prg Program) NeedsFinding(field string) bool {
	return prg != nil && prg.mode == modeFilter && prg.findingUsage.needs(field)
}

type findingUsage struct {
	fields map[string]struct{}
	all    bool
}

func (u findingUsage) needs(field string) bool {
	if u.all {
		return true
	}
	_, ok := u.fields[field]
	return ok
}

type findingUsageVisitor struct {
	fields         map[string]struct{}
	identifierUses int
	directBases    int
	dynamic        bool
}

func (v *findingUsageVisitor) Visit(node *ast.Node) {
	switch n := (*node).(type) {
	case *ast.IdentifierNode:
		if n.Value == "finding" {
			v.identifierUses++
		}
	case *ast.MemberNode:
		base, ok := n.Node.(*ast.IdentifierNode)
		if !ok || base.Value != "finding" {
			return
		}
		v.directBases++
		property, ok := n.Property.(*ast.StringNode)
		if !ok {
			v.dynamic = true
			return
		}
		v.fields[property.Value] = struct{}{}
	}
}

// inspectFindingUsage analyzes real member accesses instead of searching raw
// expression text, where comments and identifiers such as matchContext cause
// false positives. If the finding map escapes or is indexed dynamically, all
// expensive fields are conservatively enabled to preserve custom-filter
// behavior.
func inspectFindingUsageNode(node ast.Node) findingUsage {
	usage := findingUsage{fields: make(map[string]struct{})}
	if node == nil {
		usage.all = true
		return usage
	}
	visitor := &findingUsageVisitor{fields: usage.fields}
	ast.Walk(&node, visitor)
	usage.all = visitor.dynamic || visitor.identifierUses != visitor.directBases
	return usage
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
	default:
		b := e.validationBindings(context.Background(), nil, nil, nil, nil, nil)
		setCompileMaps(b)
		return b, []expr.Option{expr.WithContext("ctx")}
	}
}

// Compile and runtime bindings expose the same names. Dynamic values are layered
// onto a shallow copy so compiled programs can share static function bindings.
func (e *Runtime) EvalFilter(prg Program, finding map[string]any, attributes map[string]string) (bool, error) {
	if finding == nil {
		finding = emptyFilterFinding
	}
	eval := prg.acquireBindings()
	b := eval.values
	if attributes == nil {
		attributes = eval.scratchAttributes
	}
	b["finding"] = finding
	b["attributes"] = attributes
	if eval.runtime != nil {
		eval.runtime.attrs = attributes
	}
	result, err := runBool(prg, b, "filter", &eval.machine)
	prg.releaseBindings(eval)
	return result, err
}

func (e *Runtime) EvalPrefilter(prg Program, attributes map[string]string) (bool, error) {
	eval := prg.acquireBindings()
	b := eval.values
	b["attributes"] = nonNilStringMap(attributes)
	result, err := runBool(prg, b, "prefilter", &eval.machine)
	prg.releaseBindings(eval)
	return result, err
}

// EvalPathPrefilter evaluates a filesystem path without allocating a temporary
// one-entry attributes map for every visited path.
func (e *Runtime) EvalPathPrefilter(prg Program, path string) (bool, error) {
	eval := prg.acquireBindings()
	eval.scratchAttributes["path"] = path
	eval.values["attributes"] = eval.scratchAttributes
	result, err := runBool(prg, eval.values, "prefilter", &eval.machine)
	prg.releaseBindings(eval)
	return result, err
}

func (prg Program) acquireBindings() *evaluationBindings {
	if pooled := prg.evalPool.Get(); pooled != nil {
		return pooled.(*evaluationBindings)
	}

	b := cloneBindings(prg.bindings)
	eval := &evaluationBindings{
		values:            b,
		scratchAttributes: make(map[string]string),
	}
	if rt, ok := b["__runtime"].(*runtimeBindings); ok {
		rtCopy := *rt
		eval.runtime = &rtCopy
		eval.runtime.tokenizer = prg.tokenizer
		eval.runtime.tokenizerProvider = prg.tokenizerProvider
		b["__runtime"] = eval.runtime
		filter := filterNamespace(eval.runtime)
		if prg.mode == modeFilter {
			filter["setConfidence"] = eval.runtime.setConfidence
		}
		b["filter"] = filter
		b["failsTokenEfficiency"] = eval.runtime.failsTokenEfficiency
	}
	return eval
}

func (prg Program) releaseBindings(eval *evaluationBindings) {
	// Do not let the pool retain caller-owned finding or attribute maps. The
	// scratch map is private to this environment and can safely be reused.
	if prg.mode == modeFilter {
		eval.values["finding"] = emptyFilterFinding
	}
	eval.values["attributes"] = emptyStringMap
	if eval.runtime != nil {
		eval.runtime.attrs = emptyStringMap
	}
	clear(eval.scratchAttributes)
	// expr's reusable VM clears its operand stack on the next Run, but local
	// variables otherwise retain values while this environment sits in our
	// pool. Clear them at the ownership boundary. Programs that created scopes
	// may also leave caller data in expr's private scope pool; dropping that VM
	// is the only safe reset available without changing the dependency.
	// Run commonly leaves Stack at length zero after popping its result, while
	// the backing array still contains that result. Clear the full capacities,
	// not just the visible lengths, so a pooled VM cannot pin caller data.
	if cap(eval.machine.Stack) > 0 {
		clear(eval.machine.Stack[:cap(eval.machine.Stack)])
	}
	if cap(eval.machine.Variables) > 0 {
		clear(eval.machine.Variables[:cap(eval.machine.Variables)])
	}
	if cap(eval.machine.Scopes) > 0 {
		eval.machine = vm.VM{}
	}
	prg.evalPool.Put(eval)
}

func cloneBindings(src bindings) bindings {
	dst := make(bindings, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func runBool(prg Program, b bindings, name string, machine *vm.VM) (bool, error) {
	val, err := machine.Run(prg.vm, b)
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
	if ctx == nil {
		ctx = context.Background()
	}
	state := &evalState{debug: opts.Debug}
	ctx = context.WithValue(ctx, validationRequestContextKey{}, &validationRequestContext{
		ruleID: lookupString(finding, "rule_id"),
		state:  state,
	})
	b := e.validationBindings(ctx, finding, captures, components, attributes, state)
	val, err := expr.Run(prg.vm, b)
	return EvalResult{
		Value:           val,
		Debug:           state.meta,
		RequestLimitHit: state.validationLimitHit(),
	}, err
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
