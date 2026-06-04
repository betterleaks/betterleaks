package celenv

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

var (
	mapStringStringType = reflect.TypeFor[map[string]string]()
	mapAnyType          = reflect.TypeFor[map[string]any]()
)

// emptyStringMap is a sentinel used in place of nil maps during CEL activation.
var emptyStringMap = map[string]string{}

// maxResponseBody is the maximum number of bytes read from an HTTP response body.
const maxResponseBody = 1 << 20 // 1 MB

// ValidationEnvironment holds a compiled CEL environment and an HTTP client.
type ValidationEnvironment struct {
	env    *cel.Env
	client *http.Client

	mu    sync.RWMutex
	cache map[string]cel.Program

	// DebugResponse, when true, captures the raw HTTP request and response
	// from each evaluation call and stores them in debugMeta.
	DebugResponse bool
	debugMu       sync.Mutex
	debugMeta     map[string]any // per-eval, written by HTTP bindings, protected by debugMu

	// STSEndpoint overrides the default AWS STS endpoint (for testing).
	STSEndpoint string

	// GCPTokenEndpoint overrides the GCP OAuth token endpoint (for testing).
	GCPTokenEndpoint string

	// AllowedEnv is the set of environment variable names the env(...) CEL
	// binding may read (via os.Getenv). Names not in this set produce a CEL
	// error. Nil or empty disables env(...) entirely. Populated from
	// --validation-env-vars by the detector.
	AllowedEnv map[string]struct{}
}

// DefaultHTTPClient returns an HTTP client with reasonable timeouts.
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
	}
}

// SetHTTPClient replaces the HTTP client used by this environment.
// This must be called before any program evaluation, not after.
func (e *ValidationEnvironment) SetHTTPClient(c *http.Client) {
	e.client = c
}

// NewValidationEnv creates a CEL environment for validating secrets.
// It is an alias for NewEnvironment.
func NewValidationEnv(httpClient *http.Client) (*ValidationEnvironment, error) {
	return NewEnvironment(httpClient)
}

// NewEnvironment creates a CEL environment.
func NewEnvironment(httpClient *http.Client) (*ValidationEnvironment, error) {
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}

	// Initialise Environment first so the HTTP binding closures can capture it.
	e := &ValidationEnvironment{
		client: httpClient,
		cache:  make(map[string]cel.Program),
	}

	opts := []cel.EnvOption{
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),

		cel.Variable("captures", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("attributes", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("finding", cel.MapType(cel.StringType, cel.StringType)),
		// `secret` is retained as an alias for finding["secret"] so external
		// rule configs that reference the bare variable continue to compile.
		// New expressions should prefer finding["secret"] for consistency.
		cel.Variable("secret", cel.StringType),
	}
	opts = append(opts, validationBindingSets(e)...)

	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	e.env = env
	return e, nil
}

func validationBindingSets(e *ValidationEnvironment) []cel.EnvOption {
	var opts []cel.EnvOption
	opts = append(opts, httpBindings(e)...)
	opts = append(opts, envBindings(e)...)
	opts = append(opts, stringsBindings()...)
	opts = append(opts, validateBindings()...)
	opts = append(opts, jsonBindings()...)
	opts = append(opts, cryptoBindings()...)
	opts = append(opts, hexBindings()...)
	opts = append(opts, timeBindings()...)
	opts = append(opts, awsBindings(e)...)
	opts = append(opts, gcpBindings(e)...)
	return opts
}

// Compile compiles a CEL expression and caches the resulting program.
func (e *ValidationEnvironment) Compile(expression string) (cel.Program, error) {
	e.mu.RLock()
	if prg, ok := e.cache[expression]; ok {
		e.mu.RUnlock()
		return prg, nil
	}
	e.mu.RUnlock()

	ast, issues := e.env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("CEL compile error:\n%s", issues.String())
	}

	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("CEL program error: %w", err)
	}

	e.mu.Lock()
	e.cache[expression] = prg
	e.mu.Unlock()

	return prg, nil
}

// Eval evaluates a compiled CEL program with the given finding and captures,
// returning the raw CEL output value. The finding map should contain a "secret"
// entry; CEL expressions read the secret via finding["secret"] (or via the
// `secret` alias variable, which is bound to the same value).
func (e *ValidationEnvironment) Eval(prg cel.Program, finding, captures map[string]string) (ref.Val, error) {
	return e.EvalWithAttributes(prg, finding, captures, nil)
}

// EvalWithAttributes evaluates a compiled CEL program with the given finding,
// captures, and source attributes.
func (e *ValidationEnvironment) EvalWithAttributes(prg cel.Program, finding, captures, attributes map[string]string) (ref.Val, error) {
	if e.DebugResponse {
		e.debugMu.Lock()
		defer e.debugMu.Unlock()
		e.debugMeta = make(map[string]any)
	}

	if captures == nil {
		captures = emptyStringMap
	}

	if finding == nil {
		finding = emptyStringMap
	}

	if attributes == nil {
		attributes = emptyStringMap
	}

	vars := map[string]any{
		"captures":   captures,
		"attributes": attributes,
		"finding":    finding,
		"secret":     finding["secret"],
	}

	val, _, err := prg.Eval(vars)
	if err != nil {
		return nil, err
	}

	return val, nil
}

// DebugMeta returns the debug metadata captured during the most recent Eval
// call (when DebugResponse is true). The caller must not modify the returned map.
func (e *ValidationEnvironment) DebugMeta() map[string]any {
	return e.debugMeta
}
