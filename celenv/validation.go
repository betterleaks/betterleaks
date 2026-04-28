package celenv

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

var (
	mapStringStringType = reflect.TypeFor[map[string]string]()
	mapAnyType          = reflect.TypeFor[map[string]any]()
)

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
// Define new bindings here.
func NewEnvironment(httpClient *http.Client) (*ValidationEnvironment, error) {
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}

	// Initialise Environment first so the HTTP binding closures can capture it.
	e := &ValidationEnvironment{
		client: httpClient,
		cache:  make(map[string]cel.Program),
	}

	env, err := cel.NewEnv(
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),

		cel.Variable("secret", cel.StringType),
		cel.Variable("captures", cel.MapType(cel.StringType, cel.StringType)),

		cel.Function("http.get",
			cel.Overload("http_get_string_map",
				[]*cel.Type{cel.StringType, cel.MapType(cel.StringType, cel.StringType)},
				cel.MapType(cel.StringType, cel.DynType),
				cel.BinaryBinding(httpGetBinding(e)),
			),
		),

		cel.Function("http.post",
			cel.Overload("http_post_string_map_string",
				[]*cel.Type{
					cel.StringType,
					cel.MapType(cel.StringType, cel.StringType),
					cel.StringType,
				},
				cel.MapType(cel.StringType, cel.DynType),
				cel.FunctionBinding(httpPostBinding(e)),
			),
		),

		// unknown(response) returns {"result": "unknown", "reason": "HTTP <status>"}
		// for use as a fallback when the HTTP status is unexpected.
		cel.Function("unknown",
			cel.Overload("unknown_map",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType)},
				cel.MapType(cel.StringType, cel.DynType),
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					m := map[string]any{"result": "unknown"}
					if nativeVal, err := val.ConvertToNative(mapAnyType); err == nil {
						if resp, ok := nativeVal.(map[string]any); ok {
							if status, ok := resp["status"]; ok {
								switch status {
								case int64(429):
									m["reason"] = "rate limited"
								default:
									m["reason"] = fmt.Sprintf("HTTP %v", status)
								}
							}
						}
					}
					return types.DefaultTypeAdapter.NativeToValue(m)
				}),
			),
		),

		cel.Function("crypto.md5",
			cel.Overload("crypto_md5_bytes",
				[]*cel.Type{cel.BytesType},
				cel.BytesType,
				cel.UnaryBinding(md5Binding()),
			),
		),

		cel.Function("crypto.sha1",
			cel.Overload("crypto_sha1_bytes",
				[]*cel.Type{cel.BytesType},
				cel.BytesType,
				cel.UnaryBinding(sha1Binding()),
			),
		),

		cel.Function("hex.encode",
			cel.Overload("hex_encode_bytes",
				[]*cel.Type{cel.BytesType},
				cel.StringType,
				cel.UnaryBinding(hexEncodeBinding()),
			),
		),

		cel.Function("crypto.hmac_sha256",
			cel.Overload("crypto_hmac_sha256_bytes_bytes",
				[]*cel.Type{cel.BytesType, cel.BytesType},
				cel.BytesType,
				cel.BinaryBinding(hmacSha256Binding()),
			),
		),

		cel.Function("time.now_unix",
			cel.Overload("time_now_unix",
				[]*cel.Type{},
				cel.StringType,
				cel.FunctionBinding(timeNowUnixBinding()),
			),
		),

		cel.Function("aws.validate",
			cel.Overload("aws_validate_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.MapType(cel.StringType, cel.DynType),
				cel.FunctionBinding(awsValidateBinding(e)),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}

	e.env = env
	return e, nil
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

// Eval evaluates a compiled CEL program with the given secret and captures,
// returning the raw CEL output value.
func (e *ValidationEnvironment) Eval(prg cel.Program, secret string, captures map[string]string) (ref.Val, error) {
	if e.DebugResponse {
		e.debugMu.Lock()
		defer e.debugMu.Unlock()
		e.debugMeta = make(map[string]any)
	}

	if captures == nil {
		captures = make(map[string]string)
	}

	vars := map[string]any{
		"secret":   secret,
		"captures": captures,
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
