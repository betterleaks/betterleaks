package validate

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

var (
	mapStringStringType = reflect.TypeFor[map[string]string]()
	mapAnyType          = reflect.TypeFor[map[string]any]()
)

// debugCapture holds raw HTTP request/response data captured during a debug Eval call.
type debugCapture struct {
	// Request fields.
	reqMethod  string
	reqURL     string
	reqHeaders http.Header
	reqBody    string

	// Response fields.
	status  int64
	body    []byte
	headers http.Header
}

// validStatuses is the set of recognised validation statuses.
var validStatuses = map[string]bool{
	"valid":   true,
	"invalid": true,
	"revoked": true,
	"unknown": true,
	"error":   true,
}

// Result holds the outcome of a CEL validation evaluation.
type Result struct {
	Status   string         // "valid", "invalid", "revoked", "unknown", "error"
	Reason   string         // human-readable explanation
	Metadata map[string]any // extra fields from the CEL result map
}

// Environment holds a compiled CEL environment and an HTTP client for validation.
type Environment struct {
	env    *cel.Env
	client *http.Client

	mu    sync.RWMutex
	cache map[string]cel.Program

	// DebugResponse, when true, captures the raw HTTP request and response
	// from each validation call and injects them into Result.Metadata as
	// req_method, req_url, req_header_*, req_body, resp_status, resp_body,
	// and resp_header_*.
	DebugResponse bool
	debugCap      *debugCapture
}

// DefaultHTTPClient returns an HTTP client suitable for validation with reasonable timeouts.
func DefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
	}
}

// NewEnvironment creates a CEL environment with http.get and http.post bindings.
func NewEnvironment(httpClient *http.Client) (*Environment, error) {
	if httpClient == nil {
		httpClient = DefaultHTTPClient()
	}

	// Initialise Environment first so the HTTP binding closures can capture it.
	// This lets them write debug captures and use the correct HTTP client.
	e := &Environment{
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
								m["reason"] = fmt.Sprintf("HTTP %v", status)
							}
						}
					}
					return types.DefaultTypeAdapter.NativeToValue(m)
				}),
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
func (e *Environment) Compile(expression string) (cel.Program, error) {
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

// Eval evaluates a compiled CEL program with the given secret and captures.
func (e *Environment) Eval(prg cel.Program, secret string, captures map[string]string) (*Result, error) {
	if captures == nil {
		captures = make(map[string]string)
	}

	vars := map[string]any{
		"secret":   secret,
		"captures": captures,
	}

	val, _, err := prg.Eval(vars)
	if err != nil {
		return &Result{Status: "error", Reason: err.Error(), Metadata: map[string]any{}}, nil
	}

	r := parseResult(val)

	// Attach raw HTTP request/response data when debug mode is active.
	if e.DebugResponse && e.debugCap != nil {
		if r.Metadata == nil {
			r.Metadata = make(map[string]any)
		}

		// Request data.
		r.Metadata["req_method"] = e.debugCap.reqMethod
		r.Metadata["req_url"] = e.debugCap.reqURL
		if len(e.debugCap.reqBody) > 0 {
			reqBody := e.debugCap.reqBody
			if len(reqBody) > 2000 {
				reqBody = reqBody[:2000] + "…"
			}
			r.Metadata["req_body"] = reqBody
		}
		for k := range e.debugCap.reqHeaders {
			r.Metadata["req_header_"+strings.ToLower(k)] = e.debugCap.reqHeaders.Get(k)
		}

		// Response data.
		r.Metadata["resp_status"] = e.debugCap.status
		if len(e.debugCap.body) > 0 {
			r.Metadata["resp_body"] = string(e.debugCap.body)
		}
		for k := range e.debugCap.headers {
			r.Metadata["resp_header_"+strings.ToLower(k)] = e.debugCap.headers.Get(k)
		}
	}

	return r, nil
}

// parseResult interprets the CEL output value into a Result.
func parseResult(val ref.Val) *Result {
	switch v := val.Value().(type) {
	case map[string]any:
		return parseResultMap(v)

	default:
		nativeVal, err := val.ConvertToNative(mapAnyType)
		if err == nil {
			if m, ok := nativeVal.(map[string]any); ok {
				return parseResultMap(m)
			}
		}
		return &Result{
			Status:   "error",
			Reason:   fmt.Sprintf("expression returned unexpected type: %T", val.Value()),
			Metadata: map[string]any{},
		}
	}
}

// reservedKeys are map keys consumed by parseResultMap and excluded from metadata.
var reservedKeys = map[string]bool{
	"result": true, "reason": true,
}

// parseResultMap interprets a map result from a CEL expression.
//
// The expected form is {"result": "<status>", ...} where <status> is one of
// the validStatuses.
func parseResultMap(m map[string]any) *Result {
	result := &Result{
		Status:   "unknown",
		Metadata: make(map[string]any),
	}

	// Primary: explicit "result" key with a string status.
	if v, ok := m["result"]; ok {
		if s, ok := v.(string); ok {
			s = strings.ToLower(s)
			if validStatuses[s] {
				result.Status = s
			}
		}
	}

	// Extract reason.
	if r, ok := m["reason"]; ok {
		if s, ok := r.(string); ok {
			result.Reason = s
		}
	}

	// Everything else is metadata.
	for k, v := range m {
		if !reservedKeys[k] {
			result.Metadata[k] = v
		}
	}

	return result
}

// ---------------------------------------------------------------------------
// HTTP bindings for CEL
// ---------------------------------------------------------------------------
func httpGetBinding(e *Environment) functions.BinaryOp {
	return func(lhs, rhs ref.Val) ref.Val {
		url, ok := lhs.(types.String)
		if !ok {
			return types.NewErr("http.get: url must be a string, got %T", lhs)
		}

		headers := make(map[string]string)
		if nativeVal, err := rhs.ConvertToNative(mapStringStringType); err == nil {
			if h, ok := nativeVal.(map[string]string); ok {
				headers = h
			}
		}

		req, err := http.NewRequest("GET", string(url), nil)
		if err != nil {
			return types.NewErr("http.get: %v", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := e.client.Do(req)
		if err != nil {
			return types.NewErr("http.get: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return types.NewErr("http.get: reading body: %v", err)
		}

		if e.DebugResponse {
			e.debugCap = &debugCapture{
				reqMethod:  "GET",
				reqURL:     string(url),
				reqHeaders: req.Header.Clone(),
				status:     int64(resp.StatusCode),
				body:       body,
				headers:    resp.Header,
			}
		}

		return buildResponseMap(resp.StatusCode, body, resp.Header)
	}
}

func httpPostBinding(e *Environment) functions.FunctionOp {
	return func(args ...ref.Val) ref.Val {
		if len(args) != 3 {
			return types.NewErr("http.post: expected 3 args, got %d", len(args))
		}

		url, ok := args[0].(types.String)
		if !ok {
			return types.NewErr("http.post: url must be a string")
		}

		reqHeaders := make(map[string]string)
		if nativeVal, err := args[1].ConvertToNative(mapStringStringType); err == nil {
			if h, ok := nativeVal.(map[string]string); ok {
				reqHeaders = h
			}
		}

		reqBody := ""
		if b, ok := args[2].(types.String); ok {
			reqBody = string(b)
		}

		req, err := http.NewRequest("POST", string(url), strings.NewReader(reqBody))
		if err != nil {
			return types.NewErr("http.post: %v", err)
		}
		for k, v := range reqHeaders {
			req.Header.Set(k, v)
		}

		resp, err := e.client.Do(req)
		if err != nil {
			return types.NewErr("http.post: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return types.NewErr("http.post: reading body: %v", err)
		}

		if e.DebugResponse {
			e.debugCap = &debugCapture{
				reqMethod:  "POST",
				reqURL:     string(url),
				reqHeaders: req.Header.Clone(),
				reqBody:    reqBody,
				status:     int64(resp.StatusCode),
				body:       body,
				headers:    resp.Header,
			}
		}

		return buildResponseMap(resp.StatusCode, body, resp.Header)
	}
}

// buildResponseMap constructs the CEL map returned by http.get / http.post.
// body must already have been read from the response by the caller.
// All header keys are stored lowercased so CEL expressions can use
// consistent lowercase names (e.g. r.headers["x-oauth-scopes"]).
func buildResponseMap(statusCode int, body []byte, header http.Header) ref.Val {
	var jsonBody any
	if err := json.Unmarshal(body, &jsonBody); err != nil {
		jsonBody = map[string]any{}
	}

	headerMap := make(map[string]any)
	for k := range header {
		headerMap[strings.ToLower(k)] = header.Get(k)
	}

	result := map[string]any{
		"status":  int64(statusCode),
		"json":    jsonBody,
		"headers": headerMap,
		"body":    string(body),
	}

	return types.DefaultTypeAdapter.NativeToValue(result)
}
