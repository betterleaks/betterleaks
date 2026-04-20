package celenv

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func httpGetBinding(e *ValidationEnvironment) functions.BinaryOp {
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

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		if err != nil {
			return types.NewErr("http.get: reading body: %v", err)
		}

		if e.DebugResponse {
			e.captureDebug("GET", string(url), "", req, resp, body)
		}

		return buildResponseMap(resp.StatusCode, body, resp.Header)
	}
}

func httpPostBinding(e *ValidationEnvironment) functions.FunctionOp {
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

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
		if err != nil {
			return types.NewErr("http.post: reading body: %v", err)
		}

		if e.DebugResponse {
			e.captureDebug("POST", string(url), reqBody, req, resp, body)
		}

		return buildResponseMap(resp.StatusCode, body, resp.Header)
	}
}

// captureDebug records HTTP request/response metadata into e.debugMeta.
func (e *ValidationEnvironment) captureDebug(method, url, reqBody string, req *http.Request, resp *http.Response, body []byte) {
	e.debugMeta["req_method"] = method
	e.debugMeta["req_url"] = url
	if len(reqBody) > 0 {
		if len(reqBody) > 2000 {
			reqBody = reqBody[:2000] + "…"
		}
		e.debugMeta["req_body"] = reqBody
	}
	for k := range req.Header {
		e.debugMeta["req_header_"+strings.ToLower(k)] = req.Header.Get(k)
	}
	e.debugMeta["resp_status"] = int64(resp.StatusCode)
	if len(body) > 0 {
		respBody := string(body)
		if len(respBody) > 2000 {
			respBody = respBody[:2000] + "…"
		}
		e.debugMeta["resp_body"] = respBody
	}
	for k := range resp.Header {
		e.debugMeta["resp_header_"+strings.ToLower(k)] = resp.Header.Get(k)
	}
}

// buildResponseMap constructs the CEL map returned by http.get / http.post.
func buildResponseMap(statusCode int, body []byte, header http.Header) ref.Val {
	var jsonBody any

	// TODO log err
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
