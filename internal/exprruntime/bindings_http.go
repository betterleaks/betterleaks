package exprruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
)

func httpNamespace(rt *runtimeBindings) map[string]any {
	return map[string]any{
		"get":  rt.httpGet,
		"post": rt.httpPost,
	}
}

func (rt *runtimeBindings) httpGet(rawURL string, headers any) (map[string]any, error) {
	return rt.httpRequest(rt.ctx, http.MethodGet, rawURL, headers, "")
}

func (rt *runtimeBindings) httpPost(rawURL string, headers any, body string) (map[string]any, error) {
	return rt.httpRequest(rt.ctx, http.MethodPost, rawURL, headers, body)
}

func (rt *runtimeBindings) httpRequest(ctx context.Context, method, rawURL string, headers any, body string) (map[string]any, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	client := DefaultHTTPClient()
	if rt.validation != nil && rt.validation.client != nil {
		client = rt.validation.client
	}
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return nil, fmt.Errorf("http.%s: %w", strings.ToLower(method), err)
	}
	for k, v := range mapToStringAny(headers) {
		req.Header.Set(k, fmt.Sprint(v))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.%s: %w", strings.ToLower(method), err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("http.%s: reading body: %w", strings.ToLower(method), err)
	}
	rt.captureDebug(method, rawURL, body, req, resp, respBody)
	return buildResponseMap(resp.StatusCode, respBody, resp.Header), nil
}

func (rt *runtimeBindings) captureDebug(method, rawURL, reqBody string, req *http.Request, resp *http.Response, body []byte) {
	if rt == nil || rt.debug == nil || !rt.debug.debug {
		return
	}
	rt.debug.addDebug("req_method", method)
	rt.debug.addDebug("req_url", rawURL)
	if reqBody != "" {
		rt.debug.addDebug("req_body", truncateDebugString(reqBody))
	}
	if req != nil {
		for k, vals := range req.Header {
			rt.debug.addDebug("req_header_"+strings.ToLower(k), debugHeaderValue(k, strings.Join(vals, ",")))
		}
	}
	if resp != nil {
		rt.debug.addDebug("resp_status", int64(resp.StatusCode))
		for k, vals := range resp.Header {
			rt.debug.addDebug("resp_header_"+strings.ToLower(k), debugHeaderValue(k, strings.Join(vals, ",")))
		}
	}
	rt.debug.addDebug("resp_body", truncateDebugString(string(body)))
}

func truncateDebugString(s string) string {
	const maxDebugString = 2000
	if len(s) <= maxDebugString {
		return s
	}
	return s[:maxDebugString]
}

func debugHeaderValue(name, value string) string {
	if sensitiveHeaderName(name) {
		return "[redacted]"
	}
	return value
}

func sensitiveHeaderName(name string) bool {
	name = strings.ToLower(name)
	if name == "cookie" || name == "set-cookie" {
		return true
	}
	for _, token := range []string{"auth", "token", "key", "secret", "cookie"} {
		if strings.Contains(name, token) {
			return true
		}
	}
	return false
}

func mapToStringAny(v any) map[string]any {
	out := map[string]any{}
	switch m := v.(type) {
	case map[string]any:
		return m
	case map[string]string:
		for k, val := range m {
			out[k] = val
		}
	default:
		return out
	}
	return out
}

func buildResponseMap(statusCode int, body []byte, header http.Header) map[string]any {
	var jsonBody any
	if err := json.Unmarshal(body, &jsonBody); err != nil {
		logging.Debug().Err(err).Int("status", statusCode).Msg("http response body is not valid JSON, falling back to empty object")
		jsonBody = map[string]any{}
	}
	headerMap := make(map[string]any)
	for k := range header {
		headerMap[strings.ToLower(k)] = header.Get(k)
	}
	return map[string]any{
		"status":  int64(statusCode),
		"json":    jsonBody,
		"headers": headerMap,
		"body":    string(body),
	}
}
