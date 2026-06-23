package exprenv

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/logging"
)

// ParseValidationEnvAllowlist converts CLI flag fragments into a set of names.
func ParseValidationEnvAllowlist(parts []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		for _, name := range strings.Split(part, ",") {
			if n := strings.TrimSpace(name); n != "" {
				out[n] = struct{}{}
			}
		}
	}
	return out
}

func md5Bytes(bs []byte) []byte {
	hash := md5.Sum(bs)
	return hash[:]
}

func sha1Bytes(bs []byte) []byte {
	hash := sha1.Sum(bs)
	return hash[:]
}

func hmacSha256Bytes(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func hmacSha1Bytes(key, msg []byte) []byte {
	h := hmac.New(sha1.New, key)
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func hexEncode(bs []byte) string { return hex.EncodeToString(bs) }

func base64Encode(bs []byte) string { return base64.StdEncoding.EncodeToString(bs) }

func base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func jsonString(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("json.string: %w", err)
	}
	return string(b), nil
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

func timeNowUnix() string { return strconv.FormatInt(time.Now().Unix(), 10) }

func timeNowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

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
	if rt.validation != nil && rt.validation.DebugResponse {
		rt.validation.captureDebug(method, rawURL, body, req, resp, respBody)
	}
	return buildResponseMap(resp.StatusCode, respBody, resp.Header), nil
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

func (e *ValidationEnvironment) captureDebug(method, rawURL, reqBody string, req *http.Request, resp *http.Response, body []byte) {
	if e.debugMeta == nil {
		e.debugMeta = make(map[string]any)
	}
	e.debugMeta["req_method"] = method
	e.debugMeta["req_url"] = rawURL
	if len(reqBody) > 0 {
		if len(reqBody) > 2000 {
			reqBody = reqBody[:2000] + "..."
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
			respBody = respBody[:2000] + "..."
		}
		e.debugMeta["resp_body"] = respBody
	}
	for k := range resp.Header {
		e.debugMeta["resp_header_"+strings.ToLower(k)] = resp.Header.Get(k)
	}
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

func unknownResult(resp map[string]any) map[string]any {
	m := map[string]any{"result": "unknown"}
	if status, ok := resp["status"]; ok {
		switch status {
		case int64(429), 429:
			m["reason"] = "rate limited"
		default:
			m["reason"] = fmt.Sprintf("HTTP %v", status)
		}
	}
	return m
}
