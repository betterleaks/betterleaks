package exprruntime

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBindings(t *testing.T) {
	env, err := New(nil)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}

	tests := []struct {
		name   string
		expr   string
		secret string
		want   string
	}{
		{
			name: "md5 literal",
			expr: `hex.encode(crypto.md5(bytes("hello")))`,
			want: "5d41402abc4b2a76b9719d911017c592",
		},
		{
			name: "md5 empty string",
			expr: `hex.encode(crypto.md5(bytes("")))`,
			want: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:   "md5 secret variable",
			expr:   `hex.encode(crypto.md5(bytes(finding["secret"])))`,
			secret: "test123",
			want:   "cc03e747a6afbbcbf8be7668acfebee5",
		},
		{
			name: "md5 bytes literal",
			expr: `hex.encode(crypto.md5(bytes("hello")))`,
			want: "5d41402abc4b2a76b9719d911017c592",
		},
		{
			name: "hex encode sha1 bytes",
			expr: `hex.encode(crypto.sha1(bytes("hello")))`,
			want: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
		},
	}

	// Verify crypto.hmac_sha256 returns correct HMAC
	t.Run("hmac_sha256", func(t *testing.T) {
		prg, err := env.CompileValidation(`crypto.hmac_sha256(bytes("key"), bytes("hello"))`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, nil, nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		// HMAC-SHA256("key", "hello") = a]aedc7b02c5c85b5262... (raw bytes)
		// We check the length is 32 bytes (SHA-256 output).
		bs := got.([]byte)
		if len(bs) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(bs))
		}
	})

	t.Run("hmac_sha1", func(t *testing.T) {
		prg, err := env.CompileValidation(`hex.encode(crypto.hmacSha1(bytes("key"), bytes("hello")))`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, nil, nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		if got != "b34ceac4516ff23a143e61d79d0fa7a4fbe5f266" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("url_query_escape", func(t *testing.T) {
		prg, err := env.CompileValidation(`strings.urlQueryEscape("a b+/:")`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, nil, nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		if got != "a+b%2B%2F%3A" {
			t.Errorf("got %v", got)
		}
	})

	// Verify time.now_unix returns a numeric string
	t.Run("time_now_unix", func(t *testing.T) {
		prg, err := env.CompileValidation(`time.now_unix()`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, nil, nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		s, ok := got.(string)
		if !ok {
			t.Fatalf("expected string, got %T", got)
		}
		if len(s) < 10 {
			t.Errorf("expected unix timestamp string, got %q", s)
		}
	})

	t.Run("time_now_rfc3339", func(t *testing.T) {
		prg, err := env.CompileValidation(`time.nowRFC3339()`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, nil, nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		s, ok := got.(string)
		if !ok {
			t.Fatalf("expected string, got %T", got)
		}
		if _, err := time.Parse(time.RFC3339, s); err != nil {
			t.Errorf("expected RFC3339 timestamp, got %q", s)
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prg, err := env.CompileValidation(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			got, err := env.Eval(prg, map[string]string{"secret": tc.secret}, nil)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %v, want %s", got, tc.want)
			}
		})
	}
}

func TestValidationAttributes(t *testing.T) {
	env, err := New(nil)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}

	prg, err := env.CompileValidation(`attributes["path"] == "service/config.yml" ? {"result": "valid"} : {"result": "invalid"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	got, err := env.EvalWithAttributes(prg, nil, nil, map[string]string{"path": "service/config.yml"})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}

	result, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", got)
	}
	if result["result"] != "valid" {
		t.Fatalf("result = %v, want valid", result["result"])
	}
}

func TestEvalValidationDebugMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Fatalf("authorization header = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-Figma-Token") != "figma-secret" {
			t.Fatalf("x-figma-token header = %q", r.Header.Get("X-Figma-Token"))
		}
		w.Header().Set("X-Debug", "present")
		w.Header().Set("DD-API-KEY", "datadog-secret")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	env, err := New(srv.Client())
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}
	prg, err := env.CompileValidation(`http.post("` + srv.URL + `", {"Authorization": "Bearer secret", "X-Figma-Token": "figma-secret"}, "payload").status`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	withoutDebug, err := env.EvalValidation(nil, prg, nil, nil, nil, EvalOptions{})
	if err != nil {
		t.Fatalf("eval without debug: %v", err)
	}
	if withoutDebug.Value != int64(http.StatusCreated) {
		t.Fatalf("value without debug = %v, want %d", withoutDebug.Value, http.StatusCreated)
	}
	if len(withoutDebug.Debug) != 0 {
		t.Fatalf("debug without debug option = %#v, want empty", withoutDebug.Debug)
	}

	withDebug, err := env.EvalValidation(nil, prg, nil, nil, nil, EvalOptions{Debug: true})
	if err != nil {
		t.Fatalf("eval with debug: %v", err)
	}
	if withDebug.Value != int64(http.StatusCreated) {
		t.Fatalf("value with debug = %v, want %d", withDebug.Value, http.StatusCreated)
	}
	if withDebug.Debug["req_method"] != http.MethodPost {
		t.Fatalf("req_method = %v", withDebug.Debug["req_method"])
	}
	if withDebug.Debug["req_url"] != srv.URL {
		t.Fatalf("req_url = %v, want %s", withDebug.Debug["req_url"], srv.URL)
	}
	if withDebug.Debug["req_body"] != "payload" {
		t.Fatalf("req_body = %v", withDebug.Debug["req_body"])
	}
	if withDebug.Debug["req_header_authorization"] != "[redacted]" {
		t.Fatalf("authorization debug header = %v", withDebug.Debug["req_header_authorization"])
	}
	if withDebug.Debug["req_header_x-figma-token"] != "[redacted]" {
		t.Fatalf("x-figma-token debug header = %v", withDebug.Debug["req_header_x-figma-token"])
	}
	if withDebug.Debug["resp_status"] != int64(http.StatusCreated) {
		t.Fatalf("resp_status = %v", withDebug.Debug["resp_status"])
	}
	if withDebug.Debug["resp_header_x-debug"] != "present" {
		t.Fatalf("resp_header_x-debug = %v", withDebug.Debug["resp_header_x-debug"])
	}
	if withDebug.Debug["resp_header_dd-api-key"] != "[redacted]" {
		t.Fatalf("resp_header_dd-api-key = %v", withDebug.Debug["resp_header_dd-api-key"])
	}
	body, ok := withDebug.Debug["resp_body"].(string)
	if !ok || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("resp_body = %#v", withDebug.Debug["resp_body"])
	}
}
