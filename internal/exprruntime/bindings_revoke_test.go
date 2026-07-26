package exprruntime

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRevokeNamespace_UnknownHelper mirrors the existing pattern for
// validate.unknown: confirm revoke.unknown(resp) is reachable from a
// compiled expression and produces the expected fallback shape for a
// response the expression doesn't explicitly branch on.
func TestRevokeNamespace_UnknownHelper(t *testing.T) {
	env, err := New(nil)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}

	prg, err := env.CompileValidation(`revoke.unknown({"status": 429})`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := env.Eval(prg, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	m, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", got)
	}
	if m["result"] != "unknown" {
		t.Errorf("result = %v, want %q", m["result"], "unknown")
	}
	if m["reason"] != "rate limited" {
		t.Errorf("reason = %v, want %q", m["reason"], "rate limited")
	}
}

// TestRevokeExpr_EndToEndHTTPCall proves a realistic revoke expression -
// a DELETE call against a provider endpoint using the secret as a bearer
// token, mirroring the shape a real rule (e.g. Buildkite) would use -
// compiles and evaluates correctly against a mock server, for both the
// success and failure paths.
func TestRevokeExpr_EndToEndHTTPCall(t *testing.T) {
	env, err := New(nil)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}

	const revokeExpr = `let r = http.delete("` + "%s" + `", {"Authorization": "Bearer " + finding["secret"]});
r.status == 204 ? {"result": "revoked"} : r.status in [401, 403] ? {"result": "invalid", "reason": "unauthorized"} : revoke.unknown(r)`

	t.Run("success (204) yields revoked", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				t.Errorf("expected DELETE, got %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer test-secret-123" {
				t.Errorf("Authorization header = %q", got)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		prg, err := env.CompileValidation(sprintfExpr(revokeExpr, srv.URL))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, map[string]string{"secret": "test-secret-123"}, nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		m := got.(map[string]any)
		if m["result"] != "revoked" {
			t.Errorf("result = %v, want \"revoked\"", m["result"])
		}
	})

	t.Run("already-invalid token (401) is not reported as revoked", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		prg, err := env.CompileValidation(sprintfExpr(revokeExpr, srv.URL))
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, map[string]string{"secret": "already-dead"}, nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		m := got.(map[string]any)
		if m["result"] == "revoked" {
			t.Errorf("a 401 must never be reported as revoked - that would be a false success")
		}
	})
}

func sprintfExpr(expr, url string) string {
	// Minimal helper so the revokeExpr template above stays readable;
	// avoids importing fmt just for one call site.
	out := make([]byte, 0, len(expr)+len(url))
	for i := 0; i < len(expr); i++ {
		if i+1 < len(expr) && expr[i] == '%' && expr[i+1] == 's' {
			out = append(out, url...)
			i++
			continue
		}
		out = append(out, expr[i])
	}
	return string(out)
}
