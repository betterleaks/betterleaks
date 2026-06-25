package validate

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/internal/exprruntime"
)

func TestPoolDebugMetadata(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("X-Trace", "seen")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"debug":true}`))
	}))
	defer srv.Close()

	rt, err := exprruntime.New(srv.Client())
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}
	prg, err := rt.CompileValidation(`let r = http.get("` + srv.URL + `", {}); {"result": "valid", "status": r.status}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	p := NewPool(1, rt)
	defer p.Close()
	p.Debug = true

	finding := map[string]string{"secret": "secret"}
	result, err := p.evalWithCaptures(prg, "rule", "secret", finding, nil, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if result.Metadata["status"] != int64(http.StatusAccepted) {
		t.Fatalf("status metadata = %v", result.Metadata["status"])
	}
	if result.Metadata["resp_status"] != int64(http.StatusAccepted) {
		t.Fatalf("resp_status metadata = %v", result.Metadata["resp_status"])
	}
	if result.Metadata["resp_header_x-trace"] != "seen" {
		t.Fatalf("resp_header_x-trace = %v", result.Metadata["resp_header_x-trace"])
	}
	if result.Metadata["resp_body"] != `{"debug":true}` {
		t.Fatalf("resp_body = %v", result.Metadata["resp_body"])
	}

	if _, err := p.evalWithCaptures(prg, "rule", "secret", finding, nil, nil); err != nil {
		t.Fatalf("second eval: %v", err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("debug validation requests = %d, want 2", got)
	}
}
