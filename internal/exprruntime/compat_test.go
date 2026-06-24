package exprruntime

import "testing"

func TestCELCompatEval(t *testing.T) {
	env, err := New(nil)
	if err != nil {
		t.Fatalf("exprruntime.New: %v", err)
	}

	tests := []struct {
		name     string
		expr     string
		finding  map[string]string
		captures map[string]string
		want     any
	}{
		{
			name: "base64 decode",
			expr: `hex.encode(base64.decode("aGVsbG8="))`,
			want: "68656c6c6f",
		},
		{
			name:    "substring lastIndexOf",
			expr:    `finding["secret"].substring(finding["secret"].lastIndexOf("-") + 1)`,
			finding: map[string]string{"secret": "key-us19"},
			want:    "us19",
		},
		{
			name: "contains method",
			expr: `cel.bind(r, {"body": "abc"}, r.body.contains("b"))`,
			want: true,
		},
		{
			name: "chained replace",
			expr: `strings.urlQueryEscape("a b+").replace("+", "%20").replace("%2B", "+")`,
			want: "a%20b+",
		},
		{
			name: "nested bind and optional fallback",
			expr: `cel.bind(r, {"json": {"data": {"name": "zed"}}}, r.json.?data.?name.orValue(""))`,
			want: "zed",
		},
		{
			name:     "hmac with decoded capture",
			expr:     `size(crypto.hmac_sha256(base64.decode(captures["secret"]), bytes("msg")))`,
			captures: map[string]string{"secret": "a2V5"},
			want:     32,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prg, err := env.CompileValidation(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := env.Eval(prg, tc.finding, tc.captures)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestNeedsCELCompat(t *testing.T) {
	tests := []struct {
		expr string
		want bool
	}{
		{expr: `filter.matchesAny(finding["secret"], ["sec"])`, want: false},
		{expr: `let r = http.get("https://example.com", {}); r.status == 200`, want: false},
		{expr: `cel.bind(r, {"body": "abc"}, r.body.contains("b"))`, want: true},
		{expr: `r.json.?name.orValue("")`, want: true},
		{expr: `env("TOKEN")`, want: true},
	}

	for _, tc := range tests {
		t.Run(tc.expr, func(t *testing.T) {
			if got := NeedsCELCompat(tc.expr); got != tc.want {
				t.Fatalf("NeedsCELCompat() = %v, want %v", got, tc.want)
			}
		})
	}
}
