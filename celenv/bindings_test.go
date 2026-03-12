package celenv

import (
	"testing"
)

func TestBindings(t *testing.T) {
	env, err := NewEnvironment(nil)
	if err != nil {
		t.Fatalf("NewEnvironment: %v", err)
	}

	tests := []struct {
		name   string
		expr   string
		secret string
		want   string
	}{
		{
			name: "md5 literal",
			expr: `md5("hello")`,
			want: "5d41402abc4b2a76b9719d911017c592",
		},
		{
			name: "md5 empty string",
			expr: `md5("")`,
			want: "d41d8cd98f00b204e9800998ecf8427e",
		},
		{
			name:   "md5 secret variable",
			expr:   `md5(secret)`,
			secret: "test123",
			want:   "cc03e747a6afbbcbf8be7668acfebee5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prg, err := env.Compile(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			got, err := env.Eval(prg, tc.secret, nil)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}

			if got.Value() != tc.want {
				t.Errorf("got %v, want %s", got.Value(), tc.want)
			}
		})
	}
}
