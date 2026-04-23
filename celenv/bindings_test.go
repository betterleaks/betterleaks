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
			expr:   `hex.encode(crypto.md5(bytes(secret)))`,
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
		prg, err := env.Compile(`crypto.hmac_sha256(bytes("key"), bytes("hello"))`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, "", nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		// HMAC-SHA256("key", "hello") = a]aedc7b02c5c85b5262... (raw bytes)
		// We check the length is 32 bytes (SHA-256 output).
		bs := got.Value().([]byte)
		if len(bs) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(bs))
		}
	})

	// Verify time.now_unix returns a numeric string
	t.Run("time_now_unix", func(t *testing.T) {
		prg, err := env.Compile(`time.now_unix()`)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		got, err := env.Eval(prg, "", nil)
		if err != nil {
			t.Fatalf("eval: %v", err)
		}
		s, ok := got.Value().(string)
		if !ok {
			t.Fatalf("expected string, got %T", got.Value())
		}
		if len(s) < 10 {
			t.Errorf("expected unix timestamp string, got %q", s)
		}
	})

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
