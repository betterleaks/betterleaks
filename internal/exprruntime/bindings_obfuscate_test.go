package exprruntime

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestObfuscate(t *testing.T) {
	env, err := New(nil)
	require.NoError(t, err)
	program, err := env.CompileValidation(`strings.obfuscate(finding.secret)`)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, input, prefix, alphabet string
	}{
		{"empty", "", "", ""},
		{"short hex", "abc", "", "0123456789abcdef"},
		{"access key", "AKIAIOSFODNN7EXAMPLE", "", ""},
		{"separator prefix", "sk_live_4eC39HqLyjWDarjtT1zdp7dc", "sk_", ""},
		{"mixed case", "a1B2c3D4e5F6g7H8", "", ""},
		{"short separators", "xx-yy_zz.ww=qq", "", ""},
		{"generic classes", "aA1!bB2_cC3-dD4=eE5.fF6+gG7/hH8?", "aA1!bB2_", ""},
		{"fallback prefix", "abcdef1234567890abcdef1234567890", "abcdef", "0123456789abcdef"},
		{"short secret", "abc-def", "", ""},
		{"unicode prefix", "éééééééééééé3456789012345", "éééééé", ""},
		{"lower hex", "sha256_abcdef0123456789abcdef0123456789", "sha256_", "0123456789abcdef"},
		{"upper hex", "TOKEN.ABCDEF0123456789ABCDEF0123456789", "TOKEN.", "0123456789ABCDEF"},
		{"digits", "token_12345678901234567890", "token_", "0123456789"},
		{"body symbols", "secret.key-with_dots.and=equals", "secret.", ""},
		{"single symbol", "abcdefg-hijklmn", "", ""},
		{"non ASCII", "café-résumé", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix, body := splitPrefix(tc.input)
			require.Equal(t, tc.prefix, prefix)
			require.Equal(t, tc.input, prefix+body)
			require.True(t, utf8.ValidString(prefix) && utf8.ValidString(body))
			value, err := env.Eval(program, map[string]string{"secret": tc.input}, nil)
			require.NoError(t, err)
			got, ok := value.(string)
			require.True(t, ok)
			require.True(t, utf8.ValidString(got))
			require.Len(t, got, len(tc.input))
			require.True(t, strings.HasPrefix(got, tc.prefix))
			gotBody := []rune(strings.TrimPrefix(got, tc.prefix))
			inputBody := []rune(body)
			require.Len(t, gotBody, len(inputBody))
			for i, r := range gotBody {
				if tc.alphabet != "" {
					require.Contains(t, tc.alphabet, string(r))
				} else {
					require.Equal(t, classOf(inputBody[i]), classOf(r), "character %d", i)
					if isSymbol(r) {
						require.Contains(t, body, string(r), "symbols must come from the original body")
					} else if r > 127 {
						require.Equal(t, inputBody[i], r, "non-ASCII characters must be preserved")
					}
				}
			}
		})
	}
	_, err = env.CompileValidation(`strings.obfuscate(finding.secret, 0.0)`)
	require.Error(t, err, "only the unary expression form is supported")
}

func classOf(r rune) string {
	switch {
	case r >= 'a' && r <= 'z':
		return "lower"
	case r >= 'A' && r <= 'Z':
		return "upper"
	case r >= '0' && r <= '9':
		return "digit"
	case isSymbol(r):
		return "symbol"
	default:
		return "other"
	}
}
