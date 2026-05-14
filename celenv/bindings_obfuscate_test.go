package celenv

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestObfuscate_emptyStringPassesThrough(t *testing.T) {
	require.Equal(t, "", obfuscate(""))
}

func TestObfuscate_preservesLength(t *testing.T) {
	cases := []string{
		"abc",
		"AKIAIOSFODNN7EXAMPLE",
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"a1B2c3D4e5F6g7H8",
		"xx-yy_zz.ww=qq",
	}
	for _, in := range cases {
		got := obfuscate(in)
		require.Len(t, got, len(in), "length mismatch for %q -> %q", in, got)
	}
}

func TestObfuscate_preservesGenericAlphabetClass(t *testing.T) {
	const in = "aA1!bB2_cC3-dD4=eE5.fF6+gG7/hH8?"
	got := obfuscate(in)
	require.Len(t, got, len(in))

	prefix, _ := splitPrefix(in)
	for i := range in {
		if i < len(prefix) {
			require.Equal(t, in[i], got[i], "prefix byte %d changed", i)
			continue
		}

		r := rune(in[i])
		o := rune(got[i])
		require.Equalf(t, classOf(r), classOf(o),
			"position %d: input %q class %s, output %q class %s",
			i, string(r), classOf(r), string(o), classOf(o))
	}
}

func TestObfuscate_preservesSeparatorPrefix(t *testing.T) {
	const in = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	got := obfuscate(in)
	require.True(t, strings.HasPrefix(got, "sk_"))
	require.Len(t, got, len(in))
}

func TestObfuscate_preservesFallbackPrefix(t *testing.T) {
	const in = "abcdef1234567890abcdef1234567890"
	got := obfuscate(in)
	require.True(t, strings.HasPrefix(got, "abcdef"))
	require.Len(t, got, len(in))
}

func TestObfuscate_shortSecretHasNoPrefix(t *testing.T) {
	prefix, body := splitPrefix("abc-def")
	require.Empty(t, prefix)
	require.Equal(t, "abc-def", body)
}

func TestObfuscate_splitPrefixPreservesUTF8(t *testing.T) {
	const in = "éééééééééééé3456789012345"

	prefix, body := splitPrefix(in)
	require.Equal(t, "éééééé", prefix)
	require.True(t, utf8.ValidString(prefix))
	require.True(t, utf8.ValidString(body))

	got := obfuscate(in)
	require.True(t, utf8.ValidString(got))
	require.Len(t, []rune(got), len([]rune(in)))
}

func TestObfuscate_lowerHexBodyStaysHex(t *testing.T) {
	const in = "sha256_abcdef0123456789abcdef0123456789"
	got := obfuscate(in)
	require.True(t, strings.HasPrefix(got, "sha256_"))
	for _, r := range strings.TrimPrefix(got, "sha256_") {
		require.Truef(t, (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'),
			"output rune %q is not lower hex", string(r))
	}
}

func TestObfuscate_upperHexBodyStaysHex(t *testing.T) {
	const in = "TOKEN.ABCDEF0123456789ABCDEF0123456789"
	got := obfuscate(in)
	require.True(t, strings.HasPrefix(got, "TOKEN."))
	for _, r := range strings.TrimPrefix(got, "TOKEN.") {
		require.Truef(t, (r >= '0' && r <= '9') || (r >= 'A' && r <= 'F'),
			"output rune %q is not upper hex", string(r))
	}
}

func TestObfuscate_allDigitBodyIsNotHex(t *testing.T) {
	require.Empty(t, hexPool("1234567890"))

	const in = "token_12345678901234567890"
	got := obfuscate(in)
	require.True(t, strings.HasPrefix(got, "token_"))
	for _, r := range strings.TrimPrefix(got, "token_") {
		require.Truef(t, r >= '0' && r <= '9',
			"output rune %q is not a digit", string(r))
	}
}

func TestObfuscate_symbolsStayInBodySymbolSet(t *testing.T) {
	const in = "secret.key-with_dots.and=equals"
	got := obfuscate(in)
	prefix, body := splitPrefix(in)
	gotBody := strings.TrimPrefix(got, prefix)

	allowed := map[rune]bool{}
	for _, r := range body {
		if isSymbol(r) {
			allowed[r] = true
		}
	}
	require.GreaterOrEqual(t, len(allowed), 2,
		"test fixture must contain at least 2 distinct body symbols")

	for _, r := range gotBody {
		if isSymbol(r) {
			require.Truef(t, allowed[r],
				"output symbol %q not in body symbol set", string(r))
		}
	}
}

func TestObfuscate_singleSymbolStaysPut(t *testing.T) {
	const in = "abcdefg-hijklmn"
	got := obfuscate(in)
	require.Equal(t, "-", string(got[7]))
}

func TestObfuscate_nonAsciiPassesThrough(t *testing.T) {
	const in = "café-résumé"
	got := obfuscate(in)
	require.Equal(t, len([]rune(in)), len([]rune(got)))
	require.Contains(t, got, "é")
}

func TestObfuscate_celBindingUnary(t *testing.T) {
	env, err := NewEnvironment(nil)
	require.NoError(t, err)

	prg, err := env.Compile(`obfuscate(finding["secret"])`)
	require.NoError(t, err)

	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	got, err := env.Eval(prg, map[string]string{"secret": secret}, nil)
	require.NoError(t, err)

	out, ok := got.Value().(string)
	require.True(t, ok)
	require.Len(t, out, len(secret))
	require.True(t, strings.HasPrefix(out, "sk_"))
}

func TestObfuscate_celBindingRejectsBinaryForm(t *testing.T) {
	env, err := NewEnvironment(nil)
	require.NoError(t, err)

	_, err = env.Compile(`obfuscate(finding["secret"], 0.0)`)
	require.Error(t, err)
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
