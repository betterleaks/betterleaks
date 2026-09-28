package fingerprint

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint(t *testing.T) {
	abc := Sum([]byte("abc"))
	assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Format(abc))

	parsed, err := Parse("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
	require.NoError(t, err)
	assert.Equal(t, abc, parsed)
	assert.Equal(t, Format(abc), Format(parsed))

	// RFC 4231 test case 1 fixes the HMAC algorithm and encoding independently.
	keyed := SumWithKey([]byte("Hi There"), bytes.Repeat([]byte{0x0b}, 20))
	want := "hmac-sha256:b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	require.Equal(t, want, Format(keyed))
	parsed, err = Parse("hmac-sha256:" + strings.ToUpper(strings.TrimPrefix(want, "hmac-sha256:")))
	require.NoError(t, err)
	require.Equal(t, keyed, parsed)
	require.True(t, keyed.IsHMAC())
	require.False(t, abc.IsHMAC())
	plain, err := Parse(strings.TrimPrefix(want, "hmac-sha256:"))
	require.NoError(t, err)
	require.NotEqual(t, keyed, plain, "the same digest in different modes is not the same ignore entry")
	require.Equal(t, abc, SumWithKey([]byte("abc"), nil))
	require.NotEqual(t, keyed, SumWithKey([]byte("Hi There"), []byte("different key")))
}

func TestLoad(t *testing.T) {
	entry := Format(Sum([]byte("secret")))
	list, diagnostics, err := Load(strings.NewReader(strings.Join([]string{
		"",
		"  # comment",
		entry,
		strings.ToUpper(entry),
		"sha256:" + entry,
		"sha256:abc",
		"hmac-sha256:" + strings.Repeat("0", 64),
		"deadbeef:path:rule:1",
	}, "\n")))

	require.NoError(t, err)
	assert.Equal(t, []Hash{Sum([]byte("secret")), {keyed: true}}, list)
	require.Len(t, diagnostics, 3)
	assert.Equal(t, []int{5, 6, 8}, []int{diagnostics[0].Line, diagnostics[1].Line, diagnostics[2].Line})
}

func TestLoadPreservesOrderAndReadErrors(t *testing.T) {
	first, second := Sum([]byte("first")), Sum([]byte("second"))
	input := "  " + Format(first) + " \r\n# comment\n" + Format(second) + "\n" + Format(first) + "\n"
	hashes, diagnostics, err := Load(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, diagnostics)
	assert.Equal(t, []Hash{first, second}, hashes)
	readErr := errors.New("read failed")
	hashes, diagnostics, err = Load(io.MultiReader(strings.NewReader(input), iotest.ErrReader(readErr)))
	require.ErrorIs(t, err, readErr)
	assert.Empty(t, diagnostics)
	assert.Equal(t, []Hash{first, second}, hashes)
	hashes, diagnostics, err = Load(strings.NewReader("\n# empty policy\n"))
	require.NoError(t, err)
	assert.Empty(t, hashes)
	assert.Empty(t, diagnostics)
}

func TestParseRejectsUnsupportedForms(t *testing.T) {
	for _, entry := range []string{
		"",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("g", 64),
		"sha256:" + strings.Repeat("a", 64),
		"argon2id:anything",
		"hmac-sha256:",
		"hmac-sha256:" + strings.Repeat("g", 64),
	} {
		_, err := Parse(entry)
		assert.Error(t, err, entry)
	}
}
