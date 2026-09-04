package fingerprint

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint(t *testing.T) {
	abc := Sum([]byte("abc"))
	assert.Equal(t, "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Format(abc))

	parsed, err := Parse("sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
	require.NoError(t, err)
	assert.Equal(t, abc, parsed)
	assert.Equal(t, Format(abc), Format(parsed))
}

func TestLoad(t *testing.T) {
	entry := Format(Sum([]byte("secret")))
	list, diagnostics, err := Load(strings.NewReader(strings.Join([]string{
		"",
		"  # comment",
		entry,
		Prefix + strings.ToUpper(strings.TrimPrefix(entry, Prefix)),
		strings.TrimPrefix(entry, Prefix),
		"sha256:abc",
		"hmac-sha256:" + strings.Repeat("0", 64),
		"deadbeef:path:rule:1",
	}, "\n")))

	require.NoError(t, err)
	assert.Equal(t, 1, list.Len())
	assert.Equal(t, "sha256(finding[\"secret\"]) in [\n  \""+entry+"\",\n]", list.FilterExpression())
	require.Len(t, diagnostics, 4)
	assert.Equal(t, []int{5, 6, 7, 8}, []int{diagnostics[0].Line, diagnostics[1].Line, diagnostics[2].Line, diagnostics[3].Line})
}

func TestParseRejectsUnsupportedForms(t *testing.T) {
	for _, entry := range []string{
		strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("g", 64),
		"argon2id:anything",
	} {
		_, err := Parse(entry)
		assert.Error(t, err, entry)
	}
}
