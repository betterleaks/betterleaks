package validate

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplateEngine_Render_SimplePlaceholder(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render("token {{ secret }}", map[string]string{"secret": "abc123"})
	require.NoError(t, err)
	assert.Equal(t, "token abc123", result)
}

func TestTemplateEngine_Render_MultiplePlaceholders(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render("id={{ key_id }}&secret={{ key_secret }}", map[string]string{
		"key_id":     "AKIA123",
		"key_secret": "wJalr456",
	})
	require.NoError(t, err)
	assert.Equal(t, "id=AKIA123&secret=wJalr456", result)
}

func TestTemplateEngine_Render_BackwardCompat(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render("Bearer {{ my-rule-id }}", map[string]string{"my-rule-id": "tok"})
	require.NoError(t, err)
	assert.Equal(t, "Bearer tok", result)
}

func TestTemplateEngine_RenderMap(t *testing.T) {
	e := NewTemplateEngine()
	m := map[string]string{
		"Authorization": "Bearer {{ secret }}",
		"Content-Type":  "application/json",
	}
	result, err := e.RenderMap(m, map[string]string{"secret": "abc"})
	require.NoError(t, err)
	assert.Equal(t, "Bearer abc", result["Authorization"])
	assert.Equal(t, "application/json", result["Content-Type"])
}

func TestTemplateEngine_Filter_B64Enc(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | b64enc }}`, map[string]string{"secret": "hello"})
	require.NoError(t, err)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello")), result)
}

func TestTemplateEngine_Filter_B64Dec(t *testing.T) {
	e := NewTemplateEngine()
	encoded := base64.StdEncoding.EncodeToString([]byte("hello"))
	result, err := e.Render(`{{ secret | b64dec }}`, map[string]string{"secret": encoded})
	require.NoError(t, err)
	assert.Equal(t, "hello", result)
}

func TestTemplateEngine_Filter_URLEncode(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | url_encode }}`, map[string]string{"secret": "a b+c"})
	require.NoError(t, err)
	assert.Equal(t, "a+b%2Bc", result)
}

func TestTemplateEngine_Filter_SHA256(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | sha256 }}`, map[string]string{"secret": "test"})
	require.NoError(t, err)
	assert.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", result)
}

func TestTemplateEngine_Filter_HmacSHA256(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | hmac_sha256: key }}`, map[string]string{
		"secret": "data",
		"key":    "mykey",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Len(t, result, 64) // hex-encoded SHA256 HMAC
}

func TestTemplateEngine_Filter_HmacSHA1(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | hmac_sha1: key }}`, map[string]string{
		"secret": "data",
		"key":    "mykey",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestTemplateEngine_Filter_JsonEscape(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | json_escape }}`, map[string]string{"secret": `a "b" c`})
	require.NoError(t, err)
	assert.Equal(t, `a \"b\" c`, result)
}

func TestTemplateEngine_Filter_Prefix(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | prefix: 4 }}`, map[string]string{"secret": "AKIAIOSFODNN7"})
	require.NoError(t, err)
	assert.Equal(t, "AKIA", result)
}

func TestTemplateEngine_Filter_Suffix(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(`{{ secret | suffix: 3 }}`, map[string]string{"secret": "abcxyz"})
	require.NoError(t, err)
	assert.Equal(t, "xyz", result)
}

func TestTemplateEngine_BasicAuth_Pipeline(t *testing.T) {
	e := NewTemplateEngine()
	result, err := e.Render(
		`Basic {{ secret | prepend: "api:" | b64enc }}`,
		map[string]string{"secret": "sk_test_123"},
	)
	require.NoError(t, err)
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("api:sk_test_123"))
	assert.Equal(t, expected, result)
}

func TestTemplateEngine_Parse_ValidTemplate(t *testing.T) {
	e := NewTemplateEngine()
	err := e.Parse("{{ secret }}")
	assert.NoError(t, err)
}

func TestTemplateEngine_Parse_InvalidTemplate(t *testing.T) {
	e := NewTemplateEngine()
	err := e.Parse("{% if %}")
	assert.Error(t, err)
}
