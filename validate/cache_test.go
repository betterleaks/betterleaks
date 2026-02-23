package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseCache_GetSet(t *testing.T) {
	c := NewResponseCache()

	key := c.Key("POST", "http://example.com", map[string]string{"Auth": "token"}, "body")

	_, ok := c.Get(key)
	assert.False(t, ok)

	resp := &CachedResponse{StatusCode: 200, Body: []byte("ok")}
	c.Set(key, resp)

	got, ok := c.Get(key)
	require.True(t, ok)
	assert.Equal(t, 200, got.StatusCode)
	assert.Equal(t, []byte("ok"), got.Body)
}

func TestResponseCache_KeyDeterminism(t *testing.T) {
	c := NewResponseCache()

	k1 := c.Key("GET", "http://a.com", map[string]string{"X": "1", "Y": "2"}, "b")
	k2 := c.Key("GET", "http://a.com", map[string]string{"Y": "2", "X": "1"}, "b")
	assert.Equal(t, k1, k2, "keys should be the same regardless of header order")
}

func TestResponseCache_KeyUniqueness(t *testing.T) {
	c := NewResponseCache()

	k1 := c.Key("GET", "http://a.com", nil, "body1")
	k2 := c.Key("GET", "http://a.com", nil, "body2")
	assert.NotEqual(t, k1, k2)

	k3 := c.Key("POST", "http://a.com", nil, "body1")
	assert.NotEqual(t, k1, k3)
}

func TestResponseCache_Size(t *testing.T) {
	c := NewResponseCache()
	assert.Equal(t, 0, c.Size())

	c.Set("a", &CachedResponse{StatusCode: 200})
	c.Set("b", &CachedResponse{StatusCode: 201})
	assert.Equal(t, 2, c.Size())
}
