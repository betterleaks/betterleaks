package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
)

func TestResultCache_GetSet(t *testing.T) {
	c := NewResultCache()

	key := c.Key("test.rule", map[string][]string{
		"secret": {"my-secret"},
	})

	_, ok := c.Get(key)
	assert.False(t, ok)

	result := &CachedResult{Status: report.ValidationValid, Note: "match[0] (valid)"}
	c.Set(key, result)

	got, ok := c.Get(key)
	require.True(t, ok)
	assert.Equal(t, report.ValidationValid, got.Status)
	assert.Equal(t, "match[0] (valid)", got.Note)
}

func TestResultCache_KeyDeterminism(t *testing.T) {
	c := NewResultCache()

	secrets := map[string][]string{
		"secret": {"s1"},
		"token":  {"t1"},
	}
	k1 := c.Key("rule.a", secrets)

	// Same data, different map iteration order shouldn't matter
	// (Go maps are unordered, but Key sorts keys internally)
	k2 := c.Key("rule.a", map[string][]string{
		"token":  {"t1"},
		"secret": {"s1"},
	})
	assert.Equal(t, k1, k2, "keys should be the same regardless of map iteration order")
}

func TestResultCache_KeyUniqueness(t *testing.T) {
	c := NewResultCache()

	k1 := c.Key("rule.a", map[string][]string{"secret": {"s1"}})
	k2 := c.Key("rule.a", map[string][]string{"secret": {"s2"}})
	assert.NotEqual(t, k1, k2, "different secrets should produce different keys")

	k3 := c.Key("rule.b", map[string][]string{"secret": {"s1"}})
	assert.NotEqual(t, k1, k3, "different rule IDs should produce different keys")
}

func TestResultCache_KeyCompositeRule(t *testing.T) {
	c := NewResultCache()

	// Same primary secret, different required-finding secrets
	k1 := c.Key("composite.rule", map[string][]string{
		"secret":   {"primary"},
		"dep.rule": {"dep-val-a"},
	})
	k2 := c.Key("composite.rule", map[string][]string{
		"secret":   {"primary"},
		"dep.rule": {"dep-val-b"},
	})
	assert.NotEqual(t, k1, k2, "different required-finding secrets should produce different keys")
}

func TestResultCache_Size(t *testing.T) {
	c := NewResultCache()
	assert.Equal(t, 0, c.Size())

	c.Set("a", &CachedResult{Status: report.ValidationValid})
	c.Set("b", &CachedResult{Status: report.ValidationInvalid})
	assert.Equal(t, 2, c.Size())
}
