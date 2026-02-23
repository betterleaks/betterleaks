package validate

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlaceholderIDs(t *testing.T) {
	tmpl := "client_id={{ my.client-id }}&secret={{ my.secret }}&dup={{ my.client-id }}"
	ids := PlaceholderIDs(tmpl)
	assert.Equal(t, []string{"my.client-id", "my.secret"}, ids)
}

func TestPlaceholderIDs_None(t *testing.T) {
	ids := PlaceholderIDs("no placeholders here")
	assert.Empty(t, ids)
}

func TestRender(t *testing.T) {
	tmpl := "id={{ rule.id }}&secret={{ rule.secret }}"
	result := Render(tmpl, map[string]string{
		"rule.id":     "abc123",
		"rule.secret": "s3cret",
	})
	assert.Equal(t, "id=abc123&secret=s3cret", result)
}

func TestRender_UnknownPlaceholder(t *testing.T) {
	tmpl := "id={{ rule.id }}&secret={{ rule.unknown }}"
	result := Render(tmpl, map[string]string{
		"rule.id": "abc",
	})
	assert.Equal(t, "id=abc&secret={{ rule.unknown }}", result)
}

func TestExpand_SingleID(t *testing.T) {
	tmpl := "secret={{ rule.secret }}"
	results := Expand(tmpl, map[string][]string{
		"rule.secret": {"s1", "s2", "s3"},
	})
	sort.Strings(results)
	assert.Equal(t, []string{"secret=s1", "secret=s2", "secret=s3"}, results)
}

func TestExpand_CartesianProduct(t *testing.T) {
	tmpl := "id={{ rule.id }}&secret={{ rule.secret }}"
	results := Expand(tmpl, map[string][]string{
		"rule.id":     {"id1", "id2"},
		"rule.secret": {"s1", "s2"},
	})
	sort.Strings(results)
	expected := []string{
		"id=id1&secret=s1",
		"id=id1&secret=s2",
		"id=id2&secret=s1",
		"id=id2&secret=s2",
	}
	sort.Strings(expected)
	assert.Equal(t, expected, results)
}

func TestExpand_NoPlaceholders(t *testing.T) {
	results := Expand("static-string", map[string][]string{})
	assert.Equal(t, []string{"static-string"}, results)
}

func TestExpand_MissingSecrets(t *testing.T) {
	tmpl := "id={{ rule.id }}&secret={{ rule.secret }}"
	results := Expand(tmpl, map[string][]string{
		"rule.id": {"id1"},
	})
	assert.Equal(t, []string{"id=id1&secret={{ rule.secret }}"}, results)
}

func TestRenderMap(t *testing.T) {
	m := map[string]string{
		"Authorization": "Bearer {{ rule.token }}",
		"Content-Type":  "application/json",
	}
	result := RenderMap(m, map[string]string{"rule.token": "abc123"})
	assert.Equal(t, "Bearer abc123", result["Authorization"])
	assert.Equal(t, "application/json", result["Content-Type"])
}

func TestCombos(t *testing.T) {
	combos := Combos(
		[]string{"rule.id", "rule.secret"},
		map[string][]string{
			"rule.id":     {"id1", "id2"},
			"rule.secret": {"s1"},
		},
	)
	assert.Len(t, combos, 2)
	for _, c := range combos {
		assert.Contains(t, c, "rule.id")
		assert.Contains(t, c, "rule.secret")
		assert.Equal(t, "s1", c["rule.secret"])
	}
}

func TestCombos_NoActiveIDs(t *testing.T) {
	combos := Combos([]string{"missing"}, map[string][]string{})
	assert.Len(t, combos, 1)
	assert.Empty(t, combos[0])
}

func TestCombos_EmptyIDs(t *testing.T) {
	combos := Combos(nil, map[string][]string{"x": {"1"}})
	assert.Len(t, combos, 1)
	assert.Empty(t, combos[0])
}
