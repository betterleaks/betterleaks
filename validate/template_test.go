package validate

import (
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
