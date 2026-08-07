package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configpkg "github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/regexp"
)

func TestRenderConfigTOMLComponents(t *testing.T) {
	cfg := &configpkg.Config{
		Rules: map[string]configpkg.Rule{
			"primary": {
				RuleID: "primary",
				Regex:  regexp.MustCompile("primary"),
				Components: []*configpkg.Component{
					{
						RuleID:   "component",
						Optional: true,
						Within:   "-5L,+2L",
					},
				},
			},
			"component": {
				RuleID: "component",
				Regex:  regexp.MustCompile("component"),
			},
		},
		OrderedRules: []string{"primary", "component"},
	}

	rendered := renderConfigTOML(renderConfig(cfg))
	assert.Contains(t, rendered, `components = [
  { id = 'component', optional = true, within = '-5L,+2L' },
]`)
	assert.NotContains(t, rendered, "[[rules.required]]")

	parsed, err := configpkg.ParseTOMLString(rendered, "")
	require.NoError(t, err)
	require.Len(t, parsed.Rules["primary"].Components, 1)
	assert.True(t, parsed.Rules["primary"].Components[0].Optional)
	assert.Equal(t, "-5L,+2L", parsed.Rules["primary"].Components[0].Within)
}

func TestRenderConfigTOMLMigratesLegacyRequired(t *testing.T) {
	cfg, err := configpkg.ParseTOMLString(`
[[rules]]
id = "primary"
regex = "primary"
[[rules.required]]
id = "component"

[[rules]]
id = "component"
regex = "component"
`, "")
	require.NoError(t, err)

	rendered := renderConfigTOML(renderConfig(cfg))
	assert.Contains(t, rendered, "components = [")
	assert.NotContains(t, rendered, "optional = true")
	assert.NotContains(t, rendered, "[[rules.required]]")
}
