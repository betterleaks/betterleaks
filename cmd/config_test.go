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
		MinVersion: "v1.8.0",
		Rules: []configpkg.Rule{
			{
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
			{
				RuleID: "component",
				Regex:  regexp.MustCompile("component"),
			},
		},
	}

	rendered := renderConfigTOML(renderConfig(cfg))
	assert.Contains(t, rendered, "minVersion = 'v1.8.0'")
	assert.NotContains(t, rendered, "betterleaksMinVersion")
	assert.Contains(t, rendered, `components = [
  { id = 'component', optional = true, within = '-5L,+2L' },
]`)
	assert.NotContains(t, rendered, "[[rules.required]]")

	parsed, err := configpkg.ParseTOMLString(rendered, "")
	require.NoError(t, err)
	primary, ok := parsed.Rule("primary")
	require.True(t, ok)
	require.Len(t, primary.Components, 1)
	assert.True(t, primary.Components[0].Optional)
	assert.Equal(t, "-5L,+2L", primary.Components[0].Within)
}
