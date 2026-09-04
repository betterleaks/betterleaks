package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/regexp"
)

func TestResolveConfigIgnoresGitleaksCompatibility(t *testing.T) {
	dir := t.TempDir()
	legacyConfig := filepath.Join(dir, ".gitleaks.toml")
	require.NoError(t, os.WriteFile(legacyConfig, []byte(`title = "legacy"`), 0o600))
	t.Chdir(dir)
	t.Setenv("BETTERLEAKS_CONFIG", "")
	t.Setenv("BETTERLEAKS_CONFIG_TOML", "")
	t.Setenv("GITLEAKS_CONFIG", legacyConfig)
	t.Setenv("GITLEAKS_CONFIG_TOML", `title = "legacy environment"`)

	resolved, err := resolveConfig(&commandRuntime{stderr: io.Discard}, "", "")
	require.NoError(t, err)
	assert.Equal(t, "default", resolved.source)
}

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
