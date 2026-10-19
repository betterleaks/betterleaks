package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigDiscoveryRequiresOptIn(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		autoLoad bool
		wantRule string
		wantPath string
	}{
		{name: "no local config", wantRule: "github-pat"},
		{
			name:     "betterleaks config ignored by default",
			files:    map[string]string{".betterleaks.toml": configLoadingTestTOML("local")},
			wantRule: "github-pat",
		},
		{
			name:     "gitleaks config ignored by default",
			files:    map[string]string{".gitleaks.toml": configLoadingTestTOML("local")},
			wantRule: "github-pat",
		},
		{
			name:     "malformed betterleaks config ignored by default",
			files:    map[string]string{".betterleaks.toml": "invalid TOML ["},
			wantRule: "github-pat",
		},
		{
			name:     "malformed gitleaks config ignored by default",
			files:    map[string]string{".gitleaks.toml": "invalid TOML ["},
			wantRule: "github-pat",
		},
		{
			name:     "betterleaks config with opt-in",
			files:    map[string]string{".betterleaks.toml": configLoadingTestTOML("local")},
			autoLoad: true,
			wantRule: "local",
			wantPath: ".betterleaks.toml",
		},
		{
			name:     "gitleaks config with opt-in",
			files:    map[string]string{".gitleaks.toml": configLoadingTestTOML("local")},
			autoLoad: true,
			wantRule: "local",
			wantPath: ".gitleaks.toml",
		},
		{
			name: "betterleaks takes precedence over gitleaks with opt-in",
			files: map[string]string{
				".betterleaks.toml": configLoadingTestTOML("local"),
				".gitleaks.toml":    "invalid TOML [",
			},
			autoLoad: true,
			wantRule: "local",
			wantPath: ".betterleaks.toml",
		},
		{name: "opt-in without local config", autoLoad: true, wantRule: "github-pat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupConfigLoadingTest(t)
			if tt.autoLoad {
				require.NoError(t, rootCmd.Flags().Set("unsafe-auto-load-config", "true"))
			}
			for path, content := range tt.files {
				require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
			}
			wantSource := tt.wantPath
			if wantSource == "" {
				wantSource = "default"
			}
			assertConfigSelection(t, tt.wantRule, tt.wantPath, wantSource)

			// Each directory target must resolve independently, including the
			// config path used to exclude the loaded file from scanning.
			initConfig(t.TempDir())
			assert.Empty(t, resolvedConfigPath)
			assert.Contains(t, loadedConfig.Rules, "github-pat")
		})
	}
}

func TestExplicitConfigPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		configFlag string
		env        map[string]string
		wantRule   string
		wantPath   string
		wantSource string
	}{
		{
			name: "config flag", configFlag: "flag.toml",
			env: map[string]string{
				"BETTERLEAKS_CONFIG": "better-env.toml", "GITLEAKS_CONFIG": "legacy-env.toml",
				"BETTERLEAKS_CONFIG_TOML": configLoadingTestTOML("better-inline"),
				"GITLEAKS_CONFIG_TOML":    configLoadingTestTOML("legacy-inline"),
			},
			wantRule: "flag", wantPath: "flag.toml", wantSource: "flag.toml",
		},
		{
			name: "betterleaks config env path",
			env: map[string]string{
				"BETTERLEAKS_CONFIG": "better-env.toml", "GITLEAKS_CONFIG": "legacy-env.toml",
				"BETTERLEAKS_CONFIG_TOML": configLoadingTestTOML("better-inline"),
			},
			wantRule: "better-env", wantPath: "better-env.toml", wantSource: "env:BETTERLEAKS_CONFIG:better-env.toml",
		},
		{
			name: "legacy config env path",
			env: map[string]string{
				"GITLEAKS_CONFIG":         "legacy-env.toml",
				"BETTERLEAKS_CONFIG_TOML": configLoadingTestTOML("better-inline"),
			},
			wantRule: "legacy-env", wantPath: "legacy-env.toml", wantSource: "env:GITLEAKS_CONFIG:legacy-env.toml",
		},
		{
			name: "betterleaks inline env config",
			env: map[string]string{
				"BETTERLEAKS_CONFIG_TOML": configLoadingTestTOML("better-inline"),
				"GITLEAKS_CONFIG_TOML":    configLoadingTestTOML("legacy-inline"),
			},
			wantRule: "better-inline", wantSource: "env:BETTERLEAKS_CONFIG_TOML",
		},
		{
			name: "legacy inline env config",
			env: map[string]string{
				"GITLEAKS_CONFIG_TOML": configLoadingTestTOML("legacy-inline"),
			},
			wantRule: "legacy-inline", wantSource: "env:GITLEAKS_CONFIG_TOML",
		},
	}
	for _, tt := range tests {
		for _, autoLoad := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/auto-load=%t", tt.name, autoLoad), func(t *testing.T) {
				setupConfigLoadingTest(t)
				require.NoError(t, rootCmd.Flags().Set("unsafe-auto-load-config", strconv.FormatBool(autoLoad)))
				require.NoError(t, rootCmd.Flags().Set("config", tt.configFlag))
				for name, value := range tt.env {
					t.Setenv(name, value)
				}
				for _, id := range []string{"flag", "better-env", "legacy-env", "positional"} {
					require.NoError(t, os.WriteFile(id+".toml", []byte(configLoadingTestTOML(id)), 0o600))
				}
				require.NoError(t, os.WriteFile(".betterleaks.toml", []byte("invalid TOML ["), 0o600))
				assertConfigSelection(t, tt.wantRule, tt.wantPath, tt.wantSource)

				resolved, err := resolveConfig(rootCmd, []string{"positional.toml"})
				require.NoError(t, err)
				assert.Contains(t, resolved.cfg.Rules, "positional")
				assert.Equal(t, "positional.toml", resolved.source)
			})
		}
	}
}

func TestInitConfigFileTarget(t *testing.T) {
	for _, autoLoad := range []bool{false, true} {
		t.Run(strconv.FormatBool(autoLoad), func(t *testing.T) {
			setupConfigLoadingTest(t)
			require.NoError(t, rootCmd.Flags().Set("unsafe-auto-load-config", strconv.FormatBool(autoLoad)))
			require.NoError(t, os.WriteFile(".betterleaks.toml", []byte("invalid TOML ["), 0o600))
			initConfig(filepath.Join(".", ".betterleaks.toml"))
			assert.Empty(t, resolvedConfigPath)
			assert.Contains(t, loadedConfig.Rules, "github-pat")
		})
	}
}

func setupConfigLoadingTest(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	for _, name := range []string{"BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG", "BETTERLEAKS_CONFIG_TOML", "GITLEAKS_CONFIG_TOML"} {
		t.Setenv(name, "")
	}
	require.NoError(t, rootCmd.ParseFlags(nil))
	for _, name := range []string{"config", "unsafe-auto-load-config", "no-banner"} {
		flag := rootCmd.Flags().Lookup(name)
		require.NotNil(t, flag)
		value, changed := flag.Value.String(), flag.Changed
		t.Cleanup(func() {
			require.NoError(t, flag.Value.Set(value))
			flag.Changed = changed
		})
		require.NoError(t, rootCmd.Flags().Set(name, flag.DefValue))
	}
	require.NoError(t, rootCmd.Flags().Set("no-banner", "true"))
	previousConfig, previousPath, previousBanner := loadedConfig, resolvedConfigPath, bannerPrinted
	t.Cleanup(func() {
		loadedConfig, resolvedConfigPath, bannerPrinted = previousConfig, previousPath, previousBanner
	})
}

func configLoadingTestTOML(ruleID string) string {
	return fmt.Sprintf("[[rules]]\nid = %q\nregex = 'config-test-secret'\n", ruleID)
}

func assertConfigSelection(t *testing.T, wantRule, wantPath, wantSource string) {
	t.Helper()
	initConfig(".")
	cfg := Config(rootCmd)
	assert.Contains(t, cfg.Rules, wantRule)
	assert.Equal(t, wantPath, cfg.Path)

	resolved, err := resolveConfig(rootCmd, nil)
	require.NoError(t, err)
	assert.Contains(t, resolved.cfg.Rules, wantRule)
	assert.Equal(t, wantSource, resolved.source)
}
