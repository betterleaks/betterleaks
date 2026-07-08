package sources

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// effectiveEnv resolves an env slice the way os/exec does: on duplicate keys,
// the last value wins. This mirrors what git actually sees.
func effectiveEnv(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

// clearGitConfigEnv removes any ambient GIT_CONFIG_* indexed entries so the
// test observes only what gitConfigIsolationEnv adds, restoring them after.
func clearGitConfigEnv(t *testing.T) {
	t.Helper()
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		if k == "GIT_CONFIG_COUNT" ||
			strings.HasPrefix(k, "GIT_CONFIG_KEY_") ||
			strings.HasPrefix(k, "GIT_CONFIG_VALUE_") {
			orig := os.Getenv(k)
			require.NoError(t, os.Unsetenv(k))
			t.Cleanup(func() { _ = os.Setenv(k, orig) })
		}
	}
}

func TestGitConfigIsolationEnvDeltaCache(t *testing.T) {
	t.Run("adds delta-base cache when caller has no indexed config", func(t *testing.T) {
		clearGitConfigEnv(t)

		eff := effectiveEnv(gitConfigIsolationEnv())

		require.Equal(t, "1", eff["GIT_CONFIG_COUNT"])
		require.Equal(t, "core.deltaBaseCacheLimit", eff["GIT_CONFIG_KEY_0"])
		require.Equal(t, "128m", eff["GIT_CONFIG_VALUE_0"])
	})

	t.Run("preserves caller indexed config instead of clobbering it", func(t *testing.T) {
		clearGitConfigEnv(t)
		// Simulate CI-provided config (e.g. an auth header) at index 0.
		t.Setenv("GIT_CONFIG_COUNT", "1")
		t.Setenv("GIT_CONFIG_KEY_0", "http.https://example.com/.extraheader")
		t.Setenv("GIT_CONFIG_VALUE_0", "Authorization: Bearer token")

		eff := effectiveEnv(gitConfigIsolationEnv())

		// The caller's entry at index 0 survives.
		require.Equal(t, "http.https://example.com/.extraheader", eff["GIT_CONFIG_KEY_0"])
		require.Equal(t, "Authorization: Bearer token", eff["GIT_CONFIG_VALUE_0"])
		// Ours lands at the next index, with the count bumped so git reads both.
		require.Equal(t, "2", eff["GIT_CONFIG_COUNT"])
		require.Equal(t, "core.deltaBaseCacheLimit", eff["GIT_CONFIG_KEY_1"])
		require.Equal(t, "128m", eff["GIT_CONFIG_VALUE_1"])
	})

	t.Run("appends after multiple existing caller entries", func(t *testing.T) {
		clearGitConfigEnv(t)
		t.Setenv("GIT_CONFIG_COUNT", "2")
		t.Setenv("GIT_CONFIG_KEY_0", "safe.directory")
		t.Setenv("GIT_CONFIG_VALUE_0", "/repo")
		t.Setenv("GIT_CONFIG_KEY_1", "core.autocrlf")
		t.Setenv("GIT_CONFIG_VALUE_1", "false")

		eff := effectiveEnv(gitConfigIsolationEnv())

		require.Equal(t, "3", eff["GIT_CONFIG_COUNT"])
		require.Equal(t, "core.deltaBaseCacheLimit", eff["GIT_CONFIG_KEY_2"])
		require.Equal(t, "128m", eff["GIT_CONFIG_VALUE_2"])
		// Earlier entries untouched.
		require.Equal(t, "safe.directory", eff["GIT_CONFIG_KEY_0"])
		require.Equal(t, "core.autocrlf", eff["GIT_CONFIG_KEY_1"])
	})
}
