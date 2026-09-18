package cmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/v2/config"
	blfingerprint "github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
)

type fakeTerminal struct{ io.Reader }

func (fakeTerminal) Fd() uintptr { return 42 }

func TestFingerprintCommandHashesExactPipedBytes(t *testing.T) {
	input := " secret \n"
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	err := (&FingerprintCmd{}).Run(&commandRuntime{
		Context: context.Background(),
		stdin:   strings.NewReader(input),
		stdout:  stdout,
		stderr:  stderr,
	})
	require.NoError(t, err)
	assert.Equal(t, blfingerprint.Format(blfingerprint.Sum([]byte(input)))+"\n", stdout.String())
	assert.Empty(t, stderr.String())
}

func TestFingerprintTerminalInputUsesHiddenReader(t *testing.T) {
	stderr := new(bytes.Buffer)
	secret, err := readFingerprintInput(
		fakeTerminal{strings.NewReader("ignored")},
		stderr,
		func(int) bool { return true },
		func(fd int) ([]byte, error) {
			assert.Equal(t, 42, fd)
			return []byte("hidden"), nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, []byte("hidden"), secret)
	assert.Equal(t, "Secret: \n", stderr.String())
}

func TestFingerprintCommandRejectsInvalidInputAndPositionalSecret(t *testing.T) {
	for _, input := range []string{"", strings.Repeat("x", maxFingerprintBytes+1)} {
		stdout := new(bytes.Buffer)
		err := (&FingerprintCmd{}).Run(&commandRuntime{
			Context: context.Background(),
			stdin:   strings.NewReader(input),
			stdout:  stdout,
			stderr:  io.Discard,
		})
		assert.Error(t, err)
		assert.Empty(t, stdout.String())
	}

	_, err := parseCLIForTest(t, "fingerprint", "secret")
	assert.Error(t, err)
}

func ignoreTestConfig() *config.Config {
	return &config.Config{Rules: []config.Rule{{ID: "secret", Regex: `secret-[a-z]+`}}}
}

func writeIgnore(t *testing.T, dir, secret string) string {
	t.Helper()
	path := filepath.Join(dir, ".betterleaksignore")
	err := os.WriteFile(path, []byte(blfingerprint.Format(blfingerprint.Sum([]byte(secret)))+"\n"), 0o600)
	require.NoError(t, err)
	return path
}

func scannerWithIgnoredFingerprints(t *testing.T, cfg *config.Config, hashes []blfingerprint.Hash) *scan.Scanner {
	t.Helper()
	scanner, err := scan.New(cfg, scan.WithIgnoredFingerprints(hashes...))
	require.NoError(t, err)
	return scanner
}

func TestIgnoreFileDiscovery(t *testing.T) {
	t.Run("target root", func(t *testing.T) {
		dir := t.TempDir()
		writeIgnore(t, dir, "secret-root")
		cfg := ignoreTestConfig()
		hashes, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, "", dir)
		require.NoError(t, err)
		assert.Empty(t, scannerWithIgnoredFingerprints(t, cfg, hashes).ScanString("secret-root"))
	})

	t.Run("single file parent", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "input.txt")
		require.NoError(t, os.WriteFile(file, []byte("secret-file"), 0o600))
		writeIgnore(t, dir, "secret-file")
		cfg := ignoreTestConfig()
		hashes, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, "", file)
		require.NoError(t, err)
		assert.Empty(t, scannerWithIgnoredFingerprints(t, cfg, hashes).ScanString("secret-file"))
	})

	t.Run("cwd", func(t *testing.T) {
		dir := t.TempDir()
		writeIgnore(t, dir, "secret-cwd")
		t.Chdir(dir)
		cfg := ignoreTestConfig()
		hashes, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, "", "")
		require.NoError(t, err)
		assert.Empty(t, scannerWithIgnoredFingerprints(t, cfg, hashes).ScanString("secret-cwd"))
	})

	t.Run("absent default", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte("ignored"), 0o600))
		cfg := ignoreTestConfig()
		hashes, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, "", dir)
		require.NoError(t, err)
		assert.Empty(t, hashes)
		assert.Empty(t, cfg.Filter)
	})
}

func TestExplicitIgnoreOverridesEveryTarget(t *testing.T) {
	one := t.TempDir()
	two := t.TempDir()
	writeIgnore(t, one, "secret-one")
	writeIgnore(t, two, "secret-two")
	explicitDir := t.TempDir()
	explicit := writeIgnore(t, explicitDir, "secret-shared")

	for _, target := range []string{one, two} {
		cfg := ignoreTestConfig()
		hashes, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, explicit, target)
		require.NoError(t, err)
		scanner := scannerWithIgnoredFingerprints(t, cfg, hashes)
		assert.Empty(t, scanner.ScanString("secret-shared"))
		assert.NotEmpty(t, scanner.ScanString("secret-one secret-two"))
	}
}

func TestIgnoreFileComposesWithGlobalFilter(t *testing.T) {
	dir := t.TempDir()
	writeIgnore(t, dir, "secret-fingerprint")
	cfg := ignoreTestConfig()
	cfg.Filter = "finding[\"secret\"] == \"secret-config\""

	hashes, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, "", dir)
	require.NoError(t, err)
	scanner := scannerWithIgnoredFingerprints(t, cfg, hashes)

	assert.Empty(t, scanner.ScanString("secret-config secret-fingerprint"))
	assert.NotEmpty(t, scanner.ScanString("secret-visible"))
	assert.Equal(t, "finding[\"secret\"] == \"secret-config\"", cfg.Filter)
}

func TestIgnorePoliciesDoNotLeakBetweenDetectors(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	writeIgnore(t, first, "secret-first")
	writeIgnore(t, second, "secret-second")
	cfg := ignoreTestConfig()
	for _, target := range []struct{ path, ignored, visible string }{
		{first, "secret-first", "secret-second"},
		{second, "secret-second", "secret-first"},
	} {
		hashes, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, "", target.path)
		require.NoError(t, err)
		scanner := scannerWithIgnoredFingerprints(t, cfg, hashes)
		assert.Empty(t, scanner.ScanString(target.ignored))
		assert.Len(t, scanner.ScanString(target.visible), 1)
		assert.Empty(t, cfg.Filter)
	}
}

func TestIgnoreFileErrorsAndDiagnostics(t *testing.T) {
	_, _, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, filepath.Join(t.TempDir(), "missing"), "")
	require.ErrorContains(t, err, "open")

	dir := t.TempDir()
	path := writeIgnore(t, dir, "secret-valid")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = file.WriteString("legacy:path:rule:1\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())

	stderr := new(bytes.Buffer)
	cfg := ignoreTestConfig()
	hashes, _, err := readIgnoreFile(&commandRuntime{stderr: stderr}, path, dir)
	require.NoError(t, err)
	assert.Contains(t, stderr.String(), path+":2:")
	assert.Empty(t, scannerWithIgnoredFingerprints(t, cfg, hashes).ScanString("secret-valid"))

	if runtime.GOOS != "windows" {
		unreadable := filepath.Join(t.TempDir(), "ignore")
		require.NoError(t, os.WriteFile(unreadable, []byte("ignored"), 0o000))
		defer os.Chmod(unreadable, 0o600)
		_, _, err = readIgnoreFile(&commandRuntime{stderr: io.Discard}, unreadable, "")
		assert.Error(t, err)
	}
}

func TestSourceAndFindingFilters(t *testing.T) {
	dir := t.TempDir()
	path := writeIgnore(t, dir, "secret-value")
	cfg := ignoreTestConfig()
	cfg.Path = filepath.Join(dir, "rules.toml")
	cfg.Prefilter = `startsWithAny(attributes.path, ["archived/"])`
	filters := loadScanFilters(&commandRuntime{stderr: io.Discard}, cfg, "", dir)

	for _, excluded := range []string{path, ".betterleaksignore", cfg.Path, "archived/test.env"} {
		assert.True(t, filters.shouldSkip(map[string]string{sources.AttrPath: excluded}), excluded)
	}
	assert.False(t, filters.shouldSkip(map[string]string{sources.AttrPath: "kept.env"}))
	scanner := scannerWithIgnoredFingerprints(t, cfg, filters.fingerprints)
	assert.Empty(t, scanner.ScanString("secret-value"))
	assert.Len(t, scanner.ScanString("secret-visible"), 1)

	remote := loadScanFilters(&commandRuntime{stderr: io.Discard}, ignoreTestConfig(), path, "")
	assert.Nil(t, remote.shouldSkip)
	assert.Equal(t, filters.fingerprints, remote.fingerprints)
}

func TestActiveIgnoreFileIsExcluded(t *testing.T) {
	dir := t.TempDir()
	path := writeIgnore(t, dir, "secret-value")
	_, excluded, err := readIgnoreFile(&commandRuntime{stderr: io.Discard}, "", dir)
	require.NoError(t, err)
	skip, err := prefilter.Compile("", prefilter.Options{ExcludedPaths: excluded})
	require.NoError(t, err)
	assert.True(t, skip(map[string]string{sources.AttrPath: path}))
	assert.True(t, skip(map[string]string{sources.AttrPath: ".betterleaksignore"}))
}
