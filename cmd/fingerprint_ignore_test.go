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
	"github.com/betterleaks/betterleaks/v2/detect"
	blfingerprint "github.com/betterleaks/betterleaks/v2/internal/fingerprint"
	"github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/sources"
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
	return &config.Config{Rules: []config.Rule{{RuleID: "secret", Regex: regexp.MustCompile(`secret-[a-z]+`)}}}
}

func writeIgnore(t *testing.T, dir, secret string) string {
	t.Helper()
	path := filepath.Join(dir, ".betterleaksignore")
	err := os.WriteFile(path, []byte(blfingerprint.Format(blfingerprint.Sum([]byte(secret)))+"\n"), 0o600)
	require.NoError(t, err)
	return path
}

func detectorWithIgnoreOptions(t *testing.T, cfg *config.Config, options []detect.Option) *detect.Detector {
	t.Helper()
	detector, err := detect.NewDetector(cfg, options...)
	require.NoError(t, err)
	return detector
}

func TestIgnoreFileDiscovery(t *testing.T) {
	t.Run("target root", func(t *testing.T) {
		dir := t.TempDir()
		writeIgnore(t, dir, "secret-root")
		cfg := ignoreTestConfig()
		options, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, "", dir, cfg)
		require.NoError(t, err)
		assert.Empty(t, detectorWithIgnoreOptions(t, cfg, options).DetectString("secret-root"))
	})

	t.Run("single file parent", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "input.txt")
		require.NoError(t, os.WriteFile(file, []byte("secret-file"), 0o600))
		writeIgnore(t, dir, "secret-file")
		cfg := ignoreTestConfig()
		options, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, "", file, cfg)
		require.NoError(t, err)
		assert.Empty(t, detectorWithIgnoreOptions(t, cfg, options).DetectString("secret-file"))
	})

	t.Run("cwd", func(t *testing.T) {
		dir := t.TempDir()
		writeIgnore(t, dir, "secret-cwd")
		t.Chdir(dir)
		cfg := ignoreTestConfig()
		options, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, "", "", cfg)
		require.NoError(t, err)
		assert.Empty(t, detectorWithIgnoreOptions(t, cfg, options).DetectString("secret-cwd"))
	})

	t.Run("absent default", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte("ignored"), 0o600))
		cfg := ignoreTestConfig()
		options, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, "", dir, cfg)
		require.NoError(t, err)
		assert.Empty(t, options)
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
		options, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, explicit, target, cfg)
		require.NoError(t, err)
		detector := detectorWithIgnoreOptions(t, cfg, options)
		assert.Empty(t, detector.DetectString("secret-shared"))
		assert.NotEmpty(t, detector.DetectString("secret-one secret-two"))
	}
}

func TestIgnoreFileComposesWithGlobalFilter(t *testing.T) {
	dir := t.TempDir()
	writeIgnore(t, dir, "secret-fingerprint")
	cfg := ignoreTestConfig()
	cfg.Filter = "finding[\"secret\"] == \"secret-config\""

	options, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, "", dir, cfg)
	require.NoError(t, err)
	detector := detectorWithIgnoreOptions(t, cfg, options)

	assert.Empty(t, detector.DetectString("secret-config secret-fingerprint"))
	assert.NotEmpty(t, detector.DetectString("secret-visible"))
	assert.Contains(t, cfg.Filter, "sha256(finding[\"secret\"]) in [")
}

func TestIgnoreFileErrorsAndDiagnostics(t *testing.T) {
	_, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, filepath.Join(t.TempDir(), "missing"), "", ignoreTestConfig())
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
	options, err := applyIgnorePolicy(&commandRuntime{stderr: stderr}, path, dir, cfg)
	require.NoError(t, err)
	assert.Contains(t, stderr.String(), path+":2:")
	assert.Empty(t, detectorWithIgnoreOptions(t, cfg, options).DetectString("secret-valid"))

	if runtime.GOOS != "windows" {
		unreadable := filepath.Join(t.TempDir(), "ignore")
		require.NoError(t, os.WriteFile(unreadable, []byte("ignored"), 0o000))
		defer os.Chmod(unreadable, 0o600)
		_, err = applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, unreadable, "", ignoreTestConfig())
		assert.Error(t, err)
	}
}

func TestActiveIgnoreFileIsExcluded(t *testing.T) {
	dir := t.TempDir()
	path := writeIgnore(t, dir, "secret-value")
	cfg := ignoreTestConfig()
	options, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, "", dir, cfg)
	require.NoError(t, err)
	detector := detectorWithIgnoreOptions(t, cfg, options)

	assert.True(t, detector.SkipFunc()(map[string]string{sources.AttrPath: path}))
	assert.True(t, detector.SkipFunc()(map[string]string{sources.AttrPath: ".betterleaksignore"}))

	remoteCfg := ignoreTestConfig()
	remoteOptions, err := applyIgnorePolicy(&commandRuntime{stderr: io.Discard}, path, "", remoteCfg)
	require.NoError(t, err)
	assert.Nil(t, detectorWithIgnoreOptions(t, remoteCfg, remoteOptions).SkipFunc())
}
