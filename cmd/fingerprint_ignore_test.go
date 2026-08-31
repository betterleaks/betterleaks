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

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	blfingerprint "github.com/betterleaks/betterleaks/internal/fingerprint"
	"github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/sources"
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

func detectorWithIgnoreOptions(t *testing.T, options []detect.Option) *detect.Detector {
	t.Helper()
	detector, err := detect.NewDetector(ignoreTestConfig(), options...)
	require.NoError(t, err)
	return detector
}

func TestIgnoreFileDiscovery(t *testing.T) {
	t.Run("target root", func(t *testing.T) {
		dir := t.TempDir()
		writeIgnore(t, dir, "secret-root")
		options, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, "", dir)
		require.NoError(t, err)
		assert.Empty(t, detectorWithIgnoreOptions(t, options).DetectString("secret-root"))
	})

	t.Run("single file parent", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "input.txt")
		require.NoError(t, os.WriteFile(file, []byte("secret-file"), 0o600))
		writeIgnore(t, dir, "secret-file")
		options, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, "", file)
		require.NoError(t, err)
		assert.Empty(t, detectorWithIgnoreOptions(t, options).DetectString("secret-file"))
	})

	t.Run("cwd", func(t *testing.T) {
		dir := t.TempDir()
		writeIgnore(t, dir, "secret-cwd")
		t.Chdir(dir)
		options, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, "", "")
		require.NoError(t, err)
		assert.Empty(t, detectorWithIgnoreOptions(t, options).DetectString("secret-cwd"))
	})

	t.Run("absent default", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".gitleaksignore"), []byte("ignored"), 0o600))
		options, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, "", dir)
		require.NoError(t, err)
		assert.Empty(t, options)
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
		options, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, explicit, target)
		require.NoError(t, err)
		detector := detectorWithIgnoreOptions(t, options)
		assert.Empty(t, detector.DetectString("secret-shared"))
		assert.NotEmpty(t, detector.DetectString("secret-one secret-two"))
	}
}

func TestIgnoreFileErrorsAndDiagnostics(t *testing.T) {
	_, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, filepath.Join(t.TempDir(), "missing"), "")
	require.ErrorContains(t, err, "open")

	dir := t.TempDir()
	path := writeIgnore(t, dir, "secret-valid")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = file.WriteString("legacy:path:rule:1\n")
	require.NoError(t, err)
	require.NoError(t, file.Close())

	stderr := new(bytes.Buffer)
	options, err := ignoreOptions(&commandRuntime{stderr: stderr}, path, dir)
	require.NoError(t, err)
	assert.Contains(t, stderr.String(), path+":2:")
	assert.Empty(t, detectorWithIgnoreOptions(t, options).DetectString("secret-valid"))

	if runtime.GOOS != "windows" {
		unreadable := filepath.Join(t.TempDir(), "ignore")
		require.NoError(t, os.WriteFile(unreadable, []byte("ignored"), 0o000))
		defer os.Chmod(unreadable, 0o600)
		_, err = ignoreOptions(&commandRuntime{stderr: io.Discard}, unreadable, "")
		assert.Error(t, err)
	}
}

func TestActiveIgnoreFileIsExcluded(t *testing.T) {
	dir := t.TempDir()
	path := writeIgnore(t, dir, "secret-value")
	options, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, "", dir)
	require.NoError(t, err)
	detector := detectorWithIgnoreOptions(t, options)

	assert.True(t, detector.SkipFunc()(map[string]string{sources.AttrPath: path}))
	assert.True(t, detector.SkipFunc()(map[string]string{sources.AttrPath: ".betterleaksignore"}))

	remoteOptions, err := ignoreOptions(&commandRuntime{stderr: io.Discard}, path, "")
	require.NoError(t, err)
	assert.Nil(t, detectorWithIgnoreOptions(t, remoteOptions).SkipFunc())
}
