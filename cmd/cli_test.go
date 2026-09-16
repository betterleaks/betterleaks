package cmd

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCLIParserForTest(t *testing.T) (*CLI, *kong.Kong) {
	t.Helper()
	cli := &CLI{}
	root, _ := newTestCLI(t)
	parser, err := newCLIParser(cli, root.runtime)
	require.NoError(t, err)
	return cli, parser
}

func parseCLIForTest(t *testing.T, args ...string) (*CLI, error) {
	t.Helper()
	cli, parser := newCLIParserForTest(t)
	_, err := parser.Parse(expandRuleFlagShorthands(args))
	return cli, err
}

func TestAutoShorthand(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "current directory", args: []string{"."}},
		{name: "relative directory", args: []string{"testdata"}},
		{name: "absolute path", args: []string{t.TempDir()}},
		{name: "file", args: []string{"config.toml"}},
		{name: "multiple paths", args: []string{"src", "config.toml"}},
		{name: "command name as path", args: []string{"./git"}},
		{name: "flags after path", args: []string{".", "--offline", "--follow-symlinks", "-j", "2"}},
		{name: "flags before path", args: []string{"--offline", "-j", "2", "."}},
		{name: "global flag value matches command", args: []string{"--config", "git", "."}},
		{name: "scan flag value matches command", args: []string{"--output", "git", "."}},
		{name: "literal flag as path", args: []string{"--", "--offline"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cli, parser := newCLIParserForTest(t)
			parsed, err := parser.Parse(test.args)
			require.NoError(t, err)
			require.Equal(t, "auto <target>", parsed.Command())

			explicit, err := parseCLIForTest(t, append([]string{"filesystem"}, test.args...)...)
			require.NoError(t, err)
			require.Equal(t, explicit.Directory.ScanFlags, cli.Auto.ScanFlags)
			require.Equal(t, explicit.Directory.Paths, cli.Auto.Targets)
			require.Equal(t, explicit.Directory.FollowSymlinks, cli.Auto.FollowSymlinks)
			require.Equal(t, explicit.GlobalFlags, cli.GlobalFlags)
		})
	}
}

func TestAutoShorthandPreservesCommands(t *testing.T) {
	for _, test := range []struct {
		args    []string
		command string
	}{
		{args: []string{"filesystem", "."}, command: "filesystem <path>"},
		{args: []string{"fs", "."}, command: "filesystem <path>"},
		{args: []string{"git", "."}, command: "git <repo>"},
		{args: []string{"stdin"}, command: "stdin"},
		{args: []string{"validate"}, command: "validate"},
		{args: []string{"analyze"}, command: "analyze"},
		{args: []string{"revoke"}, command: "revoke"},
		{args: []string{"version"}, command: "version"},
		{args: []string{"--config", "config.toml", "git", "."}, command: "git <repo>"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			_, parser := newCLIParserForTest(t)
			parsed, err := parser.Parse(test.args)
			require.NoError(t, err)
			require.Equal(t, test.command, parsed.Command())

		})
	}
}

func TestInitLogConfiguresOnlyCommandRuntime(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })

	var globalOutput bytes.Buffer
	globalLogger := logging.NewConsole(&globalOutput, logging.ConsoleOptions{
		Level:   slog.LevelDebug,
		NoColor: true,
	})
	slog.SetDefault(globalLogger)

	var commandOutput bytes.Buffer
	runtime := &commandRuntime{stderr: &commandOutput}
	err := initLog(
		&GlobalFlags{LogLevel: "debug", RegexEngine: "re2"},
		&kong.Context{},
		runtime,
	)
	require.NoError(t, err)

	runtime.Logger().Debug("command message")
	slog.Debug("global message")

	assert.Contains(t, commandOutput.String(), "command message")
	assert.NotContains(t, commandOutput.String(), "global message")
	assert.Contains(t, globalOutput.String(), "global message")
	assert.NotContains(t, globalOutput.String(), "command message")
	assert.Same(t, globalLogger, slog.Default())
}

type testCLI struct {
	args    []string
	runtime *commandRuntime
}

func (c *testCLI) SetArgs(args []string) { c.args = args }
func (c *testCLI) SetIn(stdin io.Reader) { c.runtime.stdin = stdin }
func (c *testCLI) Execute() error        { return runCLI(c.args, c.runtime) }

func newTestCLI(t *testing.T) (*testCLI, *bytes.Buffer) {
	t.Helper()

	// A character device represents absent piped input without using process stdin.
	stdin, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stdin.Close() })
	stdout := new(bytes.Buffer)
	runtime := &commandRuntime{
		Context: t.Context(),
		stdin:   stdin,
		stdout:  stdout,
		stderr:  io.Discard,
		exit:    func(int) {},
	}
	return &testCLI{runtime: runtime}, stdout
}

func TestDeprecatedScanCommandsRemoved(t *testing.T) {
	for _, command := range []string{"detect", "protect", "dir", "directory", "file", "files"} {
		// Removed command names and aliases are ordinary paths for the auto shorthand.
		cli, parser := newCLIParserForTest(t)
		parsed, err := parser.Parse([]string{command})
		require.NoError(t, err)
		require.Equal(t, "auto <target>", parsed.Command())
		require.Equal(t, []string{command}, cli.Auto.Targets)
	}
}

type testErrorWriter struct{ err error }

func (w testErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestImplicitURLScanAndExplicitOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "rules.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(`[[rules]]
id = "fixture-secret"
regex = 'fixture-secret-[a-z]+'
keywords = ["fixture-secret-"]
`), 0o600))
	var probes, downloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/info/refs") {
			probes.Add(1)
			http.NotFound(w, r)
			return
		}
		downloads.Add(1)
		_, _ = io.WriteString(w, "fixture-secret-value\n")
	}))
	defer srv.Close()
	for _, command := range []string{"", "auto", "url", "filesystem"} {
		t.Run(command, func(t *testing.T) {
			probes.Store(0)
			downloads.Store(0)
			root, output := newTestCLI(t)
			var logs bytes.Buffer
			root.runtime.stderr = &logs
			var code int
			root.runtime.exit = func(n int) { code = n }
			args := []string{"--config", configPath}
			if command != "" {
				args = append(args, command)
			}
			args = append(args, srv.URL+"/secret.txt", "--offline", "--jsonl", "--no-banner", "--exit-code", "0")
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			if command == "" || command == "auto" {
				require.Contains(t, logs.String(), "auto: selected source")
			} else {
				require.NotContains(t, logs.String(), "auto:")
			}
			require.NotContains(t, output.String(), "auto:", "logs must not mix with JSONL output")
			if command == "filesystem" {
				require.NotZero(t, code)
				require.Zero(t, probes.Load())
				require.Zero(t, downloads.Load())
				return
			}
			require.Zero(t, code)
			require.Contains(t, output.String(), "fixture-secret-value")
			require.Contains(t, output.String(), "url.content")
			require.EqualValues(t, 1, downloads.Load())
			if command == "url" {
				require.Zero(t, probes.Load())
			} else {
				require.EqualValues(t, 1, probes.Load())
			}
		})
	}
}

func TestAutoArchiveDownloadAndExclusion(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("secret.txt")
	require.NoError(t, err)
	_, err = io.WriteString(entry, "fixture-secret-value\n")
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/info/refs") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", `attachment; filename="bundle.zip"`)
		_, _ = w.Write(archive.Bytes())
	}))
	defer srv.Close()
	for _, command := range []string{"", "auto", "url"} {
		for _, exclude := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/exclude=%t", command, exclude), func(t *testing.T) {
				config := `[[rules]]
id = "fixture-secret"
regex = 'fixture-secret-[a-z]+'
keywords = ["fixture-secret-"]
`
				if exclude {
					config = fmt.Sprintf(`prefilter = 'attributes["resource"] == "url.content" && attributes["url"] == "%s/download" && attributes["path"] == "download!secret.txt"'`, srv.URL) + "\n" + config
				}
				configPath := filepath.Join(t.TempDir(), "rules.toml")
				require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))
				root, output := newTestCLI(t)
				var code int
				root.runtime.exit = func(n int) { code = n }
				args := []string{"--config", configPath}
				if command != "" {
					args = append(args, command)
				}
				root.SetArgs(append(args, srv.URL+"/download", "--offline", "--jsonl", "--no-banner"))
				require.NoError(t, root.Execute())
				if exclude {
					require.Empty(t, output.String())
					require.Zero(t, code)
				} else {
					require.Contains(t, output.String(), "fixture-secret-value")
					require.Contains(t, output.String(), "download!secret.txt")
					require.Equal(t, 1, code)
				}
			})
		}
	}
}

func TestImplicitTargetsRejectAmbiguityBeforeFetching(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(401)
	}))
	defer srv.Close()
	for _, args := range [][]string{
		{srv.URL, t.TempDir()},
		{srv.URL, srv.URL + "/other"},
		{srv.URL, "--include", "commit-messages"},
		{srv.URL, "--token", "secret"},
		{srv.URL, "--follow-symlinks"},
		{"auto", srv.URL, "--follow-symlinks=false"},
	} {
		root, _ := newTestCLI(t)
		root.SetArgs(args)
		require.Error(t, root.Execute())
	}
	require.Zero(t, requests.Load())
	root, _ := newTestCLI(t)
	root.SetArgs([]string{srv.URL})
	require.ErrorContains(t, root.Execute(), "select git or url explicitly")
	require.EqualValues(t, 1, requests.Load(), "inconclusive discovery must not download the target")
}

func TestRemoteGitFlagsAndTokens(t *testing.T) {
	for _, flag := range []string{"--staged", "--pre-commit"} {
		_, err := parseCLIForTest(t, "git", "https://example.com/repo", flag)
		require.ErrorContains(t, err, "local Git repository")
	}
	cli, err := parseCLIForTest(t, "git", "https://example.com/repo", "--token", "explicit", "--include", "commit-messages")
	require.NoError(t, err)
	require.Equal(t, "explicit", cli.Git.Token)
	t.Setenv("GITHUB_TOKEN", "github")
	t.Setenv("GITLAB_TOKEN", "gitlab")
	t.Setenv("HUGGINGFACE_TOKEN", "huggingface")
	for _, tc := range []struct{ target, token string }{
		{"https://github.com/owner/repo", "github"},
		{"https://gitlab.com/group/repo", "gitlab"},
		{"https://huggingface.co/owner/model", "huggingface"},
		{"https://example.com/repo", ""},
		{"http://github.com/owner/repo", ""},
		{"https://github.com:1234/owner/repo", ""},
		{"https://user:password@github.com/owner/repo", ""},
	} {
		require.Equal(t, tc.token, remoteGitToken(tc.target))
	}
}

func TestSourceHelpDoesNotFetch(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer srv.Close()
	for _, args := range [][]string{
		nil, {"--help"}, {srv.URL, "--help"}, {srv.URL, "--version"}, {"auto", srv.URL, "--help"}, {"git", srv.URL, "--help"}, {"url", srv.URL, "--help"},
	} {
		root, _ := newTestCLI(t)
		root.runtime.exit = func(code int) { require.Zero(t, code); panic("help exit") }
		root.SetArgs(args)
		require.PanicsWithValue(t, "help exit", func() { _ = root.Execute() })
	}
	require.Zero(t, requests.Load())
}

func TestImplicitRemoteGitScansHistoryWithLocalConfig(t *testing.T) {
	local := t.TempDir()
	t.Chdir(local)
	require.NoError(t, os.WriteFile(".betterleaks.toml", []byte(`[[rules]]
id = "fixture-secret"
regex = 'fixture-secret-[a-z]+'
keywords = ["fixture-secret-"]
`), 0o600))
	repo := t.TempDir()
	gitCommand := func(args ...string) {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	gitCommand("init", "--quiet")
	gitCommand("config", "user.name", "Fixture")
	gitCommand("config", "user.email", "fixture@example.com")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret.txt"), []byte("fixture-secret-deleted\n"), 0o600))
	gitCommand("add", ".")
	gitCommand("commit", "--quiet", "-m", "add file")
	gitCommand("rm", "secret.txt")
	// This must be scanned as content, never loaded as configuration.
	require.NoError(t, os.WriteFile(filepath.Join(repo, ".betterleaks.toml"), []byte("invalid TOML ["), 0o600))
	gitCommand("add", ".")
	gitCommand("commit", "--quiet", "-m", "remove secret")
	root := t.TempDir()
	gitCommand("clone", "--bare", repo, filepath.Join(root, "repo"))
	git, err := exec.LookPath("git")
	require.NoError(t, err)
	backend := &cgi.Handler{
		Path: git,
		Args: []string{"http-backend"},
		Env:  []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"},
	}
	srv := httptest.NewServer(backend)
	defer srv.Close()
	for _, explicit := range []bool{false, true} {
		cli, output := newTestCLI(t)
		cli.runtime.exit = func(code int) { require.Zero(t, code) }
		args := []string{srv.URL + "/repo", "--offline", "--jsonl", "--no-banner", "--exit-code", "0", "-j", "1"}
		if explicit {
			args = append([]string{"git"}, args...)
		}
		cli.SetArgs(args)
		require.NoError(t, cli.Execute())
		require.Contains(t, output.String(), "fixture-secret-deleted")
		require.Contains(t, output.String(), "git.patch_content")
	}
}
