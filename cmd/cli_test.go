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
	"testing/iotest"
	"time"

	"github.com/alecthomas/kong"
	configpkg "github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/fingerprint"
	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCLIParserForTest(t *testing.T) (*CLI, *cliParser) {
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

func TestPreCommitHookCommands(t *testing.T) {
	manifest, err := os.ReadFile("../.pre-commit-hooks.yaml")
	require.NoError(t, err)
	var entries []string
	for _, line := range strings.Split(string(manifest), "\n") {
		if entry, ok := strings.CutPrefix(line, "  entry: "); ok {
			entries = append(entries, entry)
		}
	}
	require.Len(t, entries, 3)

	repo := t.TempDir()
	t.Chdir(repo)
	git := func(args ...string) {
		t.Helper()
		out, err := exec.Command("git", args...).CombinedOutput()
		require.NoError(t, err, "%s", out)
	}
	git("init", "--quiet")
	configPath := filepath.Join(t.TempDir(), "rules.toml")
	require.NoError(t, os.WriteFile(configPath, []byte("[[rules]]\nid='hook-secret'\nregex='SECRET_PRIVATE'\n"), 0o600))

	for _, entry := range entries {
		t.Run(entry, func(t *testing.T) {
			// Exercise the CLI arguments shipped by every hook, including the
			// Docker entry. Image execution belongs to the release smoke check.
			args := strings.Fields(entry)[1:]
			require.Contains(t, args, "--offline")
			for _, secret := range []bool{false, true} {
				t.Run(fmt.Sprintf("secret=%t", secret), func(t *testing.T) {
					content := "ordinary content\n"
					if secret {
						content = "SECRET_PRIVATE\n"
					}
					require.NoError(t, os.WriteFile("input.txt", []byte(content), 0o600))
					git("add", "input.txt")
					root, output := newTestCLI(t)
					code := 0
					root.runtime.exit = func(n int) { code = n; panic(n) }
					root.SetArgs(append(append([]string{}, args...), "--no-banner", "--config", configPath))
					func() {
						defer func() {
							if p := recover(); p != nil {
								if _, ok := p.(int); !ok {
									panic(p)
								}
							}
						}()
						require.NoError(t, root.Execute())
					}()
					if secret {
						require.Equal(t, 1, code)
						require.Contains(t, output.String(), "REDACTED")
					} else {
						require.Zero(t, code)
						require.Empty(t, output.String())
					}
					require.NotContains(t, output.String(), "SECRET_PRIVATE")
				})
			}
		})
	}
}

func TestRedactedTraceOutput(t *testing.T) {
	for _, test := range []struct {
		name, globalFilter, ruleFilter, suffix, extraRules, message string
	}{
		{name: "allow comment", suffix: " # betterleaks:allow", message: "allow signature found"},
		{name: "global filter", globalFilter: "filter='true'\n", message: "skipping finding: global filter"},
		{name: "rule filter", ruleFilter: "filter='true'\n", message: "skipping finding: rule filter"},
		{name: "specificity", extraRules: "\n[[rules]]\nid='specific'\nregex='(?P<other>OTHER_PRIVATE):(?P<secret>SECRET_PRIVATE)'\nsecretGroup=2\nspecificity=200\n", message: "more specific rule takes precedence"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.toml")
			config := test.globalFilter + "[[rules]]\nid='fixture'\nregex='(?P<other>OTHER_PRIVATE):(?P<secret>SECRET_PRIVATE)'\nsecretGroup=2\n" + test.ruleFilter + test.extraRules
			require.NoError(t, os.WriteFile(path, []byte(config), 0o600))
			root, output := newTestCLI(t)
			var logs bytes.Buffer
			root.runtime.stderr = &logs
			root.SetIn(strings.NewReader("OTHER_PRIVATE:SECRET_PRIVATE" + test.suffix))
			root.SetArgs([]string{"stdin", "--config", path, "--offline", "--redact", "--log-level=trace", "--no-banner"})
			require.NoError(t, root.Execute())
			require.Contains(t, logs.String(), test.message)
			for _, secret := range []string{"SECRET_PRIVATE", "OTHER_PRIVATE"} {
				require.NotContains(t, logs.String(), secret)
				require.NotContains(t, output.String(), secret)
			}
		})
	}
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
			args = append(args, strings.Replace(srv.URL, "http://", "http://user:password@", 1)+"/secret.txt?token=private#fragment", "--offline", "--jsonl", "--no-banner", "--exit-code", "0")
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
			metadata, _ := decodeScanJSONL(t, output.Bytes())
			assert.Equal(t, report.ScanSource{Type: "url", Targets: []string{srv.URL + "/secret.txt"}}, metadata.Source)
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
					_, findings := decodeScanJSONL(t, output.Bytes())
					require.Empty(t, findings)
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
	for _, flag := range []string{"--staged", "--unstaged"} {
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

func TestImplicitRemoteGitScansHistoryWithExplicitConfig(t *testing.T) {
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
		args := []string{srv.URL + "/repo", "--config", filepath.Join(local, ".betterleaks.toml"), "--offline", "--jsonl", "--no-banner", "--exit-code", "0", "-j", "1"}
		if explicit {
			args = append([]string{"git"}, args...)
		}
		cli.SetArgs(args)
		require.NoError(t, cli.Execute())
		require.Contains(t, output.String(), "fixture-secret-deleted")
		require.Contains(t, output.String(), "git.patch_content")
	}
}

func TestLeadingFlagsMatchCommandLocalFlags(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want []string
	}{
		{"boolean", []string{"--no-banner", "fs", "."}, []string{"fs", "--no-banner", "."}},
		{"output", []string{"--output", "out.json", "filesystem", "."}, []string{"filesystem", "--output", "out.json", "."}},
		{"scalar order", []string{"--output=first.json", "-j2", "fs", "--output=last.json", "-j0", "."}, []string{"fs", "--output=first.json", "-j2", "--output=last.json", "-j0", "."}},
		{"boolean override", []string{"--no-banner", "fs", "--no-banner=false", "."}, []string{"fs", "--no-banner", "--no-banner=false", "."}},
		{"repeated flags", []string{"-ir", "first", "fs", "--isolate-rule", "second", "."}, []string{"fs", "--isolate-rule", "first", "--isolate-rule", "second", "."}},
		{"short flags", []string{"-sj2", "-oout.json", "fs", "."}, []string{"fs", "-sj2", "-oout.json", "."}},
		{"implicit redaction", []string{"--redact", "fs", "."}, []string{"fs", "--redact", "."}},
		{"partial redaction", []string{"--redact=20", "fs", "."}, []string{"fs", "--redact=20", "."}},
		{"command as output", []string{"--output", "git", "fs", "."}, []string{"fs", "--output", "git", "."}},
		{"command as config", []string{"--config", "git", "--offline", "fs", "."}, []string{"fs", "--config", "git", "--offline", "."}},
		{"source flag", []string{"--staged", "--offline", "git", "."}, []string{"git", "--staged", "--offline", "."}},
		{"unstaged flag", []string{"--unstaged", "--offline", "git", "."}, []string{"git", "--unstaged", "--offline", "."}},
		{"credential flag", []string{"--rule", "token", "--jsonl", "analyze", "secret"}, []string{"analyze", "--rule", "token", "--jsonl", "secret"}},
		{"nested command", []string{"--analysis", "config", "show", "ids"}, []string{"config", "show", "ids", "--analysis"}},
		{"between nested commands", []string{"config", "--analysis", "show", "--validation", "ids"}, []string{"config", "show", "ids", "--analysis", "--validation"}},
		{"auto", []string{"--offline", "--output=out.json", "target"}, []string{"auto", "--offline", "--output=out.json", "target"}},
		{"explicit auto", []string{"--offline", "auto", "target"}, []string{"auto", "--offline", "target"}},
		{"command after path", []string{"--offline", "target", "fs"}, []string{"auto", "--offline", "target", "fs"}},
		{"literal command path", []string{"--offline", "--", "fs"}, []string{"auto", "--offline", "--", "fs"}},
		{"literal flag path", []string{"--", "--offline", "fs"}, []string{"auto", "--", "--offline", "fs"}},
		{"explicit literal paths", []string{"--offline", "fs", "--", "--no-banner", "git"}, []string{"fs", "--offline", "--", "--no-banner", "git"}},
		{"nested literal path", []string{"config", "show", "--", "ids"}, []string{"config", "show", "toml", "--", "ids"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := parseCLIForTest(t, test.args...)
			require.NoError(t, err)
			expected, err := parseCLIForTest(t, test.want...)
			require.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestLeadingFlagsAcrossCommands(t *testing.T) {
	for _, args := range [][]string{
		{"fs", "."}, {"filesystem", "."}, {"auto", "."}, {"git", "."}, {"stdin"},
		{"url", "https://example.com/file"}, {"github", "https://github.com/example/repo"},
		{"gitlab", "https://gitlab.com/example/repo"}, {"huggingface", "https://huggingface.co/example/repo"},
		{"hf", "https://huggingface.co/example/repo"}, {"s3", "s3://example"},
	} {
		t.Run(args[0], func(t *testing.T) {
			prefix := []string{"--offline", "--no-banner", "--redact", "--output=out.json"}
			actual, err := parseCLIForTest(t, append(prefix, args...)...)
			require.NoError(t, err)
			local := append([]string{args[0]}, prefix...)
			local = append(local, args[1:]...)
			expected, err := parseCLIForTest(t, local...)
			require.NoError(t, err)
			assert.Equal(t, expected, actual)
		})
	}
}

func TestLeadingFlagsRejectInvalidScopeAndValues(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--offline", "validate"}, "unknown flag --offline"},
		{[]string{"--no-banner", "config", "show", "ids"}, "unknown flag --no-banner"},
		{[]string{"--staged", "fs", "."}, "unknown flag --staged"},
		{[]string{"--unstaged", "fs", "."}, "unknown flag --unstaged"},
		{[]string{"git", "--staged", "--unstaged"}, "mutually exclusive"},
		{[]string{"--unstaged", "git", "--staged"}, "mutually exclusive"},
		{[]string{"git", "--pre-commit"}, "unknown flag --pre-commit"},
		{[]string{"git", "--staged", "--include=commit-messages"}, "requires a Git history scan"},
		{[]string{"git", "--unstaged", "--include=commit-messages"}, "requires a Git history scan"},
		{[]string{"--rule", "token", "fs", "."}, "unknown flag --rule"},
		{[]string{"--bad-opt", "fs", "."}, "unknown flag --bad-opt"},
		{[]string{"--jobs=bad", "fs", "."}, "--jobs"},
		{[]string{"--jobs=-1", "fs", "."}, "--jobs must be non-negative"},
		{[]string{"--redact=bad", "fs", "."}, "invalid redaction percentage"},
		{[]string{"--output"}, "--output"},
	} {
		t.Run(fmt.Sprint(test.args), func(t *testing.T) {
			_, err := parseCLIForTest(t, test.args...)
			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestLeadingScanFlagsTakeEffect(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	configPath := writeTestConfig(t, fmt.Sprintf(`[[rules]]
id = "fixture-token"
regex = 'fixture-secret-[a-z]+'
validate = '''let r = http.get(%q); {"result": "valid"}'''
`, server.URL))
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.txt")
	require.NoError(t, os.WriteFile(inputPath, []byte("fixture-secret-alpha\n"), 0o600))
	for _, mode := range []string{"before", "after", "auto"} {
		t.Run(mode, func(t *testing.T) {
			previousBanner := bannerPrinted
			bannerPrinted = false
			t.Cleanup(func() { bannerPrinted = previousBanner })
			root, stdout := newTestCLI(t)
			var stderr bytes.Buffer
			root.runtime.stderr = &stderr
			outputPath := filepath.Join(t.TempDir(), "report.json")
			flags := []string{"--config", configPath, "--no-banner", "--offline", "--redact", "--output", outputPath, "--exit-code=0"}
			var args []string
			switch mode {
			case "before":
				args = append(flags, "fs", inputPath)
			case "after":
				args = append([]string{"fs", inputPath}, flags...)
			case "auto":
				args = append(flags, inputPath)
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			assert.False(t, bannerPrinted)
			assert.NotContains(t, stderr.String(), banner)
			assert.Zero(t, requests.Load(), "offline must prevent provider requests")
			raw, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), "fixture-secret-alpha")
			assert.NotContains(t, stdout.String(), "fixture-secret-alpha")
			assert.NotContains(t, stderr.String(), "fixture-secret-alpha")
			_, findings := decodeScanJSON(t, raw)
			require.Len(t, findings, 1)
			assert.Equal(t, "REDACTED", findings[0].Match.Value)
			assert.True(t, findings[0].Analysis.IsZero())
		})
	}
}

func TestGitFlagsSelectHistoryStagedOrUnstaged(t *testing.T) {
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		output, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	git("init", "--quiet")
	path := filepath.Join(repo, "input.txt")
	require.NoError(t, os.WriteFile(path, []byte("SECRET_COMMITTED\n"), 0o600))
	git("add", ".")
	git("-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--quiet", "-m", "initial")
	require.NoError(t, os.WriteFile(path, []byte("SECRET_STAGED\n"), 0o600))
	git("add", ".")
	require.NoError(t, os.WriteFile(path, []byte("SECRET_UNSTAGED\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("SECRET_UNTRACKED\n"), 0o600))
	configPath := writeTestConfig(t, "[[rules]]\nid='fixture-token'\nregex='SECRET_[A-Z]+'\n")

	for _, tc := range []struct{ flag, want string }{
		{"", "SECRET_COMMITTED"},
		{"--staged", "SECRET_STAGED"},
		{"--unstaged", "SECRET_UNSTAGED"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			root, _ := newTestCLI(t)
			outputPath := filepath.Join(t.TempDir(), "report.json")
			args := []string{"git", repo, "--config", configPath, "--offline", "--no-banner", "--exit-code=0", "--output", outputPath}
			if tc.flag != "" {
				args = append(args, tc.flag)
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			raw, err := os.ReadFile(outputPath)
			require.NoError(t, err)
			metadata, findings := decodeScanJSON(t, raw)
			assert.Equal(t, report.ScanSource{Type: "git", Targets: []string{repo}}, metadata.Source)
			require.Len(t, findings, 1)
			require.Equal(t, tc.want, findings[0].Match.Value)
		})
	}
}

func TestScanReportMultipleTargets(t *testing.T) {
	configPath := writeTestConfig(t, "[[rules]]\nid='token'\nregex='TOKEN_[AB]'\n[[rules]]\nid='unused'\nregex='NEVER_MATCH'\n")
	cfg, err := configpkg.LoadFile(configPath)
	require.NoError(t, err)
	unselectedHash := cfg.Hash()
	cfg.Rules = cfg.Rules[:1]
	wantHash := cfg.Hash()
	require.NotEqual(t, unselectedHash, wantHash)
	wantRuleHash, err := cfg.RuleHash("token")
	require.NoError(t, err)
	var targets []string
	for _, token := range []string{"TOKEN_A", "TOKEN_A", "TOKEN_B"} {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".betterleaks.toml"), []byte("invalid TOML ["), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "input.txt"), []byte(token), 0o600))
		targets = append(targets, dir)
	}
	for _, jsonl := range []bool{false, true} {
		t.Run(fmt.Sprintf("jsonl=%t", jsonl), func(t *testing.T) {
			root, stdout := newTestCLI(t)
			var logs bytes.Buffer
			root.runtime.stderr = &logs
			args := append([]string{"fs"}, targets...)
			args = append(args, "--config", configPath, "--offline", "--no-banner", "--exit-code=0", "--disable-rule=unused", "--output=-")
			if jsonl {
				args = append(args, "--jsonl")
			}
			before := time.Now()
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			var metadata report.ScanMetadata
			var findings []report.Finding
			if jsonl {
				metadata, findings = decodeScanJSONL(t, stdout.Bytes())
			} else {
				metadata, findings = decodeScanJSON(t, stdout.Bytes())
			}
			assert.Equal(t, wantHash, metadata.ConfigHash)
			assert.Equal(t, report.ScanSource{Type: "filesystem", Targets: targets}, metadata.Source)
			assert.Equal(t, uint64(3*(len("TOKEN_A")+len("invalid TOML ["))), metadata.BytesScanned)
			assert.False(t, metadata.Started.Before(before))
			assert.False(t, metadata.Finished.Before(metadata.Started))
			assert.False(t, metadata.Finished.After(time.Now()))
			for _, timestamp := range []time.Time{metadata.Started, metadata.Finished} {
				_, offset := timestamp.Zone()
				assert.Zero(t, offset)
			}
			require.Len(t, findings, 3)
			for _, finding := range findings {
				assert.Equal(t, wantRuleHash, finding.RuleHash)
				assert.Equal(t, fingerprint.Format(fingerprint.Sum([]byte(finding.Match.Value))), finding.Match.Fingerprint)
			}
			assert.Equal(t, 3, strings.Count(logs.String(), "starting scan"))
			assert.Equal(t, 3, strings.Count(logs.String(), wantHash))
			assert.Equal(t, 1, strings.Count(logs.String(), "Disabling rules"), "config selection runs once per invocation")
			assert.NotContains(t, stdout.String(), "starting scan")
		})
	}
}

func TestScanIgnoresImplicitConfigFiles(t *testing.T) {
	t.Setenv("BETTERLEAKS_CONFIG", "")
	t.Setenv("BETTERLEAKS_CONFIG_TOML", "")
	cwd := t.TempDir()
	t.Chdir(cwd)
	require.NoError(t, os.WriteFile(".betterleaks.toml", []byte("invalid TOML ["), 0o600))
	var targets []string
	for range 2 {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".betterleaks.toml"), []byte("invalid TOML ["), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "input.txt"), []byte("GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5\n"), 0o600)) // betterleaks:allow
		targets = append(targets, dir)
	}
	root, stdout := newTestCLI(t)
	args := append([]string{"fs"}, targets...)
	root.SetArgs(append(args, "--offline", "--no-banner", "--exit-code=0", "--isolate-rule=github-pat", "--output=-"))
	require.NoError(t, root.Execute())
	metadata, findings := decodeScanJSON(t, stdout.Bytes())
	require.Len(t, findings, 2)
	defaults, err := configpkg.Default()
	require.NoError(t, err)
	rule, ok := defaults.Rule("github-pat")
	require.True(t, ok)
	defaults.Rules = []configpkg.Rule{rule}
	assert.Equal(t, defaults.Hash(), metadata.ConfigHash)
}

func TestFilesystemSetupFailureFinalizesIncompleteReport(t *testing.T) {
	for _, jsonl := range []bool{false, true} {
		for _, failure := range []string{"second target", "finding filter", "source prefilter"} {
			t.Run(fmt.Sprintf("%s/jsonl=%t", failure, jsonl), func(t *testing.T) {
				configText := "[[rules]]\nid='token'\nregex='TOKEN'\n"
				switch failure {
				case "finding filter":
					configText = "filter='finding.'\n" + configText
				case "source prefilter":
					configText = "prefilter='attributes.'\n" + configText
				}
				configPath := writeTestConfig(t, configText)
				cfg, err := configpkg.LoadFile(configPath)
				require.NoError(t, err)
				dir := t.TempDir()
				const content = "TOKEN\n"
				require.NoError(t, os.WriteFile(filepath.Join(dir, "input.txt"), []byte(content), 0o600))
				args := []string{"fs", dir}
				wantCount := 0
				var wantBytes uint64
				if failure == "second target" {
					args = append(args, filepath.Join(t.TempDir(), "missing"))
					wantCount, wantBytes = 1, uint64(len(content))
				}
				wantSource := report.ScanSource{Type: "filesystem", Targets: args[1:]}
				args = append(args, "--config", configPath, "--offline", "--no-banner", "--exit-code=0", "--output=-")
				if jsonl {
					args = append(args, "--jsonl")
				}
				root, stdout := newTestCLI(t)
				var exits []int
				root.runtime.exit = func(code int) { exits = append(exits, code) }
				root.SetArgs(args)
				require.NoError(t, root.Execute())
				assert.Equal(t, []int{1}, exits)
				var metadata report.ScanMetadata
				var findings []report.Finding
				if jsonl {
					metadata, findings = decodeScanJSONL(t, stdout.Bytes())
				} else {
					metadata, findings = decodeScanJSON(t, stdout.Bytes())
				}
				assert.Equal(t, report.ScanStateIncomplete, metadata.State)
				assert.Equal(t, wantSource, metadata.Source)
				assert.Equal(t, cfg.Hash(), metadata.ConfigHash)
				assert.Equal(t, wantBytes, metadata.BytesScanned)
				assert.Equal(t, wantCount, metadata.NumFindings)
				require.Len(t, findings, wantCount)
				if wantCount > 0 {
					assert.Equal(t, "TOKEN", findings[0].Match.Value)
				}
			})
		}
	}
}

func TestStdinReadFailureFinalizesIncompleteReport(t *testing.T) {
	configPath := writeTestConfig(t, "[[rules]]\nid='token'\nregex='TOKEN'\n")
	root, stdout := newTestCLI(t)
	root.SetIn(iotest.ErrReader(fmt.Errorf("input failed")))
	var exitCode int
	root.runtime.exit = func(code int) { exitCode = code }
	root.SetArgs([]string{"stdin", "--config", configPath, "--offline", "--no-banner", "--output=-"})
	require.NoError(t, root.Execute())
	metadata, findings := decodeScanJSON(t, stdout.Bytes())
	assert.Equal(t, report.ScanStateIncomplete, metadata.State)
	assert.Equal(t, 1, exitCode)
	assert.Empty(t, findings)
	assert.Zero(t, metadata.BytesScanned)
}

func TestCorruptArchiveWarningKeepsScanComplete(t *testing.T) {
	configPath := writeTestConfig(t, "[[rules]]\nid='token'\nregex='TOKEN'\n")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.gz"), []byte{0x1f, 0x8b, 0x08, 0x00}, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "input.txt"), []byte("TOKEN\n"), 0o600))
	root, stdout := newTestCLI(t)
	var logs bytes.Buffer
	root.runtime.stderr = &logs
	var exitCode int
	root.runtime.exit = func(code int) { exitCode = code }
	root.SetArgs([]string{"fs", dir, "--config", configPath, "--offline", "--no-banner", "--no-color", "--exit-code=0", "--output=-"})
	require.NoError(t, root.Execute())
	metadata, findings := decodeScanJSON(t, stdout.Bytes())
	assert.Equal(t, report.ScanStateComplete, metadata.State)
	assert.Zero(t, exitCode)
	require.Len(t, findings, 1)
	assert.Contains(t, logs.String(), "could not read compressed file")
}
