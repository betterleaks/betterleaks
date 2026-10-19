package cmd

import (
	"archive/zip"
	"bytes"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/stretchr/testify/require"
)

func TestGitBinaryArchiveMembersIncluded(t *testing.T) {
	repo := t.TempDir()
	gitCmdT(t, repo, "init", "-q")
	gitCmdT(t, repo, "config", "user.name", "Archive Test")
	gitCmdT(t, repo, "config", "user.email", "archive@example.test")
	makeZip := func(files map[string][]byte) []byte {
		t.Helper()
		var out bytes.Buffer
		writer := zip.NewWriter(&out)
		for name, content := range files {
			entry, err := writer.Create(name)
			require.NoError(t, err)
			_, err = entry.Write(content)
			require.NoError(t, err)
		}
		require.NoError(t, writer.Close())
		return out.Bytes()
	}
	nested := makeZip(map[string][]byte{
		"text.bin":  []byte("SECRET_NESTED_TEXT\n"),
		"image.txt": []byte("\x89PNG\r\n\x1a\n\x00SECRET_NESTED_BINARY\n"),
	})
	archive := makeZip(map[string][]byte{
		"text.txt":   []byte("SECRET_TEXT\n"),
		"data.bin":   []byte("\x00SECRET_BINARY\x00\n"),
		"nested.zip": nested,
	})
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secrets.zip"), archive, 0600))
	gitCmdT(t, repo, "add", ".")
	gitCmdT(t, repo, "commit", "-qm", "archive")
	configPath := writeTestConfig(t, "[[rules]]\nid='archive-secret'\nregex='SECRET_[A-Z_]+'\n")

	root, stdout := newTestCLI(t)
	root.SetArgs([]string{"git", repo, "--config", configPath, "--no-banner", "--exit-code=0", "--output=-"})
	require.NoError(t, root.Execute())
	_, findings := decodeScanJSON(t, stdout.Bytes())
	var values []string
	for _, finding := range findings {
		values = append(values, finding.Match.Value)
	}
	require.ElementsMatch(t, []string{"SECRET_TEXT", "SECRET_NESTED_TEXT", "SECRET_BINARY", "SECRET_NESTED_BINARY"}, values)
}

// A blob over --git-max-blob-mib is skipped with a warning. The rest of the
// repository is scanned, the report is complete, and findings alone decide the
// exit code, so one large binary cannot fail every scan of a repository.
func TestGitSkippedBlobDoesNotFailScan(t *testing.T) {
	repo := t.TempDir()
	gitCmdT(t, repo, "init", "-q")
	gitCmdT(t, repo, "config", "user.name", "Skip Test")
	gitCmdT(t, repo, "config", "user.email", "skip@example.test")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "big.bin"), bytes.Repeat([]byte{0}, 1<<20+1), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret.txt"), []byte("SECRET_KEPT\n"), 0600))
	gitCmdT(t, repo, "add", ".")
	gitCmdT(t, repo, "commit", "-qm", "big")
	configPath := writeTestConfig(t, "[[rules]]\nid='kept'\nregex='SECRET_[A-Z]+'\n")

	root, stdout := newTestCLI(t)
	var stderr bytes.Buffer
	code := -1
	root.runtime.stderr, root.runtime.exit = &stderr, func(n int) { code = n }
	root.SetArgs([]string{"git", repo, "--config", configPath, "--no-banner", "--no-color", "--git-max-blob-mib=1", "--exit-code=3", "--output=-"})
	require.NoError(t, root.Execute())
	metadata, findings := decodeScanJSON(t, stdout.Bytes())
	require.Equal(t, report.ScanStateComplete, metadata.State)
	require.Len(t, findings, 1)
	require.Equal(t, 3, code)
	require.Contains(t, stderr.String(), "skipped Git content over a limit")
	require.Contains(t, stderr.String(), "big.bin")
	require.NotContains(t, stderr.String(), "ERR")
}

func TestGitFindingURLs(t *testing.T) {
	repo := t.TempDir()
	gitCmdT(t, repo, "init", "-q", "-b", "main")
	gitCmdT(t, repo, "config", "user.name", "URL Test")
	gitCmdT(t, repo, "config", "user.email", "url@example.test")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "secret file.txt"), []byte("ordinary\nSECRET_FILE\n"), 0600))
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("member.txt")
	require.NoError(t, err)
	_, err = entry.Write([]byte("ordinary\nSECRET_ARCHIVE\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(filepath.Join(repo, "archive.zip"), archive.Bytes(), 0600))
	gitCmdT(t, repo, "add", ".")
	gitCmdT(t, repo, "commit", "-qm", "Subject\n\nSECRET_MESSAGE")
	sha := gitCmdT(t, repo, "rev-parse", "HEAD")
	gitCmdT(t, repo, "remote", "add", "origin", "https://github.com/org/repo.git")
	configPath := writeTestConfig(t, "[[rules]]\nid='url-secret'\nregex='SECRET_[A-Z_]+'\n")
	for _, tc := range []struct {
		name, remote, platform, base, commitPath string
	}{
		{"GitHub HTTPS", "https://user:fixture-password@github.com/org/repo.git?token=fixture-query#fixture-fragment", "", "https://github.com/org/repo", "/commit/"},
		{"GitLab SSH", "git@gitlab.com:group/sub/repo.git", "", "https://gitlab.com/group/sub/repo", "/-/commit/"},
		{"self hosted", "ssh://git@git.example.test:2222/group/repo.git", "gitlab", "https://git.example.test/group/repo", "/-/commit/"},
		{"disabled", "https://github.com/org/repo.git", "none", "", ""},
		{"unknown host", "https://example.test/org/repo.git", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gitCmdT(t, repo, "remote", "set-url", "origin", tc.remote)

			t.Setenv("PATH", t.TempDir())
			root, stdout := newTestCLI(t)
			args := []string{"git", repo, "--include=commit-messages", "--config", configPath, "--no-banner", "--exit-code=0", "--output=-"}
			if tc.platform != "" {
				args = append(args, "--platform="+tc.platform)
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			_, findings := decodeScanJSON(t, stdout.Bytes())
			require.Len(t, findings, 3)
			for _, finding := range findings {
				require.Equal(t, "Subject...", finding.Attributes["git.message"])
				if finding.Match.Value == "SECRET_MESSAGE" {
					require.Equal(t, 3, finding.Location.StartLine)
				}
				want := ""
				if tc.base != "" {
					switch finding.Match.Value {
					case "SECRET_FILE":
						want = tc.base + "/blob/" + sha + "/secret%20file.txt#L2"
					case "SECRET_ARCHIVE":
						want = tc.base + "/blob/" + sha + "/archive.zip"
					case "SECRET_MESSAGE":
						want = tc.base + tc.commitPath + sha
					default:
						t.Fatalf("unexpected fixture finding %q", finding.Match.Value)
					}
				}
				require.Equal(t, want, finding.Attributes["url"])
			}
			for _, private := range []string{"fixture-password", "fixture-query", "fixture-fragment"} {
				require.NotContains(t, stdout.String(), private)
			}
		})
	}
}

func gitCmdT(t *testing.T, repo string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).CombinedOutput()
	require.NoError(t, err, "%s", out)
	return strings.TrimSpace(string(out))
}

func TestGitIncludeMerges(t *testing.T) {
	repo := t.TempDir()
	gitCmdT(t, repo, "init", "-q", "-b", "main")
	gitCmdT(t, repo, "config", "user.name", "Merge Test")
	gitCmdT(t, repo, "config", "user.email", "merge@example.test")
	write := func(name, value string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(repo, name), []byte(value+"\n"), 0600))
		gitCmdT(t, repo, "add", name)
	}
	write("root.txt", "SECRET_ROOT")
	gitCmdT(t, repo, "commit", "-qm", "base")
	gitCmdT(t, repo, "checkout", "-qb", "side")
	write("side.txt", "SECRET_SIDE")
	gitCmdT(t, repo, "commit", "-qm", "side")
	sideSHA := gitCmdT(t, repo, "rev-parse", "HEAD")
	gitCmdT(t, repo, "rm", "side.txt")
	gitCmdT(t, repo, "commit", "-qm", "delete side secret")
	gitCmdT(t, repo, "checkout", "-q", "main")
	write("main.txt", "ordinary content")
	gitCmdT(t, repo, "commit", "-qm", "main")
	gitCmdT(t, repo, "merge", "--no-ff", "side", "-m", "SECRET_MERGE_MESSAGE")
	write("merge.txt", "SECRET_MERGE_CONTENT")
	gitCmdT(t, repo, "commit", "--amend", "--no-edit")
	mergeSHA := gitCmdT(t, repo, "rev-parse", "HEAD")
	gitCmdT(t, repo, "branch", "-D", "side")
	configPath := writeTestConfig(t, "[[rules]]\nid='merge-secret'\nregex='SECRET_[A-Z_]+'\n")

	for _, tc := range []struct {
		name      string
		flag      string
		wantMerge bool
	}{
		{"default", "", false},
		{"included", "--include=merges", true},
		{"excluded", "--exclude=merges", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			args := []string{"git", repo, "--include=commit-messages", "--config", configPath, "--no-banner", "--exit-code=0", "--output=-"}
			if tc.flag != "" {
				args = append(args, tc.flag)
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			_, findings := decodeScanJSON(t, stdout.Bytes())
			var values []string
			for _, f := range findings {
				values = append(values, f.Match.Value)
				switch f.Match.Value {
				case "SECRET_SIDE":
					require.Equal(t, sideSHA, f.Attributes["git.sha"])
				case "SECRET_MERGE_MESSAGE", "SECRET_MERGE_CONTENT":
					require.Equal(t, mergeSHA, f.Attributes["git.sha"])
				}
			}
			want := []string{"SECRET_ROOT", "SECRET_SIDE", "SECRET_MERGE_MESSAGE"}
			if tc.wantMerge {
				want = append(want, "SECRET_MERGE_CONTENT")
			}
			require.ElementsMatch(t, want, values)
		})
	}
}

func TestGoGitHistoryWithoutExecutable(t *testing.T) {
	repo := t.TempDir()
	gitCmdT(t, repo, "init", "-q", "-b", "main")
	gitCmdT(t, repo, "config", "user.email", "first@example.test")
	gitCmdT(t, repo, "config", "user.name", "First")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "root.txt"), []byte("before\nSECRET_ONE\nafter\n"), 0644))
	gitCmdT(t, repo, "add", ".")
	gitCmdT(t, repo, "commit", "-qm", "root")
	rootSHA := gitCmdT(t, repo, "rev-parse", "HEAD")
	gitCmdT(t, repo, "rm", "-q", "root.txt")
	gitCmdT(t, repo, "commit", "-qm", "deleted")
	gitCmdT(t, repo, "checkout", "-qb", "side", rootSHA)
	require.NoError(t, os.WriteFile(filepath.Join(repo, "branch.txt"), []byte("SECRET_TWO\n"), 0644))
	gitCmdT(t, repo, "add", ".")
	gitCmdT(t, repo, "-c", "user.name=Side", "commit", "-qm", "side")
	gitCmdT(t, repo, "checkout", "-q", "main")
	gitCmdT(t, repo, "repack", "-ad")
	configPath := writeTestConfig(t, "[[rules]]\nid='git-secret'\nregex='SECRET_[A-Z]+'\n")
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		name  string
		args  []string
		count int
	}{
		{"all refs", nil, 2}, {"head", []string{"--revision=HEAD"}, 1}, {"author", []string{"--author=Side"}, 1}, {"date", []string{"--since=2030-01-01"}, 0},
		{"commit limit", []string{"--revision=side", "--max-commits=1"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			args := append([]string{"git", repo, "--config", configPath, "--no-banner", "--exit-code=0", "--output=-"}, tc.args...)
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			_, findings := decodeScanJSON(t, stdout.Bytes())
			require.Len(t, findings, tc.count)
			for _, finding := range findings {
				require.Len(t, finding.Attributes["git.blob_sha"], 40)
				require.Len(t, finding.Attributes["git.sha"], 40)
			}
		})
	}
}

//nolint:exhaustruct // Fixtures specify only the options relevant to the scenario.
func TestGoGitOptionValidation(t *testing.T) {
	for _, cmd := range []GitCmd{
		{Exclude: []string{"unknown"}}, {Exclude: []string{"history"}}, {Include: []string{"notes"}, Exclude: []string{"notes"}}, {Exclude: []string{""}}, {Author: "["}, {Since: "yesterday"}, {Until: "2001-01-01", Since: "2001-01-02"},
		{MaxCommits: -1}, {GitMaxBlobMiB: -1}, {GitMaxBlobMiB: 4097}, {Revision: "main...side"},
		{CloneRefs: []string{"refs/pull/1/head"}}, {CloneAllRefs: true},
		{Repo: "https://example.test/repo", CloneRefs: []string{"main"}},
	} {
		require.Error(t, cmd.Validate())
	}
	require.NoError(t, (GitCmd{Author: "Test", Since: "2001-01-01", GitMaxBlobMiB: 4096, Revision: "main..HEAD"}).Validate())
	source, err := (GitCmd{AllowExternal: true}).gitSource()
	require.NoError(t, err)
	require.True(t, source.AllowExternalObjects)
	require.Empty(t, source.Exclude, "default resources are not excluded")
	// A date-only --until includes that whole day; --since starts at midnight.
	source, err = (GitCmd{Since: "2001-01-02", Until: "2001-01-02"}).gitSource()
	require.NoError(t, err)
	require.Equal(t, time.Date(2001, 1, 2, 0, 0, 0, 0, time.UTC), *source.Since)
	require.Equal(t, time.Date(2001, 1, 2, 23, 59, 59, 999999999, time.UTC), *source.Until)
	source, err = (GitCmd{Include: []string{"objects"}, Exclude: []string{"history"}}).gitSource()
	require.NoError(t, err)
	require.Equal(t, []string{"history"}, source.Exclude)
	cli, err := parseCLIForTest(t, "git", "--include=commit-messages,notes", "--exclude=history")
	require.NoError(t, err)
	source, err = cli.Git.gitSource()
	require.NoError(t, err)
	require.Equal(t, []string{"commit-messages", "notes"}, source.Include)
	require.Equal(t, []string{"history"}, source.Exclude)
	require.NoError(t, source.Validate())
	cli, err = parseCLIForTest(t, "git", "https://example.test/repo", "--clone-ref=refs/pull/*/head", "--clone-ref=refs/custom/with,comma", "--clone-all-refs")
	require.NoError(t, err)
	source, err = cli.Git.gitSource()
	require.NoError(t, err)
	require.Equal(t, []string{"refs/pull/*/head", "refs/custom/with,comma"}, source.CloneRefs)
	require.True(t, source.CloneAllRefs)
	require.NoError(t, source.Validate())
}

//nolint:exhaustruct // CGI and scenario fields not set keep their defaults.
func TestGitCloneOptions(t *testing.T) {
	repo := t.TempDir()
	gitCmdT(t, repo, "init", "-q", "-b", "main")
	gitCmdT(t, repo, "config", "user.name", "Test User")
	gitCmdT(t, repo, "config", "user.email", "test@example.test")
	commit := func(value string) {
		require.NoError(t, os.WriteFile(filepath.Join(repo, "secret.txt"), []byte(value+"\n"), 0600))
		gitCmdT(t, repo, "add", ".")
		gitCmdT(t, repo, "commit", "-qm", value)
	}
	commit("SECRET_MAIN")
	for _, ref := range []struct{ name, value string }{
		{"refs/pull/123/head", "SECRET_PR"},
		{"refs/pull/456/head", "SECRET_SECOND"},
		{"refs/pull/123/merge", "SECRET_MERGE"},
		{"refs/custom/review", "SECRET_CUSTOM"},
	} {
		gitCmdT(t, repo, "checkout", "-q", "--detach", "main")
		commit(ref.value)
		gitCmdT(t, repo, "update-ref", ref.name, "HEAD")
	}
	gitCmdT(t, repo, "checkout", "-q", "main")
	binary, err := exec.LookPath("git")
	require.NoError(t, err)
	server := httptest.NewServer(&cgi.Handler{Path: binary, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + repo, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1"}})
	t.Cleanup(server.Close)
	configPath := writeTestConfig(t, "[[rules]]\nid='test'\nregex='SECRET_[A-Z]+'\n")
	// Only the server invokes Git; the entire URL scan works without a Git client.
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{name: "default", want: []string{"SECRET_MAIN"}},
		{name: "one PR adds to defaults", args: []string{"--clone-ref=refs/pull/123/head"}, want: []string{"SECRET_MAIN", "SECRET_PR"}},
		{name: "PR heads", args: []string{"--clone-ref=refs/pull/*/head"}, want: []string{"SECRET_MAIN", "SECRET_PR", "SECRET_SECOND"}},
		{name: "repeated refs", args: []string{"--clone-ref=refs/pull/123/head", "--clone-ref=refs/custom/review"}, want: []string{"SECRET_MAIN", "SECRET_PR", "SECRET_CUSTOM"}},
		{name: "all refs", args: []string{"--clone-all-refs"}, want: []string{"SECRET_MAIN", "SECRET_PR", "SECRET_SECOND", "SECRET_MERGE", "SECRET_CUSTOM"}},
		{name: "PR range", args: []string{"--clone-ref=refs/pull/123/head", "--revision=main..refs/pull/123/head"}, want: []string{"SECRET_PR"}},
		{name: "all refs with range", args: []string{"--clone-all-refs", "--revision=main..refs/pull/123/head"}, want: []string{"SECRET_PR"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, stdout := newTestCLI(t)
			args := append([]string{"git", server.URL + "/.git", "--config", configPath, "--no-banner", "--exit-code=0", "--output=-"}, tc.args...)
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			_, findings := decodeScanJSON(t, stdout.Bytes())
			var got []string
			for _, finding := range findings {
				got = append(got, finding.Match.Value)
			}
			require.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestStdinGitDiff(t *testing.T) {
	repo := t.TempDir()
	gitCmdT(t, repo, "init", "-q")
	gitCmdT(t, repo, "config", "user.name", "Test User")
	gitCmdT(t, repo, "config", "user.email", "test@example.test")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "file"), []byte("context\nSECRET_OLD\ncontext\n"), 0600))
	gitCmdT(t, repo, "add", ".")
	gitCmdT(t, repo, "commit", "-qm", "initial")
	require.NoError(t, os.WriteFile(filepath.Join(repo, "file"), []byte("context\nSECRET_NEW\ncontext\n"), 0600))
	gitCmdT(t, repo, "add", ".")
	patch := gitCmdT(t, repo, "diff", "--cached", "--no-ext-diff", "--no-textconv") + "\n"
	cfg := writeTestConfig(t, "[[rules]]\nid='test'\nregex='SECRET_[A-Z]+'\n")
	t.Setenv("PATH", t.TempDir())
	root, stdout := newTestCLI(t)
	root.runtime.stdin = strings.NewReader(patch)
	root.SetArgs([]string{"stdin", "--git-diff", "--config", cfg, "--no-banner", "--output=-", "--exit-code=0"})
	require.NoError(t, root.Execute())
	_, findings := decodeScanJSON(t, stdout.Bytes())
	require.Len(t, findings, 1)
	require.Equal(t, "SECRET_NEW", findings[0].Match.Value)
	require.Equal(t, "file", findings[0].Location.Path)
	require.Equal(t, 2, findings[0].Location.StartLine)
}
