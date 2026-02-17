package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/fatih/semgroup"
)

// gitExec runs a git command in dir and returns combined output.
func gitExec(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitSHA returns the current HEAD SHA.
func gitSHA(t *testing.T, dir string) string {
	t.Helper()
	return gitExec(t, dir, "rev-parse", "HEAD")
}

// initTestRepo creates a temp git repo with some commits and returns its path.
func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	cmds := [][]string{
		{"git", "init"},
		{"git", "config", "user.email", "test@example.com"},
		{"git", "config", "user.name", "Test User"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git init: %v\n%s", err, out)
		}
	}
	return dir
}

// commitFile writes a file and commits it.
func commitFile(t *testing.T, dir, path, content, message string) {
	t.Helper()

	fullPath := filepath.Join(dir, path)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"git", "add", path},
		{"git", "commit", "-m", message},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
}

func TestCommitCount(t *testing.T) {
	dir := initTestRepo(t)

	commitFile(t, dir, "a.txt", "hello\n", "first")
	commitFile(t, dir, "b.txt", "world\n", "second")
	commitFile(t, dir, "c.txt", "foo\n", "third")

	ctx := context.Background()
	count, err := commitCount(ctx, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("commitCount = %d, want 3", count)
	}
}

func TestListCommits(t *testing.T) {
	dir := initTestRepo(t)

	commitFile(t, dir, "a.txt", "hello\n", "first")
	commitFile(t, dir, "b.txt", "world\n", "second")
	commitFile(t, dir, "c.txt", "foo\n", "third")

	ctx := context.Background()
	commits, err := listCommits(ctx, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 3 {
		t.Errorf("listCommits returned %d, want 3", len(commits))
	}
	// Each entry should be a 40-char hex SHA
	for i, sha := range commits {
		if len(sha) != 40 {
			t.Errorf("commit[%d] = %q, want 40-char SHA", i, sha)
		}
	}
	// All SHAs should be unique
	seen := make(map[string]bool)
	for _, sha := range commits {
		if seen[sha] {
			t.Errorf("duplicate SHA: %s", sha)
		}
		seen[sha] = true
	}
}

// collectFragments is a thread-safe fragment collector for tests.
type collectFragments struct {
	mu   sync.Mutex
	list []betterleaks.Fragment
}

func (c *collectFragments) yield(fragment betterleaks.Fragment, err error) error {
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.list = append(c.list, fragment)
	c.mu.Unlock()
	return nil
}

func TestParallelGitFragments(t *testing.T) {
	dir := initTestRepo(t)

	commitFile(t, dir, "a.txt", "secret_a\n", "add a")
	commitFile(t, dir, "b.txt", "secret_b\n", "add b")
	commitFile(t, dir, "c.txt", "secret_c\n", "add c")
	commitFile(t, dir, "d.txt", "secret_d\n", "add d")

	ctx := context.Background()
	src := &ParallelGit{
		RepoPath: dir,
		Config:   &config.Config{},
		Sema:     semgroup.NewGroup(ctx, 4),
		Workers:  2,
	}

	var c collectFragments
	err := src.Fragments(ctx, c.yield)
	if err != nil {
		t.Fatal(err)
	}

	// Each commit adds one file, so we should get 4 fragments
	if len(c.list) != 4 {
		t.Errorf("got %d fragments, want 4", len(c.list))
		for _, f := range c.list {
			t.Logf("  path=%s raw=%q", f.Path, f.Raw)
		}
	}

	// Verify all files are represented
	paths := make(map[string]bool)
	for _, f := range c.list {
		paths[f.Path] = true
	}
	for _, want := range []string{"a.txt", "b.txt", "c.txt", "d.txt"} {
		if !paths[want] {
			t.Errorf("missing fragment for %s", want)
		}
	}
}

func TestParallelGitSingleCommit(t *testing.T) {
	dir := initTestRepo(t)

	commitFile(t, dir, "only.txt", "content\n", "only commit")

	ctx := context.Background()
	src := &ParallelGit{
		RepoPath: dir,
		Config:   &config.Config{},
		Sema:     semgroup.NewGroup(ctx, 4),
		Workers:  4, // more workers than commits
	}

	var c collectFragments
	err := src.Fragments(ctx, c.yield)
	if err != nil {
		t.Fatal(err)
	}

	if len(c.list) != 1 {
		t.Errorf("got %d fragments, want 1", len(c.list))
	}
}

func TestParallelGitMatchesSingleGit(t *testing.T) {
	dir := initTestRepo(t)

	commitFile(t, dir, "x.txt", "line1\n", "c1")
	commitFile(t, dir, "x.txt", "line1\nline2\n", "c2")
	commitFile(t, dir, "y.txt", "stuff\n", "c3")
	commitFile(t, dir, "z.txt", "data\n", "c4")
	commitFile(t, dir, "x.txt", "line1\nline2\nline3\n", "c5")

	ctx := context.Background()

	// Run single-worker (equivalent to original Git source)
	singleSrc := &ParallelGit{
		RepoPath: dir,
		Config:   &config.Config{},
		Sema:     semgroup.NewGroup(ctx, 10),
		Workers:  1,
	}

	var single collectFragments
	if err := singleSrc.Fragments(ctx, single.yield); err != nil {
		t.Fatal(err)
	}

	// Run multi-worker
	multiSrc := &ParallelGit{
		RepoPath: dir,
		Config:   &config.Config{},
		Sema:     semgroup.NewGroup(ctx, 10),
		Workers:  3,
	}

	var multi collectFragments
	if err := multiSrc.Fragments(ctx, multi.yield); err != nil {
		t.Fatal(err)
	}

	// Same number of fragments
	if len(single.list) != len(multi.list) {
		t.Errorf("single=%d fragments, multi=%d fragments", len(single.list), len(multi.list))
	}

	// Build sets of (path, raw) to verify content parity
	singleSet := make(map[string]bool)
	for _, f := range single.list {
		singleSet[f.Path+"\x00"+strings.TrimSpace(f.Raw)] = true
	}
	multiSet := make(map[string]bool)
	for _, f := range multi.list {
		multiSet[f.Path+"\x00"+strings.TrimSpace(f.Raw)] = true
	}

	for key := range singleSet {
		if !multiSet[key] {
			parts := strings.SplitN(key, "\x00", 2)
			t.Errorf("single has fragment path=%s raw=%q not found in multi", parts[0], parts[1])
		}
	}
	for key := range multiSet {
		if !singleSet[key] {
			parts := strings.SplitN(key, "\x00", 2)
			t.Errorf("multi has fragment path=%s raw=%q not found in single", parts[0], parts[1])
		}
	}
}

// initTestRepoWithAmend creates a repo where a commit is amended, producing a
// reflog-only pre-amend commit. Returns (repoDir, preAmendSHA, postAmendSHA).
func initTestRepoWithAmend(t *testing.T) (string, string, string) {
	t.Helper()
	dir := initTestRepo(t)

	// Initial commit
	commitFile(t, dir, "a.txt", "original\n", "first commit")

	// Second commit (will be amended)
	commitFile(t, dir, "secret.txt", "pre-amend-content\n", "add secret")
	preAmendSHA := gitSHA(t, dir)

	// Amend: replace the file content
	fullPath := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(fullPath, []byte("post-amend-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitExec(t, dir, "add", "secret.txt")
	gitExec(t, dir, "commit", "--amend", "-m", "add secret (amended)")
	postAmendSHA := gitSHA(t, dir)

	if preAmendSHA == postAmendSHA {
		t.Fatal("amend did not change SHA")
	}

	return dir, preAmendSHA, postAmendSHA
}

func TestListCommitsIncludesReflog(t *testing.T) {
	dir, preAmendSHA, postAmendSHA := initTestRepoWithAmend(t)

	ctx := context.Background()
	commits, err := listCommits(ctx, dir, "")
	if err != nil {
		t.Fatal(err)
	}

	commitSet := make(map[string]bool)
	for _, sha := range commits {
		commitSet[sha] = true
	}

	if !commitSet[postAmendSHA] {
		t.Errorf("listCommits missing current HEAD %s", postAmendSHA)
	}
	if !commitSet[preAmendSHA] {
		t.Errorf("listCommits missing pre-amend SHA %s (should be reachable via --reflog)", preAmendSHA)
	}
}

func TestListDanglingCommits(t *testing.T) {
	dir, preAmendSHA, _ := initTestRepoWithAmend(t)

	// Expire all reflog entries so the pre-amend commit becomes dangling
	gitExec(t, dir, "reflog", "expire", "--expire=now", "--all")

	// Verify the pre-amend SHA is no longer in rev-list --all --reflog
	ctx := context.Background()
	reachable, err := listCommits(ctx, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	reachableSet := make(map[string]bool)
	for _, sha := range reachable {
		reachableSet[sha] = true
	}
	if reachableSet[preAmendSHA] {
		t.Fatalf("pre-amend SHA %s should not be reachable after reflog expire", preAmendSHA)
	}

	// Now it should appear as a dangling commit
	dangling, err := ListDanglingCommits(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	danglingSet := make(map[string]bool)
	for _, sha := range dangling {
		danglingSet[sha] = true
	}
	if !danglingSet[preAmendSHA] {
		t.Errorf("ListDanglingCommits did not return pre-amend SHA %s; got %v", preAmendSHA, dangling)
	}
}

func TestParallelGitWithDangling(t *testing.T) {
	dir, preAmendSHA, _ := initTestRepoWithAmend(t)

	// Expire reflog so pre-amend commit is dangling
	gitExec(t, dir, "reflog", "expire", "--expire=now", "--all")

	ctx := context.Background()
	src := &ParallelGit{
		RepoPath:        dir,
		Config:          &config.Config{},
		Sema:            semgroup.NewGroup(ctx, 4),
		Workers:         2,
		IncludeDangling: true,
	}

	var c collectFragments
	if err := src.Fragments(ctx, c.yield); err != nil {
		t.Fatal(err)
	}

	// We should find fragments from both the current commits AND the dangling one.
	// The dangling commit added "pre-amend-content" to secret.txt.
	var foundDangling bool
	for _, f := range c.list {
		if f.Resource != nil && f.Resource.ID == preAmendSHA {
			foundDangling = true
			break
		}
	}
	if !foundDangling {
		t.Errorf("ParallelGit with IncludeDangling did not yield fragment from dangling commit %s", preAmendSHA)
		for _, f := range c.list {
			id := ""
			if f.Resource != nil {
				id = f.Resource.ID
			}
			t.Logf("  path=%s commit=%s raw=%q", f.Path, id, f.Raw)
		}
	}
}

func TestRegularGitWithDangling(t *testing.T) {
	dir, preAmendSHA, _ := initTestRepoWithAmend(t)

	// Expire reflog so pre-amend commit is dangling
	gitExec(t, dir, "reflog", "expire", "--expire=now", "--all")

	ctx := context.Background()

	// Main source (regular mode)
	mainCmd, err := NewGitLogCmdContext(ctx, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	mainSrc := &Git{
		Cmd:    mainCmd,
		Config: &config.Config{},
		Sema:   semgroup.NewGroup(ctx, 4),
	}

	// Dangling source
	dangling, err := ListDanglingCommits(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dangling) == 0 {
		t.Fatal("expected dangling commits after reflog expire")
	}

	danglingCmd, err := NewGitLogCommitsCmd(ctx, dir, dangling)
	if err != nil {
		t.Fatal(err)
	}
	danglingSrc := &Git{
		Cmd:    danglingCmd,
		Config: &config.Config{},
		Sema:   semgroup.NewGroup(ctx, 4),
	}

	// Collect fragments from both sources
	var c collectFragments
	if err := mainSrc.Fragments(ctx, c.yield); err != nil {
		t.Fatal(err)
	}
	if err := danglingSrc.Fragments(ctx, c.yield); err != nil {
		t.Fatal(err)
	}

	// The dangling commit should have produced a fragment
	var foundDangling bool
	for _, f := range c.list {
		if f.Resource != nil && f.Resource.ID == preAmendSHA {
			foundDangling = true
			break
		}
	}
	if !foundDangling {
		t.Errorf("regular Git + dangling pass did not yield fragment from dangling commit %s", preAmendSHA)
		for _, f := range c.list {
			id := ""
			if f.Resource != nil {
				id = f.Resource.ID
			}
			t.Logf("  path=%s commit=%s raw=%q", f.Path, id, f.Raw)
		}
	}
}
