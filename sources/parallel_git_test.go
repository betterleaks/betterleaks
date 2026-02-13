package sources

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/fatih/semgroup"
)

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
	list []Fragment
}

func (c *collectFragments) yield(fragment Fragment, err error) error {
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
			t.Logf("  path=%s raw=%q", f.FilePath, f.Raw)
		}
	}

	// Verify all files are represented
	paths := make(map[string]bool)
	for _, f := range c.list {
		paths[f.FilePath] = true
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
		singleSet[f.FilePath+"\x00"+strings.TrimSpace(f.Raw)] = true
	}
	multiSet := make(map[string]bool)
	for _, f := range multi.list {
		multiSet[f.FilePath+"\x00"+strings.TrimSpace(f.Raw)] = true
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
