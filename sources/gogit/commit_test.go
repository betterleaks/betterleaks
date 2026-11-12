//nolint:exhaustruct // Fixtures specify only the fields relevant to each scenario.
package gogit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/stretchr/testify/require"
)

func TestCommitParents(t *testing.T) {
	repo := initRepo(t)
	root := commitFile(t, repo, "file", "a\n", "root")
	second := commitFile(t, repo, "file", "a\nb\n", "second")

	// A side branch and a no-ff merge produce a two-parent commit whose first
	// parent is the branch it was merged into.
	gitFixture(t, repo, "checkout", "-qb", "side", root)
	side := commitFile(t, repo, "side", "s\n", "side")
	gitFixture(t, repo, "checkout", "-q", "main")
	gitFixture(t, repo, "merge", "-q", "--no-ff", "side", "-m", "merge")
	merge := gitFixture(t, repo, "rev-parse", "HEAD")

	src := &Source{RepoPath: repo}

	t.Run("root has no parents", func(t *testing.T) {
		parents, err := src.CommitParents(t.Context(), root)
		require.NoError(t, err)
		require.Empty(t, parents)
	})

	t.Run("regular commit reports its first parent", func(t *testing.T) {
		parents, err := src.CommitParents(t.Context(), second)
		require.NoError(t, err)
		require.Equal(t, []string{root}, parents)
	})

	t.Run("merge commit reports both parents in order", func(t *testing.T) {
		parents, err := src.CommitParents(t.Context(), merge)
		require.NoError(t, err)
		require.Equal(t, []string{second, side}, parents)
	})

	t.Run("revision expressions resolve", func(t *testing.T) {
		// main^ is the merge's first parent (second); its only parent is root.
		parents, err := src.CommitParents(t.Context(), "main^")
		require.NoError(t, err)
		require.Equal(t, []string{root}, parents)
	})
}

func TestCommitParentsTagPeels(t *testing.T) {
	repo := initRepo(t)
	root := commitFile(t, repo, "file", "a\n", "root")
	commitFile(t, repo, "file", "a\nb\n", "second")
	gitFixture(t, repo, "tag", "-a", "release", "-m", "release")

	parents, err := (&Source{RepoPath: repo}).CommitParents(t.Context(), "release")
	require.NoError(t, err)
	require.Equal(t, []string{root}, parents, "annotated tag peels to its commit")
}

func TestCommitParentsValidation(t *testing.T) {
	repo := initRepo(t)
	commitFile(t, repo, "file", "a\n", "root")

	_, err := (&Source{RepoPath: ""}).CommitParents(t.Context(), "HEAD")
	require.EqualError(t, err, "git commit metadata requires a local repository path")

	_, err = (&Source{RepoPath: repo}).CommitParents(t.Context(), "")
	require.EqualError(t, err, "git commit metadata requires a revision")

	_, err = (&Source{RepoPath: repo}).CommitParents(t.Context(), "does-not-exist")
	require.ErrorIs(t, err, gitobj.ErrReferenceNotFound)

	_, err = (&Source{RepoPath: repo}).CommitParents(t.Context(), "HEAD~1..HEAD")
	require.EqualError(t, err, "git commit metadata requires a single revision, not a range")

	_, err = (&Source{RepoPath: repo}).CommitParents(t.Context(), "HEAD^{/root}")
	require.EqualError(t, err, "git commit metadata does not support message-search revisions")
}

func TestCommitParentsReadsQuarantine(t *testing.T) {
	// A pre-receive hook sees a pushed commit only in the receive-pack
	// quarantine, named through GIT_OBJECT_DIRECTORY. CommitParents must
	// resolve it and report its parents, with AllowExternalObjects.
	repo := initRepo(t)
	base := commitFile(t, repo, "file", "a\n", "base")
	pushed := commitFile(t, repo, "file", "a\nb\n", "pushed")

	// Move the pushed commit's objects into a quarantine the repo cannot see
	// on its own, then expose it only through the environment.
	quarantine := filepath.Join(t.TempDir(), "quarantine")
	require.NoError(t, os.Rename(filepath.Join(repo, ".git", "objects"), quarantine))
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git", "objects", "info"), 0700))
	t.Setenv("GIT_OBJECT_DIRECTORY", quarantine)

	// Confined by default: the quarantine is outside the repository.
	_, err := (&Source{RepoPath: repo}).CommitParents(t.Context(), pushed)
	require.ErrorIs(t, err, ErrExternalStore)

	// Opting in resolves the quarantined commit and returns its parent.
	parents, err := (&Source{RepoPath: repo, AllowExternalObjects: true}).CommitParents(t.Context(), pushed)
	require.NoError(t, err)
	require.Equal(t, []string{base}, parents)
}

func TestCommitParentsHonorsConfinement(t *testing.T) {
	repo := initRepo(t)
	commitFile(t, repo, "file", "a\n", "root")
	head := commitFile(t, repo, "file", "a\nb\n", "second")

	// Move the objects into an external directory and name it like a
	// receive-pack quarantine would, through objects/info/alternates.
	external := filepath.Join(t.TempDir(), "quarantine")
	require.NoError(t, os.Rename(filepath.Join(repo, ".git", "objects"), external))
	require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git", "objects", "info"), 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(repo, ".git", "objects", "info", "alternates"),
		[]byte(external+"\n"), 0600))

	// Confined by default: external storage is refused.
	_, err := (&Source{RepoPath: repo}).CommitParents(t.Context(), head)
	require.ErrorIs(t, err, ErrExternalStore)

	// Opting in reads the external objects and resolves parents.
	parents, err := (&Source{RepoPath: repo, AllowExternalObjects: true}).CommitParents(t.Context(), head)
	require.NoError(t, err)
	require.Len(t, parents, 1)
}
