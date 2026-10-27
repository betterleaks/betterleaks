//nolint:exhaustruct // Fixtures specify only the fields relevant to each scenario.
package gogit

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
	"github.com/go-git/go-billy/v5"
	"github.com/stretchr/testify/require"
)

func TestWorktreePrivateReferences(t *testing.T) {
	for _, namespace := range []string{"worktree", "bisect", "rewritten"} {
		t.Run(namespace, func(t *testing.T) {
			repo := initRepo(t)
			base := commitFile(t, repo, "file", "TOKEN_BASE\n", "base")
			local := commitFile(t, repo, "file", "TOKEN_LOCAL\n", "local")
			gitFixture(t, repo, "reset", "--hard", base)
			shared := commitFile(t, repo, "file", "TOKEN_MAIN\n", "main")
			gitFixture(t, repo, "reset", "--hard", base)
			linked := filepath.Join(t.TempDir(), "linked")
			gitFixture(t, repo, "worktree", "add", "-qb", "linked", linked)
			name := "refs/" + namespace + "/private"
			gitFixture(t, repo, "update-ref", name, shared)
			gitFixture(t, linked, "update-ref", name, local)
			require.Equal(t, map[string]string{"TOKEN_BASE\n": "file:1", "TOKEN_LOCAL\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: linked})))
			require.Equal(t, map[string]string{"TOKEN_BASE\n": "file:1", "TOKEN_MAIN\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo})))
		})
	}
}

type disappearingRefFS struct {
	billy.Filesystem
	remove string
}

func (f *disappearingRefFS) ReadDir(name string) ([]os.FileInfo, error) {
	entries, err := f.Filesystem.ReadDir(name)
	if name == "refs/heads" && f.remove != "" {
		if err := os.Remove(f.remove); err != nil {
			return nil, err
		}
		f.remove = ""
	}
	return entries, err
}

func TestReferenceDisappearsDuringEnumeration(t *testing.T) {
	repo := initRepo(t)
	id := commitFile(t, repo, "file", "TOKEN_REMAINING_REF\n", "initial")
	gitFixture(t, repo, "update-ref", "refs/heads/removed", id)
	r, close, err := (&Source{RepoPath: repo}).open(t.Context())
	require.NoError(t, err)
	defer close()
	s := r.Storer.(*objectStorage)
	s.fs.Filesystem = &disappearingRefFS{Filesystem: s.fs.Filesystem, remove: filepath.Join(repo, ".git", "refs", "heads", "removed")}
	refs, err := s.IterReferences()
	require.NoError(t, err)
	defer refs.Close()
	require.NotNil(t, s.refs[gitobj.HEAD])
	require.NotNil(t, s.refs[gitobj.ReferenceName("refs/heads/"+gitFixture(t, repo, "branch", "--show-current"))])
	require.NotContains(t, s.refs, gitobj.ReferenceName("refs/heads/removed"))
}

func TestDefaultScanIgnoresReferenceLocks(t *testing.T) {
	for _, packed := range []bool{false, true} {
		t.Run(fmt.Sprintf("packed=%v", packed), func(t *testing.T) {
			repo := initRepo(t)
			base := commitFile(t, repo, "file", "TOKEN_PUBLISHED\n", "published")
			unpublished := commitFile(t, repo, "file", "TOKEN_UNPUBLISHED\n", "pending update")
			gitFixture(t, repo, "reset", "--hard", base)
			if packed {
				gitFixture(t, repo, "pack-refs", "--all")
			}
			heads := filepath.Join(repo, ".git", "refs", "heads")
			require.NoError(t, os.MkdirAll(filepath.Join(heads, "namespace.lock"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(heads, "namespace.lock", "pending"), []byte(unpublished+"\n"), 0600))
			for _, value := range []string{"", "in progress", unpublished + "\n"} {
				require.NoError(t, os.WriteFile(filepath.Join(heads, "main.lock"), []byte(value), 0600))
				require.Equal(t, map[string]string{"TOKEN_PUBLISHED\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo})))
			}
			// Filtering temporary files must not hide a genuinely broken ref.
			require.NoError(t, os.WriteFile(filepath.Join(heads, "broken"), []byte("not a hash"), 0600))
			require.Error(t, (&Source{RepoPath: repo}).Fragments(t.Context(), func(_ sources.Fragment, err error) error { return err }))
		})
	}
}

func TestAlternateObjectDirectories(t *testing.T) {
	for _, packed := range []bool{false, true} {
		repo := initRepo(t)
		commitFile(t, repo, "file", "TOKEN_ALTERNATE\n", "initial")
		if packed {
			gitFixture(t, repo, "repack", "-adq")
		}
		// Keep both alternates inside the repository, including a cycle and a
		// directory whose name is not objects. No external-object opt-in needed.
		pool := filepath.Join(repo, "pool")
		require.NoError(t, os.Rename(filepath.Join(repo, ".git", "objects"), pool))
		bridge := filepath.Join(repo, "bridge")
		require.NoError(t, os.MkdirAll(filepath.Join(bridge, "info"), 0700))
		require.NoError(t, os.MkdirAll(filepath.Join(repo, ".git", "objects", "info"), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", "objects", "info", "alternates"), []byte(bridge+"\n"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(bridge, "info", "alternates"), []byte(pool+"\n"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(pool, "info", "alternates"), []byte(bridge+"\n"), 0600))
		require.Equal(t, map[string]string{"TOKEN_ALTERNATE\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo})))
		// Nested alternates must pass the same confinement check as direct ones.
		external := filepath.Join(t.TempDir(), "elsewhere")
		require.NoError(t, os.Mkdir(external, 0700))
		require.NoError(t, os.WriteFile(filepath.Join(bridge, "info", "alternates"), []byte(external+"\n"), 0600))
		_, _, err := (&Source{RepoPath: repo}).open(t.Context())
		require.ErrorIs(t, err, ErrExternalStore)
	}
}

func TestMissingConfig(t *testing.T) {
	repo := initRepo(t)
	commitFile(t, repo, "file", "TOKEN_NO_CONFIG\n", "initial")
	require.NoError(t, os.Remove(filepath.Join(repo, ".git", "config")))
	require.Equal(t, map[string]string{"TOKEN_NO_CONFIG\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo})))
}

func TestBranchMergeConfig(t *testing.T) {
	for _, worktree := range []bool{false, true} {
		t.Run(fmt.Sprintf("worktree=%v", worktree), func(t *testing.T) {
			repo := initRepo(t)
			commitFile(t, repo, "file", "TOKEN_REVIEW_BRANCH\n", "initial")
			gitFixture(t, repo, "remote", "add", "origin", "https://github.com/example/origin")
			gitFixture(t, repo, "remote", "add", "review", "https://github.com/example/review")
			configPath := filepath.Join(repo, ".git", "config")
			if worktree {
				gitFixture(t, repo, "config", "extensions.worktreeConfig", "true")
				linked := filepath.Join(t.TempDir(), "linked")
				gitFixture(t, repo, "worktree", "add", "-qb", "linked", linked)
				repo = linked
				configPath = gitFixture(t, repo, "rev-parse", "--git-path", "config.worktree")
			}
			branch := gitFixture(t, repo, "branch", "--show-current")
			args := []string{"config"}
			if worktree {
				args = append(args, "--worktree")
			}
			gitFixture(t, repo, append(args, "branch."+branch+".remote", "review")...)
			// An unrelated local branch must not prevent a scan either.
			gitFixture(t, repo, append(args, "branch.inactive.merge", "refs/pull/84/head")...)
			for _, merge := range []string{"", "refs/heads/main", "refs/pull/83/head", "refs/merge-requests/83/head", "refs/changes/83/12383/1", "refs/tags/v1", "main"} {
				t.Run(merge, func(t *testing.T) {
					gitFixture(t, repo, append(args, "branch."+branch+".merge", merge)...)
					before, err := os.ReadFile(configPath)
					require.NoError(t, err)
					s := &Source{RepoPath: repo}
					r, close, err := s.open(t.Context())
					require.NoError(t, err)
					defer close()
					cfg, err := r.Config()
					require.NoError(t, err)
					require.Equal(t, merge, cfg.Branches[branch].Merge.String())
					require.Equal(t, "refs/pull/84/head", cfg.Branches["inactive"].Merge.String())
					platform, remote := s.resolveRemote(r)
					require.Equal(t, scm.GitHubPlatform, platform)
					require.Equal(t, "https://github.com/example/review", remote)
					require.Equal(t, map[string]string{"TOKEN_REVIEW_BRANCH\n": "file:1"}, textOccurrences(collect(t, s)))
					after, err := os.ReadFile(configPath)
					require.NoError(t, err)
					require.Equal(t, before, after, "scanning must not rewrite repository config")
				})
			}
		})
	}
}

func TestLooseObjectValidation(t *testing.T) {
	s := &objectStorage{ctx: t.Context(), limit: 1024}
	for _, raw := range []string{"blob 3\x00abc", "blob 3\x00ab", "blob 3\x00abcd", "blob -1\x00", "blob 1025\x00", "blob 0000000000000000000000000000000000000000000000000000000000001x", "bogus 0\x00"} {
		var compressed bytes.Buffer
		w := zlib.NewWriter(&compressed)
		_, err := w.Write([]byte(raw))
		require.NoError(t, err)
		require.NoError(t, w.Close())
		obj, err := s.decodeLoose(&compressed, gitobj.ZeroHash)
		if raw == "blob 3\x00abc" {
			require.NoError(t, err)
			require.Equal(t, "abc", obj.raw)
		} else {
			require.Error(t, err, strings.ReplaceAll(raw, "\x00", "<NUL>"))
		}
	}
}

func TestExistingDashReference(t *testing.T) {
	repo := initRepo(t)
	id := commitFile(t, repo, "file", "TOKEN_DASH_REF\n", "initial")
	gitFixture(t, repo, "update-ref", "refs/heads/-r", id)
	gitFixture(t, repo, "symbolic-ref", "HEAD", "refs/heads/-r")
	for _, packed := range []bool{false, true} {
		if packed {
			gitFixture(t, repo, "pack-refs", "--all")
		}
		require.Equal(t, map[string]string{"TOKEN_DASH_REF\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo})))
	}
}

func TestRepositoryExtensions(t *testing.T) {
	repo := initRepo(t)
	for _, tc := range []struct {
		version, extensions string
		valid               bool
	}{
		{"0", "", true}, {"1", "", true}, {"2", "", false},
		{"01", "", true}, {"1", "objectFormat = SHA1", true},
		{"1", "objectFormat = sha256", true}, {"0", "objectFormat = sha256", false},
		{"1", "objectFormat = unknown", false}, {"1", "refStorage = reftable", false},
		{"1", "preciousObjects = true", false}, {"0", "noop = anything", true},
		{"1", "noop-v1 = anything", true}, {"0", "noop-v1 = anything", false},
		{"0", "worktreeConfig = true", true}, {"1", "relativeWorktrees = true", true},
		{"0", "worktreeConfig = 1", true}, {"0", "worktreeConfig = invalid", false},
		{"0", "relativeWorktrees = true", false}, {"1", "unknown = true", false},
	} {
		raw := fmt.Sprintf("[core]\nrepositoryFormatVersion = %s\n[extensions]\n%s\n", tc.version, tc.extensions)
		require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", "config"), []byte(raw), 0600))
		_, close, err := (&Source{RepoPath: repo}).open(t.Context())
		if tc.valid {
			require.NoError(t, err, raw)
			close()
		} else {
			require.Error(t, err, raw)
		}
	}
}

func TestWorktreeConfigOverlay(t *testing.T) {
	repo := initRepo(t)
	commitFile(t, repo, "file", "TOKEN_WORKTREE_CONFIG\n", "initial")
	gitFixture(t, repo, "remote", "add", "origin", "https://github.com/example/shared")
	gitFixture(t, repo, "remote", "add", "keep", "https://github.com/example/keep")
	gitFixture(t, repo, "config", "extensions.worktreeConfig", "true")
	linked := filepath.Join(t.TempDir(), "linked")
	gitFixture(t, repo, "worktree", "add", "-qb", "linked", linked)
	gitFixture(t, linked, "config", "--worktree", "remote.origin.url", "https://gitlab.com/example/linked")
	gitFixture(t, linked, "config", "--worktree", "branch.linked.remote", "origin")
	for _, tc := range []struct {
		value   string
		enabled bool
	}{
		{"true", true}, {"TRUE", true}, {"1", true}, {"yes", true}, {"on", true}, {"-2", true},
		{"false", false}, {"0", false}, {"no", false}, {"off", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			gitFixture(t, repo, "config", "extensions.worktreeConfig", tc.value)
			for _, path := range []string{repo, linked} {
				r, close, err := (&Source{RepoPath: path}).open(t.Context())
				require.NoError(t, err)
				cfg, err := r.Config()
				require.NoError(t, err)
				want := "https://github.com/example/shared"
				if path == linked && tc.enabled {
					want = "https://gitlab.com/example/linked"
					require.Equal(t, "origin", cfg.Branches["linked"].Remote)
				}
				require.Equal(t, []string{want}, cfg.Remotes["origin"].URLs)
				require.Equal(t, []string{"https://github.com/example/keep"}, cfg.Remotes["keep"].URLs)
				close()
			}
		})
	}
}

func TestWorktreeConfigPreservesSharedSettings(t *testing.T) {
	for _, linked := range []bool{false, true} {
		for _, overlay := range []string{"fetch", "url", "description"} {
			t.Run(fmt.Sprintf("linked=%v/%s", linked, overlay), func(t *testing.T) {
				repo := initRepo(t)
				commitFile(t, repo, "file", "TOKEN_CONFIG\n", "initial")
				gitFixture(t, repo, "remote", "add", "origin", "https://github.com/example/shared")
				gitFixture(t, repo, "remote", "add", "review", "https://github.com/example/review")
				gitFixture(t, repo, "config", "extensions.worktreeConfig", "true")
				gitFixture(t, repo, "config", "url.https://github.com/.insteadOf", "gh:")
				path := repo
				if linked {
					path = filepath.Join(t.TempDir(), "linked")
					gitFixture(t, repo, "worktree", "add", "-qb", "linked", path)
				}
				branch := gitFixture(t, path, "branch", "--show-current")
				gitFixture(t, repo, "config", "branch."+branch+".remote", "review")
				gitFixture(t, repo, "config", "branch."+branch+".merge", "refs/heads/main")
				want := "https://github.com/example/shared"
				switch overlay {
				case "fetch":
					gitFixture(t, path, "config", "--worktree", "remote.origin.fetch", "+refs/heads/topic:refs/remotes/origin/topic")
					gitFixture(t, path, "config", "--worktree", "--add", "remote.origin.fetch", "+refs/tags/*:refs/tags/*")
				case "url":
					gitFixture(t, path, "config", "--worktree", "remote.origin.url", "gh:example/worktree")
					gitFixture(t, path, "config", "--worktree", "--add", "remote.origin.url", "gh:example/mirror")
					want = "https://github.com/example/worktree"
				case "description":
					gitFixture(t, path, "config", "--worktree", "branch."+branch+".description", "worktree description")
				}
				s := &Source{RepoPath: path}
				r, close, err := s.open(t.Context())
				require.NoError(t, err)
				defer close()
				cfg, err := r.Config()
				require.NoError(t, err)
				require.NotEmpty(t, cfg.Remotes["origin"].URLs)
				require.Equal(t, want, cfg.Remotes["origin"].URLs[0])
				require.Equal(t, "review", cfg.Branches[branch].Remote)
				require.Equal(t, "refs/heads/main", cfg.Branches[branch].Merge.String())
				_, remote := s.resolveRemote(r)
				require.Equal(t, "https://github.com/example/review", remote)
				if overlay == "url" {
					require.Equal(t, []string{want, "https://github.com/example/mirror"}, cfg.Remotes["origin"].URLs)
					require.Len(t, cfg.Remotes["origin"].Fetch, 1, "overlay URL must preserve shared fetch settings")
				}
				if overlay == "fetch" {
					require.Len(t, cfg.Remotes["origin"].Fetch, 2, "all values of the overriding setting must be retained")
				}
			})
		}
	}
}
