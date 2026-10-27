//nolint:exhaustruct // Fixtures specify only the fields relevant to the scenario.
package gogit

import (
	"compress/zlib"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/stretchr/testify/require"
)

func TestRevisionObjectDisambiguation(t *testing.T) {
	for _, format := range []gitobj.ObjectFormat{gitobj.SHA1, gitobj.SHA256} {
		t.Run(string(format), func(t *testing.T) {
			repo := t.TempDir()
			gitFixture(t, repo, "init", "-q", "-b", "main", "--object-format="+string(format))
			tree := gitInput(t, repo, nil, "mktree")
			// Birthday search gives two real commit IDs with the same four
			// digits without depending on the current time or Git version.
			seen := make(map[string]string)
			var first, second, prefix string
			hash := func(kind gitobj.ObjectType, raw string) string {
				h := gitobj.NewHasher(format, kind, int64(len(raw)))
				h.Write([]byte(raw))
				return h.Sum().String()
			}
			for n := range 10000 {
				raw := fmt.Sprintf("tree %s\nauthor T <t@example.test> 1000000000 +0000\ncommitter T <t@example.test> 1000000000 +0000\n\ncommit %d\n", tree, n)
				id := hash(gitobj.CommitObject, raw)
				if previous, ok := seen[id[:4]]; ok {
					first, second, prefix = previous, raw, id[:4]
					break
				}
				seen[id[:4]] = raw
			}
			require.NotEmpty(t, prefix)
			write := func(kind gitobj.ObjectType, raw, objects string) string {
				t.Helper()
				id := hash(kind, raw)
				path := filepath.Join(objects, id[:2], id[2:])
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
				f, err := os.Create(path)
				require.NoError(t, err)
				w := zlib.NewWriter(f)
				_, err = fmt.Fprintf(w, "%s %d\x00%s", kind, len(raw), raw)
				require.NoError(t, err)
				require.NoError(t, w.Close())
				require.NoError(t, f.Close())
				return id
			}
			objects := filepath.Join(repo, ".git", "objects")
			id := write(gitobj.CommitObject, first, objects)
			gitFixture(t, repo, "update-ref", "refs/heads/main", id)
			var blob string
			for n := range 2_000_000 {
				raw := fmt.Sprintf("blob %d\n%s", n, strings.Repeat("x", 1024))
				if strings.HasPrefix(hash(gitobj.BlobObject, raw), prefix) {
					blob = write(gitobj.BlobObject, raw, objects)
					break
				}
			}
			require.NotEmpty(t, blob)
			gitFixture(t, repo, "update-ref", "refs/heads/"+blob, id)
			missing := strings.Repeat("f", len(id))
			gitFixture(t, repo, "update-ref", "refs/heads/"+missing, id)
			for _, packed := range []bool{false, true} {
				if packed {
					// Duplicate objects across packs and loose storage are one match.
					gitInput(t, repo, []byte(id+"\n"), "pack-objects", ".git/objects/pack/pack")
					gitInput(t, repo, []byte(id+"\n"+blob+"\n"), "pack-objects", ".git/objects/pack/pack")
				}
				r, close, err := (&Source{RepoPath: repo}).open(t.Context())
				require.NoError(t, err)
				r.Storer.(*objectStorage).limit = 256 // Non-commit candidates exceed the reconstruction budget.
				got, err := r.ResolveRevision(gitobj.Revision(prefix))
				require.NoError(t, err, "one commit plus a matching blob still identifies a unique commit")
				require.Equal(t, id, got.String())
				require.Equal(t, id, gitFixture(t, repo, "rev-parse", "--verify", prefix+"^{commit}"))
				for _, name := range []string{blob, missing} {
					_, err := r.ResolveRevision(gitobj.Revision(name))
					require.Error(t, err, "a full object ID must not fall through to a same-named branch")
					got, err := r.ResolveRevision(gitobj.Revision("refs/heads/" + name))
					require.NoError(t, err, "explicit ref names remain usable")
					require.Equal(t, id, got.String())
				}
				close()
			}

			// The second commit lives only in an alternate: ambiguity checks
			// must span every store, not stop at the first pack's match.
			alternate := filepath.Join(repo, "alternate")
			write(gitobj.CommitObject, second, alternate)
			require.NoError(t, os.WriteFile(filepath.Join(objects, "info", "alternates"), []byte(alternate+"\n"), 0600))
			r, close, err := (&Source{RepoPath: repo}).open(t.Context())
			require.NoError(t, err)
			defer close()
			_, err = r.ResolveRevision(gitobj.Revision(prefix))
			require.ErrorContains(t, err, "ambiguous revision")
			cmd := exec.Command("git", "-C", repo, "rev-parse", "--verify", prefix+"^{commit}")
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
			out, err := cmd.CombinedOutput()
			require.Error(t, err)
			require.Contains(t, string(out), "ambiguous")
		})
	}
}

func TestShortRevisionIgnoresUnrelatedObjects(t *testing.T) {
	for _, packed := range []bool{false, true} {
		repo := initRepo(t)
		id := commitFile(t, repo, "file", "TOKEN_SHORT_REVISION\n", "initial")
		if packed {
			gitFixture(t, repo, "repack", "-adq")
		}
		unrelated := "00"
		if id[0] == '0' {
			unrelated = "ff"
		}
		path := filepath.Join(repo, ".git", "objects", unrelated)
		require.NoError(t, os.RemoveAll(path))
		require.NoError(t, os.WriteFile(path, []byte("not a directory"), 0600))
		r, close, err := (&Source{RepoPath: repo}).open(t.Context())
		require.NoError(t, err)
		defer close()
		got, err := r.ResolveRevision(gitobj.Revision(id[:1]))
		require.NoError(t, err, "one-nibble lookups must not enumerate unrelated fanout directories")
		require.Equal(t, id, got.String())
	}
}

func TestRevisionIgnoresUnrelatedReferences(t *testing.T) {
	for _, packed := range []bool{false, true} {
		repo := initRepo(t)
		commitFile(t, repo, "file", "TOKEN_SELECTED_REVISION\n", "initial")
		if packed {
			gitFixture(t, repo, "pack-refs", "--all")
		}
		for _, bad := range []struct{ name, value string }{
			{"main.lock", ""}, {"main.lock", "in progress"},
			{"unrelated", "not a hash"}, {"unrelated", "ref: ../../../outside"},
		} {
			path := filepath.Join(repo, ".git", "refs", "heads", bad.name)
			require.NoError(t, os.WriteFile(path, []byte(bad.value), 0600))
			require.Equal(t, map[string]string{"TOKEN_SELECTED_REVISION\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: "HEAD"})))
			require.NoError(t, os.Remove(path))
		}
	}
}

func TestNonHexRevisionIgnoresUnrelatedObjects(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			repo := t.TempDir()
			gitFixture(t, repo, "init", "-q", "-b", "main", "--object-format="+format)
			gitFixture(t, repo, "config", "user.name", "Test")
			gitFixture(t, repo, "config", "user.email", "test@example.test")
			id := commitFile(t, repo, "file", "TOKEN_SELECTED_REVISION\n", "initial")
			// The commit has at most three loose fanout directories. Use an
			// unused one to model an unrelated unreadable object directory.
			var prefix string
			for _, candidate := range []string{"ab", "cd", "ef", "12"} {
				path := filepath.Join(repo, ".git", "objects", candidate)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					prefix = candidate
					require.NoError(t, os.WriteFile(path, []byte("not a directory"), 0600))
					break
				}
			}
			require.NotEmpty(t, prefix)
			for _, name := range []string{"z", prefix + "z"} {
				gitFixture(t, repo, "update-ref", "refs/heads/"+name, id)
				require.Equal(t, map[string]string{"TOKEN_SELECTED_REVISION\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: name})))
			}
		})
	}
}

func TestPseudoRefsAndShortObjectIDs(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		repo := t.TempDir()
		gitFixture(t, repo, "init", "-q", "-b", "main", "--object-format="+format)
		gitFixture(t, repo, "config", "user.name", "Test")
		gitFixture(t, repo, "config", "user.email", "test@example.test")
		id := commitFile(t, repo, "file", "TOKEN_PSEUDO_REF\n", "initial")
		// Native Git and main prefer the object over a same-named ref, even if
		// that ref is malformed. Full hashes must not consult unrelated refs.
		require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", "refs", "heads", id), []byte("broken"), 0600))
		require.Equal(t, map[string]string{"TOKEN_PSEUDO_REF\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: id})))
		require.NoError(t, os.Remove(filepath.Join(repo, ".git", "refs", "heads", id)))
		for _, name := range []string{"ORIG_HEAD", "MERGE_HEAD", "FETCH_HEAD"} {
			require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", name), []byte(id+"\n"), 0600))
			require.Equal(t, map[string]string{"TOKEN_PSEUDO_REF\n": "file:1"}, textOccurrences(collect(t, &Source{RepoPath: repo, Revision: name})))
		}
		for _, packed := range []bool{false, true} {
			if packed {
				gitFixture(t, repo, "repack", "-adq")
			}
			r, close, err := (&Source{RepoPath: repo}).open(t.Context())
			require.NoError(t, err)
			for n := 1; n <= 3; n++ {
				got, err := r.ResolveRevision(gitobj.Revision(id[:n]))
				require.NoError(t, err)
				require.Equal(t, id, got.String())
			}
			close()
		}
	}
}

func TestResolveRevisionAgainstGit(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			gitFixture(t, dir, "init", "-q", "-b", "main", "--object-format="+format)
			gitFixture(t, dir, "config", "user.name", "Test")
			gitFixture(t, dir, "config", "user.email", "test@example.test")
			commitFile(t, dir, "a", "one\n", "initial")
			commitFile(t, dir, "a", "two\n", "!important fix")
			commitFile(t, dir, "a", "three\n", "last")
			gitFixture(t, dir, "tag", "-am", "release", "release")
			gitFixture(t, dir, "tag", "light")
			gitFixture(t, dir, "branch", "üñicode")
			gitFixture(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
			gitFixture(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
			gitFixture(t, dir, "pack-refs", "--all")
			gitFixture(t, dir, "repack", "-adq")
			id := gitFixture(t, dir, "rev-parse", "HEAD")
			r, close, err := (&Source{RepoPath: dir}).open(t.Context())
			require.NoError(t, err)
			defer close()
			for _, rev := range []string{strings.ToUpper(id), strings.ToUpper(id[:8]), strings.ToUpper(id[:9])} {
				got, err := r.ResolveRevision(gitobj.Revision(rev))
				require.NoError(t, err)
				require.Equal(t, id, got.String())
			}
			for _, rev := range []string{"HEAD", "@", "main", "heads/main", "refs/heads/main", "release", "release^{}", "release^{commit}", "light", "üñicode", "origin", "origin/main", "HEAD^", "HEAD^^", "HEAD~", "HEAD~2", "HEAD~^", "HEAD^0", "HEAD~0", "HEAD^{/initial}", "HEAD^{/!-last}", "HEAD^{/!!important}", id, id[:8], id[:9]} {
				t.Run(rev, func(t *testing.T) {
					want := gitFixture(t, dir, "rev-parse", rev+"^{commit}")
					got, err := r.ResolveRevision(gitobj.Revision(rev))
					require.NoError(t, err)
					require.Equal(t, want, got.String())
				})
			}
			for _, rev := range []string{"", "missing", "HEAD^2", "HEAD~3", "HEAD^{/missing}", "HEAD^{/!reserved}", "HEAD^{/[}", "HEAD^{", "HEAD~x", "HEAD^999999999999999999999"} {
				_, err := r.ResolveRevision(gitobj.Revision(rev))
				require.Error(t, err, rev)
			}
		})
	}
}
