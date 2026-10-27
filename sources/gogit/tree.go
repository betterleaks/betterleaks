package gogit

import (
	"context"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/go-git/go-git/v5/plumbing/filemode"
)

// treeChanges compares a commit's tree with its first parent's, or with the
// empty tree when parent is zero, and pairs renamed files.
func treeChanges(ctx context.Context, cache *treeCache, c *gitobj.Commit, parent gitobj.Hash) (gitobj.Changes, error) {
	changes, err := rawTreeChanges(ctx, cache, c, parent)
	if err != nil {
		return nil, err
	}
	paired, err := detectRenames(changes)
	if isLimit(err) {
		// Rename scoring reads whole blobs. When one is over a limit, keep the
		// unpaired changes: a rename then scans as an addition, which can repeat
		// findings, and only the oversized blob itself is skipped.
		return changes, nil
	}
	return paired, err
}

// detectRenames keeps v5's similarity scoring. gitobj adapts its hash model
// without truncating SHA-256 IDs and uses safe placeholder names for blob reads.
func detectRenames(changes gitobj.Changes) (gitobj.Changes, error) {
	var added, deleted bool
	for _, c := range changes {
		added = added || c.From.Name == ""
		deleted = deleted || c.To.Name == ""
	}
	if !added || !deleted {
		return changes, nil
	}
	return gitobj.DetectRenames(changes, &gitobj.DiffTreeOptions{DetectRenames: true, RenameScore: 50, RenameLimit: 1000, OnlyExactRenames: false})
}

func rawTreeChanges(ctx context.Context, cache *treeCache, c *gitobj.Commit, parent gitobj.Hash) (gitobj.Changes, error) {
	var old *gitobj.Tree
	if !parent.IsZero() {
		p, err := cache.r.CommitObject(parent)
		if err != nil {
			return nil, err
		}
		if p.TreeHash == c.TreeHash {
			return nil, nil
		}
		if old, err = cache.get(p.TreeHash); err != nil {
			return nil, err
		}
	}
	current, err := cache.get(c.TreeHash)
	if err != nil {
		return nil, err
	}
	var changes gitobj.Changes
	// A small tree DAG can expand into exponentially many paths. Bound each
	// comparison (workers release it before taking another commit), including
	// empty directories and path bytes, not just the number of unique objects.
	entries, pathBytes := 0, 0
	charge := func(nameBytes int) error {
		entries++
		pathBytes += nameBytes
		if entries > maxTreeEntries || len(changes) >= maxTreeChanges || pathBytes > maxTreePathBytes {
			return limitf("tree comparison exceeds %d entries, %d changes, or %d path bytes", maxTreeEntries, maxTreeChanges, maxTreePathBytes)
		}
		return ctx.Err()
	}
	var walk func(*gitobj.Tree, *gitobj.Tree, string) error
	expand := func(tree *gitobj.Tree, entry gitobj.TreeEntry, prefix string, added bool) error {
		if err := charge(len(prefix) + len(entry.Name)); err != nil {
			return err
		}
		name := prefix + entry.Name
		if entry.Mode == filemode.Dir {
			sub, err := cache.get(entry.Hash)
			if err != nil {
				return err
			}
			if added {
				return walk(nil, sub, name+"/")
			}
			return walk(sub, nil, name+"/")
		}
		change := new(gitobj.Change)
		value := gitobj.ChangeEntry{Name: name, Tree: tree, TreeEntry: entry}
		if added {
			change.To = value
		} else {
			change.From = value
		}
		changes = append(changes, change)
		return nil
	}
	walk = func(from, to *gitobj.Tree, prefix string) error {
		if strings.Count(prefix, "/") > maxTreeDepth {
			return limitf("tree nesting exceeds %d levels", maxTreeDepth)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if from != nil && to != nil && from.Hash == to.Hash {
			return nil
		}
		var a, b []gitobj.TreeEntry
		if from != nil {
			a = from.Entries
		}
		if to != nil {
			b = to.Entries
		}
		i, j := 0, 0
		for i < len(a) || j < len(b) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if i == len(a) {
				if err := expand(to, b[j], prefix, true); err != nil {
					return err
				}
				j++
				continue
			}
			if j == len(b) {
				if err := expand(from, a[i], prefix, false); err != nil {
					return err
				}
				i++
				continue
			}
			left, right := a[i], b[j]
			if left.Name == right.Name {
				if err := charge(2 * (len(prefix) + len(left.Name))); err != nil {
					return err
				}
				i++
				j++
				if left.Mode == right.Mode && left.Hash == right.Hash {
					continue
				}
				if left.Mode == filemode.Dir && right.Mode == filemode.Dir {
					x, err := cache.get(left.Hash)
					if err != nil {
						return err
					}
					y, err := cache.get(right.Hash)
					if err != nil {
						return err
					}
					if err := walk(x, y, prefix+left.Name+"/"); err != nil {
						return err
					}
				} else if left.Mode == filemode.Dir || right.Mode == filemode.Dir {
					if err := expand(from, left, prefix, false); err != nil {
						return err
					}
					if err := expand(to, right, prefix, true); err != nil {
						return err
					}
				} else {
					changes = append(changes, &gitobj.Change{From: gitobj.ChangeEntry{Name: prefix + left.Name, Tree: from, TreeEntry: left}, To: gitobj.ChangeEntry{Name: prefix + right.Name, Tree: to, TreeEntry: right}})
				}
				continue
			}
			// Git sorts directories as if their names ended in '/', rather than by
			// plain basename. Both input entry slices already have that ordering.
			x, y := left.Name, right.Name
			if left.Mode == filemode.Dir {
				x += "/"
			}
			if right.Mode == filemode.Dir {
				y += "/"
			}
			if strings.Compare(x, y) < 0 {
				if err := expand(from, left, prefix, false); err != nil {
					return err
				}
				i++
			} else {
				if err := expand(to, right, prefix, true); err != nil {
					return err
				}
				j++
			}
		}
		return nil
	}
	if err := walk(old, current, ""); err != nil {
		return nil, err
	}
	return changes, nil
}
