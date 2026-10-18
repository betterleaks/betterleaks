package gogit

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
)

// treeChanges compares a commit's tree with its first parent's, or with the
// empty tree when parent is zero, and pairs renamed files.
func treeChanges(ctx context.Context, cache *treeCache, c *object.Commit, parent plumbing.Hash) (object.Changes, error) {
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

// detectRenames pairs similar deletions and additions. go-git's detector opens
// each blob through Tree.TreeEntryFile, which rejects names that are unsafe to
// check out (for example a literal backslash, as in GitLab's history). This
// source never checks anything out and only reads blobs by ID, so the entries
// get a placeholder name for the detector; ChangeEntry.Name keeps the real path
// used for scoring and metadata, and the entry names are restored afterwards.
// go-git offers no option to skip that validation.
func detectRenames(changes object.Changes) (object.Changes, error) {
	for _, change := range changes {
		if change.From.Name != "" {
			change.From.TreeEntry.Name = "blob"
		}
		if change.To.Name != "" {
			change.To.TreeEntry.Name = "blob"
		}
	}
	paired, err := object.DetectRenames(changes, &object.DiffTreeOptions{DetectRenames: true, RenameScore: 50, RenameLimit: 1000, OnlyExactRenames: false})
	// Restore the input too: on error it is all the caller has.
	for _, change := range slices.Concat(changes, paired) {
		if change.From.Name != "" {
			change.From.TreeEntry.Name = path.Base(change.From.Name)
		}
		if change.To.Name != "" {
			change.To.TreeEntry.Name = path.Base(change.To.Name)
		}
	}
	return paired, err
}

func rawTreeChanges(ctx context.Context, cache *treeCache, c *object.Commit, parent plumbing.Hash) (object.Changes, error) {
	var old *object.Tree
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
	var changes object.Changes
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
	var walk func(*object.Tree, *object.Tree, string) error
	expand := func(tree *object.Tree, entry object.TreeEntry, prefix string, added bool) error {
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
		change := &object.Change{}
		value := object.ChangeEntry{Name: name, Tree: tree, TreeEntry: entry}
		if added {
			change.To = value
		} else {
			change.From = value
		}
		changes = append(changes, change)
		return nil
	}
	walk = func(from, to *object.Tree, prefix string) error {
		if strings.Count(prefix, "/") > maxTreeDepth {
			return limitf("tree nesting exceeds %d levels", maxTreeDepth)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if from != nil && to != nil && from.Hash == to.Hash {
			return nil
		}
		var a, b []object.TreeEntry
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
					changes = append(changes, &object.Change{From: object.ChangeEntry{Name: prefix + left.Name, Tree: from, TreeEntry: left}, To: object.ChangeEntry{Name: prefix + right.Name, Tree: to, TreeEntry: right}})
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
