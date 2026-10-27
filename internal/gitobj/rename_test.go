//nolint:exhaustruct // Fixtures specify only the fields relevant to each change.
package gitobj

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/stretchr/testify/require"
)

type testObjectStore map[Hash]EncodedObject

func (s testObjectStore) EncodedObject(_ ObjectType, id Hash) (EncodedObject, error) {
	if o := s[id]; o != nil {
		return o, nil
	}
	return nil, ErrObjectNotFound
}

func TestRenamesPreserveFullSHA256IDs(t *testing.T) {
	// Two unrelated IDs have the same SHA-1-sized prefix. Truncating them
	// would manufacture a false exact rename and lose the new file's content.
	a := NewHash(strings.Repeat("a", 40) + strings.Repeat("1", 24))
	b := NewHash(strings.Repeat("a", 40) + strings.Repeat("2", 24))
	store := testObjectStore{
		a: encoded(t, SHA256, BlobObject, strings.Repeat("old only\n", 10)),
		b: encoded(t, SHA256, BlobObject, strings.Repeat("new only\n", 10)),
	}
	tree := &Tree{store: store}
	entry := func(name string, id Hash) ChangeEntry {
		return ChangeEntry{Name: name, Tree: tree, TreeEntry: TreeEntry{Name: name, Mode: filemode.Regular, Hash: id}}
	}
	options := &DiffTreeOptions{DetectRenames: true, RenameScore: 50, RenameLimit: 1000}
	changes := Changes{&Change{From: entry("old", a)}, &Change{To: entry("new", b)}}
	got, err := DetectRenames(changes, options)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, c := range got {
		require.True(t, c.From.Name == "" || c.To.Name == "")
	}
	changes[1].To.TreeEntry.Hash = a
	got, err = DetectRenames(changes, options)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "old", got[0].From.Name)
	require.Equal(t, "new", got[0].To.Name)
	require.Equal(t, "new", got[0].To.TreeEntry.Name)
	require.Equal(t, a, got[0].To.TreeEntry.Hash)
}

func TestRenamesPreserveModifiedChanges(t *testing.T) {
	for _, format := range []ObjectFormat{SHA1, SHA256} {
		t.Run(string(format), func(t *testing.T) {
			a, b := FromObjectFormat(format), FromObjectFormat(format)
			a.data[0], b.data[0] = 1, 2
			old, current := &Tree{Hash: a}, &Tree{Hash: b}
			entry := func(name string, tree *Tree, id Hash) ChangeEntry {
				return ChangeEntry{Name: name, Tree: tree, TreeEntry: TreeEntry{Name: name, Hash: id, Mode: filemode.Regular}}
			}
			modified := &Change{From: entry("modified", old, a), To: entry("modified", current, b)}
			changes := Changes{
				&Change{To: entry("new", current, a)},
				modified,
				&Change{From: entry("old", old, a)},
			}
			got, err := DetectRenames(changes, &DiffTreeOptions{OnlyExactRenames: true})
			require.NoError(t, err)
			require.Len(t, got, 2)
			require.Equal(t, modified, got[0], "modified entries must keep both original trees and metadata")
			require.Equal(t, "old", got[1].From.Name)
			require.Equal(t, "new", got[1].To.Name)
		})
	}
}

// Mixed commits can modify many files while also moving one. Only additions
// and deletions belong in the rename adapter's object-ID table.
func BenchmarkRenameMixedChanges(b *testing.B) {
	for _, count := range []int{100, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			tree := &Tree{}
			entry := func(name string, n uint64) ChangeEntry {
				var id Hash
				binary.BigEndian.PutUint64(id.data[:8], n)
				return ChangeEntry{Name: name, Tree: tree, TreeEntry: TreeEntry{Name: name, Hash: id, Mode: filemode.Regular}}
			}
			changes := make(Changes, 0, count+2)
			changes = append(changes, &Change{From: entry("old", 1)}, &Change{To: entry("new", 1)})
			for n := range count {
				name := fmt.Sprintf("modified-%05d", n)
				changes = append(changes, &Change{From: entry(name, uint64(n)*2+2), To: entry(name, uint64(n)*2+3)})
			}
			options := &DiffTreeOptions{OnlyExactRenames: true}
			b.ReportAllocs()
			for b.Loop() {
				got, err := DetectRenames(changes, options)
				if err != nil || len(got) != count+1 {
					b.Fatalf("rename result: %d changes, %v", len(got), err)
				}
			}
		})
	}
}
