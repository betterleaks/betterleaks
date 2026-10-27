package gitobj

import (
	"encoding/binary"
	"path"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

type DiffTreeOptions = object.DiffTreeOptions

// DetectRenames uses v5's scoring with a scan-local, bijective ID table. These
// synthetic IDs never leave the detector or identify stored Git objects. In
// particular, SHA-256 IDs are never truncated into SHA-1 IDs.
func DetectRenames(changes Changes, opts *DiffTreeOptions) (Changes, error) {
	// Modified files are already paired. Sending them through the adapter
	// duplicates their entries and hashes without contributing rename candidates,
	// which is costly for large mixed commits. Preserve those entries verbatim.
	candidates := 0
	for _, c := range changes {
		if c.From.Name == "" || c.To.Name == "" {
			candidates++
		}
	}
	store := &renameStore{Storage: memory.NewStorage(), entries: make(map[plumbing.Hash]ChangeEntry)}
	ids := make(map[Hash]plumbing.Hash)
	empty := &plumbing.MemoryObject{}
	empty.SetType(plumbing.TreeObject)
	tree, err := object.DecodeTree(store, empty)
	if err != nil {
		return nil, err
	}
	convert := func(e ChangeEntry) object.ChangeEntry {
		if e.Name == "" {
			var empty object.ChangeEntry
			return empty
		}
		id, ok := ids[e.TreeEntry.Hash]
		if !ok {
			binary.BigEndian.PutUint64(id[:8], uint64(len(ids)+1))
			ids[e.TreeEntry.Hash] = id
			store.entries[id] = e
		}
		return object.ChangeEntry{Name: e.Name, Tree: tree, TreeEntry: object.TreeEntry{Name: "blob", Hash: id, Mode: e.TreeEntry.Mode}}
	}
	input := make(object.Changes, 0, candidates)
	out := make(Changes, 0, len(changes))
	for _, c := range changes {
		if c.From.Name != "" && c.To.Name != "" {
			out = append(out, c)
			continue
		}
		input = append(input, &object.Change{From: convert(c.From), To: convert(c.To)})
	}
	paired, err := object.DetectRenames(input, opts)
	if err != nil {
		return nil, err
	}
	restore := func(e object.ChangeEntry) ChangeEntry {
		if e.Name == "" {
			var empty ChangeEntry
			return empty
		}
		original := store.entries[e.TreeEntry.Hash]
		original.Name = e.Name
		original.TreeEntry.Name = path.Base(e.Name)
		original.TreeEntry.Mode = e.TreeEntry.Mode
		return original
	}
	hasModified := len(out) != 0
	for _, c := range paired {
		out = append(out, &Change{From: restore(c.From), To: restore(c.To)})
	}
	if !hasModified {
		return out, nil // v5 has already sorted the paired changes.
	}
	// Match v5's final path ordering after putting the original modifications
	// back alongside its paired additions and deletions.
	name := func(c *Change) string {
		if c.From.Name != "" {
			return c.From.Name
		}
		return c.To.Name
	}
	slices.SortStableFunc(out, func(a, b *Change) int { return strings.Compare(name(a), name(b)) })
	return out, nil
}

type renameStore struct {
	*memory.Storage
	entries map[plumbing.Hash]ChangeEntry
}

func (s *renameStore) EncodedObject(kind plumbing.ObjectType, id plumbing.Hash) (plumbing.EncodedObject, error) {
	e, ok := s.entries[id]
	if !ok || e.Tree == nil {
		return nil, ErrObjectNotFound
	}
	o, err := e.Tree.store.EncodedObject(kind, e.TreeEntry.Hash)
	if err != nil {
		return nil, err
	}
	return v5Object{o, id}, nil
}

type v5Object struct {
	EncodedObject
	id plumbing.Hash
}

func (o v5Object) Hash() plumbing.Hash { return o.id }

type Blob struct{ Hash Hash }
