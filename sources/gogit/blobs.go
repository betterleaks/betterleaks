package gogit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/go-git/go-git/v5/plumbing/filemode"
)

// Enumerate by hash prefix so an all-object scan does not retain an inventory
// of the entire repository. The storage reader includes packs and alternates
// and deduplicates IDs present in multiple locations.
func objectIDs(ctx context.Context, store *objectStorage, yield func(gitobj.Hash) error) error {
	for prefix := 0; prefix < 256; prefix++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		ids, err := store.HashesWithPrefix([]byte{byte(prefix)})
		if err != nil {
			return err
		}
		gitobj.HashesSort(ids)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := yield(id); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (s *Source) blobs(ctx context.Context, r *repository, unreachable bool, yield sources.FragmentsFunc) error {
	store := r.Storer.(*objectStorage)
	emit := func(id gitobj.Hash) error {
		attrs := map[string]string{sources.AttrResource: sources.ResourceGitBlob, sources.AttrGitBlobSHA: id.String()}
		if s.Prefilter != nil && s.Prefilter(attrs) {
			return nil
		}
		obj, err := store.EncodedObject(gitobj.AnyObject, id)
		if isLimit(err) {
			s.skip(err, "object %s", id)
			return nil
		}
		if err != nil {
			return fmt.Errorf("object %s: %w", id, err)
		}
		if obj.Type() != gitobj.BlobObject {
			return nil
		}
		reader, err := obj.Reader()
		if err != nil {
			return err
		}
		// A blob has no intrinsic filename. Archive detection uses magic bytes.
		file := &sources.File{Path: "", Symlink: "", DetectArchive: true, StrictArchives: false, Content: reader, Attributes: attrs, MaxArchiveDepth: s.MaxArchiveDepth, Prefilter: s.Prefilter, Logger: s.Logger}
		err = file.Fragments(ctx, yield)
		closeErr := reader.Close()
		return errors.Join(err, closeErr)
	}
	if !unreachable {
		return objectIDs(ctx, store, emit)
	}
	// This optional pass retains compact IDs and one traversal byte per object,
	// not decoded objects or a commit-to-path reverse index. Fail explicitly at
	// the bound instead of producing a partial classification without warning.
	var ids []gitobj.Hash
	if err := objectIDs(ctx, store, func(id gitobj.Hash) error {
		if len(ids) == maxUnreachableObjects {
			return fmt.Errorf("unreachable-object inventory exceeds %d objects; use objects to scan all blobs without reachability classification", maxUnreachableObjects)
		}
		ids = append(ids, id)
		return nil
	}); err != nil {
		return err
	}
	reached, err := reachableObjects(ctx, r, ids)
	if err != nil {
		return fmt.Errorf("classify unreachable objects: %w", err)
	}
	for i, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if reached[i] == 0 {
			if err := emit(id); err != nil {
				return err
			}
		}
	}
	return nil
}

// Reachability always uses HEAD and every ref, including notes and tags pointing
// directly to trees or blobs. Reflogs, the index, and scan selection are not roots.
// Blob edges are marked without decompressing their contents. Gitlinks refer to
// a different repository and must not be followed.
func reachableObjects(ctx context.Context, r *repository, ids []gitobj.Hash) ([]byte, error) {
	store := r.Storer.(*objectStorage)
	reached := make([]byte, len(ids))
	type edge struct {
		id   gitobj.Hash
		kind gitobj.ObjectType
	}
	var pending []edge
	add := func(id gitobj.Hash, kind gitobj.ObjectType) error {
		i, found := slices.BinarySearchFunc(ids, id, func(a, b gitobj.Hash) int { return a.Compare(b.Bytes()) })
		if !found {
			return fmt.Errorf("reachable object %s is missing from object inventory", id)
		}
		if reached[i] != 0 {
			return nil
		}
		reached[i] = 1
		if kind != gitobj.BlobObject {
			pending = append(pending, edge{id, kind})
		}
		return nil
	}
	refs, err := r.Storer.IterReferences()
	if err != nil {
		return nil, err
	}
	defer refs.Close()
	head, err := r.Head()
	if err == nil {
		if err := add(head.Hash(), gitobj.AnyObject); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, gitobj.ErrReferenceNotFound) {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ref, err := refs.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if ref.Type() == gitobj.SymbolicReference {
			name := ref.Name()
			ref, err = gitobj.ResolveReference(r.Storer, name)
			if err != nil {
				if name == gitobj.HEAD && errors.Is(err, gitobj.ErrReferenceNotFound) {
					continue // An unborn repository can still contain stored blobs.
				}
				return nil, err
			}
		}
		if err := add(ref.Hash(), gitobj.AnyObject); err != nil {
			return nil, err
		}
	}
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		e := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		obj, err := r.Object(e.kind, e.id)
		if err != nil {
			return nil, err
		}
		switch obj := obj.(type) {
		case *gitobj.Commit:
			for _, parent := range store.parents(obj) {
				if err := add(parent, gitobj.CommitObject); err != nil {
					return nil, err
				}
			}
			if err := add(obj.TreeHash, gitobj.TreeObject); err != nil {
				return nil, err
			}
		case *gitobj.Tree:
			for _, entry := range obj.Entries {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if entry.Mode == filemode.Submodule {
					continue
				}
				kind := gitobj.BlobObject
				if entry.Mode == filemode.Dir {
					kind = gitobj.TreeObject
				}
				if err := add(entry.Hash, kind); err != nil {
					return nil, err
				}
			}
		case *gitobj.Tag:
			if err := add(obj.Target, obj.TargetType); err != nil {
				return nil, err
			}
		case *gitobj.Blob:
			// A ref can point directly to a blob.
		default:
			return nil, fmt.Errorf("unsupported reachable object %s", e.id)
		}
	}
	return reached, nil
}
