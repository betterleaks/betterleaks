package gogit

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
)

// history walks commits newest first by committer time from a set of roots,
// visiting each commit once. go-git's All iterator materializes every commit in
// a linked list, and stops a ref walk at the first shared commit even when
// other merge ancestry is pending. This keeps one visited set and a frontier of
// IDs and timestamps instead. Decoded commits (and their retained pack readers)
// live only while a worker needs them.
type history struct {
	r        *repository
	store    *objectStorage
	seen     map[gitobj.Hash]struct{}
	frontier commitHeap
	sequence uint64
}

type commitPosition struct {
	id       gitobj.Hash
	when     int64
	sequence uint64
}
type commitHeap []commitPosition

func (h commitHeap) Len() int { return len(h) }
func (h commitHeap) Less(i, j int) bool {
	if h[i].when == h[j].when {
		return h[i].sequence < h[j].sequence
	}
	return h[i].when > h[j].when
}
func (h commitHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *commitHeap) Push(v any)   { *h = append(*h, v.(commitPosition)) }
func (h *commitHeap) Pop() any {
	last := len(*h) - 1
	v := (*h)[last]
	*h = (*h)[:last]
	return v
}

//nolint:exhaustruct // An empty frontier and sequence start at zero.
func newWalk(r *repository) *history {
	return &history{r: r, store: r.Storer.(*objectStorage), seen: make(map[gitobj.Hash]struct{})}
}

// history starts at Revision when set, otherwise at HEAD and every ref except
// notes. A range A..B starts at B and excludes everything reachable from A.
func (s *Source) history(ctx context.Context, r *repository) (*history, error) {
	h := newWalk(r)
	if s.Revision == "" {
		return h, h.refs(ctx)
	}
	revision := s.Revision
	if from, to, isRange := strings.Cut(revision, ".."); isRange {
		if from == "" {
			from = "HEAD"
		}
		if to == "" {
			to = "HEAD"
		}
		id, err := r.ResolveRevision(gitobj.Revision(from))
		if err != nil {
			return nil, fmt.Errorf("resolve revision %q: %w", from, err)
		}
		if err := h.exclude(ctx, *id); err != nil {
			return nil, err
		}
		revision = to
	}
	id, err := r.ResolveRevision(gitobj.Revision(revision))
	if err != nil {
		return nil, fmt.Errorf("resolve revision %q: %w", revision, err)
	}
	return h, h.tip(ctx, *id)
}

func (h *history) refs(ctx context.Context) error {
	head, err := h.r.Head()
	if err == nil {
		if err = h.tip(ctx, head.Hash()); err != nil {
			return err
		}
	} else if !errors.Is(err, gitobj.ErrReferenceNotFound) {
		return err
	}
	refs, err := h.r.Storer.IterReferences()
	if err != nil {
		return err
	}
	defer refs.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ref, err := refs.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(ref.Name().String(), "refs/notes/") {
			continue
		}
		// IterReferences can include symbolic remote HEADs. Resolve them rather than
		// interpreting their zero hash as an object ID.
		if ref.Type() == gitobj.SymbolicReference {
			name := ref.Name()
			ref, err = gitobj.ResolveReference(h.r.Storer, name)
			if err != nil {
				if name == gitobj.HEAD && errors.Is(err, gitobj.ErrReferenceNotFound) {
					continue // Unborn HEAD; there may still be notes or loose blobs.
				}
				return fmt.Errorf("resolve ref %s: %w", name, err)
			}
		}
		if err = h.tip(ctx, ref.Hash()); err != nil {
			return fmt.Errorf("ref %s: %w", ref.Name(), err)
		}
	}
}

// tip adds a root. Annotated tags are peeled; tags naming trees or blobs have no
// commit ancestry and add nothing.
func (h *history) tip(ctx context.Context, id gitobj.Hash) error {
	c, err := h.peel(ctx, id)
	if err != nil || c == nil {
		return err
	}
	if _, ok := h.seen[c.Hash]; !ok {
		h.enqueue(c)
	}
	return nil
}

// exclude marks everything reachable from id as visited, so the walk never
// reaches it.
func (h *history) exclude(ctx context.Context, id gitobj.Hash) error {
	c, err := h.peel(ctx, id)
	if err != nil || c == nil {
		return err
	}
	pending := []gitobj.Hash{c.Hash}
	for len(pending) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, ok := h.seen[id]; ok {
			continue
		}
		h.seen[id] = struct{}{}
		c, err := h.r.CommitObject(id)
		if err != nil {
			return fmt.Errorf("excluded commit %s: %w", id, err)
		}
		pending = append(pending, h.store.parents(c)...)
	}
	return nil
}

func (h *history) peel(ctx context.Context, id gitobj.Hash) (*gitobj.Commit, error) {
	for range maxTagNesting {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		obj, err := h.r.Storer.EncodedObject(gitobj.AnyObject, id)
		if err != nil {
			return nil, fmt.Errorf("read history tip %s: %w", id, err)
		}
		switch obj.Type() {
		case gitobj.CommitObject:
			return gitobj.DecodeCommit(h.r.Storer, obj)
		case gitobj.TagObject:
			tag, err := gitobj.DecodeTag(h.r.Storer, obj)
			if err != nil {
				return nil, err
			}
			id = tag.Target
		case gitobj.BlobObject, gitobj.TreeObject:
			return nil, nil
		default:
			return nil, fmt.Errorf("invalid history tip type %s", obj.Type())
		}
	}
	return nil, fmt.Errorf("annotated tag nesting exceeds %d levels", maxTagNesting)
}

func (h *history) enqueue(c *gitobj.Commit) {
	h.seen[c.Hash] = struct{}{}
	heap.Push(&h.frontier, commitPosition{c.Hash, c.Committer.When.Unix(), h.sequence})
	h.sequence++
}

func (h *history) next(ctx context.Context) (*gitobj.Commit, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(h.frontier) == 0 {
		return nil, io.EOF
	}
	p := heap.Pop(&h.frontier).(commitPosition)
	c, err := h.r.CommitObject(p.id)
	if err != nil {
		return nil, err
	}
	for _, id := range h.store.parents(c) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := h.seen[id]; ok {
			continue
		}
		parent, err := h.r.CommitObject(id)
		if err != nil {
			return nil, fmt.Errorf("parent %s of %s: %w", id, c.Hash, err)
		}
		h.enqueue(parent)
	}
	return c, nil
}
