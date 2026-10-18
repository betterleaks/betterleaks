package gogit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/filemode"
	"github.com/go-git/go-git/v6/plumbing/object"
	"github.com/go-git/go-git/v6/plumbing/storer"
)

// Notes are ordinary commits and trees under refs/notes/*. Scan each changed
// note version, including notes later removed. Their commit metadata describes
// the note edit; git.note_target identifies the annotated object, not its author.
//
//nolint:exhaustruct // Cache bookkeeping starts empty.
func (s *Source) notes(ctx context.Context, r *git.Repository, yield sources.FragmentsFunc) error {
	refs, err := r.Storer.IterReferences()
	if err != nil {
		return err
	}
	defer refs.Close()
	trees := &treeCache{r: r}
	store := r.Storer.(*objectStorage)
	accept := s.selector()
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
		if !strings.HasPrefix(ref.Name().String(), "refs/notes/") {
			continue
		}
		name := ref.Name()
		if ref, err = storer.ResolveReference(r.Storer, name); err != nil {
			return fmt.Errorf("notes ref %s: %w", name, err)
		}
		walk := newWalk(r)
		if err := walk.tip(ctx, ref.Hash()); err != nil {
			return fmt.Errorf("notes ref %s: %w", name, err)
		}
		for selected := 0; s.MaxCount == 0 || selected < s.MaxCount; {
			commit, err := walk.next(ctx)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}
			if !accept(commit) {
				continue
			}
			selected++
			if err := s.noteVersion(ctx, store, trees, name.String(), commit, yield); err != nil {
				return err
			}
		}
	}
}

func (s *Source) noteVersion(ctx context.Context, store *objectStorage, trees *treeCache, ref string, commit *object.Commit, yield sources.FragmentsFunc) error {
	var parent plumbing.Hash
	if parents := store.parents(commit); len(parents) > 0 {
		parent = parents[0]
	}
	changes, err := treeChanges(ctx, trees, commit, parent)
	if isLimit(err) {
		s.skip(err, "notes commit %s", commit.Hash)
		return nil
	}
	if err != nil {
		return err
	}
	for _, change := range changes {
		if change.To.Name == "" || change.To.TreeEntry.Mode == filemode.Submodule {
			continue
		}
		id := change.To.TreeEntry.Hash
		attrs := commitAttributes(commit)
		attrs[sources.AttrResource] = sources.ResourceGitNote
		attrs[sources.AttrGitNotesRef], attrs[sources.AttrGitBlobSHA] = ref, id.String()
		target := strings.ReplaceAll(change.To.Name, "/", "")
		if len(target) == id.Size()*2 && plumbing.IsHash(target) {
			attrs[sources.AttrGitNoteTarget] = target
		}
		if s.Prefilter != nil && s.Prefilter(attrs) {
			continue
		}
		obj, err := store.read(id)
		if isLimit(err) {
			s.skip(err, "note %s", id)
			continue
		}
		if err != nil {
			return err
		}
		if obj.kind != plumbing.BlobObject {
			return plumbing.ErrObjectNotFound
		}
		if err := yield(sources.Fragment{Raw: obj.raw, StartLine: 1, Attributes: attrs}, nil); err != nil {
			return err
		}
	}
	return nil
}

// Lightweight tags have no message. Nested annotations are scanned too, but
// only the outer annotation has a tag ref suitable for generating a web link.
// Keep each ref occurrence: prefilters and finding attribution depend on the
// source ref, even when several refs share the same annotation object.
func (s *Source) tagMessages(ctx context.Context, r *git.Repository, yield sources.FragmentsFunc) error {
	refs, err := r.Tags()
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
		ref, err = storer.ResolveReference(r.Storer, ref.Name())
		if err != nil {
			return err
		}
		id := ref.Hash()
		for depth := 0; ; depth++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			if depth == maxTagNesting {
				return fmt.Errorf("annotated tag nesting exceeds %d levels", maxTagNesting)
			}
			obj, err := r.Storer.EncodedObject(plumbing.AnyObject, id)
			if err != nil {
				return fmt.Errorf("tag ref %s: %w", ref.Name(), err)
			}
			if obj.Type() != plumbing.TagObject {
				break
			}
			tag, err := object.DecodeTag(r.Storer, obj)
			if err != nil {
				return err
			}
			attrs := map[string]string{
				sources.AttrResource:        sources.ResourceGitTagMessage,
				sources.AttrGitTagName:      tag.Name,
				sources.AttrGitTaggerName:   tag.Tagger.Name,
				sources.AttrGitTaggerEmail:  tag.Tagger.Email,
				sources.AttrGitTaggerDate:   tag.Tagger.When.UTC().Format(time.RFC3339),
				sources.AttrGitTagSHA:       tag.Hash.String(),
				sources.AttrGitTagTarget:    tag.Target.String(),
				sources.AttrGitTagSourceRef: ref.Name().String(),
			}
			if depth == 0 {
				attrs[sources.AttrGitTagRef] = ref.Name().String()
				if s.RemoteURL != "" {
					attrs[sources.AttrGitRemoteURL] = s.RemoteURL
					attrs[sources.AttrGitPlatform] = s.Platform.String()
				}
			}
			if s.Prefilter == nil || !s.Prefilter(attrs) {
				if err := yield(sources.Fragment{Raw: tag.Message, StartLine: 1, Attributes: attrs}, nil); err != nil {
					return err
				}
			}
			if tag.TargetType != plumbing.TagObject {
				break
			}
			id = tag.Target
		}
	}
}

// resolveRemote reads only local configuration. Match Git's default fetch
// remote: the current branch's remote, otherwise the sole remote or origin.
// Link metadata is optional and must not prevent a history scan.
func (s *Source) resolveRemote(r *git.Repository) (scm.Platform, string) {
	if s.Platform == scm.NoPlatform || s.RemoteURL != "" {
		return scm.ResolveRemoteURL(s.Platform, s.RemoteURL)
	}
	cfg, err := r.Config()
	if err != nil {
		return s.Platform, ""
	}
	name := "origin"
	if len(cfg.Remotes) == 1 {
		for n := range cfg.Remotes {
			name = n
		}
	}
	if head, err := r.Storer.Reference(plumbing.HEAD); err == nil && head.Type() == plumbing.SymbolicReference && head.Target().IsBranch() {
		if branch := cfg.Branches[head.Target().Short()]; branch != nil && branch.Remote != "" {
			name = branch.Remote
		}
	}
	remote := cfg.Remotes[name]
	if remote == nil || len(remote.URLs) == 0 {
		return s.Platform, ""
	}
	return scm.ResolveRemoteURL(s.Platform, remote.URLs[0])
}
