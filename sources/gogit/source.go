// Package gogit scans committed additions using go-git's object reader.
// It never invokes Git, hooks, filters, or diff helpers. URL scans fetch an
// HTTP(S) clone; local repository scans do not use a network transport.
// Every bound on work per object, diff, and commit is defined in limits.go.
package gogit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/object"
	"golang.org/x/sync/errgroup"
)

// Source scans the history reachable from HEAD and every ref, comparing each
// commit with its first parent and scanning added lines. Include adds resources
// to that default and Exclude removes them; conflicts and empty selections are
// rejected. Object scans read whole blobs without path or commit attribution.
// Diff boundaries and rename choices can differ from Git's.
//
// Content that exceeds a limit (MaxBlobBytes, a commit's tree comparison
// budget) is reported as a source error and skipped; the scan continues and is
// marked incomplete. Fields must not change while Fragments runs, but one
// Source can be scanned concurrently.
type Source struct {
	RepoPath string
	// URL fetches branches, tags and notes into a temporary bare repository over
	// HTTP(S), excluding host review refs. Mutually exclusive with RepoPath.
	URL, Token string
	// Revision starts history at one revision, or selects a range "A..B": the
	// commits reachable from B but not from A. Empty scans HEAD and every ref.
	Revision string
	// Since and Until filter committer time inclusively, without pruning ancestors
	// based on timestamps. Non-monotonic history therefore remains traversable.
	Since, Until *time.Time
	// Author and Committer are Go regular expressions over "Name <email>".
	Author, Committer string
	// MaxCount limits scanning to the newest MaxCount selected commits.
	MaxCount int
	// Workers defaults to min(GOMAXPROCS, 8), at most 16.
	Workers int
	// CacheMiB defaults to 256 and limits cached materialized content bytes,
	// excluding object overhead. Parsed trees have a separate 32 MiB budget.
	CacheMiB int
	// DiskCacheMiB enables a private temporary cache of large reconstructed
	// objects, for repositories with deep delta chains of large files. The file
	// holds repository content, so it is off by default. It is created lazily in
	// os.TempDir and removed when the scan ends.
	DiskCacheMiB int
	// MaxBlobBytes defaults to 64 MiB. Larger blobs are skipped and reported. It
	// bounds diff inputs, not go-git's internal reads or the process's RSS.
	MaxBlobBytes int64
	// Include and Exclude accept history, merges, objects, unreachable-objects,
	// commit-messages, notes, tag-messages, reflog-messages, and reflog-history.
	Include, Exclude []string
	// AllowExternalObjects permits Git storage outside the repository: a .git
	// file, commondir, or object alternate that points elsewhere. Linked
	// worktrees registered by their main repository are always allowed.
	AllowExternalObjects bool
	Prefilter            sources.PrefilterFunc
	MaxArchiveDepth      int
	Logger               *slog.Logger
	// Platform and RemoteURL control finding links. By default they are resolved
	// from the local repository's fetch remote without invoking Git. NoPlatform
	// disables links; RemoteURL overrides the configured remote.
	Platform  scm.Platform
	RemoteURL string
}

var _ sources.Source = (*Source)(nil)

func (s *Source) Validate() error {
	switch {
	case (s.RepoPath == "") == (s.URL == ""):
		return errors.New("git source requires either a local repository path or an HTTP(S) URL")
	case s.Workers < 0 || s.Workers > maxWorkers:
		return fmt.Errorf("git workers must be between 0 and %d", maxWorkers)
	case s.CacheMiB < 0 || s.CacheMiB > maxCacheMiB:
		return fmt.Errorf("git cache must be between 0 and %d MiB", maxCacheMiB)
	case s.DiskCacheMiB < 0 || s.DiskCacheMiB > maxCacheMiB:
		return fmt.Errorf("git disk cache must be between 0 and %d MiB", maxCacheMiB)
	case s.MaxBlobBytes < 0 || s.MaxBlobBytes > maxBlobBytesLimit:
		return fmt.Errorf("git max blob size must be between 0 and %d MiB", maxBlobBytesLimit>>20)
	case s.MaxCount < 0:
		return errors.New("git max commit count must not be negative")
	case s.Since != nil && s.Until != nil && s.Until.Before(*s.Since):
		return errors.New("until must not precede since")
	case strings.Contains(s.Revision, "..."):
		return errors.New("symmetric revision ranges (A...B) are not supported; use A..B")
	}
	for _, pattern := range []string{s.Author, s.Committer} {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid identity filter: %w", err)
		}
	}
	_, err := s.selection()
	return err
}

// selection is the resolved Include/Exclude choice.
type selection struct {
	history, merges, messages, reflogHistory bool
	notes, tags, reflogMessages              bool
	objects, unreachable                     bool
}

//nolint:exhaustruct // Resources not on by default start false.
func (s *Source) selection() (selection, error) {
	sel := selection{history: true, merges: true}
	flags := map[string]*bool{
		sources.GitResourceTypeHistory:            &sel.history,
		sources.GitResourceTypeMerges:             &sel.merges,
		sources.GitResourceTypeCommitMessages:     &sel.messages,
		sources.GitResourceTypeReflogHistory:      &sel.reflogHistory,
		sources.GitResourceTypeNotes:              &sel.notes,
		sources.GitResourceTypeTagMessages:        &sel.tags,
		sources.GitResourceTypeReflogMessages:     &sel.reflogMessages,
		sources.GitResourceTypeObjects:            &sel.objects,
		sources.GitResourceTypeUnreachableObjects: &sel.unreachable,
	}
	for _, list := range [][]string{s.Include, s.Exclude} {
		for _, name := range list {
			if flags[name] == nil {
				return selection{}, fmt.Errorf("unsupported Git resource %q; supported: history, merges, objects, unreachable-objects, commit-messages, notes, tag-messages, reflog-messages, reflog-history", name)
			}
		}
	}
	for _, name := range s.Include {
		if slices.Contains(s.Exclude, name) {
			return selection{}, fmt.Errorf("git resource %q cannot be both included and excluded", name)
		}
		*flags[name] = true
	}
	for _, name := range s.Exclude {
		*flags[name] = false
	}
	// Merge patches are part of history, and reflog-history adds commits to the
	// history or message scan rather than scanning anything itself.
	if !sel.history {
		if slices.Contains(s.Include, sources.GitResourceTypeMerges) {
			return selection{}, errors.New("including merges requires history")
		}
		sel.merges = false
	}
	if sel.reflogHistory && !sel.history && !sel.messages {
		return selection{}, errors.New("reflog-history adds commits to history or commit-messages; enable one of them")
	}
	if sel == (selection{}) {
		return selection{}, errors.New("git resource selection leaves nothing to scan")
	}
	return sel, nil
}

// scope is the content scanned for each visited commit.
func (sel selection) scope() commitResources {
	var scope commitResources
	if sel.history {
		scope |= scanPatches
	}
	if sel.messages {
		scope |= scanMessages
	}
	return scope
}

type commitResources uint8

const (
	scanMessages commitResources = 1 << iota
	scanPatches
)

func (s *Source) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.URL != "" {
		logger, start := logging.OrDiscard(s.Logger), time.Now()
		logger.Info("starting clone", "url", urlredact.PublicString(s.URL))
		return scm.CloneToTempDir(ctx, s.URL, s.Token, "betterleaks-git-*", func(path string) error {
			logger.Info("clone complete, starting scan", "duration", time.Since(start).Round(time.Millisecond))
			local := *s
			local.RepoPath, local.URL, local.Token = path, "", ""
			err := local.Fragments(ctx, yield)
			if s.Revision != "" && errors.Is(err, plumbing.ErrReferenceNotFound) {
				return fmt.Errorf("%w; URL scans fetch only branches, tags and notes", err)
			}
			return err
		})
	}
	r, cleanup, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	sel, _ := s.selection() // Validate already checked the selection.
	// Resolve once per scan without mutating caller-owned settings; the same
	// Source can be scanned concurrently.
	resolved := *s
	if sel.history || sel.messages || sel.tags {
		resolved.Platform, resolved.RemoteURL = s.resolveRemote(r)
	}
	// One walk covers every commit resource. Reflogs, when selected, add roots
	// to it before it starts.
	var walk *history
	if sel.scope() != 0 {
		if walk, err = resolved.history(ctx, r); err != nil {
			return err
		}
	}
	if sel.reflogHistory || sel.reflogMessages {
		var roots *history
		if sel.reflogHistory {
			roots = walk
		}
		if err := resolved.reflogs(ctx, r.Storer.(*objectStorage), roots, sel.reflogMessages, yield); err != nil {
			return err
		}
	}
	if walk != nil {
		if err := resolved.commits(ctx, r, walk, sel, yield); err != nil {
			return err
		}
	}
	if sel.tags {
		if err := resolved.tagMessages(ctx, r, yield); err != nil {
			return err
		}
	}
	if sel.notes {
		if err := resolved.notes(ctx, r, yield); err != nil {
			return err
		}
	}
	if sel.objects || sel.unreachable {
		return resolved.blobs(ctx, r, !sel.objects, yield)
	}
	return ctx.Err()
}

func (s *Source) commits(ctx context.Context, r *git.Repository, walk *history, sel selection, yield sources.FragmentsFunc) error {
	accept := s.selector()
	workers := s.Workers
	if workers == 0 {
		workers = min(max(runtime.GOMAXPROCS(0), 1), 8)
	}
	maxBlob := s.MaxBlobBytes
	if maxBlob == 0 {
		maxBlob = defaultMaxBlobBytes
	}
	shared := worker{source: s, trees: &treeCache{r: r}, store: walk.store, maxBlob: maxBlob, patches: &patchCache{}, scope: sel.scope(), merges: sel.merges, differ: lineDiffer{}}
	// The producer owns traversal; at most one queued commit per worker.
	group, workCtx := errgroup.WithContext(ctx)
	jobs := make(chan *object.Commit, workers)
	for range workers {
		group.Go(func() error {
			w := shared
			for {
				select {
				case <-workCtx.Done():
					return workCtx.Err()
				case commit, ok := <-jobs:
					if !ok {
						return nil
					}
					if err := w.commit(workCtx, commit, yield); err != nil {
						return fmt.Errorf("commit %s: %w", commit.Hash, err)
					}
				}
			}
		})
	}
	group.Go(func() error {
		defer close(jobs)
		for selected := 0; s.MaxCount == 0 || selected < s.MaxCount; {
			commit, err := walk.next(workCtx)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			if !accept(commit) {
				continue
			}
			selected++
			select {
			case jobs <- commit:
			case <-workCtx.Done():
				return workCtx.Err()
			}
		}
		return nil
	})
	err := group.Wait()
	if s.Logger != nil {
		p := shared.patches
		s.Logger.Debug("git text patch cache", "hits", p.hits, "misses", p.misses, "entries", len(p.entries), "bytes", p.bytes)
	}
	return err
}

func (s *Source) selector() func(*object.Commit) bool {
	author, _ := regexp.Compile(s.Author)
	committer, _ := regexp.Compile(s.Committer)
	return func(c *object.Commit) bool {
		return !(s.Since != nil && c.Committer.When.Before(*s.Since)) && !(s.Until != nil && c.Committer.When.After(*s.Until)) &&
			(s.Author == "" || author.MatchString(c.Author.Name+" <"+c.Author.Email+">")) &&
			(s.Committer == "" || committer.MatchString(c.Committer.Name+" <"+c.Committer.Email+">"))
	}
}

func commitAttributes(c *object.Commit) map[string]string {
	return map[string]string{
		sources.AttrGitSHA: c.Hash.String(), sources.AttrGitAuthorName: c.Author.Name, sources.AttrGitAuthorEmail: c.Author.Email,
		sources.AttrGitDate: c.Author.When.UTC().Format(time.RFC3339), sources.AttrGitMessage: c.Message,
		sources.AttrGitCommitterName: c.Committer.Name, sources.AttrGitCommitterEmail: c.Committer.Email,
		sources.AttrGitCommitterDate: c.Committer.When.UTC().Format(time.RFC3339),
	}
}

type worker struct {
	source  *Source
	trees   *treeCache
	store   *objectStorage
	maxBlob int64
	differ  lineDiffer
	patches *patchCache
	scope   commitResources
	merges  bool
}

// skip reports content that exceeded a limit, so the scan can continue.
//
//nolint:exhaustruct // An error result carries no fragment.
func skip(yield sources.FragmentsFunc, err error, format string, args ...any) error {
	return yield(sources.Fragment{}, fmt.Errorf(format+": %w", append(args, err)...))
}

func (w *worker) commit(ctx context.Context, c *object.Commit, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	attrs := commitAttributes(c)
	if w.source.RemoteURL != "" {
		attrs[sources.AttrGitRemoteURL] = w.source.RemoteURL
		attrs[sources.AttrGitPlatform] = w.source.Platform.String()
	}
	if w.scope&scanMessages != 0 {
		messageAttrs := maps.Clone(attrs)
		messageAttrs[sources.AttrResource] = sources.ResourceGitCommitMessage
		if w.source.Prefilter == nil || !w.source.Prefilter(messageAttrs) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := yield(sources.Fragment{Raw: c.Message, StartLine: 1, Attributes: messageAttrs}, nil); err != nil {
				return err
			}
		}
	}
	parents := w.store.parents(c)
	if w.scope&scanPatches == 0 || (len(parents) > 1 && !w.merges) {
		return nil
	}
	var parent plumbing.Hash
	if len(parents) > 0 {
		parent = parents[0]
	}
	changes, err := treeChanges(ctx, w.trees, c, parent)
	if isLimit(err) {
		return skip(yield, err, "commit %s", c.Hash)
	}
	if err != nil {
		return err
	}
	for _, change := range changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if change.To.Name == "" {
			continue
		}
		fileAttrs := maps.Clone(attrs)
		fileAttrs[sources.AttrPath] = change.To.Name
		fileAttrs[sources.AttrResource] = sources.ResourceGitPatchContent
		fileAttrs[sources.AttrGitBlobSHA] = change.To.TreeEntry.Hash.String()
		if w.source.Prefilter != nil && w.source.Prefilter(fileAttrs) {
			continue
		}
		err := w.change(ctx, change, fileAttrs, yield)
		if isLimit(err) {
			err = skip(yield, err, "commit %s path %q", c.Hash, change.To.Name)
		} else if err != nil {
			err = fmt.Errorf("path %q: %w", change.To.Name, err)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
