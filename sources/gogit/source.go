// Package gogit scans committed additions with a read-only Git object reader.
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

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/internal/urlredact"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
	"golang.org/x/sync/errgroup"
)

// Source scans the history reachable from HEAD and every non-note ref, comparing
// each commit with its first parent and scanning added lines. Merge commits are
// walked but not diffed unless merges is included. Include adds resources to that
// default and Exclude removes them; conflicts and empty selections are rejected.
// Object scans read whole blobs without path or commit attribution. Diff
// boundaries and rename choices can differ from Git's.
//
// Content that exceeds a limit (MaxBlobBytes, a commit's tree comparison
// budget) is skipped with a warning on Logger, as damaged archives are, and the
// rest of the repository is still scanned. Fields must not change while
// Fragments runs, but one Source can be scanned concurrently.
type Source struct {
	RepoPath string
	// URL fetches branches, tags and notes into a temporary bare repository over
	// HTTP(S), excluding host review refs by default. Mutually exclusive with RepoPath.
	URL, Token string
	// CloneRefs adds fully qualified refs or patterns with at most one '*' to
	// the URL fetch. CloneAllRefs fetches every advertised ref under refs/.
	// These options require URL and do not restrict the subsequent scan.
	CloneRefs    []string
	CloneAllRefs bool
	// Revision starts history at one revision, or selects a range "A..B": the
	// commits reachable from B but not from A. Empty scans HEAD and every non-note
	// ref. It selects existing history and never fetches additional refs.
	Revision string
	// Since and Until filter committer time inclusively, without pruning ancestors
	// based on timestamps. Non-monotonic history therefore remains traversable.
	Since, Until *time.Time
	// Author and Committer are Go regular expressions over "Name <email>".
	Author, Committer string
	// MaxCount limits selected commits in the date-prioritized history walk.
	// It also limits note commits separately for each notes ref. Zero is unlimited.
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
	// MaxBlobBytes defaults to 64 MiB. Larger blobs are skipped with a warning. It
	// bounds diff inputs, not total working memory or the process's RSS.
	MaxBlobBytes int64
	// Include and Exclude accept history, merges, objects, unreachable-objects,
	// commit-messages, notes, tag-messages, and reflogs. Reflogs scans each entry's
	// message and adds the commits it records to history and commit-messages.
	Include, Exclude []string
	// AllowExternalObjects permits Git storage outside the repository: a .git
	// file, commondir, or object alternate that points elsewhere. Linked
	// worktrees registered by their main repository are always allowed.
	AllowExternalObjects bool
	Prefilter            sources.PrefilterFunc
	// MaxArchiveDepth controls nested archive expansion; zero disables it.
	// The CLI uses 8 by default.
	MaxArchiveDepth int
	Logger          *slog.Logger
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
	case s.URL == "" && (len(s.CloneRefs) > 0 || s.CloneAllRefs):
		return errors.New("clone-ref and clone-all-refs require an HTTP(S) repository URL")
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
	if err := (scm.CloneOptions{Refs: s.CloneRefs, AllRefs: s.CloneAllRefs}).Validate(); err != nil {
		return err
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
	history, merges, messages, reflogs bool
	notes, tags                        bool
	objects, unreachable               bool
}

//nolint:exhaustruct // Resources not on by default start false.
func (s *Source) selection() (selection, error) {
	sel := selection{history: true}
	flags := map[string]*bool{
		sources.GitResourceTypeHistory:            &sel.history,
		sources.GitResourceTypeMerges:             &sel.merges,
		sources.GitResourceTypeCommitMessages:     &sel.messages,
		sources.GitResourceTypeReflogs:            &sel.reflogs,
		sources.GitResourceTypeNotes:              &sel.notes,
		sources.GitResourceTypeTagMessages:        &sel.tags,
		sources.GitResourceTypeObjects:            &sel.objects,
		sources.GitResourceTypeUnreachableObjects: &sel.unreachable,
	}
	for _, list := range [][]string{s.Include, s.Exclude} {
		for _, name := range list {
			if flags[name] == nil {
				return selection{}, fmt.Errorf("unsupported Git resource %q; supported: history, merges, objects, unreachable-objects, commit-messages, notes, tag-messages, reflogs", name)
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
	// Merge patches are part of history.
	if sel.merges && !sel.history {
		return selection{}, errors.New("including merges requires history")
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
		options := scm.CloneOptions{Refs: s.CloneRefs, AllRefs: s.CloneAllRefs}
		return scm.CloneToTempDir(ctx, s.URL, s.Token, "betterleaks-git-*", options, func(path string) error {
			logger.Info("clone complete, starting scan", "duration", time.Since(start).Round(time.Millisecond))
			local := *s
			local.RepoPath, local.URL, local.Token = path, "", ""
			local.CloneRefs, local.CloneAllRefs = nil, false
			err := local.Fragments(ctx, yield)
			if s.Revision != "" && !s.CloneAllRefs && errors.Is(err, gitobj.ErrReferenceNotFound) {
				return fmt.Errorf("%w; --revision selects fetched history; use --clone-ref=refs/... to fetch additional refs", err)
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
	// One walk covers every commit resource. Reflogs, when selected, add the
	// commits they record to it before it starts.
	var walk *history
	if sel.scope() != 0 {
		if walk, err = resolved.history(ctx, r); err != nil {
			return err
		}
	}
	if sel.reflogs {
		if err := resolved.reflogs(ctx, r.Storer.(*objectStorage), walk, yield); err != nil {
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

func (s *Source) commits(ctx context.Context, r *repository, walk *history, sel selection, yield sources.FragmentsFunc) error {
	accept := s.selector()
	workers := s.Workers
	if workers == 0 {
		workers = min(max(runtime.GOMAXPROCS(0), 1), 8)
	}
	maxBlob := s.MaxBlobBytes
	if maxBlob == 0 {
		maxBlob = defaultMaxBlobBytes
	}
	shared := worker{source: s, trees: &treeCache{r: r}, store: walk.store, maxBlob: maxBlob, patches: &patchCache{}, scope: sel.scope(), merges: sel.merges, differ: lineDiffer{}} //nolint:exhaustruct // Scan-local caches start empty.
	// The producer owns traversal; at most one queued commit per worker.
	group, workCtx := errgroup.WithContext(ctx)
	jobs := make(chan *gitobj.Commit, workers)
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

func (s *Source) selector() func(*gitobj.Commit) bool {
	author, _ := regexp.Compile(s.Author)
	committer, _ := regexp.Compile(s.Committer)
	return func(c *gitobj.Commit) bool {
		return !(s.Since != nil && c.Committer.When.Before(*s.Since)) && !(s.Until != nil && c.Committer.When.After(*s.Until)) &&
			(s.Author == "" || author.MatchString(c.Author.Name+" <"+c.Author.Email+">")) &&
			(s.Committer == "" || committer.MatchString(c.Committer.Name+" <"+c.Committer.Email+">"))
	}
}

func commitAttributes(c *gitobj.Commit) map[string]string {
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

// skip logs content that exceeded a limit. As sources.Source asks of skippable
// input, it is a warning rather than a yielded error: a configured limit on one
// large binary must not fail the scan of everything else.
func (s *Source) skip(err error, format string, args ...any) {
	logging.OrDiscard(s.Logger).Warn("skipped Git content over a limit", "content", fmt.Sprintf(format, args...), "error", err)
}

func (w *worker) commit(ctx context.Context, c *gitobj.Commit, yield sources.FragmentsFunc) error {
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
	var parent gitobj.Hash
	if len(parents) > 0 {
		parent = parents[0]
	}
	changes, err := treeChanges(ctx, w.trees, c, parent)
	if isLimit(err) {
		w.source.skip(err, "commit %s", c.Hash)
		return nil
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
			w.source.skip(err, "commit %s path %q", c.Hash, change.To.Name)
			continue
		}
		if err != nil {
			return fmt.Errorf("path %q: %w", change.To.Name, err)
		}
	}
	return nil
}
