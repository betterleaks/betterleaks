package gogit

import (
	"context"
	"errors"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/gitobj"
)

// CommitParents resolves rev and returns the object IDs of its parent commits,
// in recorded order, as lowercase hex strings. The first entry is the first
// parent. A root commit has no parents; a merge commit has more than one.
//
// rev names a single commit: a full or abbreviated object ID, a ref name, a
// tag that peels to a commit, or a bounded suffix such as HEAD^ or HEAD~2. It
// is not a range; forms like A..B are rejected. Reading the resolved commit's
// parents does not walk history, so a repository operator can detect merge
// commits in-process instead of invoking "git rev-list --parents -n 1".
// Message-search suffixes (^{/pattern}) are rejected because resolving them
// would walk history, which this metadata lookup does not do.
//
// Like Git, a shallow boundary commit reports no parents because its parents
// were never fetched. CommitParents reads object storage under the same
// confinement as a scan: a quarantine or alternate outside the repository,
// including the directories GIT_OBJECT_DIRECTORY and
// GIT_ALTERNATE_OBJECT_DIRECTORIES name, requires AllowExternalObjects.
//
// CommitParents requires a local RepoPath; it does not clone a URL.
func (s *Source) CommitParents(ctx context.Context, rev string) ([]string, error) {
	if s.RepoPath == "" {
		return nil, errors.New("git commit metadata requires a local repository path")
	}
	if rev == "" {
		return nil, errors.New("git commit metadata requires a revision")
	}
	if strings.Contains(rev, "..") {
		return nil, errors.New("git commit metadata requires a single revision, not a range")
	}
	if strings.Contains(rev, "^{/") {
		return nil, errors.New("git commit metadata does not support message-search revisions")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	r, cleanup, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	id, err := r.ResolveRevision(gitobj.Revision(rev))
	if err != nil {
		return nil, err
	}
	commit, err := r.CommitObject(*id)
	if err != nil {
		return nil, err
	}

	parents := r.Storer.(*objectStorage).parents(commit)
	ids := make([]string, len(parents))
	for i, p := range parents {
		ids[i] = p.String()
	}
	return ids, nil
}
