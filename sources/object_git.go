package sources

import (
	"context"
	"maps"
	"time"

	"github.com/betterleaks/betterleaks/internal/gitobject"
	"github.com/betterleaks/betterleaks/sources/scm"
)

// ObjectGit reads added lines directly from loose objects and packfiles.
type ObjectGit struct {
	RepoPath        string
	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	MaxArchiveDepth int
}

// Fragments implements Source.
func (s *ObjectGit) Fragments(ctx context.Context, yield FragmentsFunc) error {
	return gitobject.WalkAdditions(ctx, s.RepoPath, func(blob gitobject.Blob) error {
		attrs := map[string]string{
			AttrPath:           blob.Appearance.Path,
			AttrResource:       ResourceGitPatchContent,
			AttrGitSHA:         blob.Appearance.Commit,
			AttrGitMessage:     blob.Appearance.Message,
			AttrGitAuthorName:  blob.Appearance.AuthorName,
			AttrGitAuthorEmail: blob.Appearance.AuthorEmail,
		}
		if !blob.Appearance.AuthorTime.IsZero() {
			attrs[AttrGitDate] = blob.Appearance.AuthorTime.UTC().Format(time.RFC3339)
		}
		if s.RemoteURL != "" {
			attrs[AttrGitRemoteURL] = s.RemoteURL
			attrs[AttrGitPlatform] = s.Platform.String()
		}
		if shouldSkipAttrs(s.ShouldSkip, attrs) {
			return nil
		}

		if !blob.Binary {
			return yield(Fragment{Raw: blob.Text, StartLine: blob.StartLine, Attributes: attrs}, nil)
		}
		if !isArchive(ctx, blob.Appearance.Path) {
			return nil
		}

		file := File{
			Content:         blob.Content,
			Path:            blob.Appearance.Path,
			ShouldSkip:      s.ShouldSkip,
			MaxArchiveDepth: s.MaxArchiveDepth,
		}
		return file.Fragments(ctx, func(fragment Fragment, err error) error {
			if err == nil {
				merged := maps.Clone(attrs)
				maps.Copy(merged, fragment.Attributes)
				fragment.Attributes = merged
			}
			return yield(fragment, err)
		})
	})
}
