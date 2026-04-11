package report

import (
	"maps"

	"github.com/betterleaks/betterleaks/sources"
)

// SetAttributes stores a copy of attrs and syncs deprecated source fields for compatibility.
func (f *Finding) SetAttributes(attrs map[string]string) {
	f.Attributes = maps.Clone(attrs)
	f.SyncDeprecatedSourceFields()
}

// Attribute returns a source metadata value, preferring the new Attributes map
// and falling back to deprecated top-level fields when needed.
func (f Finding) Attribute(key string) string {
	if f.Attributes != nil {
		if value := f.Attributes[key]; value != "" {
			return value
		}
	}

	switch key {
	case sources.AttrPath:
		return f.File
	case sources.AttrFSSymlink:
		return f.SymlinkFile
	case sources.AttrGitSHA:
		return f.Commit
	case sources.AttrGitAuthorName:
		return f.Author
	case sources.AttrGitAuthorEmail:
		return f.Email
	case sources.AttrGitDate:
		return f.Date
	case sources.AttrGitMessage:
		return f.Message
	default:
		return ""
	}
}

func (f Finding) Path() string {
	return f.Attribute(sources.AttrPath)
}

func (f Finding) SymlinkPath() string {
	return f.Attribute(sources.AttrFSSymlink)
}

func (f Finding) CommitSHA() string {
	return f.Attribute(sources.AttrGitSHA)
}

func (f Finding) AuthorName() string {
	return f.Attribute(sources.AttrGitAuthorName)
}

func (f Finding) AuthorEmail() string {
	return f.Attribute(sources.AttrGitAuthorEmail)
}

func (f Finding) CommitDate() string {
	return f.Attribute(sources.AttrGitDate)
}

func (f Finding) CommitMessage() string {
	return f.Attribute(sources.AttrGitMessage)
}

func (f Finding) ScmRemoteURL() string {
	return f.Attribute(sources.AttrGitRemoteURL)
}

func (f Finding) ScmPlatform() string {
	return f.Attribute(sources.AttrGitPlatform)
}

// SyncDeprecatedSourceFields backfills deprecated fields from Attributes so
// legacy reporters, baselines, and templates continue to work.
func (f *Finding) SyncDeprecatedSourceFields() {
	f.File = f.Path()
	f.SymlinkFile = f.SymlinkPath()
	f.Commit = f.CommitSHA()
	f.Author = f.AuthorName()
	f.Email = f.AuthorEmail()
	f.Date = f.CommitDate()
	f.Message = f.CommitMessage()
}
