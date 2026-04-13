package report

import (
	"maps"

	"github.com/betterleaks/betterleaks/sources"
)

func (f *Finding) SetAttr(key, value string) {
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
}

func (f Finding) Attr(key string) string {
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

// SetAttributes stores a copy of attrs and syncs deprecated source fields for compatibility.
func (f *Finding) SetAttributes(attrs map[string]string) {
	f.Attributes = maps.Clone(attrs)
	f.SyncDeprecatedSourceFields()
}

// Attribute is retained as a compatibility wrapper around Attr.
func (f Finding) Attribute(key string) string {
	return f.Attr(key)
}

// SyncDeprecatedSourceFields backfills deprecated fields from Attributes so
// legacy reporters, baselines, and templates continue to work.
func (f *Finding) SyncDeprecatedSourceFields() {
	f.File = f.Attr(sources.AttrPath)
	f.SymlinkFile = f.Attr(sources.AttrFSSymlink)
	f.Commit = f.Attr(sources.AttrGitSHA)
	f.Author = f.Attr(sources.AttrGitAuthorName)
	f.Email = f.Attr(sources.AttrGitAuthorEmail)
	f.Date = f.Attr(sources.AttrGitDate)
	f.Message = f.Attr(sources.AttrGitMessage)
}
