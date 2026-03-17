package betterleaks

// Metadata keys used across resources
const (
	MetaPath            = "path"
	MetaSymlinkPath     = "symlink_path"
	MetaCommitSHA       = "commit_sha"
	MetaAuthorName      = "author_name"
	MetaAuthorEmail     = "author_email"
	MetaCommitDate      = "commit_date"
	MetaCommitMessage   = "commit_message"
	MetaSymlinkFile     = "symlink_file"
	MetaWindowsFilePath = "windows_file_path"
	MetaLink            = "link"
	MetaScmPlatform     = "scm_platform"
	MetaScmRemoteURL    = "scm_remote_url"
)

// ResourceKind represents the kind of resource.
type ResourceKind string

// Resource represents a resource from a source which yields fragments.
type Resource struct {
	Name     string
	ID       string
	Path     string
	SourceID string
	Source   string // Source type: "git", "file", "s3", "github", etc.

	Kind ResourceKind

	Metadata map[string]string

	// cached fingerprint identity string, computed once on first call
	fingerprintIdentity string
}

func (r *Resource) Set(key, value string) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]string)
	}
	r.Metadata[key] = value
}

// Get returns a metadata value by key, or empty string if not found.
func (r *Resource) Get(key string) string {
	if r == nil || r.Metadata == nil {
		return ""
	}
	return r.Metadata[key]
}
