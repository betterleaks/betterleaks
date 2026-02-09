package betterleaks

import "strings"

// Metadata keys used across sources.
const (
	MetaPath            = "path"
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

// Resource represents a resource from a source which yields fragments.
type Resource struct {
	Name     string
	ID       string
	Path     string
	Kind     ResourceKind
	SourceID string
	Source   string // Source type: "git", "file", "s3", "github", etc.

	// TODO ParentResourceID string
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

// ResourceKind represents the kind of resource.
type ResourceKind string

// File Resource Kinds
const (
	FileContent ResourceKind = "file_content"
)

// Git Resource Kinds
const (
	GitCommitMessage ResourceKind = "git_commit_message"
	GitCommitBody    ResourceKind = "git_commit_body"
	GitPatchContent  ResourceKind = "git_patch_content"
)

// GitHub Resource Kinds
const (
	GitHubComment          ResourceKind = "github_comment"
	GitHubIssueDescription ResourceKind = "github_issue_description"
	GitHubIssueTitle       ResourceKind = "github_issue_title"
	GitHubPullRequestTitle ResourceKind = "github_pull_request_title"
	GitHubPullRequestBody  ResourceKind = "github_pull_request_body"
)

// S3 Resource Kinds
const (
	S3Object ResourceKind = "s3_object"
)

// FingerprintKeys returns the metadata keys forming the unique identity for this resource kind.
// Keys are returned in alphabetical order.
func (k ResourceKind) FingerprintKeys() []string {
	switch k {
	case GitPatchContent, GitCommitMessage, GitCommitBody:
		return []string{MetaCommitSHA, MetaPath} // "commit_sha", "path" — already alphabetical
	case FileContent:
		return []string{MetaPath}
	case GitHubComment:
		return []string{"comment_id", "repo"}
	case GitHubIssueDescription, GitHubIssueTitle:
		return []string{"issue_id", "repo"}
	case GitHubPullRequestTitle, GitHubPullRequestBody:
		return []string{"pr_id", "repo"}
	case S3Object:
		return []string{"bucket", "key"}
	default:
		return []string{MetaPath}
	}
}

// FingerprintIdentity returns the sorted key=value pairs that uniquely identify
// this resource. The result is cached on the Resource since it's shared across
// fragments.
func (r *Resource) FingerprintIdentity() string {
	if r.fingerprintIdentity != "" {
		return r.fingerprintIdentity
	}
	keys := r.Kind.FingerprintKeys()
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(r.Metadata[k])
	}
	r.fingerprintIdentity = b.String()
	return r.fingerprintIdentity
}
