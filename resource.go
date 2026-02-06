package betterleaks

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
