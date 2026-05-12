package sources

// TODO move to a separate package (attrkeys/) once stable.

const (
	// Universal
	AttrPath = "path"
	AttrURL  = "url"

	// Resource Key
	AttrResource = "resource"

	// Resource values — what kind of thing the fragment is.
	ResourceFileContent        = "fs.content"
	ResourceGitPatchContent    = "git.patch_content"
	ResourceGitHubRepo         = "github.repository"
	ResourceGitHubIssue        = "github.issue"
	ResourceGitHubPR           = "github.pr"
	ResourceGitHubComment      = "github.comment"
	ResourceGitHubActions      = "github.actions"
	ResourceGitHubDiscussion   = "github.discussion"
	ResourceGitHubRelease      = "github.release"
	ResourceGitHubReleaseAsset = "github.release_asset"
	ResourceGitHubGist         = "github.gist"

	// Git
	AttrGitSHA         = "git.sha"
	AttrGitAuthorName  = "git.author_name"
	AttrGitAuthorEmail = "git.author_email"
	AttrGitDate        = "git.date"
	AttrGitMessage     = "git.message"
	AttrGitRemoteURL   = "git.remote_url"
	AttrGitPlatform    = "git.platform"

	// Filesystem
	AttrFSSymlink = "fs.symlink"

	// GitHub
	AttrGitHubOwner       = "github.owner"
	AttrGitHubOwnerType   = "github.owner_type"
	AttrGitHubRepo        = "github.repo"
	AttrGitHubRepoURL     = "github.repo_url"
	AttrGitHubVisibility  = "github.visibility"
	AttrGitHubIssueNumber = "github.issue.number"
	AttrGitHubPRNumber    = "github.pr.number"
	AttrGitHubCommentID   = "github.comment.id"

	AttrGitHubActionsRunID   = "github.actions.run_id"
	AttrGitHubActionsRunName = "github.actions.run_name"
	AttrGitHubActionsRunURL  = "github.actions.run_url"
	AttrGitHubActionsEvent   = "github.actions.event"

	AttrGitHubDiscussionNumber = "github.discussion.number"
	AttrGitHubReleaseTag       = "github.release.tag"
	AttrGitHubReleaseAssetName = "github.release.asset_name"
	AttrGitHubGistID           = "github.gist.id"
	AttrGitHubGistFilename     = "github.gist.filename"
	AttrGitHubGistOwner        = "github.gist.owner"

	// S3 (and S3-compatible object stores)
	AttrS3Bucket       = "s3.bucket"
	AttrS3Key          = "s3.key"
	AttrS3Region       = "s3.region"
	AttrS3Endpoint     = "s3.endpoint"
	AttrS3LastModified = "s3.last_modified"
	AttrS3ETag         = "s3.etag"
	AttrS3Size         = "s3.size"
	AttrS3StorageClass = "s3.storage_class"

	ResourceS3Object = "s3.object"
)
