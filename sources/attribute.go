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

	ResourceGitLabProject      = "gitlab.project"
	ResourceGitLabIssue        = "gitlab.issue"
	ResourceGitLabMR           = "gitlab.mr"
	ResourceGitLabComment      = "gitlab.comment"
	ResourceGitLabSnippet      = "gitlab.snippet"
	ResourceGitLabRelease      = "gitlab.release"
	ResourceGitLabReleaseAsset = "gitlab.release_asset"
	ResourceGitLabCIJob        = "gitlab.ci_job"
	ResourceGitLabCIArtifact   = "gitlab.ci_artifact"

	ResourceHuggingFaceRepo       = "huggingface.repository"
	ResourceHuggingFaceDiscussion = "huggingface.discussion"
	ResourceHuggingFacePR         = "huggingface.pr"
	ResourceHuggingFaceComment    = "huggingface.comment"
	ResourceHuggingFaceBucket     = "huggingface.bucket"

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

	// GitLab
	AttrGitLabProjectID        = "gitlab.project.id"
	AttrGitLabProjectPath      = "gitlab.project.path"
	AttrGitLabProjectURL       = "gitlab.project.url"
	AttrGitLabVisibility       = "gitlab.visibility"
	AttrGitLabNamespace        = "gitlab.namespace"
	AttrGitLabIssueIID         = "gitlab.issue.iid"
	AttrGitLabMRIID            = "gitlab.mr.iid"
	AttrGitLabCommentID        = "gitlab.comment.id"
	AttrGitLabSnippetID        = "gitlab.snippet.id"
	AttrGitLabSnippetFilename  = "gitlab.snippet.filename"
	AttrGitLabReleaseTag       = "gitlab.release.tag"
	AttrGitLabReleaseAssetName = "gitlab.release.asset_name"
	AttrGitLabCIJobID          = "gitlab.ci_job.id"
	AttrGitLabCIJobName        = "gitlab.ci_job.name"
	AttrGitLabCIPipelineID     = "gitlab.ci_pipeline.id"

	// Hugging Face
	AttrHuggingFaceOwner             = "huggingface.owner"
	AttrHuggingFaceRepo              = "huggingface.repo"
	AttrHuggingFaceRepoType          = "huggingface.repo_type"
	AttrHuggingFaceRepoURL           = "huggingface.repo_url"
	AttrHuggingFaceVisibility        = "huggingface.visibility"
	AttrHuggingFaceDiscussionNumber  = "huggingface.discussion.number"
	AttrHuggingFaceCommentID         = "huggingface.comment.id"
	AttrHuggingFaceAuthor            = "huggingface.author"
	AttrHuggingFaceCommunityResource = "huggingface.community.resource"
	AttrHuggingFaceBucket            = "huggingface.bucket"
	AttrHuggingFaceBucketURL         = "huggingface.bucket_url"
	AttrHuggingFaceBucketPath        = "huggingface.bucket.path"
	AttrHuggingFaceBucketSize        = "huggingface.bucket.size"
	AttrHuggingFaceBucketMTime       = "huggingface.bucket.mtime"
	AttrHuggingFaceBucketXetHash     = "huggingface.bucket.xet_hash"

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
