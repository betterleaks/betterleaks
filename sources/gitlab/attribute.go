package gitlab

// Attribute keys and resource values retain their serialized provider names.
const (
	ResourceProject      = "gitlab.project"
	ResourceIssue        = "gitlab.issue"
	ResourceMR           = "gitlab.mr"
	ResourceComment      = "gitlab.comment"
	ResourceSnippet      = "gitlab.snippet"
	ResourceRelease      = "gitlab.release"
	ResourceReleaseAsset = "gitlab.release_asset"
	ResourceCIJob        = "gitlab.ci_job"
	ResourceCIArtifact   = "gitlab.ci_artifact"
	AttrProjectID        = "gitlab.project.id"
	AttrProjectPath      = "gitlab.project.path"
	AttrProjectURL       = "gitlab.project.url"
	AttrVisibility       = "gitlab.visibility"
	AttrNamespace        = "gitlab.namespace"
	AttrIssueIID         = "gitlab.issue.iid"
	AttrMRIID            = "gitlab.mr.iid"
	AttrCommentID        = "gitlab.comment.id"
	AttrSnippetID        = "gitlab.snippet.id"
	AttrSnippetFilename  = "gitlab.snippet.filename"
	AttrReleaseTag       = "gitlab.release.tag"
	AttrReleaseAssetName = "gitlab.release.asset_name"
	AttrCIJobID          = "gitlab.ci_job.id"
	AttrCIJobName        = "gitlab.ci_job.name"
	AttrCIPipelineID     = "gitlab.ci_pipeline.id"
)
