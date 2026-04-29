package sources

// TODO move this to a separate package called something like "detectkeys"

// Well-known attribute keys (constants prevent typos at call sites).
const (
	ResourceKey             = "resource"
	ResourceGitPatchContent = "git.patch_content"
	ResourceFileContent     = "fs.content"

	// universal attributes
	AttrPath = "path"

	// Git attributes
	AttrGitSHA         = "git.sha"
	AttrGitAuthorName  = "git.author_name"
	AttrGitAuthorEmail = "git.author_email"
	AttrGitDate        = "git.date"
	AttrGitMessage     = "git.message"
	AttrGitRemoteURL   = "git.remote_url"
	AttrGitPlatform    = "git.platform"

	// Filesystem attributes
	AttrFSSymlink     = "fs.symlink"
	AttrFSWindowsPath = "fs.windows_path"

	AttrResourceKind             = "resource_kind"
	ResourceKindGitHubRepository = "github.repository"
	ResourceKindGitHubIssue      = "github.issue"
	ResourceKindGitHubPR         = "github.pr"
	ResourceKindGitHubComment    = "github.comment"

	// Source ancestry
	AttrSourceChain            = "source_chain"
	SourceChainGitHub          = "github"
	SourceChainIssue           = "issue"
	SourceChainPR              = "pr"
	SourceChainComment         = "comment"
	SourceChainPRReviewComment = "pr_review_comment"
	SourceChainActions         = "actions"

	// GitHub attributes
	AttrGitHubOwner       = "github.owner"
	AttrGitHubOwnerType   = "github.owner_type"
	AttrGitHubRepo        = "github.repo"
	AttrGitHubRepoURL     = "github.repo_url"
	AttrGitHubVisibility  = "github.visibility"
	AttrGitHubIssueNumber = "github.issue.number"
	AttrGitHubPRNumber    = "github.pr.number"
	AttrGitHubCommentID   = "github.comment.id"

	// GitHub Actions attributes
	AttrGitHubActionsRunID   = "github.actions.run_id"
	AttrGitHubActionsRunName = "github.actions.run_name"
	AttrGitHubActionsRunURL  = "github.actions.run_url"
	AttrGitHubActionsEvent   = "github.actions.event"
)
