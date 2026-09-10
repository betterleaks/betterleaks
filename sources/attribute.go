package sources

// Common source attributes. Provider-specific keys live in their source packages.

const (
	// Universal
	AttrPath = "path"
	AttrURL  = "url"

	// Resource Key
	AttrResource = "resource"

	// Resource values — what kind of thing the fragment is.
	ResourceFileContent      = "fs.content"
	ResourceGitPatchContent  = "git.patch_content"
	ResourceGitCommitMessage = "git.commit_message"
	ResourceGitTagMessage    = "git.tag_message"
	ResourceGitReflogMessage = "git.reflog_message"

	// Git
	AttrGitSHA              = "git.sha"
	AttrGitAuthorName       = "git.author_name"
	AttrGitAuthorEmail      = "git.author_email"
	AttrGitDate             = "git.date"
	AttrGitMessage          = "git.message"
	AttrGitRemoteURL        = "git.remote_url"
	AttrGitPlatform         = "git.platform"
	AttrGitTagName          = "git.tag_name"
	AttrGitTagRef           = "git.tag_ref"
	AttrGitTaggerName       = "git.tagger_name"
	AttrGitTaggerEmail      = "git.tagger_email"
	AttrGitReflogSelector   = "git.reflog_selector"
	AttrGitReflogRef        = "git.reflog_ref"
	AttrGitReflogActorName  = "git.reflog_actor_name"
	AttrGitReflogActorEmail = "git.reflog_actor_email"

	// Filesystem
	AttrFSSymlink       = "fs.symlink"
	AttrFSFirstFragment = "fs.first_fragment"
)
