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
	ResourceURLContent       = "url.content"
	ResourceGitPatchContent  = "git.patch_content"
	ResourceGitCommitMessage = "git.commit_message"
	ResourceGitTagMessage    = "git.tag_message"
	ResourceGitReflogMessage = "git.reflog_message"
	ResourceGitNote          = "git.note"
	ResourceGitBlob          = "git.blob"

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
	AttrGitCommitterName    = "git.committer_name"
	AttrGitCommitterEmail   = "git.committer_email"
	AttrGitCommitterDate    = "git.committer_date"
	AttrGitBlobSHA          = "git.blob_sha"
	AttrGitTagSHA           = "git.tag_sha"
	AttrGitTagTarget        = "git.tag_target"
	AttrGitTagSourceRef     = "git.tag_source_ref"
	AttrGitTaggerDate       = "git.tagger_date"
	AttrGitNotesRef         = "git.notes_ref"
	AttrGitNoteTarget       = "git.note_target"
	AttrGitReflogSelector   = "git.reflog_selector"
	AttrGitReflogRef        = "git.reflog_ref"
	AttrGitReflogActorName  = "git.reflog_actor_name"
	AttrGitReflogActorEmail = "git.reflog_actor_email"
	AttrGitReflogDate       = "git.reflog_date"
	AttrGitReflogOldSHA     = "git.reflog_old_sha"
	AttrGitReflogNewSHA     = "git.reflog_new_sha"
	AttrGitReflogLog        = "git.reflog_log"
	AttrGitReflogLine       = "git.reflog_line"

	// Filesystem
	AttrFSSymlink       = "fs.symlink"
	AttrFSFirstFragment = "fs.first_fragment"
)
