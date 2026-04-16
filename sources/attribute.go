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

	AttrResourceKind = "resource_kind"
)
