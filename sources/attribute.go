package sources

// Well-known attribute keys (constants prevent typos at call sites).
const (
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
