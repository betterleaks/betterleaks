package sources

// Attribute is a key-value pair attached to a Fragment.
// Keys use dotted namespaces: "git.sha", "fs.symlink", "s3.bucket", etc.
// Values are always strings to avoid boxing/GC overhead.
type Attribute struct {
	Key   string
	Value string
}

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
