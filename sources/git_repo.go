package sources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/logging"
)

// errNoGitRemote is returned when a repository has no remote to link findings to.
var errNoGitRemote = errors.New("no remote configured")

// gitRepo is where the Git commands for one scan run.
//
// Unless the repository is trusted, that is a private Git directory:
// Betterleaks writes its configuration, copies the source's HEAD, refs, and
// reflogs as plain files, and lists the source's object directory in
// objects/info/alternates. Source configuration is parsed as data, but is never
// loaded as active configuration by scanning commands. Hooks and attributes in
// .git/info are not copied; sparse-checkout patterns are copied for diffs. Writes
// stay in the private repository.
type gitRepo struct {
	source         string // directory to scan
	gitDir         string // private Git directory; empty when trusted
	workTree       string // original for diffs; temporary worktree with only .mailmap for history
	commandDir     string
	sourceWorkTree string // used to translate absolute history pathspecs
	tempDir        string
	once           sync.Once
}

// openGitRepo prepares source for scanning. withWorkTree is required by
// staged and working-tree scans, which also get a private copy of the index.
func openGitRepo(ctx context.Context, source string, opts GitOptions, withWorkTree bool) (*gitRepo, error) {
	if opts.TrustLocalGitConfig {
		return &gitRepo{source: filepath.Clean(source)}, nil
	}
	layout, err := findGitLayout(source)
	if err != nil {
		return nil, err
	}
	cfg, err := readGitConfig(ctx, filepath.Join(layout.commonDir, "config"))
	if err != nil {
		return nil, err
	}
	var worktreeConfig bool
	if value, ok := cfg.last("extensions.worktreeconfig"); ok {
		worktreeConfig, err = parseGitBool(value)
		if err != nil {
			return nil, fmt.Errorf("extensions.worktreeConfig: %w", err)
		}
		if worktreeConfig {
			worktreeCfg, err := readGitConfig(ctx, filepath.Join(layout.gitDir, "config.worktree"))
			if err != nil {
				return nil, err
			}
			for _, entry := range worktreeCfg {
				// Repository format is determined by the common config;
				// only permitted working-tree settings may override it.
				if slices.Contains(gitWorktreeBoolSettings, entry.key) || entry.key == "core.autocrlf" || entry.key == "core.eol" || entry.key == "core.worktree" || entry.key == "core.bare" {
					cfg = append(cfg, entry)
				}
			}
		}
	}
	if err := layout.setWorkTree(cfg, worktreeConfig); err != nil {
		return nil, err
	}
	if withWorkTree && layout.workTree == "" {
		return nil, fmt.Errorf("%s has no working tree", source)
	}
	config, err := privateGitConfig(cfg, withWorkTree)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	tempDir, err := os.MkdirTemp("", "betterleaks-git-*")
	if err != nil {
		return nil, err
	}
	r := &gitRepo{source: layout.source, gitDir: tempDir, tempDir: tempDir, commandDir: tempDir}
	if withWorkTree {
		r.workTree = layout.workTree
		r.commandDir = layout.source
	} else if layout.workTree != "" {
		// Let Git resolve pathspec magic and relative paths itself, without
		// exposing the original worktree's attributes or submodule repositories.
		r.workTree = filepath.Join(tempDir, "worktree")
		r.sourceWorkTree = layout.workTree
		rel, err := filepath.Rel(layout.workTree, layout.source)
		if err != nil || !filepath.IsLocal(rel) {
			rel = "." // GIT_WORK_TREE may point outside the source directory.
		}
		r.commandDir = filepath.Join(r.workTree, rel)
		if err := os.MkdirAll(r.commandDir, 0o700); err != nil {
			r.Close()
			return nil, err
		}
	}
	if err := r.populate(ctx, layout, config, withWorkTree); err != nil {
		r.Close()
		return nil, fmt.Errorf("could not isolate Git repository %s: %w", source, err)
	}
	return r, nil
}

// populate fills the private Git directory from the source repository.
func (r *gitRepo) populate(ctx context.Context, layout gitLayout, config string, withIndex bool) error {
	objects := filepath.Join(layout.commonDir, "objects")
	if info, err := os.Stat(objects); err != nil || !info.IsDir() {
		return fmt.Errorf("missing object directory %s", objects)
	}
	if err := os.MkdirAll(filepath.Join(r.tempDir, "objects", "info"), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(r.tempDir, "config"), []byte(config), 0o600); err != nil {
		return err
	}
	if err := copyGitRefs(ctx, layout.commonDir, r.tempDir); err != nil {
		return err
	}
	if !withIndex && layout.workTree != "" {
		// Mailmaps contain author identities, not commands. Preserve the
		// worktree's mapping without exposing its attributes or configuration.
		// Like Git, do not follow a .mailmap symlink.
		mailmap := filepath.Join(layout.workTree, ".mailmap")
		info, err := os.Lstat(mailmap)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err == nil && info.Mode().IsRegular() {
			if err := copyGitFile(ctx, mailmap, filepath.Join(r.workTree, ".mailmap")); err != nil {
				return err
			}
		}
	}

	// Copy every linked worktree's HEAD and refs, since --all includes them,
	// and use the scanned worktree's copy as the Git directory.
	worktrees := filepath.Join(layout.commonDir, "worktrees")
	entries, err := os.ReadDir(worktrees)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		src := filepath.Join(worktrees, entry.Name())
		dst := filepath.Join(r.tempDir, "worktrees", entry.Name())
		if err := copyGitRefs(ctx, src, dst); err != nil {
			return err
		}
		if err := copyGitFile(ctx, filepath.Join(src, "gitdir"), filepath.Join(dst, "gitdir")); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, "commondir"), []byte("../..\n"), 0o600); err != nil {
			return err
		}
		if samePath(src, layout.gitDir) {
			r.gitDir = dst
		}
	}
	if !samePath(layout.gitDir, layout.commonDir) && r.gitDir == r.tempDir {
		return fmt.Errorf("unsupported worktree layout %s", layout.gitDir)
	}

	// Objects are read in place. Pre-receive hooks keep incoming objects in
	// a quarantine directory named by these variables.
	objectDirs := []string{objects}
	if dir := os.Getenv("GIT_OBJECT_DIRECTORY"); dir != "" {
		objectDirs = append(objectDirs, gitPath(layout.source, dir))
	}
	alternates, err := splitGitPathList(os.Getenv("GIT_ALTERNATE_OBJECT_DIRECTORIES"))
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	for _, dir := range objectDirs {
		buf.WriteString(quoteGitPath(filepath.ToSlash(dir)) + "\n")
	}
	for _, dir := range alternates {
		buf.WriteString(quoteGitPath(filepath.ToSlash(gitPath(layout.source, dir))) + "\n")
	}
	if err := os.WriteFile(filepath.Join(r.tempDir, "objects", "info", "alternates"), buf.Bytes(), 0o600); err != nil {
		return err
	}

	if withIndex {
		// Git may refresh the index while diffing; it only ever writes this copy.
		index := filepath.Join(layout.gitDir, "index")
		if file := os.Getenv("GIT_INDEX_FILE"); file != "" {
			index = gitPath(layout.source, file)
		}
		if err := copyGitFile(ctx, index, filepath.Join(r.gitDir, "index")); err != nil {
			return err
		}
		// Sparse indexes need the worktree's patterns as well as its settings.
		// These are path patterns, not executable attributes or configuration.
		if err := copyGitFile(ctx, filepath.Join(layout.gitDir, "info", "sparse-checkout"), filepath.Join(r.gitDir, "info", "sparse-checkout")); err != nil {
			return err
		}
		// A split index keeps most entries in a shared index file.
		entries, err := os.ReadDir(layout.gitDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), "sharedindex.") {
				if err := copyGitFile(ctx, filepath.Join(layout.gitDir, entry.Name()), filepath.Join(r.gitDir, entry.Name())); err != nil {
					return err
				}
			}
		}
	}

	// Fail now, rather than mid-scan, if Git cannot use the private directory.
	if out, err := r.command(ctx, "rev-parse", "--git-dir").CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// command returns a Git command that runs against the repository.
func (r *gitRepo) command(ctx context.Context, args ...string) *exec.Cmd {
	if r.gitDir == "" {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.source}, args...)...)
		cmd.Env = gitConfigIsolationEnv()
		return cmd
	}
	prefix := []string{"--git-dir=" + r.gitDir}
	if r.workTree != "" {
		prefix = append(prefix, "--work-tree="+r.workTree)
	}
	if r.sourceWorkTree != "" {
		args = append([]string(nil), args...)
		paths := false
		for i, arg := range args {
			if paths && filepath.IsAbs(arg) {
				if rel, ok := relativeGitPath(r.sourceWorkTree, arg); ok {
					args[i] = filepath.Join(r.workTree, rel)
				}
			}
			if arg == "--" {
				paths = true
			}
		}
	}
	cmd := exec.CommandContext(ctx, "git", append(prefix, args...)...)
	cmd.Dir = r.commandDir
	cmd.Env = isolatedGitEnv()
	return cmd
}

// relativeGitPath translates an absolute pathspec into a worktree-relative
// path. Resolve symlinks only outside the worktree, as Git does; the suffix
// may contain globs or refer to historical files that no longer exist.
func relativeGitPath(worktree, path string) (string, bool) {
	path = filepath.Clean(path)
	if rel, err := filepath.Rel(worktree, path); err == nil && filepath.IsLocal(rel) {
		return rel, true
	}
	prefix := filepath.VolumeName(path) + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(path, prefix), string(filepath.Separator))
	for i, part := range parts {
		prefix = filepath.Join(prefix, part)
		if samePath(worktree, prefix) {
			return filepath.Join(parts[i+1:]...), true
		}
	}
	return "", false
}

// Close removes the private Git directory, if any.
func (r *gitRepo) Close() {
	r.once.Do(func() {
		if r.tempDir == "" {
			return
		}
		if err := os.RemoveAll(r.tempDir); err != nil {
			logging.Debug().Err(err).Str("path", r.tempDir).Msg("could not remove private Git directory")
		}
	})
}

// isolatedGitEnv drops inherited GIT_* variables, which could point Git back
// at the source repository, its index, or other configuration.
func isolatedGitEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(e), "GIT_") {
			env = append(env, e)
		}
	}
	// Git recognizes /dev/null on Windows too; Git for Windows 2.56.0 rejects NUL.
	return append(env,
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_ATTR_NOSYSTEM=1",
		"GIT_NO_REPLACE_OBJECTS=1",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_TERMINAL_PROMPT=0",
	)
}

var gitWorktreeBoolSettings = []string{
	"core.filemode", "core.symlinks", "core.ignorecase", "core.precomposeunicode",
	"core.sparsecheckout", "core.sparsecheckoutcone", "index.sparse",
}

// privateGitConfig returns the configuration for a private Git directory.
// It carries over only the settings Git needs to read the source's object and
// ref formats and, for diffs, to compare the working tree the same way. Values
// are validated and rewritten, never copied verbatim.
func privateGitConfig(cfg gitConfig, withWorkTree bool) (string, error) {
	if _, ok := cfg.last("extensions.partialclone"); ok {
		return "", errors.New("partial clones are not supported: missing objects cannot be fetched without the repository's configuration (use --trust-local-git-config)")
	}
	version := 0
	if v, ok := cfg.last("core.repositoryformatversion"); ok {
		var err error
		if version, err = strconv.Atoi(v); err != nil || version < 0 || version > 1 {
			return "", fmt.Errorf("unsupported repository format version %q", v)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[core]\n\trepositoryformatversion = %d\n\tbare = %t\n", version, !withWorkTree)
	if withWorkTree {
		if v, ok := cfg.last("core.autocrlf"); ok {
			if v = strings.ToLower(v); v != "input" {
				enabled, err := parseGitBool(v)
				if err != nil {
					return "", fmt.Errorf("core.autocrlf: %w", err)
				}
				v = strconv.FormatBool(enabled)
			}
			fmt.Fprintf(&b, "\tautocrlf = %s\n", v)
		}
		if v, ok := cfg.last("core.eol"); ok {
			switch v = strings.ToLower(v); v {
			case "lf", "crlf", "native":
				fmt.Fprintf(&b, "\teol = %s\n", v)
			default:
				return "", fmt.Errorf("core.eol: invalid value %q", v)
			}
		}
		for _, key := range gitWorktreeBoolSettings {
			if v, ok := cfg.last(key); ok {
				enabled, err := parseGitBool(v)
				if err != nil {
					return "", fmt.Errorf("%s: %w", key, err)
				}
				section, name, _ := strings.Cut(key, ".")
				fmt.Fprintf(&b, "[%s]\n\t%s = %t\n", section, name, enabled)
			}
		}
	}

	// Object and ref format extensions require version 1. worktreeConfig is
	// also recognized in version 0 and was handled when reading the config.
	if version == 1 {
		var extensions []string
		seen := make(map[string]bool)
		for _, e := range cfg {
			name, ok := strings.CutPrefix(e.key, "extensions.")
			if !ok || seen[name] {
				continue
			}
			seen[name] = true
			value, _ := cfg.last(e.key)
			switch v := strings.ToLower(value); name {
			case "objectformat":
				if v == "sha1" || v == "sha256" {
					extensions = append(extensions, "objectformat = "+v)
					continue
				}
			case "refstorage":
				if v == "files" || v == "reftable" {
					extensions = append(extensions, "refstorage = "+v)
					continue
				}
			case "worktreeconfig":
				// Permitted worktree overrides are already merged above.
				continue
			case "compatobjectformat", "noop", "preciousobjects", "relativeworktrees", "submodulepathconfig":
				// These affect how the source is maintained, not how it is read.
				continue
			}
			return "", fmt.Errorf("unsupported repository extension %s = %q (use --trust-local-git-config)", e.key, value)
		}
		if len(extensions) > 0 {
			b.WriteString("[extensions]\n\t" + strings.Join(extensions, "\n\t") + "\n")
		}
	}
	return b.String(), nil
}

func parseGitBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off", "":
		return false, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return false, fmt.Errorf("invalid boolean %q", v)
	}
	return n != 0, nil
}

type gitConfigEntry struct {
	key, value string
}

// gitConfig holds a config file's entries in order, with keys as
// `git config --list` prints them.
type gitConfig []gitConfigEntry

func (c gitConfig) last(key string) (string, bool) {
	for i := len(c) - 1; i >= 0; i-- {
		if c[i].key == key {
			return c[i].value, true
		}
	}
	return "", false
}

// readGitConfig parses a config file as data. Includes are not followed, and
// the unusable GIT_DIR stops Git from discovering and configuring itself from
// a repository.
func readGitConfig(ctx context.Context, path string) (gitConfig, error) {
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, "git", "config", "--file", path, "--no-includes", "--null", "--list")
	cmd.Dir = os.TempDir()
	cmd.Env = append(isolatedGitEnv(), "GIT_DIR=/dev/null")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("could not read %s: %s", path, bytes.TrimSpace(exitErr.Stderr))
		}
		return nil, fmt.Errorf("could not read %s: %w", path, err)
	}
	var cfg gitConfig
	for _, record := range strings.Split(string(out), "\x00") {
		if record == "" {
			continue
		}
		key, value, ok := strings.Cut(record, "\n")
		if !ok {
			value = "true" // a key without a value is a true boolean
		}
		cfg = append(cfg, gitConfigEntry{key, value})
	}
	return cfg, nil
}

// gitRemoteURL returns the URL `git ls-remote --get-url` would print,
// reading the repository's configuration as data.
func gitRemoteURL(ctx context.Context, source string) (string, error) {
	layout, err := findGitLayout(source)
	if err != nil {
		return "", err
	}
	cfg, err := readGitConfig(ctx, filepath.Join(layout.commonDir, "config"))
	if err != nil {
		return "", err
	}

	// Like Git: the current branch's remote, else the only remote, else origin.
	name := ""
	if head, err := readGitFile(filepath.Join(layout.gitDir, "HEAD")); err == nil {
		if branch, ok := strings.CutPrefix(strings.TrimSpace(string(head)), "ref: refs/heads/"); ok {
			name, _ = cfg.last("branch." + branch + ".remote")
		}
	}
	if name == "" {
		remotes := make(map[string]bool)
		for _, e := range cfg {
			if rest, ok := strings.CutPrefix(e.key, "remote."); ok {
				if i := strings.LastIndexByte(rest, '.'); i > 0 {
					remotes[rest[:i]] = true
					name = rest[:i]
				}
			}
		}
		if len(remotes) != 1 {
			name = "origin"
		}
	}

	remoteURL := ""
	for _, e := range cfg {
		if e.key == "remote."+name+".url" {
			remoteURL = e.value
			break
		}
	}
	if remoteURL == "" {
		return "", errNoGitRemote
	}

	// Apply the longest matching url.<base>.insteadOf rewrite.
	var prefix, base string
	for _, e := range cfg {
		if rest, ok := strings.CutPrefix(e.key, "url."); ok {
			if b, ok := strings.CutSuffix(rest, ".insteadof"); ok && strings.HasPrefix(remoteURL, e.value) && len(e.value) > len(prefix) {
				prefix, base = e.value, b
			}
		}
	}
	if prefix != "" {
		remoteURL = base + remoteURL[len(prefix):]
	}
	return remoteURL, nil
}

type gitLayout struct {
	source    string // absolute directory to scan
	gitDir    string
	commonDir string
	workTree  string // empty for bare repositories
}

// setWorkTree resolves the small, non-executable subset of configuration that
// determines the working-tree root. Keep it out of the generated config: the
// private command receives an explicit, resolved --work-tree instead.
func (l *gitLayout) setWorkTree(cfg gitConfig, worktreeConfig bool) error {
	if dir := os.Getenv("GIT_WORK_TREE"); dir != "" {
		l.workTree = gitPath(l.source, dir)
	} else if worktreeConfig || samePath(l.gitDir, l.commonDir) {
		// Without worktreeConfig, common core.bare/core.worktree settings
		// apply only to the main worktree, matching Git's linked-worktree rules.
		bare := false
		if value, ok := cfg.last("core.bare"); ok {
			var err error
			bare, err = parseGitBool(value)
			if err != nil {
				return fmt.Errorf("core.bare: %w", err)
			}
		}
		dir, configured := cfg.last("core.worktree")
		if bare && configured {
			return errors.New("core.bare=true cannot be combined with core.worktree")
		}
		if bare {
			l.workTree = ""
		} else if configured {
			l.workTree = gitPath(l.gitDir, dir)
		}
	}
	if l.workTree != "" {
		path, err := filepath.EvalSymlinks(l.workTree)
		if err != nil {
			return fmt.Errorf("resolve Git working tree: %w", err)
		}
		if info, err := os.Stat(path); err != nil || !info.IsDir() {
			return fmt.Errorf("not a working-tree directory: %s", path)
		}
		l.workTree = path
	}
	return nil
}

// findGitLayout locates the repository containing source as Git does, reading
// .git files and commondir as data rather than running Git there.
func findGitLayout(source string) (gitLayout, error) {
	abs, err := filepath.Abs(source)
	if err != nil {
		return gitLayout{}, err
	}
	if info, err := os.Stat(abs); err != nil || !info.IsDir() {
		return gitLayout{}, fmt.Errorf("not a directory: %s", source)
	}
	// git -C changes into the physical directory before discovering parents.
	// Walking the lexical parents of a symlink can select a different repo.
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return gitLayout{}, err
	}
	l := gitLayout{source: abs}
	if dir := os.Getenv("GIT_DIR"); dir != "" {
		if l.gitDir, err = resolveGitDir(gitPath(abs, dir)); err != nil {
			return gitLayout{}, err
		}
		l.workTree = abs
	} else {
		for dir := abs; l.gitDir == ""; {
			dot := filepath.Join(dir, ".git")
			if info, err := os.Stat(dot); err == nil && (!info.IsDir() || isGitDir(dot)) {
				if l.gitDir, err = resolveGitDir(dot); err != nil {
					return gitLayout{}, err
				}
				l.workTree = dir
			} else if isGitDir(dir) {
				l.gitDir = dir
			} else if parent := filepath.Dir(dir); parent != dir {
				dir = parent
			} else {
				return gitLayout{}, fmt.Errorf("not a git repository: %s", source)
			}
		}
	}
	if dir := os.Getenv("GIT_WORK_TREE"); dir != "" {
		l.workTree = gitPath(abs, dir)
	}

	l.commonDir = l.gitDir
	if data, err := readGitFile(filepath.Join(l.gitDir, "commondir")); err == nil {
		l.commonDir = gitPath(l.gitDir, strings.TrimSpace(string(data)))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return gitLayout{}, err
	}
	return l, nil
}

// resolveGitDir follows a "gitdir:" file, as used by linked worktrees and
// submodules, to the Git directory it names.
func resolveGitDir(path string) (string, error) {
	if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
		data, err := readGitFile(path)
		if err != nil {
			return "", err
		}
		target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
		if !ok {
			return "", fmt.Errorf("invalid gitfile format: %s", path)
		}
		path = gitPath(filepath.Dir(path), target)
	}
	if !isGitDir(path) {
		return "", fmt.Errorf("not a git repository: %s", path)
	}
	return filepath.EvalSymlinks(path)
}

func isGitDir(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "commondir")); err == nil {
		return true
	}
	info, err := os.Stat(filepath.Join(dir, "objects"))
	return err == nil && info.IsDir()
}

// gitPath resolves a path Git would interpret relative to base.
func gitPath(base, path string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}
	return filepath.Clean(path)
}

func samePath(a, b string) bool {
	if a == b {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

// readGitFile reads a small metadata file such as HEAD or a gitfile.
func readGitFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fmt.Errorf("invalid Git metadata file: %s", path)
	}
	return os.ReadFile(path)
}

// Files and directories holding a repository's HEAD, refs, and reflogs. Both
// the common directory and each worktree's directory can contain them.
var (
	gitRefFiles = []string{"HEAD", "packed-refs", "shallow", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_HEAD", "REBASE_HEAD", "AUTO_MERGE"}
	gitRefDirs  = []string{"refs", "logs", "reftable"}
)

func copyGitRefs(ctx context.Context, src, dst string) error {
	for _, name := range gitRefFiles {
		if err := copyGitFile(ctx, filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			return err
		}
	}
	for _, name := range gitRefDirs {
		if err := copyGitTree(ctx, filepath.Join(src, name), filepath.Join(dst, name)); err != nil {
			return err
		}
	}
	return nil
}

func copyGitTree(ctx context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			if path == src && errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		if strings.HasSuffix(entry.Name(), ".lock") {
			return nil // an update in progress
		}
		return copyGitFile(ctx, path, filepath.Join(dst, rel))
	})
}

var gitCopyBuffers = sync.Pool{New: func() any {
	buffer := make([]byte, 32*1024)
	return &buffer
}}

// copyGitFile copies a regular file. A missing file is skipped; anything else,
// including a symbolic link, is an error.
func copyGitFile(ctx context.Context, src, dst string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(src)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file: %s", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	buffer := gitCopyBuffers.Get().(*[]byte)
	defer gitCopyBuffers.Put(buffer)
	// Hide File.ReadFrom so CopyBuffer reuses the buffer across small refs.
	_, err = io.CopyBuffer(struct{ io.Writer }{out}, gitContextReader{ctx, in}, *buffer)
	return errors.Join(err, out.Close())
}

// gitContextReader bounds cancellation latency while copying large indexes or reflogs.
type gitContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r gitContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// quoteGitPath C-quotes a path for objects/info/alternates when Git would
// otherwise misread it.
func quoteGitPath(path string) string {
	needsQuote := strings.HasPrefix(path, "#") || strings.HasPrefix(path, `"`)
	for i := 0; i < len(path) && !needsQuote; i++ {
		needsQuote = path[i] < 0x20 || path[i] == 0x7f
	}
	if !needsQuote {
		return path
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(path); i++ {
		switch c := path[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, "\\%03o", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// splitGitPathList splits a path list such as GIT_ALTERNATE_OBJECT_DIRECTORIES.
// Like Git, it accepts C-quoted entries, which may contain the separator.
func splitGitPathList(list string) ([]string, error) {
	var paths []string
	for list != "" {
		var path string
		if list[0] == '"' {
			end := 1
			for ; end < len(list) && list[end] != '"'; end++ {
				if list[end] == '\\' {
					end++
				}
			}
			if end >= len(list) {
				return nil, fmt.Errorf("unterminated quote in path list %q", list)
			}
			var err error
			if path, err = strconv.Unquote(list[:end+1]); err != nil {
				return nil, fmt.Errorf("invalid quoted path %s: %w", list[:end+1], err)
			}
			list = list[end+1:]
			if list != "" && list[0] != os.PathListSeparator {
				return nil, fmt.Errorf("invalid path list after %s", path)
			}
			list = strings.TrimPrefix(list, string(os.PathListSeparator))
		} else {
			path, list, _ = strings.Cut(list, string(os.PathListSeparator))
		}
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths, nil
}
