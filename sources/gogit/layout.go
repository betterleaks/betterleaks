package gogit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/betterleaks/betterleaks/v2/internal/gitfs"
	git "github.com/go-git/go-git/v5"
)

// ErrExternalStore reports Git storage outside the scanned repository. A
// repository can name other directories through a .git file, commondir, or
// objects/info/alternates, and Git itself names them through
// GIT_OBJECT_DIRECTORY and GIT_ALTERNATE_OBJECT_DIRECTORIES. Following them
// would scan content the caller did not select, so the source refuses unless
// AllowExternalObjects is set.
var ErrExternalStore = errors.New("git storage is outside the scanned repository")

// layout locates a repository's Git directories.
type layout struct {
	root   string // Work tree, or the Git directory of a bare repository.
	gitDir string // Per-worktree state such as HEAD and logs/HEAD.
	common string // Objects, refs, config, and branch reflogs.
}

// discover finds the repository containing path the way Git does: from path
// upward, each directory is checked for a .git entry and then for being a Git
// directory itself.
func discover(path string) (layout, error) {
	dir, err := filepath.Abs(path)
	if err != nil {
		return layout{}, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return layout{}, err
	}
	if !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		dotGit := filepath.Join(dir, ".git")
		info, err := os.Stat(dotGit)
		switch {
		case err == nil && info.IsDir():
			return newLayout(dir, dotGit)
		case err == nil && info.Mode().IsRegular():
			gitDir, err := readGitFile(dotGit)
			if err != nil {
				return layout{}, err
			}
			return newLayout(dir, gitDir)
		case err == nil:
			return layout{}, fmt.Errorf("%s is not a file or directory", dotGit)
		case !errors.Is(err, os.ErrNotExist):
			return layout{}, err
		}
		if isGitDir(dir) {
			return newLayout(dir, dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return layout{}, fmt.Errorf("%w: %s", git.ErrRepositoryNotExists, path)
		}
		dir = parent
	}
}

func newLayout(root, gitDir string) (layout, error) {
	l := layout{root: root, gitDir: gitDir, common: gitDir}
	common, err := readSmallFile(filepath.Join(gitDir, "commondir"))
	if err == nil {
		l.common = resolveFrom(gitDir, strings.TrimSpace(common))
	} else if !errors.Is(err, os.ErrNotExist) {
		return layout{}, err
	}
	for _, dir := range []string{l.gitDir, l.common} {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			return layout{}, fmt.Errorf("%w: %s", git.ErrRepositoryNotExists, dir)
		}
	}
	return l, nil
}

// A Git directory has HEAD plus objects and refs, or a commondir that holds them.
func isGitDir(dir string) bool {
	if info, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil || !info.Mode().IsRegular() {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "commondir")); err == nil {
		return true
	}
	objects, objectsErr := os.Stat(filepath.Join(dir, "objects"))
	refs, refsErr := os.Stat(filepath.Join(dir, "refs"))
	return objectsErr == nil && refsErr == nil && objects.IsDir() && refs.IsDir()
}

func readGitFile(path string) (string, error) {
	data, err := readSmallFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(data, "\n")
	target, ok := strings.CutPrefix(strings.TrimSpace(line), "gitdir: ")
	if !ok {
		return "", fmt.Errorf("%s has no gitdir line", path)
	}
	return resolveFrom(filepath.Dir(path), strings.TrimSpace(target)), nil
}

// storeRoot returns the directory that must contain all Git storage. A linked
// worktree's Git directory lives in its main repository; it is accepted when
// that repository registered this worktree, which an unrelated directory
// cannot forge.
func (l layout) storeRoot() (string, error) {
	root, err := filepath.EvalSymlinks(l.root)
	if err != nil {
		return "", err
	}
	inside, err := within(root, l.gitDir)
	if err != nil {
		return "", err
	}
	if !inside {
		main, ok := l.registeredWorktree()
		if !ok {
			return "", fmt.Errorf("%w: %s", ErrExternalStore, l.gitDir)
		}
		root = main
	}
	if inside, err := within(root, l.common); err != nil || !inside {
		return "", errors.Join(err, fmt.Errorf("%w: %s", ErrExternalStore, l.common))
	}
	return root, nil
}

// git worktree add creates <main>/worktrees/<name> and records the worktree's
// .git file in its gitdir file.
func (l layout) registeredWorktree() (string, bool) {
	worktrees := filepath.Dir(l.gitDir)
	if filepath.Base(worktrees) != "worktrees" || !samePath(l.common, filepath.Dir(worktrees)) {
		return "", false
	}
	back, err := readSmallFile(filepath.Join(l.gitDir, "gitdir"))
	if err != nil || !samePath(resolveFrom(l.gitDir, strings.TrimSpace(back)), filepath.Join(l.root, ".git")) {
		return "", false
	}
	main := l.common
	if filepath.Base(main) == ".git" {
		main = filepath.Dir(main)
	}
	main, err = filepath.EvalSymlinks(main)
	return main, err == nil
}

// alternates lists the object directories Git would read, in Git's precedence
// order: the directories named by GIT_OBJECT_DIRECTORY and
// GIT_ALTERNATE_OBJECT_DIRECTORIES come before objects/info/alternates. A
// receive-pack quarantine names its objects this way, so a hook that inherits
// the environment can scan the pushed objects in-process.
func (l layout) alternates() ([]string, error) {
	fromFile, err := readAlternates(storageFS(l.common))
	if err != nil {
		return nil, err
	}
	fromEnv, err := objectDirsFromEnv()
	if err != nil {
		return nil, err
	}
	return append(fromEnv, fromFile...), nil
}

// objectDirsFromEnv returns the object directories named by the environment, as
// absolute paths. GIT_OBJECT_DIRECTORY names one directory; it is taken
// literally, as Git does. GIT_ALTERNATE_OBJECT_DIRECTORIES names a list
// separated by filepath.ListSeparator, where an entry beginning with '"' is a
// C-quoted path that may itself contain the separator; other entries are
// literal, including surrounding whitespace. Git resolves relative paths
// against the working directory, which the process shares, so each path is made
// absolute here for the confinement check.
func objectDirsFromEnv() ([]string, error) {
	var dirs []string
	add := func(path string) error {
		if path == "" {
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		dirs = append(dirs, abs)
		return nil
	}
	if err := add(os.Getenv("GIT_OBJECT_DIRECTORY")); err != nil {
		return nil, err
	}
	entries, err := splitAlternateList(os.Getenv("GIT_ALTERNATE_OBJECT_DIRECTORIES"))
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err := add(entry); err != nil {
			return nil, err
		}
	}
	return dirs, nil
}

// splitAlternateList parses GIT_ALTERNATE_OBJECT_DIRECTORIES with Git's grammar:
// entries are separated by filepath.ListSeparator; an entry beginning with '"'
// is C-quoted and may contain the separator inside the quotes; other entries
// are literal. Empty entries are dropped. Git does not trim unquoted entries.
func splitAlternateList(value string) ([]string, error) {
	sep := byte(filepath.ListSeparator)
	var entries []string
	for i := 0; i < len(value); {
		if value[i] == '"' {
			unquoted, next, err := unquoteCStyle(value, i)
			if err != nil {
				return nil, err
			}
			entries = append(entries, unquoted)
			i = next
			// A separator must follow a quoted entry; skip it.
			if i < len(value) && value[i] == sep {
				i++
			}
			continue
		}
		j := i
		for j < len(value) && value[j] != sep {
			j++
		}
		if entry := value[i:j]; entry != "" {
			entries = append(entries, entry)
		}
		i = j
		if i < len(value) {
			i++ // skip separator
		}
	}
	return entries, nil
}

// unquoteCStyle decodes a C-quoted path beginning at value[start] (which is a
// '"') the way Git's unquote_c_style does, returning the decoded path and the
// index just past the closing quote.
func unquoteCStyle(value string, start int) (string, int, error) {
	var b strings.Builder
	i := start + 1 // past opening quote
	for i < len(value) {
		c := value[i]
		i++
		switch c {
		case '"':
			return b.String(), i, nil
		case '\\':
			if i >= len(value) {
				return "", 0, errors.New("unterminated escape in GIT_ALTERNATE_OBJECT_DIRECTORIES")
			}
			e := value[i]
			i++
			switch e {
			case 'a':
				b.WriteByte('\a')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'v':
				b.WriteByte('\v')
			case '\\', '"':
				b.WriteByte(e)
			case '0', '1', '2', '3', '4', '5', '6', '7':
				// Up to three octal digits, Git-style.
				oct := e - '0'
				for k := 0; k < 2 && i < len(value) && value[i] >= '0' && value[i] <= '7'; k++ {
					oct = oct*8 + (value[i] - '0')
					i++
				}
				b.WriteByte(oct)
			default:
				return "", 0, fmt.Errorf("unsupported escape %q in GIT_ALTERNATE_OBJECT_DIRECTORIES", e)
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", 0, errors.New("unterminated quote in GIT_ALTERNATE_OBJECT_DIRECTORIES")
}

func readAlternates(fs readOnlyFS) ([]string, error) {
	data, err := readLimited(fs, "objects/info/alternates", maxAlternatesBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Preserve the source's existing absolute-alternate contract.
		if !filepath.IsAbs(line) {
			return nil, errors.New("relative object alternates are not supported")
		}
		paths = append(paths, filepath.Clean(line))
	}
	return paths, nil
}

// within reports whether path resolves inside root, which is already resolved.
func within(root, path string) (bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(root, resolved)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

func samePath(a, b string) bool {
	a, errA := filepath.EvalSymlinks(a)
	b, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && a == b
}

func resolveFrom(dir, path string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	return filepath.Clean(path)
}

// readSmallFile reads a regular pointer file such as .git or commondir.
func readSmallFile(path string) (string, error) {
	return readLimited(storageFS(filepath.Dir(path)), filepath.Base(path), maxPathFileBytes)
}

func storageFS(root string) readOnlyFS {
	return readOnlyFS{Filesystem: gitfs.New(root), objectRoot: root, pool: nil}
}
