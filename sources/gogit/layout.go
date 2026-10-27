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
// objects/info/alternates. Following them would scan content the caller did
// not select, so the source refuses unless AllowExternalObjects is set.
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

// alternates lists the object directories named by objects/info/alternates.
func (l layout) alternates() ([]string, error) {
	return readAlternates(storageFS(l.common))
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
