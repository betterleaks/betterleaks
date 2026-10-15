package gogit

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v6"
	"github.com/go-git/go-billy/v6/osfs"
	git "github.com/go-git/go-git/v6"
	"github.com/go-git/go-git/v6/plumbing"
	"github.com/go-git/go-git/v6/plumbing/cache"
	"github.com/go-git/go-git/v6/storage/filesystem"
	"github.com/go-git/go-git/v6/storage/filesystem/dotgit"
)

//nolint:exhaustruct // Unspecified storage options and cache bookkeeping use their zero values.
func (s *Source) open(ctx context.Context) (*git.Repository, func(), error) {
	l, err := discover(s.RepoPath)
	if err != nil {
		return nil, nil, err
	}
	var root string
	if !s.AllowExternalObjects {
		root, err = l.storeRoot()
		if err != nil {
			return nil, nil, err
		}
	}
	alternates, err := l.alternates()
	if err != nil {
		return nil, nil, err
	}
	if !s.AllowExternalObjects {
		for _, path := range alternates {
			if inside, err := within(root, path); err != nil || !inside {
				return nil, nil, errors.Join(err, fmt.Errorf("%w: %s", ErrExternalStore, path))
			}
		}
	}
	dot := osfs.New(l.gitDir, osfs.WithBoundOS())
	var common billy.Filesystem
	if l.common != l.gitDir {
		common = osfs.New(l.common, osfs.WithBoundOS())
	}
	fs := readOnlyFS{Filesystem: dotgit.NewRepositoryFilesystem(dot, common), objectRoot: l.common}
	shallow, err := readShallow(fs)
	if err != nil {
		return nil, nil, err
	}
	budget := s.CacheMiB
	if budget == 0 {
		budget = 256
	}
	// Billy confines absolute paths to its root, and alternates can lie outside
	// the Git directory, so alternate reads get a filesystem root. Confinement
	// above has already checked each alternate path.
	volumeRoot := filepath.VolumeName(l.common) + string(filepath.Separator)
	altFS := readOnlyFS{Filesystem: osfs.New(volumeRoot), objectRoot: volumeRoot}
	objects := &objectCache{cache.NewObjectLRU(cache.FileSize(budget) << 20)}
	store := filesystem.NewStorageWithOptions(fs, objects, filesystem.Options{LargeObjectThreshold: 1 << 20, AlternatesFS: altFS})
	reader := &objectStorage{Storage: store, objects: objects, ctx: ctx, limit: max(s.MaxBlobBytes, defaultMaxBlobBytes), shallow: shallow}
	if s.DiskCacheMiB > 0 {
		reader.disk = &diskObjectCache{segmentSize: int64(s.DiskCacheMiB) << 20 / 8}
	}
	if err := reader.openPacks(fs); err != nil {
		reader.closePacks()
		store.Close()
		return nil, nil, err
	}
	r, err := git.Open(reader, nil)
	if err != nil {
		reader.closePacks()
		store.Close()
		return nil, nil, err
	}
	return r, func() { reader.closePacks(); store.Close() }, nil
}

// readShallow lists the boundary commits of a shallow clone. Like Git, the
// source treats them as root commits: their parents were never fetched.
func readShallow(fs billy.Filesystem) (map[plumbing.Hash]struct{}, error) {
	data, err := readLimited(fs, "shallow", maxShallowBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ids := make(map[plumbing.Hash]struct{})
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !plumbing.IsHash(line) {
			return nil, errors.New("malformed Git shallow file")
		}
		ids[plumbing.NewHash(line)] = struct{}{}
	}
	return ids, nil
}

// readLimited reads a small metadata file such as .git, commondir, alternates,
// or shallow, refusing one larger than limit.
func readLimited(fs billy.Filesystem, path string, limit int64) (string, error) {
	f, err := fs.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return string(data), nil
}

// Read-only mappings remove random pack/index read syscalls. Resident mapped
// pages count toward RSS separately from the bounded object caches; the OS can
// reclaim clean pages. This wrapper preserves upstream's commondir/alternate
// routing and forbids repository mutations.
type readOnlyFS struct {
	billy.Filesystem
	objectRoot string
}

func (f readOnlyFS) Open(path string) (billy.File, error) {
	fs := f.Filesystem
	if strings.HasPrefix(filepath.ToSlash(path), "objects/pack/") && (strings.HasSuffix(path, ".idx") || strings.HasSuffix(path, ".rev") || strings.HasSuffix(path, ".pack")) {
		fs = osfs.New(f.objectRoot, osfs.WithMmap())
	}
	// osfs opens through os.Root, so symlinks cannot leave the repository. A FIFO
	// or device would block or never end; open without waiting and reject it.
	file, err := fs.OpenFile(path, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return nil, err
	}
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.Join(err, fmt.Errorf("git storage %q is not a regular file", path))
	}
	return file, nil
}

// Git ignores dotfiles in ref directories (for example fixture .gitkeep files).
func (f readOnlyFS) ReadDir(path string) ([]os.DirEntry, error) {
	// Listing opens the path, which would block on a FIFO.
	if info, err := f.Filesystem.Stat(path); err == nil && !info.IsDir() {
		return nil, fmt.Errorf("git storage %q is not a directory", path)
	}
	entries, err := f.Filesystem.ReadDir(path)
	if err != nil {
		return nil, err
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	// Object enumeration must not silently skip a linked fanout directory or
	// follow a loose object symlink/FIFO while looking for abandoned content.
	if clean == "objects" {
		for _, entry := range entries {
			if len(entry.Name()) == 2 {
				if _, err := hex.DecodeString(entry.Name()); err == nil && !entry.IsDir() {
					return nil, fmt.Errorf("loose object directory %q is not a directory", entry.Name())
				}
			}
		}
	} else if strings.HasPrefix(clean, "objects/") && len(clean) == len("objects/00") {
		prefix := strings.TrimPrefix(clean, "objects/")
		for _, entry := range entries {
			if plumbing.IsHash(prefix+entry.Name()) && !entry.Type().IsRegular() {
				return nil, fmt.Errorf("loose object %s is not a regular file", prefix+entry.Name())
			}
		}
	}
	if clean == "refs" || strings.HasPrefix(clean, "refs/") {
		visible := entries[:0]
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".") {
				visible = append(visible, entry)
			}
		}
		return visible, nil
	}
	return entries, nil
}

func (f readOnlyFS) OpenFile(path string, flag int, perm os.FileMode) (billy.File, error) {
	if flag != os.O_RDONLY {
		return nil, os.ErrPermission
	}
	return f.Open(path)
}
func (readOnlyFS) Create(string) (billy.File, error)           { return nil, os.ErrPermission }
func (readOnlyFS) TempFile(string, string) (billy.File, error) { return nil, os.ErrPermission }
func (readOnlyFS) Rename(string, string) error                 { return os.ErrPermission }
func (readOnlyFS) Remove(string) error                         { return os.ErrPermission }
func (readOnlyFS) MkdirAll(string, os.FileMode) error          { return os.ErrPermission }
func (readOnlyFS) Symlink(string, string) error                { return os.ErrPermission }
func (f readOnlyFS) Chroot(path string) (billy.Filesystem, error) {
	fs, err := f.Filesystem.Chroot(path)
	if err != nil {
		return nil, err
	}
	return readOnlyFS{Filesystem: fs, objectRoot: fs.Root()}, nil
}
