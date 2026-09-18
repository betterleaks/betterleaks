package sources

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/charlievieth/fastwalk"
	"golang.org/x/sync/errgroup"

	sourceworkers "github.com/betterleaks/betterleaks/v2/sources/internal/workers"

	"github.com/betterleaks/betterleaks/v2/logging"
)

type filePath struct {
	path    string
	symlink string
}

// walkCallbackError distinguishes callback failures from directory read failures
// when fastwalk reports either through a second walk callback.
type walkCallbackError struct{ err error }

func (e *walkCallbackError) Error() string { return e.err.Error() }
func (e *walkCallbackError) Unwrap() error { return e.err }

// Files is a source for yielding fragments from a collection of files
type Files struct {
	// Logger receives source diagnostics. A nil logger disables logging.
	Logger          *slog.Logger
	ShouldSkip      SkipFunc
	FollowSymlinks  bool // Follow file and directory links; visit each directory once.
	MaxFileSize     int
	Path            string
	MaxArchiveDepth int
	Workers         int // 0 is automatic
	budget          *sourceworkers.Budget
}

// walkFiles serializes callbacks while fastwalk inspects paths concurrently.
func (s *Files) walkFiles(ctx context.Context, yield func(filePath) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := os.Lstat(s.Path)
	if err != nil {
		return err
	}
	logger := logging.OrDiscard(s.Logger)
	var yieldMu sync.Mutex
	visit := func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			var callbackErr *walkCallbackError
			if errors.As(walkErr, &callbackErr) {
				return walkErr
			}
			logger.Warn("skipping directory", "path", path, "error", walkErr)
			return nil
		}
		if fastwalk.DirEntryDepth(entry) == 0 {
			path = s.Path
			// fastwalk stats its root; retain the caller's symlink identity.
			entry = fs.FileInfoToDirEntry(root)
		}
		name := filePath{path: path}
		mode := entry.Type()
		var info fs.FileInfo
		if mode&fs.ModeSymlink != 0 {
			if !s.FollowSymlinks {
				return nil
			}
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				logger.Warn("skipping symlink", "path", path, "error", err)
				return nil
			}
			info, err = os.Stat(realPath)
			if err != nil {
				logger.Warn("skipping symlink", "path", path, "error", err)
				return nil
			}
			mode = info.Mode()
			name = filePath{path: realPath, symlink: path}
		}

		if shouldSkipPath(s.ShouldSkip, path) || (name.symlink != "" && shouldSkipPath(s.ShouldSkip, name.path)) {
			if mode.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !mode.IsRegular() {
			return nil
		}

		// Directory entries supply the type. Only a size limit needs metadata;
		// otherwise even empty files go through the reader.
		if s.MaxFileSize > 0 {
			if info == nil {
				var err error
				info, err = entry.Info()
				if err != nil {
					logger.Warn("skipping file", "path", path, "error", err)
					return nil
				}
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				return nil
			}
			if info.Size() > int64(s.MaxFileSize) {
				logger.Warn("skipping file: too large", "path", path,
					"max_size_mb", s.MaxFileSize/1_000_000, "size_mb", info.Size()/1_000_000)
				return nil
			}
		}

		yieldMu.Lock()
		defer yieldMu.Unlock()
		if err := yield(name); err != nil {
			return &walkCallbackError{err: err}
		}
		return nil
	}

	rootIsDir := root.IsDir()
	if !rootIsDir && s.FollowSymlinks && root.Mode()&fs.ModeSymlink != 0 {
		if info, err := os.Stat(s.Path); err == nil {
			rootIsDir = info.IsDir()
		}
	}
	if !rootIsDir {
		return visit(s.Path, fs.FileInfoToDirEntry(root), nil)
	}
	// Clean once so descendant paths match filepath.Join. Preserve the root's
	// original spelling in visit. Native separators also preserve Windows paths.
	walkRoot := filepath.Clean(s.Path)
	walkConfig := fastwalk.Config{}
	if s.FollowSymlinks {
		deduplicated := fastwalk.IgnoreDuplicateDirs(visit)
		return fastwalk.Walk(&walkConfig, walkRoot, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				// A read-error callback revisits a directory. Deduplicating it
				// would turn a recoverable read failure into an escaping SkipDir.
				return visit(path, entry, err)
			}
			return deduplicated(path, entry, nil)
		})
	}
	return fastwalk.Walk(&walkConfig, walkRoot, visit)
}

// Fragments yields fragments from files discovered under the path
func (s *Files) Fragments(ctx context.Context, yield FragmentsFunc) error {
	g, groupCtx := errgroup.WithContext(ctx)
	workers := sourceworkers.WithinBudget(s.Workers, sourceworkers.AutomaticFiles(), s.budget)
	paths := make(chan filePath, workers)
	for range workers {
		g.Go(func() error {
			for name := range paths {
				if err := groupCtx.Err(); err != nil {
					return err
				}
				if err := s.budget.Run(groupCtx, func() error {
					return s.readFile(groupCtx, name, yield)
				}); err != nil {
					return err
				}
			}
			return nil
		})
	}
	producerErr := s.walkFiles(groupCtx, func(name filePath) error {
		select {
		case paths <- name:
			return nil
		case <-groupCtx.Done():
			return groupCtx.Err()
		}
	})
	close(paths)
	return errors.Join(producerErr, g.Wait())
}

func (s *Files) readFile(ctx context.Context, name filePath, yield FragmentsFunc) error {
	f, err := os.Open(name.path)
	if err != nil {
		if os.IsPermission(err) {
			logging.OrDiscard(s.Logger).Warn("skipping file: permission denied", "path", name.path)
		}
		return nil
	}

	defer f.Close()

	file := File{
		Logger:          s.Logger,
		Content:         f,
		Path:            name.path,
		Symlink:         name.symlink,
		ShouldSkip:      s.ShouldSkip,
		MaxArchiveDepth: s.MaxArchiveDepth,
		prefiltered:     true,
	}

	return file.Fragments(ctx, yield)
}
