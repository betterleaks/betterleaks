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
)

// TODO: remove this in v9 and have scanTargets yield file sources
type ScanTarget struct {
	Path    string
	Symlink string
}

// Files is a source for yielding fragments from a collection of files
type Files struct {
	// Logger receives source diagnostics. A nil logger disables logging.
	Logger          *slog.Logger
	ShouldSkip      SkipFunc
	FollowSymlinks  bool
	MaxFileSize     int
	Path            string
	MaxArchiveDepth int
	Jobs            int // 0 is automatic
	budget          *jobBudget
}

// scanTargets yields scan targets to a callback func
func (s *Files) scanTargets(ctx context.Context, yield func(ScanTarget, error) error) error {
	// fastwalk only accepts directory roots. Lstat also preserves the existing
	// symlink handling when the requested root is a single file or symlink.
	rootInfo, err := os.Lstat(s.Path)
	if err != nil {
		logger := loggerOrDiscard(s.Logger).With("path", s.Path)
		if os.IsPermission(err) {
			logger.Warn("skipping directory", "error", errors.New("permission denied"))
		} else {
			logger.Warn("skipping", "error", err)
		}
		return nil
	}

	// fastwalk visits paths concurrently, but scanTargets has always exposed a
	// serial callback. Keep that contract without serializing file inspection.
	var yieldMu sync.Mutex
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		scanTarget := ScanTarget{Path: path}
		logger := loggerOrDiscard(s.Logger).With("path", path)

		if err != nil {
			if os.IsPermission(err) {
				// This seems to only fail on directories at this stage.
				logger.Warn("skipping directory", "error", errors.New("permission denied"))
				return filepath.SkipDir
			}
			logger.Warn("skipping", "error", err)
			return nil
		}

		info, err := d.Info()
		if err != nil {
			if d.IsDir() {
				logger.Error("skipping directory: could not get info", "error", err)
				return filepath.SkipDir
			}
			logger.Error("skipping file: could not get info", "error", err)
			return nil
		}

		if !d.IsDir() {
			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug("skipping empty file")
				return nil
			}

			// Too large; nothing to do here.
			if s.MaxFileSize > 0 && info.Size() > int64(s.MaxFileSize) {
				logger.Warn("skipping file: too large",
					"max_size_mb", s.MaxFileSize/1_000_000,
					"size_mb", info.Size()/1_000_000,
				)
				return nil
			}
		}

		// set the initial scan target values
		if d.Type() == fs.ModeSymlink {
			if !s.FollowSymlinks {
				logger.Debug("skipping symlink: follow symlinks disabled")
				return nil
			}
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				logger.Error("skipping symlink: could not evaluate", "error", err)
				return nil
			}
			if realPathFileInfo, _ := os.Stat(realPath); realPathFileInfo.IsDir() {
				logger.Debug("skipping symlink: target is directory", "target", realPath)
				return nil
			}
			scanTarget = ScanTarget{
				Path:    realPath,
				Symlink: path,
			}
		}

		// handle dir cases (mainly just see if it should be skipped
		if info.IsDir() {
			if shouldSkipPath(s.ShouldSkip, path) {
				logger.Debug("skipping directory: global prefilter")
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipPath(s.ShouldSkip, path) {
			logger.Debug("skipping file: global prefilter")
			return nil
		}

		yieldMu.Lock()
		defer yieldMu.Unlock()
		return yield(scanTarget, nil)
	}

	if !rootInfo.IsDir() {
		return walkFn(s.Path, fs.FileInfoToDirEntry(rootInfo), nil)
	}

	// filepath.WalkDir preserves the root path exactly as supplied, then uses
	// filepath.Join for descendants. fastwalk joins paths by concatenating the
	// directory, separator, and entry name, which leaves lexical elements such
	// as "./" in descendant paths. Preserve the filepath.WalkDir behavior that
	// callers and report output relied on before switching walkers.
	compatibleWalkFn := func(path string, d fs.DirEntry, err error) error {
		if fastwalk.DirEntryDepth(d) == 0 {
			path = s.Path
		} else {
			path = filepath.Clean(path)
		}
		return walkFn(path, d, err)
	}
	return fastwalk.Walk(nil, s.Path, compatibleWalkFn)
}

// Fragments yields fragments from files discovered under the path
func (s *Files) Fragments(ctx context.Context, yield FragmentsFunc) error {
	g, groupCtx := errgroup.WithContext(ctx)
	jobs := jobsWithinBudget(s.Jobs, automaticFileJobs(), s.budget)
	g.SetLimit(jobs)

	producerErr := s.scanTargets(groupCtx, func(scanTarget ScanTarget, scanErr error) error {
		if scanErr != nil {
			return scanErr
		}
		if err := groupCtx.Err(); err != nil {
			return err
		}

		g.Go(func() error {
			if s.budget == nil {
				return s.scanFile(groupCtx, scanTarget, yield)
			}
			return s.budget.run(groupCtx, func() error {
				return s.scanFile(groupCtx, scanTarget, yield)
			})
		})
		return nil
	})

	return errors.Join(producerErr, g.Wait())
}

func (s *Files) scanFile(ctx context.Context, target ScanTarget, yield FragmentsFunc) error {
	logger := loggerOrDiscard(s.Logger).With("path", target.Path)
	logTrace(ctx, logger, "scanning path")

	f, err := os.Open(target.Path)
	if err != nil {
		if os.IsPermission(err) {
			logger.Warn("skipping file: permission denied")
		}
		return nil
	}

	file := File{
		Logger:          s.Logger,
		Content:         f,
		Path:            target.Path,
		Symlink:         target.Symlink,
		ShouldSkip:      s.ShouldSkip,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}

	err = file.Fragments(ctx, yield)
	// Avoid a defer in this hot path.
	_ = f.Close()
	return err
}
