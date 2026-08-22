package sources

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/charlievieth/fastwalk"
)

const defaultFileWorkers = 20

type scanTarget struct {
	Path    string
	Symlink string
}

// Files is a source for yielding fragments from a collection of files
type Files struct {
	ShouldSkip     SkipFunc
	ShouldSkipPath PathSkipFunc
	FollowSymlinks bool
	MaxFileSize    int
	Path           string
	// Workers controls the fixed file worker pool. Zero uses 20 workers.
	Workers         int
	MaxArchiveDepth int
}

// scanTargets yields scan targets to a callback func
func (s *Files) scanTargets(ctx context.Context, yield func(scanTarget, error) error) error {
	// fastwalk only accepts directory roots. Lstat also preserves the existing
	// symlink handling when the requested root is a single file or symlink.
	rootInfo, err := os.Lstat(s.Path)
	if err != nil {
		if os.IsPermission(err) {
			logging.Warn().Err(errors.New("permission denied")).Str("path", s.Path).Msg("skipping directory")
		} else {
			logging.Warn().Err(err).Str("path", s.Path).Msg("skipping")
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
		target := scanTarget{Path: path}

		if err != nil {
			if os.IsPermission(err) {
				// This seems to only fail on directories at this stage.
				logging.Warn().Err(errors.New("permission denied")).Str("path", path).Msg("skipping directory")
				return filepath.SkipDir
			}
			logging.Warn().Err(err).Str("path", path).Msg("skipping")
			return nil
		}

		// DirEntry already carries the directory type. Avoid an lstat for every
		// directory; file metadata is only needed for size checks below.
		if d.IsDir() {
			if shouldSkipFilePath(s.ShouldSkipPath, s.ShouldSkip, path) {
				logging.Debug().Str("path", path).Msg("skipping directory: global allowlist")
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			logging.Error().Err(err).Str("path", path).Msg("skipping file: could not get info")
			return nil
		}
		effectiveInfo := info
		// set the initial scan target values
		if d.Type()&fs.ModeSymlink != 0 {
			if !s.FollowSymlinks {
				logging.Debug().Str("path", path).Msg("skipping symlink: follow symlinks disabled")
				return nil
			}
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				logging.Error().Err(err).Str("path", path).Msg("skipping symlink: could not evaluate")
				return nil
			}
			realPathFileInfo, err := os.Stat(realPath)
			if err != nil {
				logging.Error().Err(err).Str("path", path).Str("target", realPath).Msg("skipping symlink: could not get target info")
				return nil
			}
			effectiveInfo = realPathFileInfo
			target = scanTarget{
				Path:    realPath,
				Symlink: path,
			}
		}

		// Use the resolved target metadata for symlinks. Lstat reports the length
		// of the link text, not the target file size, so applying limits before
		// resolution can reject a small file solely because its path is long.
		if !effectiveInfo.Mode().IsRegular() {
			logging.Debug().Str("path", path).Msg("skipping non-regular file")
			return nil
		}
		if effectiveInfo.Size() == 0 {
			logging.Debug().Str("path", path).Msg("skipping empty file")
			return nil
		}
		if s.MaxFileSize > 0 && effectiveInfo.Size() > int64(s.MaxFileSize) {
			logging.Warn().Str("path", path).Msgf(
				"skipping file: too large max_size=%dMB, size=%dMB",
				s.MaxFileSize/1_000_000, effectiveInfo.Size()/1_000_000,
			)
			return nil
		}

		if shouldSkipFilePath(s.ShouldSkipPath, s.ShouldSkip, path) {
			logging.Debug().Str("path", path).Msg("skipping file: global allowlist")
			return nil
		}

		yieldMu.Lock()
		defer yieldMu.Unlock()
		return yield(target, nil)
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
	if s == nil {
		return errors.New("sources: files source is required")
	}
	if yield == nil {
		return errors.New("sources: files fragment callback is required")
	}
	workers := s.Workers
	if workers <= 0 {
		workers = defaultFileWorkers
	}
	return s.fragmentsWithWorkers(ctx, yield, workers)
}

func (s *Files) fragmentsWithWorkers(ctx context.Context, yield FragmentsFunc, workerCount int) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan scanTarget, workerCount)
	var workers sync.WaitGroup
	workers.Add(workerCount)

	var scanErr error
	var scanErrMu sync.Mutex
	recordError := func(err error) {
		if err == nil {
			return
		}
		scanErrMu.Lock()
		scanErr = errors.Join(scanErr, err)
		scanErrMu.Unlock()
		cancel()
	}

	for range workerCount {
		go func() {
			defer workers.Done()
			for target := range jobs {
				if runCtx.Err() != nil {
					continue
				}
				recordError(s.scanFile(runCtx, target, yield))
			}
		}()
	}

	walkErr := s.scanTargets(runCtx, func(target scanTarget, err error) error {
		if err != nil {
			recordError(err)
			return nil
		}
		select {
		case jobs <- target:
			return nil
		case <-runCtx.Done():
			return runCtx.Err()
		}
	})
	close(jobs)
	workers.Wait()
	if scanErr != nil {
		if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
			return errors.Join(scanErr, walkErr)
		}
		return scanErr
	}
	return walkErr
}

func (s *Files) scanFile(ctx context.Context, target scanTarget, yield FragmentsFunc) error {
	logging.Trace().Str("path", target.Path).Msg("scanning path")
	f, err := os.Open(target.Path)
	if err != nil {
		if os.IsPermission(err) {
			logging.Warn().Str("path", target.Path).Msg("skipping file: permission denied")
		} else {
			logging.Warn().Err(err).Str("path", target.Path).Msg("skipping file: could not open")
		}
		return nil
	}

	file := File{
		Content:         f,
		Path:            target.Path,
		Symlink:         target.Symlink,
		ShouldSkip:      s.ShouldSkip,
		MaxArchiveDepth: s.MaxArchiveDepth,
	}
	err = file.Fragments(ctx, yield)
	closeErr := f.Close()
	return errors.Join(err, closeErr)
}
