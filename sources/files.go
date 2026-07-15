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
	"github.com/fatih/semgroup"
)

// TODO: remove this in v9 and have scanTargets yield file sources
type ScanTarget struct {
	Path    string
	Symlink string
}

// Files is a source for yielding fragments from a collection of files
type Files struct {
	ShouldSkip      SkipFunc
	FollowSymlinks  bool
	MaxFileSize     int
	Path            string
	Sema            *semgroup.Group
	MaxArchiveDepth int
}

// scanTargets yields scan targets to a callback func
func (s *Files) scanTargets(ctx context.Context, yield func(ScanTarget, error) error) error {
	// fastwalk only accepts directory roots. Lstat also preserves the existing
	// symlink handling when the requested root is a single file or symlink.
	rootInfo, err := os.Lstat(s.Path)
	if err != nil {
		logger := logging.With().Str("path", s.Path).Logger()
		if os.IsPermission(err) {
			logger.Warn().Err(errors.New("permission denied")).Msg("skipping directory")
		} else {
			logger.Warn().Err(err).Msg("skipping")
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
		logger := logging.With().Str("path", path).Logger()

		if err != nil {
			if os.IsPermission(err) {
				// This seems to only fail on directories at this stage.
				logger.Warn().Err(errors.New("permission denied")).Msg("skipping directory")
				return filepath.SkipDir
			}
			logger.Warn().Err(err).Msg("skipping")
			return nil
		}

		info, err := d.Info()
		if err != nil {
			if d.IsDir() {
				logger.Error().Err(err).Msg("skipping directory: could not get info")
				return filepath.SkipDir
			}
			logger.Error().Err(err).Msg("skipping file: could not get info")
			return nil
		}

		if !d.IsDir() {
			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping empty file")
				return nil
			}

			// Too large; nothing to do here.
			if s.MaxFileSize > 0 && info.Size() > int64(s.MaxFileSize) {
				logger.Warn().Msgf(
					"skipping file: too large max_size=%dMB, size=%dMB",
					s.MaxFileSize/1_000_000, info.Size()/1_000_000,
				)
				return nil
			}
		}

		// set the initial scan target values
		if d.Type() == fs.ModeSymlink {
			if !s.FollowSymlinks {
				logger.Debug().Msg("skipping symlink: follow symlinks disabled")
				return nil
			}
			realPath, err := filepath.EvalSymlinks(path)
			if err != nil {
				logger.Error().Err(err).Msg("skipping symlink: could not evaluate")
				return nil
			}
			if realPathFileInfo, _ := os.Stat(realPath); realPathFileInfo.IsDir() {
				logger.Debug().Str("target", realPath).Msgf("skipping symlink: target is directory")
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
				logger.Debug().Msg("skipping directory: global allowlist")
				return filepath.SkipDir
			}
			return nil
		}

		if shouldSkipPath(s.ShouldSkip, path) {
			logger.Debug().Msg("skipping file: global allowlist")
			return nil
		}

		yieldMu.Lock()
		defer yieldMu.Unlock()
		return yield(scanTarget, nil)
	}

	if !rootInfo.IsDir() {
		return walkFn(s.Path, fs.FileInfoToDirEntry(rootInfo), nil)
	}
	return fastwalk.Walk(nil, s.Path, walkFn)
}

// Fragments yields fragments from files discovered under the path
func (s *Files) Fragments(ctx context.Context, yield FragmentsFunc) error {
	var wg sync.WaitGroup

	err := s.scanTargets(ctx, func(scanTarget ScanTarget, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			wg.Add(1)
			s.Sema.Go(func() error {
				logger := logging.With().Str("path", scanTarget.Path).Logger()
				logger.Trace().Msg("scanning path")

				f, err := os.Open(scanTarget.Path)
				if err != nil {
					if os.IsPermission(err) {
						logger.Warn().Msg("skipping file: permission denied")
					}
					wg.Done()
					return nil
				}

				// Convert this to a file source
				file := File{
					Content:         f,
					Path:            scanTarget.Path,
					Symlink:         scanTarget.Symlink,
					ShouldSkip:      s.ShouldSkip,
					MaxArchiveDepth: s.MaxArchiveDepth,
				}

				err = file.Fragments(ctx, yield)
				// Avoiding a defer in a hot loop
				_ = f.Close()
				wg.Done()
				return err
			})

			return nil
		}
	})

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		wg.Wait()
		return err
	}
}
