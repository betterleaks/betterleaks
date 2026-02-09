package files

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/file"
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
	Config          *config.Config
	FollowSymlinks  bool
	MaxFileSize     int
	Path            string
	Sema            *semgroup.Group
	MaxArchiveDepth int
}

// scanTargets yields scan targets to a callback func
func (s *Files) scanTargets(ctx context.Context, yield func(ScanTarget, error) error) error {
	// Configure fastwalk for parallel directory traversal
	// Note: We handle symlinks manually so we don't use fastwalk's Follow option
	conf := &fastwalk.Config{
		Follow: false, // We handle symlinks ourselves for more control
	}

	err := fastwalk.Walk(conf, s.Path, func(path string, d fs.DirEntry, err error) error {
		scanTarget := ScanTarget{Path: path}
		logger := logging.With().Str("path", path).Logger()

		if err != nil {
			if os.IsPermission(err) {
				// This seems to only fail on directories at this stage.
				logger.Warn().Err(errors.New("permission denied")).Msg("skipping directory")
				return fastwalk.SkipDir
			}
			logger.Warn().Err(err).Msg("skipping")
			return nil
		}

		// Handle directories first using d.IsDir() which doesn't require stat
		if d.IsDir() {
			if sources.ShouldSkipPath(s.Config, "file", path) {
				logger.Debug().Msg("skipping directory: global allowlist")
				return fastwalk.SkipDir
			}
			return nil
		}

		// Handle symlinks using d.Type() which is cached and doesn't require stat
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

		// Check allowlist before expensive stat call
		if sources.ShouldSkipPath(s.Config, "file", path) {
			logger.Debug().Msg("skipping file: global allowlist")
			return nil
		}

		// Only call d.Info() (which triggers stat) when we need file size,
		// and only if MaxFileSize is configured
		if s.MaxFileSize > 0 {
			info, err := d.Info()
			if err != nil {
				logger.Error().Err(err).Msg("skipping file: could not get info")
				return nil
			}

			// Empty; nothing to do here.
			if info.Size() == 0 {
				logger.Debug().Msg("skipping empty file")
				return nil
			}

			// Too large; nothing to do here.
			if info.Size() > int64(s.MaxFileSize) {
				logger.Warn().Msgf(
					"skipping file: too large max_size=%dMB, size=%dMB",
					s.MaxFileSize/1_000_000, info.Size()/1_000_000,
				)
				return nil
			}
		}

		return yield(scanTarget, nil)
	})

	// Handle the case where the root path doesn't exist - fastwalk returns this
	// as an error, but we want to just log it and continue (like filepath.WalkDir
	// does via the callback). This maintains backwards compatibility.
	if err != nil && os.IsNotExist(err) {
		logging.Warn().Err(err).Str("path", s.Path).Msg("skipping")
		return nil
	}

	return err
}

// Fragments yields fragments from files discovered under the path
func (s *Files) Fragments(ctx context.Context, yield betterleaks.FragmentsFunc) error {
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
				fileSource := file.File{
					Content:         f,
					Path:            scanTarget.Path,
					Symlink:         scanTarget.Symlink,
					Config:          s.Config,
					MaxArchiveDepth: s.MaxArchiveDepth,
					Source:          "file",
				}

				err = fileSource.Fragments(ctx, yield)
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
