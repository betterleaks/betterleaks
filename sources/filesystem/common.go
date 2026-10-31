package filesystem

import (
	"context"
	"path/filepath"
	"runtime"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/mholt/archives"
)

var isWindows = runtime.GOOS == "windows"

// isArchive does a light check to see if the provided path is an archive or
// compressed file. The File source already does this, so this exists mainly
// to avoid expensive calls before sending things to the File source
func isArchive(ctx context.Context, path string) bool {
	format, _, err := archives.Identify(ctx, path, nil)
	return err == nil && format != nil
}

// shouldSkipPath checks a path against the skip callback.
// Also handles the Windows forward-slash path normalization workaround.
func shouldSkipPath(skip sources.PrefilterFunc, path string) bool {
	if skip == nil {
		return false
	}
	attrs := map[string]string{sources.AttrPath: path}
	if skip(attrs) {
		return true
	}
	// TODO: Remove this Windows workaround in v9 (gitleaks/gitleaks#1641).
	if isWindows {
		attrs[sources.AttrPath] = filepath.ToSlash(path)
		return skip(attrs)
	}
	return false
}
