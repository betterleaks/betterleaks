package sources

import (
	"context"
	"path/filepath"
	"runtime"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/mholt/archives"
)

const InnerPathSeparator = "!"

var isWindows = runtime.GOOS == "windows"

// IsArchive does a light check to see if the provided path is an archive or
// compressed file. The File source already does this, so this exists mainly
// to avoid expensive calls before sending things to the File source
func IsArchive(ctx context.Context, path string) bool {
	format, _, err := archives.Identify(ctx, path, nil)
	return err == nil && format != nil
}

// ShouldSkipPath checks a path against all the allowlists to see if it can
// be skipped
func ShouldSkipPath(cfg *config.Config, source string, path string) bool {
	if cfg == nil {
		logging.Trace().Str("path", path).Msg("not skipping path because config is nil")
		return false
	}

	for _, a := range cfg.Allowlists {
		if a.ResourceKeyAllowed(source, betterleaks.MetaPath, path) ||
			// TODO: Remove this in v9.
			// This is an awkward hack to mitigate https://github.com/gitleaks/gitleaks/issues/1641.
			(isWindows && a.ResourceKeyAllowed(source, betterleaks.MetaPath, filepath.ToSlash(path))) {
			return true
		}
	}

	return false
}
