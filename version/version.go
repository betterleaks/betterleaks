package version

import "strings"

// these two gotta be the same
var DefaultMsg = "dev"
var Version = "dev"

// IsDevelopment reports whether Version is the default or an untagged Git build.
// git describe --always --dirty emits a commit hash when no tag is available.
func IsDevelopment() bool {
	if Version == DefaultMsg {
		return true
	}
	revision := strings.TrimSuffix(Version, "-dirty")
	if len(revision) < 4 || len(revision) > 64 {
		return false
	}
	for _, c := range revision {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
