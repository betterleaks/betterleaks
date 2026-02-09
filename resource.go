package betterleaks

import (
	"fmt"
	"strings"
)

// Metadata keys used across sources.
const (
	MetaPath            = "path"
	MetaCommitSHA       = "commit_sha"
	MetaAuthorName      = "author_name"
	MetaAuthorEmail     = "author_email"
	MetaCommitDate      = "commit_date"
	MetaCommitMessage   = "commit_message"
	MetaSymlinkFile     = "symlink_file"
	MetaWindowsFilePath = "windows_file_path"
	MetaLink            = "link"
	MetaScmPlatform     = "scm_platform"
	MetaScmRemoteURL    = "scm_remote_url"
)

// Resource represents a resource from a source which yields fragments.
type Resource struct {
	Name     string
	ID       string
	Path     string
	Kind     ResourceKind
	SourceID string
	Source   string // Source type: "git", "file", "s3", "github", etc.

	// TODO ParentResourceID string
	Metadata map[string]string

	// cached fingerprint identity string, computed once on first call
	fingerprintIdentity string
}

func (r *Resource) Set(key, value string) {
	if r.Metadata == nil {
		r.Metadata = make(map[string]string)
	}
	r.Metadata[key] = value
}

// Get returns a metadata value by key, or empty string if not found.
func (r *Resource) Get(key string) string {
	if r == nil || r.Metadata == nil {
		return ""
	}
	return r.Metadata[key]
}

// ResourceKind represents the kind of resource.
type ResourceKind string

// ResourceKindInfo holds the registration details for a ResourceKind.
type ResourceKindInfo struct {
	Kind         ResourceKind
	IdentityKeys []string // must be alphabetically ordered
	Source       string
}

var resourceKindRegistry = map[ResourceKind]ResourceKindInfo{}

// RegisterResourceKind registers a ResourceKind with its identity keys.
// This is typically called from init() in each source package.
func RegisterResourceKind(info ResourceKindInfo) {
	for i := 1; i < len(info.IdentityKeys); i++ {
		if info.IdentityKeys[i] <= info.IdentityKeys[i-1] {
			panic(fmt.Sprintf("ResourceKind %q: identity keys must be alphabetically ordered", info.Kind))
		}
	}
	if _, exists := resourceKindRegistry[info.Kind]; exists {
		panic(fmt.Sprintf("ResourceKind %q already registered", info.Kind))
	}
	resourceKindRegistry[info.Kind] = info
}

// FingerprintKeys returns the metadata keys forming the unique identity for this resource kind.
// Keys are returned in alphabetical order.
func (k ResourceKind) FingerprintKeys() []string {
	info, ok := resourceKindRegistry[k]
	if !ok {
		panic(fmt.Sprintf("unregistered ResourceKind %q", k))
	}
	return info.IdentityKeys
}

// FingerprintIdentity returns the sorted key=value pairs that uniquely identify
// this resource. The result is cached on the Resource since it's shared across
// fragments.
func (r *Resource) FingerprintIdentity() string {
	if r.fingerprintIdentity != "" {
		return r.fingerprintIdentity
	}
	keys := r.Kind.FingerprintKeys()
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(r.Metadata[k])
	}
	r.fingerprintIdentity = b.String()
	return r.fingerprintIdentity
}
