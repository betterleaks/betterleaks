package betterleaks

// Fragment represents a fragment of a source with its meta data
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw   string
	Bytes []byte
	Path  string

	// StartLine is the line number where the fragment starts in the resource
	StartLine int

	Resource *Resource
}

// ResourceContext returns the source type and metadata for allowlist matching.
func (f *Fragment) ResourceContext() (string, map[string]string) {
	if f == nil || f.Resource == nil {
		return "", nil
	}
	return f.Resource.Source, f.Resource.Metadata
}
