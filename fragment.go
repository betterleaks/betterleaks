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
