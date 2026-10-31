package sources

// InnerPathSeparator separates an archive path from the path of a file inside it.
const InnerPathSeparator = "!"

// Fragment represents a fragment of a source with its meta data
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	// StartLine is the line number this fragment starts on (SetDefaults sets it to 1 if unset)
	StartLine int

	// StartColumnOffset is the zero-based byte offset of the fragment on its first
	// source line. Zero means the fragment starts at the beginning of that line.
	StartColumnOffset int

	// Attributes holds source metadata, including the optional path at AttrPath.
	Attributes map[string]string
}

func (f *Fragment) SetAttr(key, value string) {
	if f.Attributes == nil {
		f.Attributes = make(map[string]string)
	}
	f.Attributes[key] = value
}

func (f *Fragment) Attr(key string) string {
	if f.Attributes == nil {
		return ""
	}
	return f.Attributes[key]
}

// SetDefaults sets default fields that might not have been set on the fragment
func (f *Fragment) SetDefaults() {
	if f.StartLine == 0 {
		f.StartLine = 1 // Lines start at 1
	}
}
