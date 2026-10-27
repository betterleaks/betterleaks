package sources

// Git resource selectors name what a Git source scans. They are values for a
// source's Include and Exclude lists, not fragment attributes.
const (
	GitResourceTypeHistory            = "history"
	GitResourceTypeMerges             = "merges"
	GitResourceTypeCommitMessages     = "commit-messages"
	GitResourceTypeNotes              = "notes"
	GitResourceTypeTagMessages        = "tag-messages"
	GitResourceTypeReflogs            = "reflogs"
	GitResourceTypeObjects            = "objects"
	GitResourceTypeUnreachableObjects = "unreachable-objects"
)
