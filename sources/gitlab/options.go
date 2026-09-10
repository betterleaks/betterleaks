package gitlab

import "time"

// DateRangeOptions controls date-range filtering across API-backed GitLab resources.
type DateRangeOptions struct {
	Since time.Time // only scan items created on or after this time (zero = no lower bound)
	Until time.Time // only scan items created before this time (zero = no upper bound)
}
