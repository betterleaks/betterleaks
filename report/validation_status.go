package report

// ValidationStatus describes the liveness state of a finding's secret as
// determined by the validation engine. It is a string-backed type so that it
// serializes identically to the previous plain-string field, while giving
// callers a single, type-safe set of values to compare against.
type ValidationStatus string

const (
	// ValidationStatusNone is the zero value: no validation was performed.
	ValidationStatusNone ValidationStatus = ""
	// ValidationStatusValid means the secret was confirmed active.
	ValidationStatusValid ValidationStatus = "valid"
	// ValidationStatusNeedsValidation means the secret could not be validated
	// automatically and needs a manual check.
	ValidationStatusNeedsValidation ValidationStatus = "needs_validation"
	// ValidationStatusInvalid means the secret was rejected by the provider.
	ValidationStatusInvalid ValidationStatus = "invalid"
	// ValidationStatusRevoked means the secret is known to be revoked.
	ValidationStatusRevoked ValidationStatus = "revoked"
	// ValidationStatusUnknown means validation produced an indeterminate result.
	ValidationStatusUnknown ValidationStatus = "unknown"
	// ValidationStatusError means validation could not be completed due to an error.
	ValidationStatusError ValidationStatus = "error"
)

// String returns the underlying string value, satisfying fmt.Stringer.
func (s ValidationStatus) String() string { return string(s) }
