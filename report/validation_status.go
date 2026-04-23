package report

import "strings"

// ValidationStatus is the normalized status produced by secret validation.
type ValidationStatus string

const (
	ValidationStatusValid   ValidationStatus = "valid"
	ValidationStatusInvalid ValidationStatus = "invalid"
	ValidationStatusRevoked ValidationStatus = "revoked"
	ValidationStatusUnknown ValidationStatus = "unknown"
	ValidationStatusError   ValidationStatus = "error"

	// ValidationStatusNone is a CLI filter pseudo-status for findings that did
	// not run validation. It is not written to Finding.ValidationStatus.
	ValidationStatusNone ValidationStatus = "none"
)

var validationStatuses = map[ValidationStatus]struct{}{
	ValidationStatusValid:   {},
	ValidationStatusInvalid: {},
	ValidationStatusRevoked: {},
	ValidationStatusUnknown: {},
	ValidationStatusError:   {},
}

func ParseValidationStatus(status string) (ValidationStatus, bool) {
	normalized := ValidationStatus(strings.ToLower(strings.TrimSpace(status)))
	_, ok := validationStatuses[normalized]
	return normalized, ok
}

func (s ValidationStatus) String() string {
	return string(s)
}
