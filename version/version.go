package version

// these two gotta be the same
var DefaultMsg = "dev"
var Version = "dev"

// GitleaksCompat is the gitleaks config format version this build supports.
// Checked against the minVersion field in config files.
const GitleaksCompat = "8.25.0"
