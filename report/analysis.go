package report

import "github.com/betterleaks/betterleaks/v2/internal/color"

// Severity is a provider-neutral lower bound derived from observed
// capabilities. Rules cannot assign it directly.
type Severity string

const (
	SeverityNone     Severity = ""
	SeverityUnknown  Severity = "unknown"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Capability is a security-relevant grant that an analysis program has
// positively identified. Absence means unknown, not denied.
type Capability string

const (
	CapabilityRead              Capability = "read"
	CapabilityWrite             Capability = "write"
	CapabilityReadSecrets       Capability = "read_secrets"
	CapabilityCreateCredentials Capability = "create_credentials"
	CapabilityManageUsers       Capability = "manage_users"
	CapabilityAdmin             Capability = "admin"
)

// KnownCapabilities returns the capability vocabulary in stable report order.
func KnownCapabilities() []Capability {
	return []Capability{
		CapabilityRead,
		CapabilityWrite,
		CapabilityReadSecrets,
		CapabilityCreateCredentials,
		CapabilityManageUsers,
		CapabilityAdmin,
	}
}

// Analysis is the normalized output of a credential analysis program.
type Analysis struct {
	Reason       string            `json:"reason,omitempty"`
	Severity     Severity          `json:"severity,omitempty"`
	Identity     *AnalysisIdentity `json:"identity,omitempty"`
	Capabilities []Capability      `json:"capabilities,omitempty"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
	Debug        map[string]any    `json:"debug,omitempty"`
}

func (a Analysis) IsZero() bool {
	return a.Reason == "" && a.Severity == "" &&
		a.Identity == nil && len(a.Capabilities) == 0 &&
		len(a.Metadata) == 0 && len(a.Debug) == 0
}

// AnalysisIdentity identifies the principal that owns a credential.
type AnalysisIdentity struct {
	ID       string           `json:"id,omitempty"`
	Username string           `json:"username,omitempty"`
	Name     string           `json:"name,omitempty"`
	Email    string           `json:"email,omitempty"`
	Account  *AnalysisAccount `json:"account,omitempty"`
}

// AnalysisAccount identifies one unambiguous account or tenant reached by a
// credential. Analysis omits it when the credential spans multiple accounts.
type AnalysisAccount struct {
	ID      string   `json:"id,omitempty"`
	Name    string   `json:"name,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

// AnalysisSeverity derives severity from positive capability evidence.
func AnalysisSeverity(capabilities []Capability) Severity {
	severity := SeverityUnknown
	for _, capability := range capabilities {
		switch capability {
		case CapabilityAdmin, CapabilityCreateCredentials, CapabilityManageUsers, CapabilityReadSecrets:
			return SeverityCritical
		case CapabilityWrite:
			severity = SeverityHigh
		case CapabilityRead:
			if severity == SeverityUnknown {
				severity = SeverityMedium
			}
		}
	}
	return severity
}

// severityStyle returns the terminal style used for an analysis severity.
func severityStyle(severity Severity, noColor bool) color.Style {
	if noColor {
		return color.New()
	}
	if severity == SeverityHigh {
		return color.New().Bold().Foreground("#ef4444")
	}
	return color.New()
}

// SanitizeAnalysis removes credential material from all provider-controlled
// strings before analysis enters a report. Callers should pass both the
// primary secret and any component secrets.
func SanitizeAnalysis(analysis Analysis, secrets []string) Analysis {
	secrets = credentialSecretsForRedaction(secrets)
	analysis.Reason = sanitizeCredentialString(analysis.Reason, secrets)
	analysis.Metadata = sanitizeCredentialMetadata(analysis.Metadata, secrets, false)
	analysis.Debug = sanitizeCredentialMetadata(analysis.Debug, secrets, true)
	if analysis.Identity == nil {
		return analysis
	}

	identity := *analysis.Identity
	identity.ID = sanitizeCredentialString(identity.ID, secrets)
	identity.Username = sanitizeCredentialString(identity.Username, secrets)
	identity.Name = sanitizeCredentialString(identity.Name, secrets)
	identity.Email = sanitizeCredentialString(identity.Email, secrets)
	if identity.Account != nil {
		account := *identity.Account
		account.ID = sanitizeCredentialString(account.ID, secrets)
		account.Name = sanitizeCredentialString(account.Name, secrets)
		account.Domains = append([]string(nil), account.Domains...)
		for i := range account.Domains {
			account.Domains[i] = sanitizeCredentialString(account.Domains[i], secrets)
		}
		identity.Account = &account
	}
	analysis.Identity = &identity
	return analysis
}
