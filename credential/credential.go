// Package credential defines inputs and capture requirements shared by
// validation, analysis, and explicit revocation.
package credential

// Input is an already-extracted secret and the inputs needed by its rule's
// provider programs. Secret is passed verbatim: it is not matched against the
// detection regex, decoded, or trimmed. Additional captures are supplied explicitly.
// Primary and component secrets must each contain between 1 byte and 1 MiB.
// Provider expressions read Secret as finding.secret and Captures as
// finding.captures. Components are exposed as components[ruleID], with the
// same secret and captures fields for each component.
type Input struct {
	RuleID   string
	Secret   string
	Captures map[string]string
	// Components contains one credential combination, keyed by component rule ID.
	Components map[string]Component
	// Attributes are report metadata only; provider expressions cannot read them.
	Attributes map[string]string
}

// Component supplies a component value and its named captures.
type Component struct {
	Secret   string
	Captures map[string]string
}

// Requirements describes the statically named inputs consumed by a rule's
// provider expressions. Optional accesses and null-coalescing fallbacks do not
// require a capture. Dynamic capture names cannot be inferred.
type Requirements struct {
	Captures   []string                `json:"captures,omitempty"`
	Components []ComponentRequirements `json:"components,omitempty"`
}

// ComponentRequirements describes one declared credential component. Captures
// are required only when that component is supplied.
type ComponentRequirements struct {
	RuleID   string   `json:"rule_id"`
	Optional bool     `json:"optional,omitempty"`
	Captures []string `json:"captures,omitempty"`
}
