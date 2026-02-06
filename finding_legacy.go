package betterleaks

import "encoding/json"

// --------------------------------------------------------------------------
// Legacy (gitleaks-compatible) JSON serialization.
//
// The legacy format flattens a fixed set of metadata keys into top-level
// fields with gitleaks field names (File, Commit, Author, …).  This is used
// when --legacy mode is enabled, or when deserializing old baselines.
// --------------------------------------------------------------------------

// legacyFindingJSON is the gitleaks-compatible JSON shape.
type legacyFindingJSON struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	SymlinkFile string   `json:"SymlinkFile"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
	Link        string   `json:"Link,omitempty"`
}

// LegacyMarshalJSON serializes the finding into the gitleaks-compatible JSON
// format, flattening known metadata keys into top-level fields.
func (f Finding) LegacyMarshalJSON() ([]byte, error) {
	j := legacyFindingJSON{
		RuleID:      f.RuleID,
		Description: f.Description,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		Match:       f.Match,
		Secret:      f.Secret,
		Entropy:     f.Entropy,
		Tags:        f.Tags,
		Fingerprint: f.Fingerprint,
		File:        f.Metadata[MetaPath],
		SymlinkFile: f.Metadata[MetaSymlinkFile],
		Commit:      f.Metadata[MetaCommitSHA],
		Link:        f.Metadata[MetaLink],
		Author:      f.Metadata[MetaAuthorName],
		Email:       f.Metadata[MetaAuthorEmail],
		Date:        f.Metadata[MetaCommitDate],
		Message:     f.Metadata[MetaCommitMessage],
	}
	return json.Marshal(j)
}

// unmarshalLegacyJSON attempts to deserialize the gitleaks-compatible JSON
// shape into a Finding. Returns true if the data matched the legacy format.
func (f *Finding) unmarshalLegacyJSON(data []byte) bool {
	var j legacyFindingJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return false
	}
	// Distinguish legacy from new format: legacy has a "File" key, new has "Metadata".
	// We check for a non-empty File or Commit as a strong signal.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	if _, hasFile := raw["File"]; !hasFile {
		return false
	}
	if _, hasMeta := raw["Metadata"]; hasMeta {
		// New format also present — prefer new.
		return false
	}

	f.RuleID = j.RuleID
	f.Description = j.Description
	f.StartLine = j.StartLine
	f.EndLine = j.EndLine
	f.StartColumn = j.StartColumn
	f.EndColumn = j.EndColumn
	f.Match = j.Match
	f.Secret = j.Secret
	f.Entropy = j.Entropy
	f.Tags = j.Tags
	f.Fingerprint = j.Fingerprint

	meta := map[string]string{
		MetaPath:          j.File,
		MetaSymlinkFile:   j.SymlinkFile,
		MetaCommitSHA:     j.Commit,
		MetaLink:          j.Link,
		MetaAuthorName:    j.Author,
		MetaAuthorEmail:   j.Email,
		MetaCommitDate:    j.Date,
		MetaCommitMessage: j.Message,
	}
	f.Metadata = meta
	f.Fragment = &Fragment{
		Path: j.File,
		Resource: &Resource{
			Path:     j.File,
			Metadata: meta,
		},
	}
	return true
}
