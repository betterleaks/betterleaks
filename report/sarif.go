package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/sources"
)

type SarifReporter struct {
	OrderedRules []config.Rule
}

var _ Reporter = (*SarifReporter)(nil)
var _ StreamReporter = (*SarifReporter)(nil)

func (r *SarifReporter) Write(w io.Writer, findings []Finding) error {
	return r.WriteStream(w, len(findings), iterateFindings(findings))
}

func (r *SarifReporter) WriteStream(w io.Writer, _ int, findings FindingIterator) error {
	if _, err := io.WriteString(w, "{\n \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n \"version\": \"2.1.0\",\n \"runs\": [\n  {\n   \"tool\": "); err != nil {
		return err
	}

	tool, err := json.Marshal(r.getTool())
	if err != nil {
		return err
	}
	if _, err := w.Write(tool); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ",\n   \"results\": ["); err != nil {
		return err
	}

	first := true
	if err := findings(func(f Finding) error {
		if first {
			first = false
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		} else if _, err := io.WriteString(w, ",\n"); err != nil {
			return err
		}

		result, err := json.Marshal(resultFromFinding(f))
		if err != nil {
			return err
		}
		_, err = w.Write(result)
		return err
	}); err != nil {
		return err
	}
	if !first {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	_, err = io.WriteString(w, "   ]\n  }\n ]\n}\n")
	return err
}

func (r *SarifReporter) getTool() Tool {
	tool := Tool{
		Driver: Driver{
			Name:            driver,
			SemanticVersion: version,
			InformationUri:  "https://github.com/gitleaks/gitleaks",
			Rules:           r.getRules(),
		},
	}

	// if this tool has no rules, ensure that it is represented as [] instead of null/nil
	if hasEmptyRules(tool) {
		tool.Driver.Rules = make([]Rules, 0)
	}

	return tool
}

func hasEmptyRules(tool Tool) bool {
	return len(tool.Driver.Rules) == 0
}

func (r *SarifReporter) getRules() []Rules {
	var rules []Rules
	for _, rule := range r.OrderedRules {
		rules = append(rules, Rules{
			ID: rule.RuleID,
			Description: ShortDescription{
				Text: rule.Description,
			},
		})
	}
	return rules
}

func messageText(f Finding) string {
	path := f.Attr(sources.AttrPath)
	commit := f.Attr(sources.AttrGitSHA)
	if commit == "" {
		return fmt.Sprintf("%s has detected secret for file %s.", f.RuleID, path)
	}

	return fmt.Sprintf("%s has detected secret for file %s at commit %s.", f.RuleID, path, commit)
}

func resultFromFinding(f Finding) Results {
	return Results{
		Message: Message{
			Text: messageText(f),
		},
		RuleId:    f.RuleID,
		Locations: getLocation(f),
		// This information goes in partial fingerprints until revision data
		// can be added somewhere else.
		PartialFingerPrints: PartialFingerPrints{
			CommitSha:     f.Attr(sources.AttrGitSHA),
			Email:         f.Attr(sources.AttrGitAuthorEmail),
			CommitMessage: f.Attr(sources.AttrGitMessage),
			Date:          f.Attr(sources.AttrGitDate),
			Author:        f.Attr(sources.AttrGitAuthorName),
		},
		Properties: Properties{
			Tags: f.Tags,
		},
	}
}

func getLocation(f Finding) []Locations {
	uri := f.Attr(sources.AttrPath)
	if symlink := f.Attr(sources.AttrFSSymlink); symlink != "" {
		uri = symlink
	}
	loc := Locations{
		PhysicalLocation: PhysicalLocation{
			ArtifactLocation: ArtifactLocation{
				URI: uri,
			},
			Region: Region{
				StartLine:   f.StartLine,
				EndLine:     f.EndLine,
				StartColumn: f.StartColumn,
				EndColumn:   f.EndColumn,
				Snippet: Snippet{
					Text: f.Secret,
				},
			},
		},
	}
	if f.MatchContext != "" {
		loc.PhysicalLocation.ContextRegion = &ContextRegion{
			Snippet: Snippet{
				Text: f.MatchContext,
			},
		}
	}
	return []Locations{loc}
}

type PartialFingerPrints struct {
	CommitSha     string `json:"commitSha"`
	Email         string `json:"email"`
	Author        string `json:"author"`
	Date          string `json:"date"`
	CommitMessage string `json:"commitMessage"`
}

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Runs `json:"runs"`
}

type ShortDescription struct {
	Text string `json:"text"`
}

type FullDescription struct {
	Text string `json:"text"`
}

type Rules struct {
	ID          string           `json:"id"`
	Description ShortDescription `json:"shortDescription"`
}

type Driver struct {
	Name            string  `json:"name"`
	SemanticVersion string  `json:"semanticVersion"`
	InformationUri  string  `json:"informationUri"`
	Rules           []Rules `json:"rules"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Message struct {
	Text string `json:"text"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int     `json:"startLine"`
	StartColumn int     `json:"startColumn"`
	EndLine     int     `json:"endLine"`
	EndColumn   int     `json:"endColumn"`
	Snippet     Snippet `json:"snippet"`
}

type Snippet struct {
	Text string `json:"text"`
}

type ContextRegion struct {
	Snippet Snippet `json:"snippet"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
	ContextRegion    *ContextRegion   `json:"contextRegion,omitempty"`
}

type Locations struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type Properties struct {
	Tags []string `json:"tags"`
}

type Results struct {
	Message             Message     `json:"message"`
	RuleId              string      `json:"ruleId"`
	Locations           []Locations `json:"locations"`
	PartialFingerPrints `json:"partialFingerprints"`
	Properties          Properties `json:"properties"`
}

type Runs struct {
	Tool    Tool      `json:"tool"`
	Results []Results `json:"results"`
}
