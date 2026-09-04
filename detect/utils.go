package detect

import (
	// "encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

// samePath reports whether two file paths refer to the same location, tolerating
// OS separator differences. The file source normalizes fragment paths to forward
// slashes (filepath.ToSlash), whereas config/baseline paths keep the native
// separator, so a raw == comparison misses on Windows and the config or baseline
// file ends up being scanned against itself.
func samePath(a, b string) bool {
	return filepath.ToSlash(filepath.Clean(a)) == filepath.ToSlash(filepath.Clean(b))
}

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

func createScmLink(platform, remoteURL string, finding report.Finding) string {
	p, _ := scm.PlatformFromString(platform)
	commitSha := finding.Attr(sources.AttrGitSHA)
	path := finding.Attr(sources.AttrPath)
	location := finding.Location
	if p == scm.UnknownPlatform || p == scm.NoPlatform || commitSha == "" || path == "" {
		return ""
	}

	// Clean the path.
	filePath, _, hasInnerPath := strings.Cut(path, sources.InnerPathSeparator)
	filePath = linkCleaner.Replace(filePath)

	switch p {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?plain=1"
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#L%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("-L%d", location.EndLine)
		}
		return link
	case scm.GitLabPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#L%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("-%d", location.EndLine)
		}
		return link
	case scm.AzureDevOpsPlatform:
		link := fmt.Sprintf("%s/commit/%s?path=/%s", remoteURL, commitSha, filePath)
		// Add line information if applicable
		if hasInnerPath {
			return link
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("&line=%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("&lineEnd=%d", location.EndLine)
		}
		// This is a bit dirty, but Azure DevOps does not highlight the line when the lineStartColumn and lineEndColumn are not provided
		link += "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files"
		return link
	case scm.GiteaPlatform:
		link := fmt.Sprintf("%s/src/commit/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?display=source"
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#L%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("-L%d", location.EndLine)
		}
		return link
	case scm.BitbucketPlatform:
		link := fmt.Sprintf("%s/src/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#lines-%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf(":%d", location.EndLine)
		}
		return link
	default:
		// This should never happen.
		return ""
	}
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
// Another way to think about what this is doing is calculating the number of bits
// needed to on average encode the data. So, the higher the entropy, the more random the data, the
// more bits needed to encode that data.
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// filter will dedupe and redact findings
func (d *Detector) filter(findings []report.Finding) []report.Finding {
	// Collect every component finding's (rule, line, secret) identity so the
	// corresponding top-level finding can be suppressed.
	componentSet := make(map[string]struct{})
	for _, f := range findings {
		for _, set := range f.ComponentSets {
			for _, comp := range set.Components {
				componentSet[fmt.Sprintf("%s:%d:%d:%d:%d:%s", comp.RuleID, comp.Location.StartLine, comp.Location.StartColumn, comp.Location.EndLine, comp.Location.EndColumn, comp.Secret)] = struct{}{}
			}
		}
	}

	var retFindings []report.Finding
	for _, f := range findings {
		include := true

		// Skip findings already surfaced as the same rule's component of a
		// composite finding in this batch.
		_, isComponent := componentSet[fmt.Sprintf("%s:%d:%d:%d:%d:%s", f.RuleID, f.Location.StartLine, f.Location.StartColumn, f.Location.EndLine, f.Location.EndColumn, f.Secret)]
		if isComponent {
			redactedMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
			logTrace(d.logger, "skipping finding already used as a component", "rule_id", f.RuleID, "finding", redactedMatch)
			include = false
		} else if d.isSuppressedByHigherSpecificityFinding(f, findings) {
			include = false
		}

		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func (d *Detector) isSuppressedByHigherSpecificityFinding(f report.Finding, findings []report.Finding) bool {
	for _, fPrime := range findings {
		if f.Location.StartLine == fPrime.Location.StartLine &&
			f.Attributes[sources.AttrGitSHA] == fPrime.Attributes[sources.AttrGitSHA] &&
			f.RuleID != fPrime.RuleID &&
			strings.Contains(fPrime.Secret, f.Secret) &&
			fPrime.RuleSpecificity > f.RuleSpecificity {
			genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
			betterMatch := strings.ReplaceAll(fPrime.Match, fPrime.Secret, "REDACTED")
			d.logger.Debug("skipping finding because a more specific rule takes precedence",
				"rule_id", f.RuleID,
				"finding", genericMatch,
				"precedence_rule_id", fPrime.RuleID,
				"precedence_finding", betterMatch,
			)
			return true
		}
		for _, set := range fPrime.ComponentSets {
			for _, comp := range set.Components {
				if f.RuleID != fPrime.RuleID &&
					f.Location.StartLine == comp.Location.StartLine &&
					f.RuleID != comp.RuleID &&
					strings.Contains(comp.Secret, f.Secret) &&
					comp.RuleSpecificity > f.RuleSpecificity {
					genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
					betterMatch := strings.ReplaceAll(comp.Match, comp.Secret, "REDACTED")
					logTrace(d.logger, "skipping finding because a more specific component takes precedence",
						"rule_id", f.RuleID,
						"finding", genericMatch,
						"precedence_rule_id", comp.RuleID,
						"precedence_finding", betterMatch,
					)
					return true
				}
			}
		}
	}
	return false
}

// stripEmptyMeta removes keys whose value is an empty string or nil.
func stripEmptyMeta(m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if v == nil {
			continue
		}
		out[k] = v
	}
	return out
}

// containsAllowSignature checks whether the line contains an allow comment.
func containsAllowSignature(line string) bool {
	for _, signature := range allowSignatures {
		if strings.Contains(line, signature) {
			return true
		}
	}
	return false
}
