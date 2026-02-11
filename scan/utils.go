package scan

import (
	// "encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"github.com/betterleaks/betterleaks"
	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/git"
	"github.com/betterleaks/betterleaks/sources/scm"
	"golang.org/x/exp/maps"
)

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

// CreateScmLink generates a link to the finding in the SCM platform (GitHub, GitLab, etc.)
// TODO find a better home for this
func CreateScmLink(remote *git.RemoteInfo, finding betterleaks.Finding) string {
	commit := finding.Metadata[betterleaks.MetaCommitSHA]
	file := finding.Metadata[betterleaks.MetaPath]
	if remote.Platform == scm.UnknownPlatform ||
		remote.Platform == scm.NoPlatform ||
		commit == "" {
		return ""
	}

	// Clean the path.
	filePath, _, hasInnerPath := strings.Cut(file, sources.InnerPathSeparator)
	filePath = linkCleaner.Replace(filePath)

	switch remote.Platform {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remote.Url, commit, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?plain=1"
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-L%d", finding.EndLine)
		}
		return link
	case scm.GitLabPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remote.Url, commit, filePath)
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-%d", finding.EndLine)
		}
		return link
	case scm.AzureDevOpsPlatform:
		link := fmt.Sprintf("%s/commit/%s?path=/%s", remote.Url, commit, filePath)
		// Add line information if applicable
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("&line=%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("&lineEnd=%d", finding.EndLine)
		}
		// This is a bit dirty, but Azure DevOps does not highlight the line when the lineStartColumn and lineEndColumn are not provided
		link += "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files"
		return link
	case scm.GiteaPlatform:
		link := fmt.Sprintf("%s/src/commit/%s/%s", remote.Url, commit, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?display=source"
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-L%d", finding.EndLine)
		}
		return link
	case scm.BitbucketPlatform:
		link := fmt.Sprintf("%s/src/%s/%s", remote.Url, commit, filePath)
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#lines-%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf(":%d", finding.EndLine)
		}
		return link
	default:
		// This should never happen.
		return ""
	}
}

// filter will dedupe and redact finding
func filter(fs []betterleaks.Finding, redact uint) []betterleaks.Finding {
	var retFindings []betterleaks.Finding
	for _, f := range fs {
		include := true
		if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range fs {
				if f.StartLine == fPrime.StartLine &&
					f.Metadata[betterleaks.MetaCommitSHA] == fPrime.Metadata[betterleaks.MetaCommitSHA] &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
					betterMatch := strings.ReplaceAll(fPrime.Match, fPrime.Secret, "REDACTED")
					logging.Trace().Msgf("skipping %s finding (%s), %s rule takes precedence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if redact > 0 {
			f.Redact(redact)
		}
		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

// CreateFinding creates a Finding from a fragment, match, and rule without
// computing location data. Call HydrateFindingLocation after filtering to add
// line/column information.
func CreateFinding(fragment betterleaks.Fragment, match betterleaks.Match, rule config.Rule) *betterleaks.Finding {
	secret := extractSecret(rule, match.MatchString)
	entropy := shannonEntropy(secret)

	f := betterleaks.Finding{
		RuleID:   match.RuleID,
		Match:    match.MatchString,
		Secret:   secret,
		Entropy:  entropy,
		Line:     match.FullDecodedLine,
		Fragment: &fragment,
		Tags:     match.MetaTags,
		Metadata: make(map[string]string),
	}

	// Copy resource metadata so each finding has its own map.
	// Finding-specific augmentations (e.g. SCM link) won't bleed across
	// findings that share the same Resource.
	if fragment.Resource != nil {
		maps.Copy(f.Metadata, fragment.Resource.Metadata)
	}

	return &f
}

// AddLocationToFinding populates location fields on a finding.
func AddLocationToFinding(finding *betterleaks.Finding, fragment betterleaks.Fragment, match betterleaks.Match, newLineIndices [][]int) {
	loc := location(newLineIndices, fragment.Raw, []int{match.MatchStart, match.MatchEnd})

	// Account for fragment offset when a resource is split into multiple fragments.
	// fragment.StartLine is 1-based, so we subtract 1 before adding.
	fragmentOffset := 0
	if fragment.StartLine > 0 {
		fragmentOffset = fragment.StartLine - 1
	}

	finding.StartLine = loc.startLine + 1 + fragmentOffset
	finding.EndLine = loc.endLine + 1 + fragmentOffset
	finding.StartColumn = loc.startColumn
	finding.EndColumn = loc.endColumn
}

func extractSecret(r config.Rule, matchedString string) string {
	if r.Regex == nil {
		return matchedString
	}
	groups := r.Regex.FindStringSubmatch(matchedString)
	if len(groups) >= 2 {
		if r.SecretGroup > 0 {
			if len(groups) <= r.SecretGroup {
				return ""
			}
			return groups[r.SecretGroup]
		} else {
			for _, s := range groups[1:] {
				if len(s) > 0 {
					return s
				}
			}
		}
	}
	return matchedString
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
func shannonEntropy(data string) float64 {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	var entropy float64
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// Location represents a location in a file
type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

func location(newlineIndices [][]int, raw string, matchIndex []int) Location {
	var (
		prevNewLine int
		location    Location
		lineSet     bool
		_lineNum    int
	)

	start := matchIndex[0]
	end := matchIndex[1]

	location.startLineIndex = 0

	if len(newlineIndices) == 0 {
		newlineIndices = [][]int{
			{len(raw), len(raw) + 1},
		}
	}

	for lineNum, pair := range newlineIndices {
		_lineNum = lineNum
		newLineByteIndex := pair[0]
		if prevNewLine <= start && start < newLineByteIndex {
			lineSet = true
			location.startLine = lineNum
			location.endLine = lineNum
			location.startColumn = (start - prevNewLine) + 1
			location.startLineIndex = prevNewLine
			location.endLineIndex = newLineByteIndex
		}
		if prevNewLine < end && end <= newLineByteIndex {
			location.endLine = lineNum
			location.endColumn = (end - prevNewLine)
			location.endLineIndex = newLineByteIndex
		}

		prevNewLine = pair[0]
	}

	if !lineSet {
		location.startColumn = (start - prevNewLine) + 1
		location.endColumn = (end - prevNewLine)
		location.startLine = _lineNum + 1
		location.endLine = _lineNum + 1

		i := 0
		for end+i < len(raw) {
			if raw[end+i] == '\n' {
				break
			}
			if raw[end+i] == '\r' {
				break
			}
			i++
		}
		location.endLineIndex = end + i
	}
	return location
}
