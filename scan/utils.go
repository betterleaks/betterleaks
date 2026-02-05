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
	sources2 "github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"

	"github.com/charmbracelet/lipgloss"
)

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

// CreateScmLink generates a link to the finding in the SCM platform (GitHub, GitLab, etc.)
// TODO find a better home for this
func CreateScmLink(remote *sources2.RemoteInfo, finding betterleaks.Finding) string {
	if remote.Platform == scm.UnknownPlatform ||
		remote.Platform == scm.NoPlatform ||
		finding.Commit == "" {
		return ""
	}

	// Clean the path.
	filePath, _, hasInnerPath := strings.Cut(finding.File, sources2.InnerPathSeparator)
	filePath = linkCleaner.Replace(filePath)

	switch remote.Platform {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remote.Url, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/blob/%s/%s", remote.Url, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/commit/%s?path=/%s", remote.Url, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/src/commit/%s/%s", remote.Url, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/src/%s/%s", remote.Url, finding.Commit, filePath)
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
					f.Commit == fPrime.Commit &&
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

// PrintFinding prints a finding to stdout with optional color formatting.
func PrintFinding(f betterleaks.Finding, noColor bool) {
	// trim all whitespace and tabs
	f.Line = strings.TrimSpace(f.Line)
	f.Secret = strings.TrimSpace(f.Secret)
	f.Match = strings.TrimSpace(f.Match)

	isFileMatch := strings.HasPrefix(f.Match, "file detected:")
	skipColor := noColor
	finding := ""
	var secret lipgloss.Style

	// Matches from filenames do not have a |line| or |secret|
	if !isFileMatch {
		matchInLineIDX := strings.Index(f.Line, f.Match)
		secretInMatchIdx := strings.Index(f.Match, f.Secret)

		skipColor = false

		if matchInLineIDX == -1 || noColor {
			skipColor = true
			matchInLineIDX = 0
		}

		start := f.Line[0:matchInLineIDX]
		startMatchIdx := 0
		if matchInLineIDX > 20 {
			startMatchIdx = matchInLineIDX - 20
			start = "..." + f.Line[startMatchIdx:matchInLineIDX]
		}

		matchBeginning := lipgloss.NewStyle().SetString(f.Match[0:secretInMatchIdx]).Foreground(lipgloss.Color("#f5d445"))
		secret = lipgloss.NewStyle().SetString(f.Secret).
			Bold(true).
			Italic(true).
			Foreground(lipgloss.Color("#f05c07"))
		matchEnd := lipgloss.NewStyle().SetString(f.Match[secretInMatchIdx+len(f.Secret):]).Foreground(lipgloss.Color("#f5d445"))

		lineEndIdx := matchInLineIDX + len(f.Match)
		if len(f.Line)-1 <= lineEndIdx {
			lineEndIdx = len(f.Line)
		}

		lineEnd := f.Line[lineEndIdx:]

		if len(f.Secret) > 100 {
			secret = lipgloss.NewStyle().SetString(f.Secret[0:100] + "...").
				Bold(true).
				Italic(true).
				Foreground(lipgloss.Color("#f05c07"))
		}
		if len(lineEnd) > 20 {
			lineEnd = lineEnd[0:20] + "..."
		}

		finding = fmt.Sprintf("%s%s%s%s%s\n", strings.TrimPrefix(strings.TrimLeft(start, " "), "\n"), matchBeginning, secret, matchEnd, lineEnd)
	}

	if skipColor || isFileMatch {
		fmt.Printf("%-12s %s\n", "Finding:", f.Match)
		fmt.Printf("%-12s %s\n", "Secret:", f.Secret)
	} else {
		fmt.Printf("%-12s %s", "Finding:", finding)
		fmt.Printf("%-12s %s\n", "Secret:", secret)
	}

	fmt.Printf("%-12s %s\n", "RuleID:", f.RuleID)
	fmt.Printf("%-12s %f\n", "Entropy:", f.Entropy)

	if f.File == "" {
		f.PrintRequiredFindings()
		fmt.Println("")
		return
	}
	if len(f.Tags) > 0 {
		fmt.Printf("%-12s %s\n", "Tags:", f.Tags)
	}
	fmt.Printf("%-12s %s\n", "File:", f.File)
	fmt.Printf("%-12s %d\n", "Line:", f.StartLine)
	if f.Commit == "" {
		fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
		f.PrintRequiredFindings()
		fmt.Println("")
		return
	}
	fmt.Printf("%-12s %s\n", "Commit:", f.Commit)
	fmt.Printf("%-12s %s\n", "Author:", f.Author)
	fmt.Printf("%-12s %s\n", "Email:", f.Email)
	fmt.Printf("%-12s %s\n", "Date:", f.Date)
	fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
	if f.Link != "" {
		fmt.Printf("%-12s %s\n", "Link:", f.Link)
	}

	f.PrintRequiredFindings()
	fmt.Println("")
}

// CreateFinding creates a Finding from a fragment, match, and rule without
// computing location data. Call HydrateFindingLocation after filtering to add
// line/column information.
func CreateFinding(fragment betterleaks.Fragment, match betterleaks.Match, rule config.Rule) *betterleaks.Finding {
	secret := extractSecret(rule, match.MatchString)
	entropy := shannonEntropy(secret)

	return &betterleaks.Finding{
		RuleID:      match.RuleID,
		Match:       match.MatchString,
		Secret:      secret,
		Entropy:     entropy,
		File:        fragment.Path,
		SymlinkFile: fragment.Resource.Get(betterleaks.MetaSymlinkFile),
		Commit:      fragment.Resource.Get(betterleaks.MetaCommitSHA),
		Author:      fragment.Resource.Get(betterleaks.MetaAuthorName),
		Email:       fragment.Resource.Get(betterleaks.MetaAuthorEmail),
		Date:        fragment.Resource.Get(betterleaks.MetaCommitDate),
		Message:     fragment.Resource.Get(betterleaks.MetaCommitMessage),
		Line:        match.FullDecodedLine,
		Fragment:    &fragment,
		Tags:        match.MetaTags,
	}
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

func AddFingerprintToFinding(finding *betterleaks.Finding) {
	globalFingerprint := fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
	if finding.Commit != "" {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	} else {
		finding.Fingerprint = globalFingerprint
	}
}
