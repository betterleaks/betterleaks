package detect

import (
	// "encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"

	"github.com/charmbracelet/lipgloss"
)

// fragmentPathMatches reports whether re matches fragment.Path or, on Windows,
// the WindowsPath attribute.
func fragmentPathMatches(re interface{ MatchString(string) bool }, path, windowsPath string) bool {
	if re.MatchString(path) {
		return true
	}
	if windowsPath != "" {
		return re.MatchString(windowsPath)
	}
	return false
}

// locateMatch returns the byte index of match within rawLine, using startCol
// (1-indexed byte offset) to disambiguate duplicate occurrences. When the
// exact position doesn't match, it searches forward then backward from the
// expected position before falling back to the first occurrence.
func locateMatch(rawLine, rawMatch string, startCol int) int {
	if rawLine == "" || rawMatch == "" {
		return -1
	}

	if startCol > 0 {
		idx := startCol - 1 // assumes StartColumn is a 1-based byte offset

		if idx >= 0 && idx+len(rawMatch) <= len(rawLine) &&
			rawLine[idx:idx+len(rawMatch)] == rawMatch {
			return idx
		}

		// Search near the expected position first, not from the start.
		if idx < 0 {
			idx = 0
		}
		if idx > len(rawLine) {
			idx = len(rawLine)
		}
		if rel := strings.Index(rawLine[idx:], rawMatch); rel >= 0 {
			return idx + rel
		}
		if prev := strings.LastIndex(rawLine[:idx], rawMatch); prev >= 0 {
			return prev
		}
	}

	// startCol <= 0 (no hint provided) or, redundantly, when the
	// forward+backward searches above already covered the full line.
	return strings.Index(rawLine, rawMatch)
}

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

func createScmLink(platform, remoteURL string, finding report.Finding) string {
	p, _ := scm.PlatformFromString(platform)
	if p == scm.UnknownPlatform || p == scm.NoPlatform || finding.Commit == "" {
		return ""
	}

	// Clean the path.
	filePath, _, hasInnerPath := strings.Cut(finding.File, sources.InnerPathSeparator)
	filePath = linkCleaner.Replace(filePath)

	switch p {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/commit/%s?path=/%s", remoteURL, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/src/commit/%s/%s", remoteURL, finding.Commit, filePath)
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
		link := fmt.Sprintf("%s/src/%s/%s", remoteURL, finding.Commit, filePath)
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
func filter(findings []report.Finding) []report.Finding {
	// Collect every required finding's (line, secret) so we can suppress
	// standalone duplicates that are already surfaced as components.
	requiredSet := make(map[string]struct{})
	for _, f := range findings {
		for _, set := range f.RequiredSets {
			for _, comp := range set.Components {
				requiredSet[fmt.Sprintf("%d:%s", comp.StartLine, comp.Secret)] = struct{}{}
			}
		}
	}

	var retFindings []report.Finding
	for _, f := range findings {
		include := true

		// Skip findings that are already surfaced as a required component
		// of another (composite) finding in this batch.
		if _, isRequired := requiredSet[fmt.Sprintf("%d:%s", f.StartLine, f.Secret)]; isRequired {
			redactedMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
			logging.Trace().Msgf("skipping %s finding (%s), already a required component of another finding", f.RuleID, redactedMatch)
			include = false
		} else if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
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

		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func formatMatchContext(context string, match string, secret string, noColor bool) string {
	indent := "    " // 4 spaces
	matchStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#f5d445"))
	secretStyle := lipgloss.NewStyle().
		Bold(true).
		Italic(true).
		Foreground(lipgloss.Color("#f05c07"))

	lines := strings.Split(context, "\n")
	for i, line := range lines {
		if !noColor {
			if secretIdx := strings.Index(line, secret); secret != "" && secretIdx != -1 {
				// Try to highlight the full match with the secret emphasized inside it
				if matchIdx := strings.Index(line, match); match != "" && matchIdx != -1 {
					before, after, _ := strings.Cut(match, secret)
					highlighted := matchStyle.Render(before) +
						secretStyle.Render(secret) +
						matchStyle.Render(after)
					line = line[:matchIdx] + highlighted + line[matchIdx+len(match):]
				} else {
					// Fall back to highlighting just the secret
					line = line[:secretIdx] + secretStyle.Render(secret) + line[secretIdx+len(secret):]
				}
			}
		}
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}

func printFinding(f report.Finding, noColor bool, redact uint) {
	if redact > 0 {
		// Redact top-level fields only (f is a value copy so this is safe).
		// RequiredSets share pointers with the original finding stored in
		// d.findings, so we must not mutate them here — they are redacted
		// separately for display by PrintRequiredFindings.
		secret := report.MaskSecret(f.Secret, redact)
		if redact >= 100 {
			secret = "REDACTED"
		}
		f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
		f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
		f.MatchContext = strings.ReplaceAll(f.MatchContext, f.Secret, secret)
		f.Secret = secret
	}
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
		matchInLineIDX := locateMatch(f.Line, f.Match, f.StartColumn)
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

		if secretInMatchIdx == -1 {
			secretInMatchIdx = 0
		}

		matchBeginning := lipgloss.NewStyle().SetString(f.Match[0:secretInMatchIdx]).Foreground(lipgloss.Color("#f5d445"))
		secret = lipgloss.NewStyle().SetString(f.Secret).
			Bold(true).
			Italic(true).
			Foreground(lipgloss.Color("#f05c07"))
		matchEnd := lipgloss.NewStyle().SetString(f.Match[secretInMatchIdx+len(f.Secret):]).Foreground(lipgloss.Color("#f5d445"))

		lineEndIdx := matchInLineIDX + len(f.Match)
		if lineEndIdx > len(f.Line) {
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
		if f.MatchContext != "" {
			fmt.Printf("%-12s\n%s\n", "Context:", formatMatchContext(f.MatchContext, f.Match, f.Secret, noColor))
		}
		printValidation(f, noColor)
		f.PrintRequiredFindings(noColor, redact)
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
		if f.MatchContext != "" {
			fmt.Printf("%-12s\n%s\n", "Context:", formatMatchContext(f.MatchContext, f.Match, f.Secret, noColor))
		}
		printValidation(f, noColor)
		f.PrintRequiredFindings(noColor, redact)
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

	if f.MatchContext != "" {
		fmt.Printf("%-12s\n%s\n", "Context:", formatMatchContext(f.MatchContext, f.Match, f.Secret, noColor))
	}
	printValidation(f, noColor)
	f.PrintRequiredFindings(noColor, redact)
	fmt.Println("")
}

// printValidation prints the validation status block when validation has run.
func printValidation(f report.Finding, noColor bool) {
	if f.ValidationStatus == "" {
		return
	}

	var statusStyle lipgloss.Style
	if !noColor {
		switch f.ValidationStatus {
		case "valid":
			statusStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00d26a"))
		case "invalid":
			statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
		case "revoked":
			statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#f5d445"))
		case "unknown":
			statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#c0c0c0"))
		case "error":
			statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#f05c07"))
		default:
			statusStyle = lipgloss.NewStyle()
		}
	} else {
		statusStyle = lipgloss.NewStyle()
	}

	fmt.Printf("%-12s %s", "Validation:", statusStyle.Render(strings.ToUpper(f.ValidationStatus)))
	if f.ValidationReason != "" {
		fmt.Printf("  (%s)", f.ValidationReason)
	}
	fmt.Println()

	var metaStyle lipgloss.Style
	if !noColor {
		metaStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#9ca3af"))
	} else {
		metaStyle = lipgloss.NewStyle()
	}

	for _, k := range sortedMapKeys(f.ValidationMeta) {
		fmt.Printf("  %s\n", metaStyle.Render(fmt.Sprintf("%-10s %v", k+" =", f.ValidationMeta[k])))
	}
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

func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
