package scan

import (
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks"
	"github.com/charmbracelet/lipgloss"
)

// --------------------------------------------------------------------------
// Legacy (gitleaks-compatible) printing.
//
// LegacyPrintFinding prints a finding in the gitleaks-compatible format,
// showing a fixed set of metadata fields (File, Commit, Author, Email, Date).
// Activated by --legacy.
// --------------------------------------------------------------------------

// LegacyPrintFinding prints a finding to stdout in the gitleaks-compatible
// format with optional color formatting.
func LegacyPrintFinding(f betterleaks.Finding, noColor bool) {
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
			_ = startMatchIdx
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

	// Legacy format: fixed metadata fields only.
	file := f.Metadata[betterleaks.MetaPath]
	commit := f.Metadata[betterleaks.MetaCommitSHA]

	if file == "" {
		f.PrintRequiredFindings()
		fmt.Println("")
		return
	}
	if len(f.Tags) > 0 {
		fmt.Printf("%-12s %s\n", "Tags:", f.Tags)
	}
	fmt.Printf("%-12s %s\n", "File:", file)
	fmt.Printf("%-12s %d\n", "Line:", f.StartLine)
	if commit == "" {
		fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
		f.PrintRequiredFindings()
		fmt.Println("")
		return
	}
	fmt.Printf("%-12s %s\n", "Commit:", commit)
	fmt.Printf("%-12s %s\n", "Author:", f.Metadata[betterleaks.MetaAuthorName])
	fmt.Printf("%-12s %s\n", "Email:", f.Metadata[betterleaks.MetaAuthorEmail])
	fmt.Printf("%-12s %s\n", "Date:", f.Metadata[betterleaks.MetaCommitDate])
	fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
	if link := f.Metadata[betterleaks.MetaLink]; link != "" {
		fmt.Printf("%-12s %s\n", "Link:", link)
	}

	f.PrintRequiredFindings()
	fmt.Println("")
}
