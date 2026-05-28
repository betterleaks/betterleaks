package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/internal/color"
)

// PrintLegacy prints a finding using the legacy key/value verbose format.
func (f Finding) PrintLegacy(noColor bool, redact uint) {
	if redact > 0 {
		secret := MaskSecret(f.Secret, redact)
		if redact >= 100 {
			secret = "REDACTED"
		}
		f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
		f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
		f.MatchContext = strings.ReplaceAll(f.MatchContext, f.Secret, secret)
		f.Secret = secret
	}
	f.Line = strings.TrimSpace(f.Line)
	f.Secret = strings.TrimSpace(f.Secret)
	f.Match = strings.TrimSpace(f.Match)

	isFileMatch := strings.HasPrefix(f.Match, "file detected:")
	skipColor := noColor
	finding := ""
	secretDisplay := ""
	matchStyle := color.New().Foreground("#f5d445")
	secretStyle := color.New().Bold().Italic().Foreground("#f05c07")

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

		matchBeginning := matchStyle.Render(f.Match[0:secretInMatchIdx])
		secretDisplay = f.Secret
		if len(f.Secret) > 100 {
			secretDisplay = f.Secret[0:100] + "..."
		}
		styledSecret := secretStyle.Render(secretDisplay)
		matchEnd := matchStyle.Render(f.Match[secretInMatchIdx+len(f.Secret):])

		lineEndIdx := matchInLineIDX + len(f.Match)
		if lineEndIdx > len(f.Line) {
			lineEndIdx = len(f.Line)
		}

		lineEnd := f.Line[lineEndIdx:]

		if len(lineEnd) > 20 {
			lineEnd = lineEnd[0:20] + "..."
		}

		finding = fmt.Sprintf("%s%s%s%s%s\n", strings.TrimPrefix(strings.TrimLeft(start, " "), "\n"), matchBeginning, styledSecret, matchEnd, lineEnd)
		secretDisplay = styledSecret
	}

	if skipColor || isFileMatch {
		fmt.Printf("%-12s %s\n", "Finding:", f.Match)
		fmt.Printf("%-12s %s\n", "Secret:", f.Secret)
	} else {
		fmt.Printf("%-12s %s", "Finding:", finding)
		fmt.Printf("%-12s %s\n", "Secret:", secretDisplay)
	}

	fmt.Printf("%-12s %s\n", "RuleID:", f.RuleID)
	fmt.Printf("%-12s %f\n", "Entropy:", f.Entropy)

	if len(f.Tags) > 0 {
		fmt.Printf("%-12s %s\n", "Tags:", strings.Join(f.Tags, ", "))
	}

	if len(f.Attributes) > 0 {
		fmt.Printf("%-12s\n", "Attributes:")
		keys := make([]string, 0, len(f.Attributes))
		for k := range f.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			fmt.Printf("  %s: %s\n", k, f.Attributes[k])
		}
	}

	fmt.Printf("%-12s %d\n", "Line:", f.StartLine)
	fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)

	if f.Link != "" {
		fmt.Printf("%-12s %s\n", "Link:", f.Link)
	}

	if f.MatchContext != "" {
		fmt.Printf("%-12s\n%s\n", "Context:", formatMatchContextLegacy(f.MatchContext, f.Match, f.Secret, noColor))
	}

	printValidationLegacy(f, noColor)
	f.printRequiredFindingsLegacy(noColor, redact)
	fmt.Println("")
}

func (f *Finding) printRequiredFindingsLegacy(noColor bool, redact uint) {
	if len(f.RequiredSets) == 0 {
		return
	}

	fmt.Println("Required:")

	orangeStyle := color.New()
	if !noColor {
		orangeStyle = orangeStyle.Foreground("#bf9478")
	}

	for _, set := range f.RequiredSets {
		statusSuffix := ""
		if set.ValidationStatus != "" {
			statusSuffix = " " + formatSetStatusLegacy(set.ValidationStatus, noColor)
		}

		if len(set.Components) == 1 {
			comp := set.Components[0]
			secret := redactForDisplay(comp.Secret, redact)
			fmt.Printf("  - %s:%d: %s%s\n", comp.RuleID, comp.StartLine, orangeStyle.Render(secret), statusSuffix)
			continue
		}

		if statusSuffix != "" {
			fmt.Printf("  - %s\n", formatSetStatusLegacy(set.ValidationStatus, noColor))
		} else {
			fmt.Println("  -")
		}

		maxLabelLen := 0
		for _, comp := range set.Components {
			label := fmt.Sprintf("%s:%d:", comp.RuleID, comp.StartLine)
			if len(label) > maxLabelLen {
				maxLabelLen = len(label)
			}
		}

		for _, comp := range set.Components {
			secret := redactForDisplay(comp.Secret, redact)
			label := fmt.Sprintf("%s:%d:", comp.RuleID, comp.StartLine)
			fmt.Printf("    %-*s %s\n", maxLabelLen, label, orangeStyle.Render(secret))
		}
	}
}

func formatSetStatusLegacy(status string, noColor bool) string {
	if noColor {
		return "[" + strings.ToUpper(status) + "]"
	}
	var style color.Style
	switch status {
	case "valid":
		style = color.New().Foreground("#00d26a")
	case "needs_validation":
		style = color.New().Foreground("#60a5fa")
	case "invalid":
		style = color.New().Foreground("#888888")
	case "revoked":
		style = color.New().Foreground("#f5d445")
	case "error":
		style = color.New().Foreground("#f05c07")
	default:
		style = color.New().Foreground("#c0c0c0")
	}
	return style.Render("[" + strings.ToUpper(status) + "]")
}

func printValidationLegacy(f Finding, noColor bool) {
	if f.ValidationStatus == "" {
		return
	}

	statusStyle := validationStyle(f.ValidationStatus, noColor)

	fmt.Printf("%-12s %s", "Validation:", statusStyle.Render(strings.ToUpper(f.ValidationStatus)))
	if f.ValidationReason != "" {
		fmt.Printf("  (%s)", f.ValidationReason)
	}
	fmt.Println()

	metaStyle := color.New()
	if !noColor {
		metaStyle = metaStyle.Foreground("#9ca3af")
	}

	for _, k := range sortedMapKeys(f.ValidationMeta) {
		fmt.Printf("  %s\n", metaStyle.Render(fmt.Sprintf("%-10s %v", k+" =", f.ValidationMeta[k])))
	}
}

func validationStyle(status string, noColor bool) color.Style {
	if noColor {
		return color.New()
	}
	switch status {
	case "valid":
		return color.New().Bold().Foreground("#00d26a")
	case "needs_validation":
		return color.New().Bold().Foreground("#60a5fa")
	case "invalid":
		return color.New().Foreground("#888888")
	case "revoked":
		return color.New().Foreground("#f5d445")
	case "unknown":
		return color.New().Foreground("#c0c0c0")
	case "error":
		return color.New().Foreground("#f05c07")
	default:
		return color.New()
	}
}

func formatMatchContextLegacy(context string, match string, secret string, noColor bool) string {
	indent := "    "
	matchStyle := color.New().Foreground("#f5d445")
	secretStyle := color.New().Bold().Italic().Foreground("#f05c07")

	lines := strings.Split(context, "\n")
	for i, line := range lines {
		if !noColor {
			if secretIdx := strings.Index(line, secret); secret != "" && secretIdx != -1 {
				if matchIdx := strings.Index(line, match); match != "" && matchIdx != -1 {
					before, after, _ := strings.Cut(match, secret)
					highlighted := matchStyle.Render(before) +
						secretStyle.Render(secret) +
						matchStyle.Render(after)
					line = line[:matchIdx] + highlighted + line[matchIdx+len(match):]
				} else {
					line = line[:secretIdx] + secretStyle.Render(secret) + line[secretIdx+len(secret):]
				}
			}
		}
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}
