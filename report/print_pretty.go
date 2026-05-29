package report

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/internal/color"
)

// terminalControlRe matches ANSI escape sequences and zero-width / disruptive
// control characters (CR, BS, BEL, VT, FF, NUL, …). These have byte length but
// zero or destructive display effects, so they must be removed before any
// caret math runs. Tab (\t) and newline (\n) are intentionally preserved.
var terminalControlRe = regexp.MustCompile(
	`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]`,
)

const (
	defaultTermCols = 100
	minTermCols     = 60
	tabStop         = 8
	windowEllipsis  = "…" // one rune, one display column
	maxHeadLines    = 3
	maxTailLines    = 1
	minLineNumWidth = 1
)

// terminalCols reads $COLUMNS, falling back to defaultTermCols. Re-read per finding
// so tests and resizes pick up new values without a process restart.
func terminalCols() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= minTermCols {
			return n
		}
	}
	return defaultTermCols
}

// displayWidth returns the number of display columns s occupies. Tabs are
// assumed to be pre-expanded (see expandTabsForBody). Every rune counts as one
// column — CJK / fullwidth / emoji are not double-counted. Secrets in practice
// are ASCII (base64, hex, tokens).
func displayWidth(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

func runePrefixWidth(s string, byteEnd int) int {
	if byteEnd > len(s) {
		byteEnd = len(s)
	}
	if byteEnd < 0 {
		byteEnd = 0
	}
	return displayWidth(s[:byteEnd])
}

// byteAtCol returns the byte index of the (targetCol+1)th rune in s. If targetCol
// is past the end, returns len(s).
func byteAtCol(s string, targetCol int) int {
	col := 0
	for i := range s {
		if col == targetCol {
			return i
		}
		col++
	}
	return len(s)
}

// expandTabsForBody replaces tabs in s with the spaces a terminal would render
// when s is printed starting at column gutterCols. The byte-offset mapping is
// (len(s)+1) long; mapping[i] holds the new byte offset for the rune that began
// at byte offset i in the original string. Inner bytes of multi-byte runes are
// not populated and should not be queried.
func expandTabsForBody(s string, gutterCols int) (string, []int) {
	mapping := make([]int, len(s)+1)
	var b strings.Builder
	col := gutterCols
	for i, r := range s {
		mapping[i] = b.Len()
		if r == '\t' {
			w := tabStop - (col % tabStop)
			for range w {
				b.WriteByte(' ')
			}
			col += w
			continue
		}
		b.WriteRune(r)
		col++
	}
	mapping[len(s)] = b.Len()
	return b.String(), mapping
}

func truncateRunes(s string, maxRunes int) (string, bool) {
	if maxRunes <= 0 {
		return "", true
	}
	n := 0
	for i := range s {
		if n == maxRunes {
			return s[:i], true
		}
		n++
	}
	return s, false
}

func lineNumWidth(startLine, lineCount int) int {
	maxLine := max(startLine+lineCount-1, 1)
	w := 0
	for maxLine > 0 {
		w++
		maxLine /= 10
	}
	if w < minLineNumWidth {
		return minLineNumWidth
	}
	return w
}

// normalizeSnippet trims trailing EOL on Line/Match/Secret, strips a leading
// \n/\r run from Line (detect/location often prepends one), and removes ANSI
// escape sequences so byte positions in Line equal display columns when
// rendered. StartColumn is reset because escape stripping shifts byte offsets;
// secretByteBounds will relocate the secret by searching.
func normalizeSnippet(f Finding) Finding {
	out := f
	out.Line = strings.TrimRight(f.Line, "\r\n")
	out.Match = strings.TrimRight(f.Match, "\r\n")
	out.Secret = strings.TrimRight(f.Secret, "\r\n")
	n := 0
	for n < len(out.Line) && (out.Line[n] == '\n' || out.Line[n] == '\r') {
		n++
	}
	if n > 0 {
		out.Line = out.Line[n:]
		if out.StartColumn > n {
			out.StartColumn -= n
		} else {
			out.StartColumn = 0
		}
	}
	if terminalControlRe.MatchString(out.Line) {
		out.Line = terminalControlRe.ReplaceAllString(out.Line, "")
		out.Match = terminalControlRe.ReplaceAllString(out.Match, "")
		out.Secret = terminalControlRe.ReplaceAllString(out.Secret, "")
		out.StartColumn = 0
	}
	return out
}

func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], "\r")
	}
	return lines
}

// segmentForSecret returns (segment index, byte offset within that segment) for
// the byte at secretStartByte inside multi-line text.
func segmentForSecret(text string, secretStartByte int) (segIdx, secretByteInSeg int) {
	if secretStartByte > len(text) {
		secretStartByte = len(text)
	}
	lineStart := 0
	for i := 0; i < secretStartByte; i++ {
		if text[i] == '\n' {
			segIdx++
			lineStart = i + 1
		}
	}
	return segIdx, secretStartByte - lineStart
}

// secretByteBounds locates the secret's start byte and length in line, using
// match and the optional 1-based column hint to disambiguate duplicates.
func secretByteBounds(line, match, secret string, startCol1 int) (start, length int, ok bool) {
	if secret == "" {
		mi := locateMatch(line, match, startCol1)
		if mi < 0 {
			mi = strings.Index(line, match)
		}
		if mi < 0 {
			return 0, 0, false
		}
		return mi, len(match), true
	}
	if mi := locateMatch(line, match, startCol1); mi >= 0 {
		if rel := strings.Index(match, secret); rel >= 0 {
			s := mi + rel
			if s+len(secret) <= len(line) && line[s:s+len(secret)] == secret {
				return s, len(secret), true
			}
		}
	}
	if si := strings.Index(line, secret); si >= 0 {
		return si, len(secret), true
	}
	if startCol1 > 0 {
		b := startCol1 - 1
		if b >= 0 && b+len(secret) <= len(line) && line[b:b+len(secret)] == secret {
			return b, len(secret), true
		}
	}
	return 0, 0, false
}

// windowLine fits a single line of (tab-expanded) text to budgetCols, centering
// on the secret. Returns:
//
//	display              -- the rendered line (with optional "…" prefix/suffix)
//	secretStartCol       -- columns from body start to the visible secret start
//	secretRenderedLenCol -- display width of the *visible* portion of the secret
//	secretTruncated      -- true if windowing clipped any of the secret
//
// All caret math downstream reads these display-column values directly — no
// byte-to-column conversions happen outside this function. Input must be
// tab-free (see expandTabsForBody).
func windowLine(line string, secretStartByte, secretLenByte, budgetCols int) (
	display string, secretStartCol, secretRenderedLenCol int, secretTruncated bool,
) {
	if budgetCols < 10 {
		budgetCols = 10
	}
	secretStartByte = max(secretStartByte, 0)
	secretStartByte = min(secretStartByte, len(line))
	secretEndByte := max(min(secretStartByte+secretLenByte, len(line)), secretStartByte)

	fullCols := displayWidth(line)
	secretStartColAbs := runePrefixWidth(line, secretStartByte)

	if fullCols <= budgetCols {
		secretRenderedLenCol = displayWidth(line[secretStartByte:secretEndByte])
		return line, secretStartColAbs, secretRenderedLenCol, false
	}

	// Need to window. Give the secret roughly a quarter of the budget as leading
	// context, then take the rest. Reserve up to 2 cols for "…" markers.
	contextBefore := max(budgetCols/4, 6)
	winStartCol := max(secretStartColAbs-contextBefore, 0)
	innerBudget := budgetCols - 2
	if innerBudget < 4 {
		innerBudget = budgetCols - 1
	}
	winEndCol := winStartCol + innerBudget
	if winEndCol > fullCols {
		winEndCol = fullCols
		winStartCol = max(winEndCol-innerBudget, 0)
	}

	winStartByte := byteAtCol(line, winStartCol)
	winEndByte := max(byteAtCol(line, winEndCol), winStartByte)

	hasLead := winStartByte > 0
	hasTrail := winEndByte < len(line)
	lead, trail := "", ""
	if hasLead {
		lead = windowEllipsis
	}
	if hasTrail {
		trail = windowEllipsis
	}
	display = lead + line[winStartByte:winEndByte] + trail
	leadCols := displayWidth(lead)

	winStartColActual := runePrefixWidth(line, winStartByte)
	if secretStartByte >= winStartByte {
		secretStartCol = leadCols + (secretStartColAbs - winStartColActual)
	} else {
		// Secret started before the window — anchor carets at the leading ellipsis.
		secretStartCol = leadCols
	}

	visStart := max(secretStartByte, winStartByte)
	visEnd := max(min(secretEndByte, winEndByte), visStart)
	secretRenderedLenCol = displayWidth(line[visStart:visEnd])

	secretTruncated = visStart != secretStartByte || visEnd != secretEndByte
	return display, secretStartCol, secretRenderedLenCol, secretTruncated
}

// fitToBudget trims s to budgetCols display columns, appending "…" if cut.
// Input must be tab-free.
func fitToBudget(s string, budgetCols int) string {
	s = strings.TrimRight(s, " \r")
	if displayWidth(s) <= budgetCols {
		return s
	}
	cut := byteAtCol(s, budgetCols-1)
	return s[:cut] + windowEllipsis
}

func redactForDisplay(secret string, redact uint) string {
	if redact > 0 {
		if redact >= 100 {
			return "REDACTED"
		}
		secret = MaskSecret(secret, redact)
	}
	secret = strings.TrimSpace(secret)
	if t, truncated := truncateRunes(secret, 40); truncated {
		return t + "..."
	}
	return secret
}

func prettySetIcon(status string, noColor bool) string {
	statusLower := strings.ToLower(strings.TrimSpace(status))
	var icon string
	switch statusLower {
	case "valid":
		icon = "✓"
	case "invalid", "error":
		icon = "✗"
	case "needs_validation":
		icon = "?"
	case "revoked":
		icon = "!"
	case "":
		icon = "-"
	default:
		icon = "?"
	}
	if noColor {
		return icon
	}
	switch statusLower {
	case "valid":
		return color.New().Foreground("#00d26a").Render(icon)
	case "invalid", "error":
		return color.New().Foreground("#888888").Render(icon)
	case "needs_validation":
		return color.New().Foreground("#60a5fa").Render(icon)
	case "revoked":
		return color.New().Foreground("#f5d445").Render(icon)
	default:
		return color.New().Foreground("#c0c0c0").Render(icon)
	}
}

func (f *Finding) PrintRequiredFindings(noColor bool, redact uint) {
	if len(f.RequiredSets) == 0 {
		return
	}

	sort.SliceStable(f.RequiredSets, func(i, j int) bool {
		return strings.ToLower(f.RequiredSets[i].ValidationStatus) == "valid" &&
			strings.ToLower(f.RequiredSets[j].ValidationStatus) != "valid"
	})

	hasValid := false
	for _, set := range f.RequiredSets {
		if strings.ToLower(set.ValidationStatus) == "valid" {
			hasValid = true
			break
		}
	}

	var toRender []RequiredSet
	maxKey := 0
	invalidCount := 0
	for _, set := range f.RequiredSets {
		if hasValid && strings.ToLower(set.ValidationStatus) != "valid" {
			invalidCount++
			continue
		}
		toRender = append(toRender, set)
		for _, comp := range set.Components {
			k := fmt.Sprintf("%s:%d", comp.RuleID, comp.StartLine)
			if len(k) > maxKey {
				maxKey = len(k)
			}
		}
	}

	cGrey := color.New().Foreground("#888888")
	fmt.Printf("│ components:\n")

	// Each set's first row carries the status icon; continuation rows leave the
	// icon column blank. The icon's presence-or-absence is the set delimiter.
	for _, set := range toRender {
		icon := prettySetIcon(set.ValidationStatus, noColor)
		for j, comp := range set.Components {
			key := fmt.Sprintf("%s:%d", comp.RuleID, comp.StartLine)
			dots := strings.Repeat(".", maxKey+6-len(key))
			val := redactForDisplay(comp.Secret, redact)
			if j == 0 {
				fmt.Printf("│   %s  %s %s %s\n", icon, key, dots, val)
			} else {
				fmt.Printf("│      %s %s %s\n", key, dots, val)
			}
		}
	}

	if invalidCount > 0 {
		summary := fmt.Sprintf("+ %d invalid set", invalidCount)
		if invalidCount > 1 {
			summary += "s"
		}
		if !noColor {
			summary = cGrey.Render(summary)
		}
		fmt.Printf("│   %s\n", summary)
	}
}

func writeHeader(f Finding) {
	fmt.Printf("┌─%s──○\n", f.RuleID)
	fmt.Println("│")
}

func writeRow(lineNum, pad int, body string) {
	fmt.Printf("│ %-*d │ %s\n", pad, lineNum, body)
}

func writeCaretRow(pad, padCols, ptrCols int, ptrTruncated bool, label string, noColor bool) {
	if ptrCols < 0 {
		ptrCols = 0
	}
	if padCols < 0 {
		padCols = 0
	}
	carets := strings.Repeat("^", ptrCols)
	if ptrTruncated && ptrCols >= 1 {
		// Replace the final "^" with "." to indicate truncation.
		carets = carets[:ptrCols-1] + "."
	}
	gutter := "│ " + strings.Repeat(" ", pad) + " │ "
	body := strings.Repeat(" ", padCols) + carets + label
	if !noColor {
		body = color.New().Bold().Foreground("#ef4444").Render(body)
	}
	fmt.Printf("%s%s\n", gutter, body)
}

func writeMoreLinesRow(pad, hidden int) {
	gutter := "│ " + strings.Repeat(" ", pad) + " │ "
	fmt.Printf("%s%s (%d more lines)\n", gutter, windowEllipsis, hidden)
}

func writeFooter() {
	fmt.Printf("└○\n\n\n")
}

func (f Finding) printPretty(noColor bool, redact uint) {
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

	if strings.HasPrefix(strings.TrimSpace(f.Match), "file detected:") {
		f.printPrettyFileOnly(noColor, redact)
		return
	}

	work := normalizeSnippet(f)
	writeHeader(work)

	rawLines := splitLines(work.Line)
	if len(rawLines) == 0 {
		rawLines = []string{""}
	}
	pad := lineNumWidth(work.StartLine, len(rawLines))
	// gutterCols is the terminal display width of "│ %*d │ " — 5 single-column
	// runes (│ + 2 spaces + │ + 1 separator space) plus `pad` digits.
	gutterCols := pad + 5
	budget := max(terminalCols()-gutterCols, minTermCols-10)

	// Pre-expand tabs in every line so byte positions in the rendered output
	// equal display columns. The caret pipeline below operates entirely on the
	// expanded text.
	lines := make([]string, len(rawLines))
	mappings := make([][]int, len(rawLines))
	for i, l := range rawLines {
		lines[i], mappings[i] = expandTabsForBody(l, gutterCols)
	}

	startByte, lenByte, ok := secretByteBounds(work.Line, work.Match, work.Secret, work.StartColumn)
	if !ok {
		renderLinesOnly(lines, work.StartLine, pad, budget)
		(&work).printPrettyMeta(noColor, redact)
		writeFooter()
		return
	}

	segIdx, secretByteInSegRaw := segmentForSecret(work.Line, startByte)
	segIdx = min(segIdx, len(lines)-1)
	mapping := mappings[segIdx]
	secretByteInSeg := mapping[min(secretByteInSegRaw, len(mapping)-1)]
	rawBytesInSeg := max(min(lenByte, len(rawLines[segIdx])-secretByteInSegRaw), 0)
	bytesInSeg := mapping[min(secretByteInSegRaw+rawBytesInSeg, len(mapping)-1)] - secretByteInSeg

	if len(lines) == 1 {
		renderLineWithCaret(lines[segIdx], work.StartLine, secretByteInSeg, bytesInSeg, lenByte, budget, pad, noColor)
	} else {
		renderMultiLine(lines, work.StartLine, segIdx, secretByteInSeg, bytesInSeg, lenByte, budget, pad, noColor)
	}

	(&work).printPrettyMeta(noColor, redact)
	writeFooter()
}

func renderLineWithCaret(secretLine string, lineNum, secretByteInSeg, bytesInSeg, fullSecretLen, budget, pad int, noColor bool) {
	display, secretStartCol, secretLenCol, winTrunc := windowLine(secretLine, secretByteInSeg, bytesInSeg, budget)
	writeRow(lineNum, pad, display)

	ptrTrunc := winTrunc || bytesInSeg < fullSecretLen
	label := ""
	if ptrTrunc {
		label = fmt.Sprintf(" (%d bytes)", fullSecretLen)
	}
	writeCaretRow(pad, secretStartCol, secretLenCol, ptrTrunc, label, noColor)
}

func renderLinesOnly(lines []string, startLine, pad, budget int) {
	n := len(lines)
	mark := make([]bool, n)
	for i := 0; i < maxHeadLines && i < n; i++ {
		mark[i] = true
	}
	for i := n - maxTailLines; i < n; i++ {
		if i >= 0 {
			mark[i] = true
		}
	}
	for i := 0; i < n; i++ {
		if mark[i] {
			writeRow(startLine+i, pad, fitToBudget(lines[i], budget))
			continue
		}
		j := i
		for j < n && !mark[j] {
			j++
		}
		writeMoreLinesRow(pad, j-i)
		i = j - 1
	}
}

func renderMultiLine(lines []string, startLine, segIdx, secretByteInSeg, bytesInSeg, fullSecretLen, budget, pad int, noColor bool) {
	n := len(lines)
	mark := make([]bool, n)
	for i := 0; i < maxHeadLines && i < n; i++ {
		mark[i] = true
	}
	for i := n - maxTailLines; i < n; i++ {
		if i >= 0 {
			mark[i] = true
		}
	}
	mark[segIdx] = true // always show the secret's line

	emitLine := func(i int) {
		if i == segIdx {
			renderLineWithCaret(lines[i], startLine+i, secretByteInSeg, bytesInSeg, fullSecretLen, budget, pad, noColor)
			return
		}
		writeRow(startLine+i, pad, fitToBudget(lines[i], budget))
	}

	for i := 0; i < n; i++ {
		if mark[i] {
			emitLine(i)
			continue
		}
		j := i
		for j < n && !mark[j] {
			j++
		}
		writeMoreLinesRow(pad, j-i)
		i = j - 1
	}
}

func (f Finding) printPrettyFileOnly(noColor bool, redact uint) {
	f.Match = strings.TrimRight(f.Match, "\r\n")
	f.Secret = strings.TrimRight(f.Secret, "\r\n")

	writeHeader(f)
	fp := &f
	fp.printPrettyMeta(noColor, redact)
	writeFooter()
}

// dotLeader prints "│   <key> <dots> <value>" where dots pad so that
// `key + " " + dots` aligns to a fixed width of `maxKey + 7` columns (matching
// the longest key, with a minimum of 6 trailing dots after it).
func dotLeader(key, value string, maxKey int) {
	dots := strings.Repeat(".", maxKey+6-len(key))
	fmt.Printf("│   %s %s %s\n", key, dots, value)
}

func (f *Finding) printPrettyMeta(noColor bool, redact uint) {
	if len(f.Attributes) > 0 {
		fmt.Println("│")
		fmt.Printf("│ attributes:\n")
		maxK := 0
		keys := make([]string, 0, len(f.Attributes))
		for k := range f.Attributes {
			keys = append(keys, k)
			if len(k) > maxK {
				maxK = len(k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			dotLeader(k, f.Attributes[k], maxK)
		}
	}
	if f.ValidationStatus != "" {
		fmt.Printf("│ validation:\n")
		maxVK := 6 // "status"/"reason" baseline
		vk := sortedMapKeys(f.ValidationMeta)
		for _, k := range vk {
			if len(k) > maxVK {
				maxVK = len(k)
			}
		}
		vs := strings.ToUpper(f.ValidationStatus)
		if !noColor {
			vs = validationStyle(f.ValidationStatus, noColor).Render(vs)
		}
		dotLeader("status", vs, maxVK)
		if f.ValidationReason != "" {
			dotLeader("reason", f.ValidationReason, maxVK)
		}
		for _, k := range vk {
			dotLeader(k, fmt.Sprintf("%v", f.ValidationMeta[k]), maxVK)
		}
	}
	f.PrintRequiredFindings(noColor, redact)
}
