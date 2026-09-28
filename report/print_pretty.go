package report

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/v2/internal/color"
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

// PrettyOptions controls presentation without consulting process-global state.
type PrettyOptions struct {
	NoColor bool
	Redact  uint
	// Width is the terminal width in columns. Zero uses 100; values below 60 use 60.
	Width int
}

// WritePretty writes one finding to w. The caller owns the writer.
func WritePretty(w io.Writer, finding Finding, options PrettyOptions) error {
	if w == nil {
		return errors.New("report writer is nil")
	}
	if options.Width == 0 {
		options.Width = defaultTermCols
	}
	p := prettyRenderer{w: w, width: max(options.Width, minTermCols)}
	p.finding(finding, options.NoColor, options.Redact)
	return p.err
}

type prettyRenderer struct {
	w     io.Writer
	width int
	err   error
}

func (p *prettyRenderer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

func (p *prettyRenderer) println(args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintln(p.w, args...)
	}
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

// escapeSnippet makes binary bytes and terminal controls visible without
// letting them alter the terminal. Tabs and newlines keep their layout meaning.
func escapeSnippet(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		part := s[:size]
		s = s[size:]
		if (r == utf8.RuneError && size == 1) || (r != '\t' && r != '\n' && !unicode.IsPrint(r)) {
			quoted := strconv.Quote(part)
			b.WriteString(quoted[1 : len(quoted)-1])
		} else {
			b.WriteString(part)
		}
	}
	return b.String()
}

// normalizeSnippet changes presentation only. Preserve the column hint through
// escaping so repeated secrets still highlight the correct occurrence.
func normalizeSnippet(f Finding) Finding {
	out := f
	out.Match.Line = strings.TrimRight(f.Match.Line, "\r\n")
	out.Match.Full = strings.TrimRight(f.Match.Full, "\r\n")
	out.Match.Value = strings.TrimRight(f.Match.Value, "\r\n")
	n := 0
	for n < len(out.Match.Line) && (out.Match.Line[n] == '\n' || out.Match.Line[n] == '\r') {
		n++
	}
	if n > 0 {
		out.Match.Line = out.Match.Line[n:]
		if out.Location.StartColumn > n {
			out.Location.StartColumn -= n
		} else {
			out.Location.StartColumn = 0
		}
	}
	if out.Location.StartColumn > 0 {
		prefix := out.Match.Line[:min(out.Location.StartColumn-1, len(out.Match.Line))]
		out.Location.StartColumn = len(escapeSnippet(prefix)) + 1
	}
	out.Match.Line = escapeSnippet(out.Match.Line)
	out.Match.Full = escapeSnippet(out.Match.Full)
	out.Match.Value = escapeSnippet(out.Match.Value)
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

func (p *prettyRenderer) components(f Finding, noColor bool, redact uint) {
	if f.ComponentSetsTruncated {
		p.println("│ components: combination limit reached; additional combinations omitted")
	}
	if len(f.ComponentSets) == 0 {
		return
	}

	sets := slices.Clone(f.ComponentSets)
	sort.SliceStable(sets, func(i, j int) bool {
		return sets[i].Analysis.Status == ValidationStatusValid &&
			sets[j].Analysis.Status != ValidationStatusValid
	})

	hasValid := false
	for _, set := range sets {
		if set.Analysis.Status == ValidationStatusValid {
			hasValid = true
			break
		}
	}

	var toRender []ComponentSet
	maxKey := 0
	invalidCount := 0
	for _, set := range sets {
		if hasValid && set.Analysis.Status != ValidationStatusValid {
			invalidCount++
			continue
		}
		toRender = append(toRender, set)
		for _, comp := range set.Components {
			k := fmt.Sprintf("%s:%d", comp.RuleID, comp.Location.StartLine)
			if len(k) > maxKey {
				maxKey = len(k)
			}
		}
	}

	cGrey := color.New().Foreground("#888888")
	p.printf("│ components:\n")

	// Each set's first row carries the status icon; continuation rows leave the
	// icon column blank. The icon's presence-or-absence is the set delimiter.
	for _, set := range toRender {
		icon := prettySetIcon(string(set.Analysis.Status), noColor)
		for j, comp := range set.Components {
			key := fmt.Sprintf("%s:%d", comp.RuleID, comp.Location.StartLine)
			dots := strings.Repeat(".", maxKey+6-len(key))
			val := redactForDisplay(comp.Match.Value, redact)
			if j == 0 {
				p.printf("│   %s  %s %s %s\n", icon, key, dots, val)
			} else {
				p.printf("│      %s %s %s\n", key, dots, val)
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
		p.printf("│   %s\n", summary)
	}
}

func (p *prettyRenderer) writeHeader(f Finding) {
	p.printf("┌─%s──○\n", f.RuleID)
	p.println("│")
}

func (p *prettyRenderer) writeRow(lineNum, pad int, body string) {
	p.printf("│ %-*d │ %s\n", pad, lineNum, body)
}

func (p *prettyRenderer) writeCaretRow(pad, padCols, ptrCols int, ptrTruncated bool, label string, noColor bool) {
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
	p.printf("%s%s\n", gutter, body)
}

func (p *prettyRenderer) writeMoreLinesRow(pad, hidden int) {
	gutter := "│ " + strings.Repeat(" ", pad) + " │ "
	p.printf("%s%s (%d more lines)\n", gutter, windowEllipsis, hidden)
}

func (p *prettyRenderer) writeFooter() {
	p.printf("└○\n\n\n")
}

func (p *prettyRenderer) finding(f Finding, noColor bool, redact uint) {
	if redact > 0 {
		f = f.RedactedCopy(redact)
		redact = 0 // Component values were already masked with the full finding.
	}

	if strings.HasPrefix(strings.TrimSpace(f.Match.Full), "file detected:") {
		p.fileOnly(f, noColor, redact)
		return
	}

	work := f
	decoded := len(f.Encodings) > 0
	if decoded {
		// Source coordinates refer to the encoded bytes. Use the decoded match
		// for the preview so the usual caret can point to the extracted secret.
		work.Match.Line = work.Match.Full
		if work.Match.Line == "" {
			work.Match.Line = work.Match.Value
		}
		work.Location.StartColumn = 1
	}
	if work.Match.Value != "" && (decoded || hasBinaryBytes(work.Match.Line)) {
		p.writeHeader(f)
		p.binarySnippet(work, noColor)
		p.meta(f, noColor, redact)
		p.writeFooter()
		return
	}
	work = normalizeSnippet(work)
	p.writeHeader(work)

	rawLines := splitLines(work.Match.Line)
	if len(rawLines) == 0 {
		rawLines = []string{""}
	}
	pad := lineNumWidth(work.Location.StartLine, len(rawLines))
	// gutterCols is the terminal display width of "│ %*d │ " — 5 single-column
	// runes (│ + 2 spaces + │ + 1 separator space) plus `pad` digits.
	gutterCols := pad + 5
	budget := max(p.width-gutterCols, minTermCols-10)

	// Pre-expand tabs in every line so byte positions in the rendered output
	// equal display columns. The caret pipeline below operates entirely on the
	// expanded text.
	lines := make([]string, len(rawLines))
	mappings := make([][]int, len(rawLines))
	for i, l := range rawLines {
		lines[i], mappings[i] = expandTabsForBody(l, gutterCols)
	}

	startByte, lenByte, ok := secretByteBounds(work.Match.Line, work.Match.Full, work.Match.Value, work.Location.StartColumn)
	if !ok {
		if f.Match.Value == "" {
			p.renderLinesOnly(lines, work.Location.StartLine, pad, budget)
		} else {
			p.printf("│ value: %s\n", fitToBudget(strconv.QuoteToGraphic(f.Match.Value), p.width-9))
			p.printf("│ source: line %d, column %d\n", f.Location.StartLine, f.Location.StartColumn)
		}
		p.meta(work, noColor, redact)
		p.writeFooter()
		return
	}

	segIdx, secretByteInSegRaw := segmentForSecret(work.Match.Line, startByte)
	segIdx = min(segIdx, len(lines)-1)
	mapping := mappings[segIdx]
	secretByteInSeg := mapping[min(secretByteInSegRaw, len(mapping)-1)]
	rawBytesInSeg := max(min(lenByte, len(rawLines[segIdx])-secretByteInSegRaw), 0)
	bytesInSeg := mapping[min(secretByteInSegRaw+rawBytesInSeg, len(mapping)-1)] - secretByteInSeg

	if len(lines) == 1 {
		p.renderLineWithCaret(lines[segIdx], work.Location.StartLine, secretByteInSeg, bytesInSeg, lenByte, budget, pad, noColor)
	} else {
		p.renderMultiLine(lines, work.Location.StartLine, segIdx, secretByteInSeg, bytesInSeg, lenByte, budget, pad, noColor)
	}

	p.meta(work, noColor, redact)
	p.writeFooter()
}

func (p *prettyRenderer) renderLineWithCaret(secretLine string, lineNum, secretByteInSeg, bytesInSeg, fullSecretLen, budget, pad int, noColor bool) {
	display, secretStartCol, secretLenCol, winTrunc := windowLine(secretLine, secretByteInSeg, bytesInSeg, budget)
	p.writeRow(lineNum, pad, display)

	ptrTrunc := winTrunc || bytesInSeg < fullSecretLen
	label := ""
	if ptrTrunc {
		label = fmt.Sprintf(" (%d bytes)", fullSecretLen)
	}
	p.writeCaretRow(pad, secretStartCol, secretLenCol, ptrTrunc, label, noColor)
}

func hasBinaryBytes(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool {
		return r != '\n' && r != '\r' && r != '\t' && !unicode.IsPrint(r)
	})
}

// readableContext keeps binary runs from joining otherwise unrelated strings.
// Whitespace is flattened because this preview has no source-line gutter.
func readableContext(s string) string {
	var b strings.Builder
	inBinary := false
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		part := s[:size]
		s = s[size:]
		if r == '\n' || r == '\r' || r == '\t' {
			b.WriteByte(' ')
			inBinary = false
		} else if (r == utf8.RuneError && size == 1) || !unicode.IsPrint(r) {
			if !inBinary {
				b.WriteString(" ⟨binary⟩ ")
			}
			inBinary = true
		} else {
			b.WriteString(part)
			inBinary = false
		}
	}
	return b.String()
}

func (p *prettyRenderer) binarySnippet(f Finding, noColor bool) {
	line := f.Match.Line
	start, length, ok := secretByteBounds(line, f.Match.Full, f.Match.Value, f.Location.StartColumn)
	if !ok {
		line = f.Match.Full
		start, length, ok = secretByteBounds(line, f.Match.Full, f.Match.Value, 1)
		if !ok {
			line, start, length = f.Match.Value, 0, len(f.Match.Value)
		}
	}
	prefix := readableContext(line[:start])
	// Never collapse bytes inside the secret itself: escaped bytes must remain
	// visible and covered by the caret, even when surrounding bytes are omitted.
	quoted := strconv.QuoteToGraphic(line[start : start+length])
	secret := quoted[1 : len(quoted)-1]
	text := prefix + secret + readableContext(line[start+length:])
	pad := lineNumWidth(f.Location.StartLine, 1)
	budget := max(p.width-pad-5, minTermCols-10)
	p.renderLineWithCaret(text, f.Location.StartLine, len(prefix), len(secret), length, budget, pad, noColor)
}

func (p *prettyRenderer) renderLinesOnly(lines []string, startLine, pad, budget int) {
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
			p.writeRow(startLine+i, pad, fitToBudget(lines[i], budget))
			continue
		}
		j := i
		for j < n && !mark[j] {
			j++
		}
		p.writeMoreLinesRow(pad, j-i)
		i = j - 1
	}
}

func (p *prettyRenderer) renderMultiLine(lines []string, startLine, segIdx, secretByteInSeg, bytesInSeg, fullSecretLen, budget, pad int, noColor bool) {
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
			p.renderLineWithCaret(lines[i], startLine+i, secretByteInSeg, bytesInSeg, fullSecretLen, budget, pad, noColor)
			return
		}
		p.writeRow(startLine+i, pad, fitToBudget(lines[i], budget))
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
		p.writeMoreLinesRow(pad, j-i)
		i = j - 1
	}
}

func (p *prettyRenderer) fileOnly(f Finding, noColor bool, redact uint) {
	f.Match.Full = strings.TrimRight(f.Match.Full, "\r\n")
	f.Match.Value = strings.TrimRight(f.Match.Value, "\r\n")

	p.writeHeader(f)
	p.meta(f, noColor, redact)
	p.writeFooter()
}

// dotLeader prints "│   <key> <dots> <value>" where dots pad so that
// `key + " " + dots` aligns to a fixed width of `maxKey + 7` columns (matching
// the longest key, with a minimum of 6 trailing dots after it).
func (p *prettyRenderer) dotLeader(key, value string, maxKey int) {
	dots := strings.Repeat(".", maxKey+6-len(key))
	p.printf("│   %s %s %s\n", key, dots, value)
}

func (p *prettyRenderer) meta(f Finding, noColor bool, redact uint) {
	encodings := f.Encodings
	if f.Location.Path != "" || f.Confidence != "" || len(encodings) > 0 {
		maxKey := len("path")
		if len(encodings) > 0 {
			maxKey = len("encoding")
		}
		if f.Confidence != "" {
			maxKey = len("confidence")
		}
		p.println("│")
		if f.Location.Path != "" {
			p.dotLeader("path", f.Location.Path, maxKey)
		}
		if f.Confidence != "" {
			p.dotLeader("confidence", strings.ToUpper(f.Confidence), maxKey)
		}
		if len(encodings) > 0 {
			p.dotLeader("encoding", strings.Join(encodings, ", "), maxKey)
		}
	}
	attributes := reportAttributes(f.Attributes)
	if len(attributes) > 0 {
		if f.Location.Path == "" && f.Confidence == "" && len(encodings) == 0 {
			p.println("│")
		}
		p.printf("│ attributes:\n")
		maxK := 0
		keys := make([]string, 0, len(attributes))
		for k := range attributes {
			keys = append(keys, k)
			if len(k) > maxK {
				maxK = len(k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			p.dotLeader(k, attributes[k], maxK)
		}
	}
	if !f.Analysis.IsZero() {
		p.analysis(f, noColor)
	}
	p.components(f, noColor, redact)
}

func analysisDisplayValues(analysis Analysis, noColor bool) map[string]string {
	values := map[string]string{
		"status":        formatCredentialStatus(analysis.Status, noColor),
		"severity":      formatAnalysisSeverity(analysis.Severity, noColor),
		"status_reason": analysis.StatusReason,
		"capabilities":  capabilitiesText(analysis.Capabilities),
	}
	if identity := analysis.Identity; identity != nil {
		values["identity.id"] = identity.ID
		values["identity.username"] = identity.Username
		values["identity.name"] = identity.Name
		values["identity.email"] = identity.Email
		if account := identity.Account; account != nil {
			values["identity.account.id"] = account.ID
			values["identity.account.name"] = account.Name
			values["identity.account.domains"] = strings.Join(account.Domains, ", ")
		}
	}
	for key, value := range analysis.Debug {
		values["debug."+key] = fmt.Sprintf("%v", value)
	}
	for key, value := range analysis.StatusMetadata {
		values["status_metadata."+key] = formatMetadataValue(value)
	}
	for key, value := range analysis.Metadata {
		values["metadata."+key] = formatMetadataValue(value)
	}

	return values
}

func (p *prettyRenderer) analysis(f Finding, noColor bool) {
	values := analysisDisplayValues(f.Analysis, noColor)

	keys := make([]string, 0, len(values))
	maxKey := 0
	for key, value := range values {
		if value == "" {
			continue
		}
		keys = append(keys, key)
		maxKey = max(maxKey, len(key))
	}
	sort.Strings(keys)
	p.printf("│ analysis:\n")
	for _, key := range keys {
		p.dotLeader(key, values[key], maxKey)
	}
}

func formatAnalysisSeverity(severity Severity, noColor bool) string {
	text := strings.ToUpper(string(severity))
	return severityStyle(severity, noColor).Render(text)
}

func capabilitiesText(capabilities []Capability) string {
	values := make([]string, len(capabilities))
	for i, capability := range capabilities {
		values[i] = string(capability)
	}
	return strings.Join(values, ", ")
}
