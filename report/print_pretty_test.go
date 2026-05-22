package report

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func capturePrettyStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	fn()

	require.NoError(t, w.Close())
	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	os.Stdout = old
	return buf.String()
}

// snippetAndCaret returns the snippet row (the line before the caret row) and
// the caret row from rendered output.
func snippetAndCaret(t *testing.T, out string) (snippet, caret string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "^") && i > 0 {
			return lines[i-1], l
		}
	}
	return "", ""
}

// bodyDispCol returns the display column (rune count) of substr within the body
// area of a rendered row. The body area is everything past the "│ <n> │ "
// gutter. Returns -1 if not found.
func bodyDispCol(t *testing.T, row, substr string) int {
	t.Helper()
	first := strings.Index(row, "│")
	require.GreaterOrEqual(t, first, 0, "no │ in row: %q", row)
	rest := row[first+len("│"):]
	second := strings.Index(rest, "│")
	require.GreaterOrEqual(t, second, 0, "no second │ in row: %q", row)
	bodyStart := first + len("│") + second + len("│") + 1
	if bodyStart > len(row) {
		return -1
	}
	body := row[bodyStart:]
	before, _, found := strings.Cut(body, substr)
	if !found {
		return -1
	}
	col := 0
	for range before {
		col++
	}
	return col
}

// TestPrintPretty_ASCIIMidLineCaret pins the canonical case: an ASCII secret
// in the middle of a short line, terminal wide enough to show everything.
// The caret row must start at the same byte offset as the secret in the snippet
// row — regression test for the byte/column-conflation bug.
func TestPrintPretty_ASCIIMidLineCaret(t *testing.T) {
	t.Setenv("COLUMNS", "120")
	f := Finding{
		RuleID:      "aws-amazon-bedrock-api-key-short-lived",
		StartLine:   233,
		StartColumn: 12,
		Match:       "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
		Secret:      "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
		Line:        "regex = '''bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t'''",
		Fingerprint: "config/betterleaks.toml:bedrock:233",
		Attributes:  map[string]string{"path": "config/betterleaks.toml"},
	}

	out := capturePrettyStdout(t, func() { f.Print(true, 0) })
	snippet, caret := snippetAndCaret(t, out)
	require.NotEmpty(t, snippet, "snippet row not found in:\n%s", out)
	require.NotEmpty(t, caret, "caret row not found in:\n%s", out)

	bIdx := strings.Index(snippet, "bedrock")
	caretIdx := strings.Index(caret, "^")
	assert.Equal(t, bIdx, caretIdx,
		"carets must start at the same byte offset as the secret\nsnippet=%q\ncaret=%q", snippet, caret)

	assert.Equal(t, 44, strings.Count(caret, "^"),
		"expected 44 carets for 44-byte secret, got %q", caret)
	assert.NotContains(t, caret, "bytes)", "no (N bytes) suffix expected when secret fits")
	assert.NotContains(t, caret, "secret [", "secret [line:col] label must be removed")
}

// TestPrintPretty_LongSecretTruncatedCaret pins truncation: a 176-byte secret
// on a 120-col terminal must produce a windowed snippet, carets only under the
// *visible* portion of the secret, a trailing "." marker, and "(176 bytes)" in
// the label.
func TestPrintPretty_LongSecretTruncatedCaret(t *testing.T) {
	t.Setenv("COLUMNS", "120")
	longSecret := strings.Repeat("a", 176)
	prefix := strings.Repeat("x", 52)
	f := Finding{
		RuleID:      "cloudflare-origin-ca-key",
		StartLine:   76,
		StartColumn: 53,
		Match:       longSecret,
		Secret:      longSecret,
		Line:        prefix + longSecret + ")",
		Fingerprint: "config/long.go:long:76",
		Attributes:  map[string]string{"path": "config/long.go"},
	}

	out := capturePrettyStdout(t, func() { f.Print(true, 0) })
	_, caret := snippetAndCaret(t, out)
	require.NotEmpty(t, caret, "caret row not found in:\n%s", out)

	assert.Contains(t, caret, "(176 bytes)", "label must include full secret byte count")
	caretGroup := caret[strings.Index(caret, "^"):strings.Index(caret, " (")]
	assert.True(t, strings.HasSuffix(caretGroup, "."),
		"expected trailing '.' truncation marker in caret group %q", caretGroup)
	assert.Greater(t, strings.Count(caretGroup, "^"), 10,
		"expected the visible secret portion to be covered by carets, got %q", caretGroup)
}

// TestPrintPretty_ANSIEscapeStripping locks the ANSI/control fix: GitHub Actions
// logs (and similar sources) include zero-width escape sequences whose bytes
// previously offset caret math. Carets must still land under the secret after
// escapes are stripped from the rendered output.
func TestPrintPretty_ANSIEscapeStripping(t *testing.T) {
	t.Setenv("COLUMNS", "120")
	secret := "xoxs-416843729158-132049654-5609968301-e708ba56e1"
	line := "2025-10-15T15:09:08Z \x1b[36m##[debug]\x1b[0m slack-legacy-token value=\"slackToken=\\\"" + secret + "\\\"\""
	f := Finding{
		RuleID:      "slack-legacy-token",
		StartLine:   11295,
		StartColumn: strings.Index(line, secret) + 1,
		Match:       secret,
		Secret:      secret,
		Line:        line,
		Attributes:  map[string]string{"path": "actions.log"},
	}

	out := capturePrettyStdout(t, func() { f.Print(true, 0) })
	snippet, caret := snippetAndCaret(t, out)
	require.NotEmpty(t, snippet, "snippet row not found in:\n%s", out)
	require.NotEmpty(t, caret, "caret row not found in:\n%s", out)

	assert.NotContains(t, snippet, "\x1b", "escape bytes must be stripped from snippet")
	secretCol := bodyDispCol(t, snippet, "xoxs")
	caretCol := bodyDispCol(t, caret, "^")
	assert.Equal(t, secretCol, caretCol,
		"carets must align with secret in display columns\nsnippet=%q\ncaret=%q", snippet, caret)
}

// TestPrintPretty_TabPrefixAlignment locks the tab-handling fix: a tab in the
// line shifts the secret on screen based on its terminal column, not byte
// position. Carets must still land directly under the secret.
func TestPrintPretty_TabPrefixAlignment(t *testing.T) {
	t.Setenv("COLUMNS", "120")
	// Use the same shape as the atlassian-api-token finding that surfaced the
	// bug: tab-indented Go source with the secret embedded in a backtick string.
	line := "\ttps = append(tps, `JIRA_API_TOKEN=HXe8DGg1iJd2AopzyxkFB7F2`)"
	f := Finding{
		RuleID:      "atlassian-api-token",
		StartLine:   30,
		StartColumn: strings.Index(line, "HXe8") + 1,
		Match:       "HXe8DGg1iJd2AopzyxkFB7F2",
		Secret:      "HXe8DGg1iJd2AopzyxkFB7F2",
		Line:        line,
		Fingerprint: "config/atlassian.go:jira:30",
		Attributes:  map[string]string{"path": "config/atlassian.go"},
	}

	out := capturePrettyStdout(t, func() { f.Print(true, 0) })
	snippet, caret := snippetAndCaret(t, out)
	require.NotEmpty(t, snippet, "snippet row not found in:\n%s", out)
	require.NotEmpty(t, caret, "caret row not found in:\n%s", out)

	secretIdx := strings.Index(snippet, "HXe8")
	caretIdx := strings.Index(caret, "^")
	assert.Equal(t, secretIdx, caretIdx,
		"carets must align under secret even with a leading tab\nsnippet=%q\ncaret=%q", snippet, caret)
}
