package report

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/sources"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedact(t *testing.T) {
	tests := []struct {
		findings []Finding
		redact   bool
	}{
		{
			redact: true,
			findings: []Finding{
				{
					Match:  "line containing secret",
					Secret: "secret",
				},
			}},
	}
	for _, test := range tests {
		for _, f := range test.findings {
			f.Redact(100)
			assert.Equal(t, "REDACTED", f.Secret)
			assert.Equal(t, "line containing REDACTED", f.Match)
		}
	}
}

// TestRedact_LineFromDifferentEncodingLayerIsBlanked covers a decode-depth
// finding: Secret is captured from decoded text, while Line intentionally
// stays as the original, still-encoded source (see detect.go), so Secret is
// never a literal substring of Line. Previously this silently left Line
// completely unredacted, containing the raw encoded secret; now it must be
// replaced with a safe placeholder instead of being displayed untouched.
func TestRedact_LineFromDifferentEncodingLayerIsBlanked(t *testing.T) {
	f := Finding{
		Match:  "secret: decoded-secret-value",
		Secret: "decoded-secret-value",
		Line:   "    secret: ZGVjb2RlZC1zZWNyZXQtdmFsdWU=", // base64 of the decoded value above
	}
	f.Redact(100)
	assert.Equal(t, "REDACTED", f.Secret)
	assert.Equal(t, "secret: REDACTED", f.Match)
	assert.Equal(t, redactedUnlocatable, f.Line)
	assert.NotContains(t, f.Line, "ZGVjb2RlZC1zZWNyZXQtdmFsdWU=")
}

func TestRedact_ComponentSets(t *testing.T) {
	f := Finding{
		Match:  "line containing secret",
		Secret: "secret",
		ComponentSets: []ComponentSet{
			{
				Components: []*ComponentFinding{
					{
						RuleID: "rule-a", Secret: "comp-secret-1", Line: "line comp-secret-1 here", Match: "match comp-secret-1 here",
						CaptureGroups: map[string]string{"token": "comp-secret-1", "label": "safe"},
					},
					{RuleID: "rule-b", Secret: "comp-secret-2", Match: "match comp-secret-2 here"},
				},
			},
		},
	}
	f.Redact(100)
	assert.Equal(t, "REDACTED", f.Secret)
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[0].Secret)
	assert.Equal(t, "line REDACTED here", f.ComponentSets[0].Components[0].Line)
	assert.Equal(t, "match REDACTED here", f.ComponentSets[0].Components[0].Match)
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[0].CaptureGroups["token"])
	assert.Equal(t, "safe", f.ComponentSets[0].Components[0].CaptureGroups["label"])
	assert.Equal(t, "REDACTED", f.ComponentSets[0].Components[1].Secret)
	assert.Equal(t, "match REDACTED here", f.ComponentSets[0].Components[1].Match)
}

func TestRedact_SharedPointerDedup(t *testing.T) {
	// When the same ComponentFinding pointer appears in multiple sets (Cartesian product),
	// partial redaction (percent < 100) must only mask the secret once.
	shared := &ComponentFinding{
		RuleID: "rule-a", Secret: "abcdefghij", Line: "line abcdefghij here", Match: "found abcdefghij here",
		CaptureGroups: map[string]string{"token": "abcdefghij"},
	}
	f := Finding{
		Match:  "primary",
		Secret: "primary",
		ComponentSets: []ComponentSet{
			{Components: []*ComponentFinding{shared}},
			{Components: []*ComponentFinding{shared}},
		},
	}
	f.Redact(75)
	// 75% mask on 10-char secret: RoundToEven(10 * 25/100) = 2 chars kept → "ab..."
	assert.Equal(t, "ab...", shared.Secret)
	assert.Equal(t, "line ab... here", shared.Line)
	assert.Equal(t, "found ab... here", shared.Match)
	assert.Equal(t, "ab...", shared.CaptureGroups["token"])
}

// TestRedactLineAndMatch exercises the fail-closed helper shared by
// Finding.Redact(), printPretty(), and PrintLegacy() directly, covering the
// same decode-depth-shaped mismatch as TestRedact_LineFromDifferentEncodingLayerIsBlanked.
// startColumn is 0 (unavailable) here, exercising the Contains-based fallback
// path — see TestRedactLine_PositionVerified* for the startColumn > 0 paths.
func TestRedactLineAndMatch(t *testing.T) {
	line, match, matchContext := redactLineAndMatch(
		"    secret: ZGVjb2RlZC1zZWNyZXQtdmFsdWU=", // Line: original, still-encoded source
		"secret: decoded-secret-value",              // Match: decoded-level, consistent with Secret
		"",
		"decoded-secret-value",
		"REDACTED",
		0,
	)
	assert.Equal(t, redactedUnlocatable, line)
	assert.Equal(t, "secret: REDACTED", match)
	assert.Equal(t, "", matchContext)
}

// TestRedactLine_PositionVerifiedReplacesExactSpan is the normal, common
// case: secret is a narrower capture group within match (e.g. after a
// "secret: " prefix, exactly like the generic-api-key rule), and
// secretOffsetInLine correctly combines startColumn (match's own offset)
// with secret's offset within match to find secret's real position.
func TestRedactLine_PositionVerifiedReplacesExactSpan(t *testing.T) {
	line := "secret: value"
	match := "secret: value" // match spans the whole line here
	startColumn := 1          // match starts at the beginning of line
	got := redactLine(line, match, "value", "REDACTED", startColumn)
	assert.Equal(t, "secret: REDACTED", got)
}

// TestRedactLine_ReplacesDuplicateOccurrences: once secret's position is
// verified, every identical occurrence in line is redacted, not just the
// verified one — a repeated token must not survive un-redacted just because
// only its first copy anchored the check.
func TestRedactLine_ReplacesDuplicateOccurrences(t *testing.T) {
	line := "token; token"
	match := "token"
	startColumn := 1 // match/secret both start at the first "token"
	got := redactLine(line, match, "token", "REDACTED", startColumn)
	assert.Equal(t, "REDACTED; REDACTED", got)
}

// TestRedactLine_DoesNotTrustUnrelatedCoincidentalOccurrence covers a
// decode-depth-shaped finding (match/secret both decoded-level, consistent
// with each other, but line kept in its original still-encoded form) where
// line additionally contains an unrelated plaintext copy of the decoded
// secret ahead of the real, encoded credential. secretOffsetInLine correctly
// locates where the real match should be, but verifying line's content
// there fails (it's still-encoded, not the decoded secret) — the
// coincidental plaintext copy earlier in line must not be mistaken for it.
func TestRedactLine_DoesNotTrustUnrelatedCoincidentalOccurrence(t *testing.T) {
	encoded := "ZGVjb2RlZC1zZWNyZXQtdmFsdWU="
	line := "# hint: decoded-secret-value secret: " + encoded
	match := "secret: decoded-secret-value" // decoded-level, consistent with secret
	startColumn := strings.Index(line, "secret: "+encoded) + 1 // where the real (encoded) match starts in line

	got := redactLine(line, match, "decoded-secret-value", "REDACTED", startColumn)

	assert.Equal(t, redactedUnlocatable, got)
	assert.NotContains(t, got, encoded, "the real, still-encoded secret must never survive un-redacted")
}

// TestRedactContext_PositionVerifiedViaLineAnchor covers MatchContext: since
// it isn't itself addressable by startColumn, verification anchors on line's
// own (already-verified) position within it.
func TestRedactContext_PositionVerifiedViaLineAnchor(t *testing.T) {
	line := "secret: value"
	match := "secret: value"
	matchContext := "before\n" + line + "\nafter"
	startColumn := 1

	got := redactContext(matchContext, line, match, "value", "REDACTED", startColumn)
	assert.Equal(t, "before\nsecret: REDACTED\nafter", got)
}

// TestRedactContext_DuplicateLineDoesNotLeaveRealOccurrenceRaw covers
// MatchContext containing two copies of the same line text: verification
// anchors on whichever copy strings.Index finds first, but since it then
// replaces every occurrence of the verified secret throughout matchContext
// (not just the anchored span), the real finding's copy is redacted too,
// regardless of which copy happened to anchor the check.
func TestRedactContext_DuplicateLineDoesNotLeaveRealOccurrenceRaw(t *testing.T) {
	line := "secret: value"
	match := "secret: value"
	matchContext := line + "\nunrelated\n" + line // line appears twice
	startColumn := 1

	got := redactContext(matchContext, line, match, "value", "REDACTED", startColumn)
	assert.Equal(t, "secret: REDACTED\nunrelated\nsecret: REDACTED", got)
}

// TestRedactContext_DoesNotTrustUnrelatedCoincidentalOccurrence is
// TestRedactLine_DoesNotTrustUnrelatedCoincidentalOccurrence's MatchContext
// counterpart: an unrelated plaintext copy of the secret elsewhere in the
// context window must not cause the real, still-encoded copy (anchored via
// line) to be mistaken for already-handled.
func TestRedactContext_DoesNotTrustUnrelatedCoincidentalOccurrence(t *testing.T) {
	encoded := "ZGVjb2RlZC1zZWNyZXQtdmFsdWU="
	line := "secret: " + encoded
	match := "secret: decoded-secret-value"
	matchContext := "# hint: decoded-secret-value\n" + line
	startColumn := 1 // match starts at the beginning of line

	got := redactContext(matchContext, line, match, "decoded-secret-value", "REDACTED", startColumn)

	assert.Equal(t, redactedUnlocatable, got)
	assert.NotContains(t, got, encoded)
}

// TestRedactContext_ClippedWindowFailsClosedNotLenient covers a column-based
// --match-context window clipped shorter than the full line: matchContext
// doesn't contain line intact even though a real position was established,
// so it must fail closed rather than falling through to the same lenient
// Contains-based search reserved for when no position exists at all — which
// here would incorrectly match an unrelated, coincidental occurrence.
func TestRedactContext_ClippedWindowFailsClosedNotLenient(t *testing.T) {
	line := "prefix secret: value suffix"
	match := "secret: value"
	startColumn := strings.Index(line, match) + 1
	matchContext := "unrelated value mention, not the real match"

	got := redactContext(matchContext, line, match, "value", "REDACTED", startColumn)

	assert.Equal(t, redactedUnlocatable, got)
}

// TestRedactLine_SkipsLeadingNewlineNotReflectedInStartColumn covers a
// multiline rule (e.g. "\n(secret)"): the detector trims a leading newline
// from Match/Secret without adjusting StartColumn, so StartColumn can still
// point at that newline byte in line rather than at match's actual first
// byte post-trim.
func TestRedactLine_SkipsLeadingNewlineNotReflectedInStartColumn(t *testing.T) {
	line := "prefix\nsecret-value"
	match := "secret-value" // already trimmed of its leading \n
	startColumn := strings.Index(line, "\n") + 1 // 1-indexed, pointing at the newline itself

	got := redactLine(line, match, "secret-value", "REDACTED", startColumn)

	assert.Equal(t, "prefix\nREDACTED", got)
}

// TestRedactLine_HandlesUntrimmedCRLFPrefix covers a CRLF-leading multiline
// rule (e.g. "\r\n(secret)"): the detector's strings.Trim(rawMatch, "\n")
// only strips a run of pure \n characters from the very edges, so a leading
// "\r\n" (whose first byte is \r, not in that cutset) is left completely
// untrimmed — match still holds it verbatim, unlike the pure-\n case above.
func TestRedactLine_HandlesUntrimmedCRLFPrefix(t *testing.T) {
	line := "\r\nsecret-value"
	match := "\r\nsecret-value" // untrimmed: detector's Trim didn't touch it
	startColumn := 1            // points at the leading \r

	got := redactLine(line, match, "secret-value", "REDACTED", startColumn)

	assert.Equal(t, "\r\nREDACTED", got)
}

// TestRedactLine_AmbiguousMatchOccurrenceFailsClosed covers the
// generic-credential-uri rule decoding a URI whose username coincidentally
// equals its decoded password (e.g.
// "https://plaintext-secret:<base64(plaintext-secret)>@host"), producing a
// decoded match where "plaintext-secret" appears twice: once as the harmless
// username, once as the actual captured secret. strings.Index alone can't
// tell them apart — trusting the first (username) occurrence would verify
// and redact it while leaving the real, still-encoded password elsewhere in
// line completely untouched.
func TestRedactLine_AmbiguousMatchOccurrenceFailsClosed(t *testing.T) {
	encoded := "cGxhaW50ZXh0LXNlY3JldA==" // base64("plaintext-secret")
	line := "https://plaintext-secret:" + encoded + "@host"
	match := "https://plaintext-secret:plaintext-secret@host" // decoded-level
	secret := "plaintext-secret"
	startColumn := 1 // match starts at the beginning of line

	got := redactLine(line, match, secret, "REDACTED", startColumn)

	assert.Equal(t, redactedUnlocatable, got)
	assert.NotContains(t, got, encoded, "the real, still-encoded password must never survive un-redacted")
}

// TestRedactContext_AnchorsDespiteMissingTrailingNewline covers box-mode
// MatchContext (see detect.go, contextwindow.extractBox), which ends at a
// line's trailing newline rather than past it, while Line itself (for any
// but the file's last line) includes that trailing newline — so the anchor
// lookup must still succeed via a trailing-newline-trimmed retry rather than
// failing closed on an otherwise perfectly ordinary finding.
func TestRedactContext_AnchorsDespiteMissingTrailingNewline(t *testing.T) {
	line := "secret: value\n"
	match := "secret: value"
	startColumn := 1
	matchContext := "before\nsecret: value" // no trailing \n on this line's copy

	got := redactContext(matchContext, line, match, "value", "REDACTED", startColumn)

	assert.Equal(t, "before\nsecret: REDACTED", got)
}

// sharedComponentFixture returns a Finding whose single ComponentSet holds a
// *ComponentFinding also returned separately, so a test can call a printer on
// the Finding and then assert the ComponentFinding's own fields are untouched
// — proving the printer didn't mutate data shared with the finding collector.
func sharedComponentFixture() (Finding, *ComponentFinding) {
	comp := &ComponentFinding{
		RuleID: "rule-a", Secret: "abcdefghij", Line: "line abcdefghij here", Match: "found abcdefghij here",
		CaptureGroups: map[string]string{"token": "abcdefghij"},
	}
	f := Finding{
		Match:         "primary",
		Secret:        "primary",
		ComponentSets: []ComponentSet{{Components: []*ComponentFinding{comp}}},
	}
	return f, comp
}

// TestPrintPrettyDoesNotMutateSharedComponentData guards against a
// regression where printPretty routed redaction through the full
// Finding.Redact(), which mutates the *ComponentFinding pointers and
// CaptureGroups map shared with the collector's copy of the same finding —
// causing double-redaction (e.g. a partial mask applied twice) once that
// finding was later written to a report, and once more within the very same
// print call via PrintComponentFindings' own masking.
func TestPrintPrettyDoesNotMutateSharedComponentData(t *testing.T) {
	f, comp := sharedComponentFixture()
	f.printPretty(true, 50)
	assert.Equal(t, "abcdefghij", comp.Secret, "printPretty must not mutate a shared ComponentFinding")
	assert.Equal(t, "line abcdefghij here", comp.Line)
	assert.Equal(t, "found abcdefghij here", comp.Match)
	assert.Equal(t, "abcdefghij", comp.CaptureGroups["token"])
}

// TestPrintLegacyDoesNotMutateSharedComponentData is the PrintLegacy
// counterpart to TestPrintPrettyDoesNotMutateSharedComponentData.
func TestPrintLegacyDoesNotMutateSharedComponentData(t *testing.T) {
	f, comp := sharedComponentFixture()
	f.PrintLegacy(true, 50)
	assert.Equal(t, "abcdefghij", comp.Secret, "PrintLegacy must not mutate a shared ComponentFinding")
	assert.Equal(t, "line abcdefghij here", comp.Line)
	assert.Equal(t, "found abcdefghij here", comp.Match)
	assert.Equal(t, "abcdefghij", comp.CaptureGroups["token"])
}

// TestPrintLegacyRedactsLineFromDifferentEncodingLayer covers the same
// decode-depth Secret/Line mismatch as TestRedact_LineFromDifferentEncodingLayerIsBlanked,
// but for PrintLegacy specifically: it used to run its own separate, ad hoc
// redaction that (like the pre-fix printPretty) silently left Line raw
// whenever Secret wasn't a literal substring of it.
func TestPrintLegacyRedactsLineFromDifferentEncodingLayer(t *testing.T) {
	f := Finding{
		Match:  "secret: decoded-secret-value",
		Secret: "decoded-secret-value",
		Line:   "    secret: ZGVjb2RlZC1zZWNyZXQtdmFsdWU=", // base64 of the decoded value above
	}

	out := capturePrintLegacyOutput(t, f, 100)

	// PrintLegacy has its own pre-existing fallback for when it can't locate
	// Match within Line (locateMatch returns -1): it prints Match directly
	// instead of a Line-derived snippet. Since Match/Secret share the same
	// (decoded) representation, that fallback already avoided a raw leak here
	// even before this fix — the real, previously-unfixed gap was that
	// PrintLegacy ran its own separate, non-fail-closed redaction at all
	// (this assertion pins down that no raw leak occurs, regardless of which
	// internal path produced the output).
	assert.NotContains(t, out, "ZGVjb2RlZC1zZWNyZXQtdmFsdWU=", "PrintLegacy must never print the raw, un-redacted line")
}

// TestPrintLegacyRedactsMatchContextFromDifferentEncodingLayer covers
// MatchContext, which — like Line — is sliced from the original,
// still-encoded fragment text (see detect.go), so it has the same
// Secret/representation mismatch risk for decode-depth findings. Unlike
// Line, PrintLegacy prints MatchContext's content directly and unconditionally
// via formatMatchContextLegacy whenever it's non-empty, with no fallback.
func TestPrintLegacyRedactsMatchContextFromDifferentEncodingLayer(t *testing.T) {
	f := Finding{
		Match:        "secret: decoded-secret-value",
		Secret:       "decoded-secret-value",
		Line:         "    secret: ZGVjb2RlZC1zZWNyZXQtdmFsdWU=",
		MatchContext: "context around:\n    secret: ZGVjb2RlZC1zZWNyZXQtdmFsdWU=\nmore context",
	}

	out := capturePrintLegacyOutput(t, f, 100)

	assert.NotContains(t, out, "ZGVjb2RlZC1zZWNyZXQtdmFsdWU=", "PrintLegacy must never print the raw, un-redacted match context")
	assert.Contains(t, out, redactedUnlocatable)
}

// capturePrintLegacyOutput redirects os.Stdout for the duration of a
// PrintLegacy call and returns everything it printed.
func capturePrintLegacyOutput(t *testing.T, f Finding, redact uint) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	f.PrintLegacy(true, redact)

	require.NoError(t, w.Close())
	os.Stdout = old
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestMask(t *testing.T) {

	tests := map[string]struct {
		finding Finding
		percent uint
		expect  Finding
	}{
		"normal secret": {
			finding: Finding{Match: "line containing secret", Secret: "secret"},
			expect:  Finding{Match: "line containing se...", Secret: "se..."},
			percent: 75,
		},
		"empty secret": {
			finding: Finding{Match: "line containing", Secret: ""},
			expect:  Finding{Match: "line containing", Secret: ""},
			percent: 75,
		},
		"short secret": {
			finding: Finding{Match: "line containing", Secret: "ss"},
			expect:  Finding{Match: "line containing", Secret: "..."},
			percent: 75,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f := test.finding
			e := test.expect
			f.Redact(test.percent)
			assert.Equal(t, e.Secret, f.Secret)
			assert.Equal(t, e.Match, f.Match)
		})
	}
}

func TestMaskSecret(t *testing.T) {

	tests := map[string]struct {
		secret  string
		percent uint
		expect  string
	}{
		"normal masking":  {secret: "secret", percent: 75, expect: "se..."},
		"high masking":    {secret: "secret", percent: 90, expect: "s..."},
		"low masking":     {secret: "secret", percent: 10, expect: "secre..."},
		"invalid masking": {secret: "secret", percent: 1000, expect: "..."},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got := MaskSecret(test.secret, test.percent)
			assert.Equal(t, test.expect, got)
		})
	}
}

func TestBuildComponentSets_Empty(t *testing.T) {
	f := &Finding{}
	f.BuildComponentSets(nil, 100)
	assert.Nil(t, f.ComponentSets)
}

func TestBuildComponentSets_SingleRuleSingleFinding(t *testing.T) {
	rf := &ComponentFinding{RuleID: "rule-a", Secret: "secret-a", StartLine: 1}
	f := &Finding{}
	f.BuildComponentSets([]*ComponentFinding{rf}, 100)

	require.Len(t, f.ComponentSets, 1)
	require.Len(t, f.ComponentSets[0].Components, 1)
	assert.Equal(t, "rule-a", f.ComponentSets[0].Components[0].RuleID)
	assert.Equal(t, "secret-a", f.ComponentSets[0].Components[0].Secret)
}

func TestBuildComponentSets_MultiRuleMultiFinding(t *testing.T) {
	reqs := []*ComponentFinding{
		{RuleID: "rule-a", Secret: "a1", StartLine: 1},
		{RuleID: "rule-a", Secret: "a2", StartLine: 2},
		{RuleID: "rule-b", Secret: "b1", StartLine: 3},
	}
	f := &Finding{}
	f.BuildComponentSets(reqs, 100)

	// 2 values for rule-a × 1 value for rule-b = 2 sets
	require.Len(t, f.ComponentSets, 2)
	for _, set := range f.ComponentSets {
		require.Len(t, set.Components, 2, "each set should have one component per rule")
		assert.Equal(t, "rule-a", set.Components[0].RuleID)
		assert.Equal(t, "rule-b", set.Components[1].RuleID)
	}
	// Verify distinct secrets in rule-a position.
	secrets := map[string]bool{
		f.ComponentSets[0].Components[0].Secret: true,
		f.ComponentSets[1].Components[0].Secret: true,
	}
	assert.True(t, secrets["a1"])
	assert.True(t, secrets["a2"])
}

func TestBuildComponentSets_MaxCap(t *testing.T) {
	// 3 × 3 = 9 sets, cap at 5
	reqs := []*ComponentFinding{
		{RuleID: "r1", Secret: "s1"},
		{RuleID: "r1", Secret: "s2"},
		{RuleID: "r1", Secret: "s3"},
		{RuleID: "r2", Secret: "t1"},
		{RuleID: "r2", Secret: "t2"},
		{RuleID: "r2", Secret: "t3"},
	}
	f := &Finding{}
	f.BuildComponentSets(reqs, 5)
	assert.Len(t, f.ComponentSets, 5)
}

func TestBuildComponentSets_JSONSerialization(t *testing.T) {
	reqs := []*ComponentFinding{
		{RuleID: "aws-secret", Secret: "wJalrXUtnFEMI", StartLine: 10},
		{RuleID: "aws-region", Optional: true, Secret: "us-east-1", StartLine: 11},
	}
	f := &Finding{
		RuleID: "aws-access-key",
		Secret: "AKIAIOSFODNN7EXAMPLE",
	}
	f.BuildComponentSets(reqs, 100)

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	sets, ok := parsed["ComponentSets"]
	require.True(t, ok, "ComponentSets should be present in JSON")
	assert.NotContains(t, parsed, "RequiredSets")
	setSlice, ok := sets.([]any)
	require.True(t, ok)
	require.Len(t, setSlice, 1)

	set := setSlice[0].(map[string]any)
	components := set["components"].([]any)
	require.Len(t, components, 2)
	assert.Equal(t, false, components[0].(map[string]any)["Optional"])
	assert.Equal(t, true, components[1].(map[string]any)["Optional"])
}

func TestFindingAttrFallsBackToDeprecatedFields(t *testing.T) {
	f := Finding{
		File:   "fallback.txt",
		Commit: "abc123",
		Author: "alice",
		Email:  "alice@example.com",
		Date:   "2026-04-13",
	}

	assert.Equal(t, "fallback.txt", f.Attr(sources.AttrPath))
	assert.Equal(t, "abc123", f.Attr(sources.AttrGitSHA))
	assert.Equal(t, "alice", f.Attr(sources.AttrGitAuthorName))
	assert.Equal(t, "alice@example.com", f.Attr(sources.AttrGitAuthorEmail))
	assert.Equal(t, "2026-04-13", f.Attr(sources.AttrGitDate))
}

func TestRedactMasksCaptureGroups(t *testing.T) {
	f := Finding{
		Secret: "supersecret",
		Match:  "key=supersecret",
		Line:   "api key=supersecret here",
		CaptureGroups: map[string]string{
			"token": "supersecret",
			"user":  "alice",
		},
	}
	f.Redact(100)

	if f.CaptureGroups["token"] != "REDACTED" {
		t.Errorf("capture group holding the secret must be redacted, got %q", f.CaptureGroups["token"])
	}
	if f.CaptureGroups["user"] != "alice" {
		t.Errorf("non-secret capture group should be left intact, got %q", f.CaptureGroups["user"])
	}
}

func TestRedactPartiallyMasksCaptureGroups(t *testing.T) {
	f := Finding{
		Secret:        "abcdefghij",
		CaptureGroups: map[string]string{"t": "abcdefghij"},
	}
	f.Redact(50)
	if want := MaskSecret("abcdefghij", 50); f.CaptureGroups["t"] != want {
		t.Errorf("capture group should be partially masked to %q, got %q", want, f.CaptureGroups["t"])
	}
}

func TestMaskSecretMultibyteUTF8(t *testing.T) {
	secret := "日本語パスワード" // 8 runes, 24 bytes

	// At 70% the old byte-based slice cut at byte 7 (inside the 3rd rune),
	// producing invalid UTF-8. The rune-based mask keeps whole runes.
	got := MaskSecret(secret, 70)
	if !utf8.ValidString(got) {
		t.Fatalf("masked multi-byte secret is not valid UTF-8: %q", got)
	}
	if want := string([]rune(secret)[:2]) + "..."; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
