package detect

import (
	"context"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

var (
	allocationFindings []report.Finding
	allocationMatches  [][]int
)

func allocationDetector(t testing.TB) (*Detector, *blregexp.Regexp) {
	t.Helper()
	re := blregexp.MustCompile(`candidate_[A-Z]{20}`)
	rule := config.Rule{
		RuleID:   "allocation-test",
		Keywords: []string{"candidate_"},
		Regex:    re,
	}
	cfg := &config.Config{
		Rules:          map[string]config.Rule{rule.RuleID: rule},
		Keywords:       map[string]struct{}{"candidate_": {}},
		KeywordToRules: map[string][]string{"candidate_": {rule.RuleID}},
		OrderedRules:   []string{rule.RuleID},
	}
	return newTestDetector(t, cfg), re
}

func TestDetectPrefilterMissAllocations(t *testing.T) {
	detector, _ := allocationDetector(t)
	fragment := sources.Fragment{Raw: []byte("ordinary source text")}
	ctx := context.Background()
	allocationFindings = detector.detectFragment(ctx, fragment) // warm pools

	allocs := testing.AllocsPerRun(500, func() {
		allocationFindings = detector.detectFragment(ctx, fragment)
	})
	if allocs != 0 {
		t.Fatalf("prefilter miss allocated %.2f times; want zero", allocs)
	}
}

func TestDetectStringPrefilterMissAllocations(t *testing.T) {
	detector, _ := allocationDetector(t)
	const content = "ordinary source text"
	allocationFindings = detector.DetectString(content) // warm pools

	allocs := testing.AllocsPerRun(500, func() {
		allocationFindings = detector.DetectString(content)
	})
	if allocs != 0 {
		t.Fatalf("string prefilter miss allocated %.2f times; want zero", allocs)
	}
}

func TestDetectRejectedCandidateStaysAtRegexAllocationFloor(t *testing.T) {
	detector, re := allocationDetector(t)
	fragment := sources.Fragment{Raw: []byte("candidate_without_a_matching_secret")}
	ctx := context.Background()
	allocationFindings = detector.detectFragment(ctx, fragment)
	allocationMatches = re.FindAllIndex(fragment.Raw, -1)

	backend := testing.AllocsPerRun(500, func() {
		allocationMatches = re.FindAllIndex(fragment.Raw, -1)
	})
	detectAllocs := testing.AllocsPerRun(500, func() {
		allocationFindings = detector.detectFragment(ctx, fragment)
	})
	if extra := detectAllocs - backend; extra > 1 {
		t.Fatalf("rejected candidate allocated %.2f times above regex floor %.2f", extra, backend)
	}
}

func TestDetectAcceptedCandidateAllocationBudget(t *testing.T) {
	detector, re := allocationDetector(t)
	fragment := sources.Fragment{Raw: []byte("candidate_ABCDEFGHIJKLMNOPQRST")}
	ctx := context.Background()
	allocationFindings = detector.detectFragment(ctx, fragment)
	allocationMatches = re.FindAllIndex(fragment.Raw, -1)

	backend := testing.AllocsPerRun(200, func() {
		allocationMatches = re.FindAllIndex(fragment.Raw, -1)
	})
	detectAllocs := testing.AllocsPerRun(200, func() {
		allocationFindings = detector.detectFragment(ctx, fragment)
	})
	if extra := detectAllocs - backend; extra > 8 {
		t.Fatalf("accepted candidate allocated %.2f times above regex floor %.2f (total %.2f)", extra, backend, detectAllocs)
	}
}
