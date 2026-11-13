package scan

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sync/semaphore"

	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// ErrLimitExceeded identifies a scan stopped by a detection or output limit.
var ErrLimitExceeded = errors.New("scan limit exceeded")

// ScanLimits bounds one ScanWithLimits call. All fields must be positive.
// Candidates include matches later filtered out, component matches, and matches
// from decoding passes. Bytes are cumulative, conservative allocation charges,
// not a measurement or ceiling of the Go heap or process RSS. Configuration,
// regex-engine internals, and expression execution are outside this accounting.
type ScanLimits struct {
	// MaxFindings counts findings surviving the final fragment filters.
	MaxFindings int
	// MaxCandidates counts raw regex matches and path-only matches.
	MaxCandidates int
	// MaxBytes caps cumulative allocation charges, including discarded work.
	MaxBytes int64
	// MaxFragmentBytes rejects oversized source fragments before detection.
	MaxFragmentBytes int
	// MaxMatchIndexBytes bounds shared scratch reserved for regex calls.
	// Scratch is additional to MaxBytes while the backend collects indices.
	MaxMatchIndexBytes int64
}

// ScanWithLimits is Scan with per-call limits shared by its detection workers.
// It fails rather than silently truncating candidates. A handler may have seen
// findings from earlier fragments before an error; consumers needing atomic
// results must discard them on failure. Each concurrent call has its own budget.
func (s *Scanner) ScanWithLimits(ctx context.Context, source sources.Source, limits ScanLimits, handler Handler) (ScanSummary, error) {
	if limits.MaxFindings < 1 || limits.MaxCandidates < 1 || limits.MaxCandidates == int(^uint(0)>>1) ||
		limits.MaxBytes < 1 || limits.MaxFragmentBytes < 1 || limits.MaxMatchIndexBytes < 1 ||
		limits.MaxMatchIndexBytes > limits.MaxBytes {
		return ScanSummary{}, errors.New("scan limits must be positive, with match-index bytes no greater than detection bytes")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	budget := &scanBudget{limits: limits, ctx: ctx, cancel: cancel, scratch: semaphore.NewWeighted(limits.MaxMatchIndexBytes)} //nolint:exhaustruct // Counters, mutex, and error start at their zero values.
	return s.scan(ctx, source, handler, budget)
}

type scanBudget struct {
	limits  ScanLimits
	ctx     context.Context
	cancel  context.CancelCauseFunc
	scratch *semaphore.Weighted
	mu      sync.Mutex
	bytes   int64
	matches int
	results int
	err     error
}

func (b *scanBudget) failLocked(reason string) error {
	if b.err == nil {
		b.err = fmt.Errorf("%w: %s", ErrLimitExceeded, reason)
		b.cancel(b.err)
	}
	return b.err
}

func (b *scanBudget) fail(reason string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failLocked(reason)
}

// Reservations precede the corresponding allocation. Charges are never
// refunded: discarded candidates still consume work and allocation budget.
func (b *scanBudget) reserve(count int, bytes int64) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if err := context.Cause(b.ctx); err != nil {
		return err
	}
	if count < 0 || count > b.limits.MaxCandidates-b.matches {
		return b.failLocked("maximum detection candidates")
	}
	if bytes < 0 || bytes > b.limits.MaxBytes-b.bytes {
		return b.failLocked("maximum detection allocation bytes")
	}
	b.matches += count
	b.bytes += bytes
	return nil
}

func (b *scanBudget) reserveMany(count int, bytesEach int64) error {
	if b == nil {
		return nil
	}
	if count < 0 || bytesEach < 0 || (count > 0 && bytesEach > b.limits.MaxBytes/int64(count)) {
		return b.fail("maximum detection allocation bytes")
	}
	return b.reserve(0, int64(count)*bytesEach)
}

func (b *scanBudget) accept(count int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	if err := context.Cause(b.ctx); err != nil {
		return err
	}
	if count > b.limits.MaxFindings-b.results {
		return b.failLocked("maximum returned findings")
	}
	b.results += count
	return nil
}

// Match-index scratch is reserved before asking the backend to allocate it.
// Waiting uses a separate, releasable budget, so workers cannot deadlock while
// retaining candidate results. Once returned, actual indices are charged to
// the cumulative detection budget before the scratch reservation is released.
func (b *scanBudget) find(ctx context.Context, regex *blregexp.Regexp, raw string, candidateBytes int64) ([][]int, error) {
	b.mu.Lock()
	if b.err != nil {
		err := b.err
		b.mu.Unlock()
		return nil, err
	}
	remaining := b.limits.MaxCandidates - b.matches
	bytesLeft := b.limits.MaxBytes - b.bytes
	b.mu.Unlock()
	// Include captures even for whole-match searches: backends may allocate
	// them internally. Allow for slice growth and temporary backing arrays.
	indexBytes := int64(128) + 64*int64(regex.NumSubexp()+1)
	capacity := b.limits.MaxMatchIndexBytes / indexBytes
	if capacity < 2 {
		return nil, b.fail("regex capture indices exceed scratch budget")
	}
	limit := min(remaining+1, len(raw)+1)
	if byBytes := bytesLeft/(candidateBytes+indexBytes) + 1; int64(limit) > byBytes {
		limit = int(byBytes)
	}
	if int64(limit) > capacity {
		limit = int(capacity)
	}
	reservation := int64(limit) * indexBytes
	if err := b.scratch.Acquire(ctx, reservation); err != nil {
		return nil, context.Cause(ctx)
	}
	defer b.scratch.Release(reservation)
	if err := b.reserve(0, 0); err != nil {
		return nil, err
	}
	var found [][]int
	if regex.NumSubexp() > 0 {
		found = regex.FindAllStringSubmatchIndex(raw, limit)
	} else {
		found = regex.FindAllStringIndex(raw, limit)
	}
	if len(found) > remaining {
		return nil, b.fail("maximum detection candidates")
	}
	// At the scratch boundary, the last slot is a sentinel. Never report a
	// successful scan that might have omitted further matches.
	if len(found) == limit && int64(limit) == capacity && limit < len(raw)+1 {
		return nil, b.fail("maximum regex match-index bytes")
	}
	perMatch := candidateBytes + indexBytes
	if len(found) > 0 && perMatch > b.limits.MaxBytes/int64(len(found)) {
		return nil, b.fail("maximum detection allocation bytes")
	}
	if err := b.reserve(len(found), int64(len(found))*perMatch); err != nil {
		return nil, err
	}
	return found, nil
}

func candidateAllocationBytes(fragment sources.Fragment, rule *compiledRule, hasFilter bool) int64 {
	// Findings move through per-rule, per-fragment, filtered, and queued
	// slices. Filters may allocate a private attribute map for each candidate.
	var finding report.Finding
	cost := 4*int64(unsafe.Sizeof(finding)) + 2048 + 128*int64(len(fragment.Attributes))
	// The final filter constructs an identity containing the rule ID.
	cost += 2 * int64(len(rule.rule.ID))
	if hasFilter {
		cost += scmLinkAllocationBytes(fragment.Attributes, fragment.Attr(sources.AttrPath))
	}
	cost += 64 * int64(len(rule.rule.Tags))
	if rule.regex != nil {
		cost += 128 * int64(rule.regex.NumSubexp())
	}
	return cost
}

func matchAllocationBytes(match report.Match) int64 {
	cost := int64(len(match.Line)) + 2*int64(len(match.Full)+len(match.Value)+len(match.Context))
	for name, value := range match.Captures {
		cost += 128 + 2*int64(len(name)+len(value))
	}
	return cost
}

func componentAllocationBytes(f report.ComponentFinding) int64 {
	return 4*int64(unsafe.Sizeof(f)) + matchAllocationBytes(f.Match) + 64*int64(len(f.Encodings))
}

// Reserve ownership copies and a conservative JSON-size upper bound before
// handing findings to consumers such as the C bridge. JSON strings can expand
// to six bytes per source byte. Fixed allowances cover field names, punctuation,
// numeric fields, fingerprints, and container overhead in the detection schema.
func findingAllocationBytes(f report.Finding) int64 {
	cost := int64(2048) + matchJSONBytes(f.Match)
	if f.Location.StartLine > 0 {
		cost += scmLinkAllocationBytes(f.Attributes, f.Location.Path)
	}
	cost += 6 * int64(len(f.RuleID)+len(f.RuleHash)+len(f.Description)+len(f.Confidence)+len(f.Location.Path))
	for key, value := range f.Attributes {
		cost += 128 + 6*int64(len(key)+len(value))
	}
	for _, tag := range f.Tags {
		cost += 32 + 6*int64(len(tag))
	}
	for _, encoding := range f.Encodings {
		cost += 32 + 6*int64(len(encoding))
	}
	for _, set := range f.ComponentSets {
		cost += 64
		for _, component := range set.Components {
			cost += 1024 + matchJSONBytes(component.Match)
			cost += 6 * int64(len(component.RuleID)+len(component.RuleHash)+len(component.Location.Path))
			for _, encoding := range component.Encodings {
				cost += 32 + 6*int64(len(encoding))
			}
		}
	}
	return cost
}

// Link construction can escape paths and copy its growing output several
// times. Charge both construction and JSON expansion before generating it.
func scmLinkAllocationBytes(attributes map[string]string, path string) int64 {
	if attributes[sources.AttrGitPlatform] == "" || attributes[sources.AttrGitRemoteURL] == "" {
		return 0
	}
	length := int64(256) + int64(len(attributes[sources.AttrGitRemoteURL])+len(attributes[sources.AttrGitSHA]))
	length += 3 * int64(len(path)+len(attributes[sources.AttrGitTagRef]))
	return 16 * length
}

func (b *scanBudget) indexFinding(f report.Finding) error {
	if b == nil {
		return nil
	}
	charge := func(loc report.Location) error {
		end := max(loc.StartLine, loc.EndLine)
		entries := end - loc.StartLine + 1
		if end-loc.StartLine >= findingLineBlockSize {
			entries = end/findingLineBlockSize - loc.StartLine/findingLineBlockSize + 1
		}
		return b.reserveMany(entries, 128)
	}
	if err := charge(f.Location); err != nil {
		return err
	}
	for _, set := range f.ComponentSets {
		for _, component := range set.Components {
			if err := charge(component.Location); err != nil {
				return err
			}
		}
	}
	return nil
}

func matchJSONBytes(match report.Match) int64 {
	cost := int64(len(match.Line)) + 6*int64(len(match.Full)+len(match.Value)+len(match.Fingerprint)+len(match.Context))
	for key, value := range match.Captures {
		cost += 128 + 6*int64(len(key)+len(value))
	}
	return cost
}

func (b *scanBudget) componentSets(findings []report.ComponentFinding) error {
	if b == nil || len(findings) == 0 {
		return nil
	}
	if err := b.reserveMany(len(findings), 256); err != nil {
		return err
	}
	type group struct {
		count int
		bytes int64
	}
	groups := make(map[string]group)
	for _, f := range findings {
		g := groups[f.RuleID]
		g.count++
		g.bytes = max(g.bytes, componentAllocationBytes(f))
		groups[f.RuleID] = g
	}
	sets, rowBytes := 1, int64(64)
	for _, g := range groups {
		if sets > maxComponentSets/g.count {
			sets = maxComponentSets
		} else {
			sets *= g.count
		}
		rowBytes += g.bytes
	}
	return b.reserveMany(sets, rowBytes)
}
