package exprruntime

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/internal/confidence"
	"github.com/betterleaks/betterleaks/internal/words"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	tiktoken "github.com/pkoukk/tiktoken-go"
)

var (
	regexCache    sync.Map // uint64 -> *regexCacheBucket
	containsCache sync.Map // uint64 -> *containsCacheBucket
)

type patternList struct {
	strings []string
	values  []any
}

func newPatternList(value any) (patternList, bool) {
	switch patterns := value.(type) {
	case []string:
		return patternList{strings: patterns}, true
	case []any:
		for _, pattern := range patterns {
			if _, ok := pattern.(string); !ok {
				return patternList{}, false
			}
		}
		return patternList{values: patterns}, true
	default:
		return patternList{}, false
	}
}

func (p patternList) len() int {
	if p.strings != nil {
		return len(p.strings)
	}
	return len(p.values)
}

func (p patternList) at(index int) string {
	if p.strings != nil {
		return p.strings[index]
	}
	return p.values[index].(string)
}

func (p patternList) clone() []string {
	patterns := make([]string, p.len())
	for i := range patterns {
		patterns[i] = p.at(i)
	}
	return patterns
}

// hash returns a non-cryptographic content hash. Cache hits are always checked
// against the original strings, so collisions affect performance, not results.
func (p patternList) hash() uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	hash := uint64(offset64)
	for i := 0; i < p.len(); i++ {
		pattern := p.at(i)
		hash ^= uint64(len(pattern))
		hash *= prime64
		for j := 0; j < len(pattern); j++ {
			hash ^= uint64(pattern[j])
			hash *= prime64
		}
	}
	hash ^= uint64(p.len())
	return hash * prime64
}

type compiledRegex struct {
	patterns []string
	regexp   *blregexp.Regexp
}

// regexCacheBucket keeps the overwhelmingly common first hash entry immutable
// and lock-free. The mutex is used only for the extremely unlikely hash-
// collision path, where string comparison still guarantees correct results.
type regexCacheBucket struct {
	primary compiledRegex
	mu      sync.RWMutex
	extra   []compiledRegex
}

func samePatterns(cached []string, patterns patternList) bool {
	if len(cached) != patterns.len() {
		return false
	}
	for i, pattern := range cached {
		if pattern != patterns.at(i) {
			return false
		}
	}
	return true
}

func (b *regexCacheBucket) load(patterns patternList) (*blregexp.Regexp, bool) {
	if samePatterns(b.primary.patterns, patterns) {
		return b.primary.regexp, true
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, cached := range b.extra {
		if samePatterns(cached.patterns, patterns) {
			return cached.regexp, true
		}
	}
	return nil, false
}

func (b *regexCacheBucket) storeExtra(compiled compiledRegex) *blregexp.Regexp {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, cached := range b.extra {
		if samePatterns(cached.patterns, patternList{strings: compiled.patterns}) {
			return cached.regexp
		}
	}
	b.extra = append(b.extra, compiled)
	return compiled.regexp
}

func filterNamespace(rt *runtimeBindings) map[string]any {
	return map[string]any{
		"matchesAny":           matchesAny,
		"findMatch":            findMatch,
		"containsAny":          containsAny,
		"entropy":              shannonEntropy,
		"failsTokenEfficiency": rt.failsTokenEfficiency,
		"tokenRatio":           rt.tokenRatio,
	}
}

func (rt *runtimeBindings) setConfidence(value string) (string, error) {
	if !confidence.Valid(value) {
		return "", fmt.Errorf("filter.setConfidence: invalid confidence %q (expected low, medium, or high)", value)
	}
	rt.attrs.(map[string]string)[confidence.Attribute] = value
	return value, nil
}

func getOrCompileJoinedRegex(value any) *blregexp.Regexp {
	patterns, ok := newPatternList(value)
	if !ok || patterns.len() == 0 {
		return nil
	}
	key := patterns.hash()
	if cached, ok := regexCache.Load(key); ok {
		if re, found := cached.(*regexCacheBucket).load(patterns); found {
			return re
		}
	}

	stablePatterns := patterns.clone()
	re, err := blregexp.Compile(joinRegexPatterns(stablePatterns))
	if err != nil {
		return nil
	}
	compiled := compiledRegex{patterns: stablePatterns, regexp: re}
	bucket := &regexCacheBucket{primary: compiled}
	actual, loaded := regexCache.LoadOrStore(key, bucket)
	if !loaded {
		return re
	}
	existing := actual.(*regexCacheBucket)
	if cached, found := existing.load(patterns); found {
		return cached
	}
	return existing.storeExtra(compiled)
}

func joinRegexPatterns(patterns []string) string {
	var builder strings.Builder
	for i, pattern := range patterns {
		if i > 0 {
			_ = builder.WriteByte('|')
		}
		builder.WriteString("(?:")
		builder.WriteString(pattern)
		_ = builder.WriteByte(')')
	}
	return builder.String()
}

type compiledContains struct {
	patterns   []string
	normalized []string
}

type containsCacheBucket struct {
	primary compiledContains
	mu      sync.RWMutex
	extra   []compiledContains
}

func (b *containsCacheBucket) load(patterns patternList) (*compiledContains, bool) {
	if samePatterns(b.primary.patterns, patterns) {
		return &b.primary, true
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for i := range b.extra {
		if samePatterns(b.extra[i].patterns, patterns) {
			return &b.extra[i], true
		}
	}
	return nil, false
}

func (b *containsCacheBucket) storeExtra(compiled compiledContains) *compiledContains {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.extra {
		if samePatterns(b.extra[i].patterns, patternList{strings: compiled.patterns}) {
			return &b.extra[i]
		}
	}
	b.extra = append(b.extra, compiled)
	return &b.extra[len(b.extra)-1]
}

func getOrCompileContains(value any) *compiledContains {
	patterns, ok := newPatternList(value)
	if !ok || patterns.len() == 0 {
		return nil
	}
	key := patterns.hash()
	if cached, ok := containsCache.Load(key); ok {
		if compiled, found := cached.(*containsCacheBucket).load(patterns); found {
			return compiled
		}
	}

	stablePatterns := patterns.clone()
	normalized := make([]string, len(stablePatterns))
	for i, pattern := range stablePatterns {
		normalized[i] = strings.ToLower(pattern)
	}
	compiled := compiledContains{patterns: stablePatterns, normalized: normalized}
	bucket := &containsCacheBucket{primary: compiled}
	actual, loaded := containsCache.LoadOrStore(key, bucket)
	if !loaded {
		return &bucket.primary
	}
	existing := actual.(*containsCacheBucket)
	if cached, found := existing.load(patterns); found {
		return cached
	}
	return existing.storeExtra(compiled)
}

func matchesAny(s string, patterns any) bool {
	re := getOrCompileJoinedRegex(patterns)
	return re != nil && re.MatchString(s)
}

func findMatch(s, pattern string) string {
	re := getOrCompileJoinedRegex([]string{pattern})
	if re == nil {
		return ""
	}
	return re.FindString(s)
}

func containsAny(s string, terms any) bool {
	compiled := getOrCompileContains(terms)
	return compiled != nil && compiled.matches(s)
}

func (compiled *compiledContains) matches(s string) bool {
	if isASCII(s) {
		for _, pattern := range compiled.normalized {
			if containsFoldASCII(s, pattern) {
				return true
			}
		}
		return false
	}

	lower := strings.ToLower(s)
	for _, pattern := range compiled.normalized {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// containsFoldASCII is strings.Contains(strings.ToLower(s), lowerPattern)
// without allocating the lowercase copy for the common all-ASCII case.
func containsFoldASCII(s, lowerPattern string) bool {
	if len(lowerPattern) == 0 {
		return true
	}
	if len(lowerPattern) > len(s) {
		return false
	}
	for start := 0; start <= len(s)-len(lowerPattern); start++ {
		matched := true
		for i := 0; i < len(lowerPattern); i++ {
			b := s[start+i]
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if b != lowerPattern[i] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]float64
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, f := range freq {
		if f > 0 {
			p := f / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

var newlineReplacer = strings.NewReplacer("\n", "", "\r", "")

func (rt *runtimeBindings) tokenizerInstance() *tiktoken.Tiktoken {
	if rt.tokenizer == nil {
		if rt.tokenizerProvider == nil {
			return nil
		}
		rt.tokenizer = rt.tokenizerProvider()
	}
	return rt.tokenizer
}

func (rt *runtimeBindings) failsTokenEfficiency(secret string) bool {
	tke := rt.tokenizerInstance()
	return tke != nil && failsTokenEfficiency(tke, secret)
}

func (rt *runtimeBindings) tokenRatio(secret string) float64 {
	tke := rt.tokenizerInstance()
	if tke == nil {
		return 0
	}
	_, ratio, _ := calculateTokenRatio(tke, secret)
	return ratio
}

func calculateTokenRatio(tke *tiktoken.Tiktoken, secret string) (string, float64, bool) {
	analyzed := tokenAnalysisText(secret)
	ratio, ok := tokenRatioForText(tke, analyzed)
	return analyzed, ratio, ok
}

func tokenAnalysisText(secret string) string {
	if len(secret) < 20 && strings.ContainsAny(secret, "\n\r") {
		return newlineReplacer.Replace(secret)
	}
	return secret
}

func tokenRatioForText(tke *tiktoken.Tiktoken, analyzed string) (float64, bool) {
	// Filters never allow or reject special-token sentinels, so EncodeOrdinary
	// has the same tokenization semantics as Encode with two empty allowlists.
	// It skips the special-token regex pass, which is particularly expensive for
	// the many short candidates evaluated by repository scans.
	tokens := tke.EncodeOrdinary(analyzed)
	if len(tokens) == 0 {
		return 0, false
	}
	return float64(len(analyzed)) / float64(len(tokens)), true
}

func failsTokenEfficiency(tke *tiktoken.Tiktoken, secret string) bool {
	analyzed := tokenAnalysisText(secret)
	if len(analyzed) == 0 {
		return false
	}
	// Dictionary matches are an unconditional rejection in the original
	// heuristic. Check them before tokenization so common readable placeholders
	// avoid the regex and token-slice allocations in tiktoken entirely.
	if words.HasAnyMatchInList(analyzed, 5) {
		return true
	}
	ratio, ok := tokenRatioForText(tke, analyzed)
	if !ok {
		return false
	}
	threshold := 2.5
	if len(analyzed) < 12 {
		threshold = 2.1
		if !words.HasAnyMatchInList(analyzed, 4) {
			threshold = 2.5
		}
	}
	return ratio >= threshold
}
