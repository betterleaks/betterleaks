package celenv

import (
	"strings"
	"sync"
	"testing"
)

func resetRegexCache() {
	regexCache = sync.Map{}
}

func TestGetOrCompileJoinedRegexCachesCompileErrors(t *testing.T) {
	resetRegexCache()
	t.Cleanup(resetRegexCache)

	patterns := []string{"["}

	re, err := getOrCompileJoinedRegex(patterns)
	if err == nil {
		t.Fatal("expected compile error, got nil")
	}
	if re != nil {
		t.Fatalf("expected nil regex on compile error, got %v", re)
	}

	cached, ok := regexCache.Load(orderedKey(patterns))
	if !ok {
		t.Fatal("expected compile failure to be cached")
	}
	entry := cached.(regexCacheEntry)
	if entry.err == nil {
		t.Fatal("expected cached entry to preserve compile error")
	}
	if entry.re != nil {
		t.Fatalf("expected cached regex to be nil, got %v", entry.re)
	}

	re, err = getOrCompileJoinedRegex(patterns)
	if err == nil {
		t.Fatal("expected compile error from cache, got nil")
	}
	if re != nil {
		t.Fatalf("expected nil regex from cache on compile error, got %v", re)
	}
}

func TestMatchesAnyBindingReturnsEvalErrorOnInvalidRegex(t *testing.T) {
	resetRegexCache()
	t.Cleanup(resetRegexCache)

	env, err := NewFilterEnv(nil)
	if err != nil {
		t.Fatalf("NewFilterEnv: %v", err)
	}

	prg, err := env.Compile(`matchesAny(finding["secret"], ["["])`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, err = EvalFilter(prg, map[string]string{"secret": "token"}, nil)
	if err == nil {
		t.Fatal("expected eval error, got nil")
	}
	if !strings.Contains(err.Error(), "matchesAny: invalid regex") {
		t.Fatalf("expected matchesAny compile error, got %v", err)
	}
}

func TestMatchesAnyBindingStillMatchesValidRegex(t *testing.T) {
	resetRegexCache()
	t.Cleanup(resetRegexCache)

	env, err := NewFilterEnv(nil)
	if err != nil {
		t.Fatalf("NewFilterEnv: %v", err)
	}

	prg, err := env.Compile(`matchesAny(finding["secret"], ["foo.+bar"])`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	matched, err := EvalFilter(prg, map[string]string{"secret": "foo123bar"}, nil)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !matched {
		t.Fatal("expected regex to match")
	}
}
