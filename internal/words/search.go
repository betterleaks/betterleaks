package words

import (
	"strings"
)

type Result struct {
	WordCount   int
	UniqueWords []string
	Matches     []Match
}

type Match struct {
	Word string
	Len  int
}

// HasMatchInList finds all dictionary words that appear as substrings of word,
// matching Aho-Corasick–style behavior by walking the word: at each starting
// position we check every substring length >= minLen. Returns one Result
// aggregating all matches, or nil if none.
func HasMatchInList(word string, minLen int) []Result {
	// Trigger the lazy load. sync.Once guarantees this is thread-safe and
	// only executes the decompression once, even with thousands of goroutines.
	wordsOnce.Do(loadWords)

	word = strings.ToLower(word)
	if len(word) < minLen {
		return nil
	}

	var matches []Match
	seen := make(map[string]struct{})

	// Walk the word: at each start position, try every substring length >= minLen
	for start := 0; start <= len(word)-minLen; start++ {
		for length := minLen; start+length <= len(word); length++ {
			sub := word[start : start+length]
			if _, exists := nltkWords[sub]; exists {
				if _, ok := seen[sub]; !ok {
					seen[sub] = struct{}{}
				}
				matches = append(matches, Match{Word: sub, Len: length})
			}
		}
	}

	if len(matches) == 0 {
		return nil
	}

	uniqueWords := make([]string, 0, len(seen))
	for w := range seen {
		uniqueWords = append(uniqueWords, w)
	}

	return []Result{{
		WordCount:   len(matches),
		UniqueWords: uniqueWords,
		Matches:     matches,
	}}
}
