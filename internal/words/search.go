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

// HasAnyMatchInList reports whether word contains at least one dictionary word
// of minLen bytes. It is the allocation-free boolean form used by hot-path
// heuristics that do not need match details.
func HasAnyMatchInList(word string, minLen int) bool {
	wordsOnce.Do(loadWords)

	if len(word) < minLen {
		return false
	}
	if isASCII(word) {
		var local [256]byte
		var lower []byte
		if len(word) <= len(local) {
			lower = local[:len(word)]
		} else {
			lower = make([]byte, len(word))
		}
		for i := range word {
			b := word[i]
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			lower[i] = b
		}
		for start := 0; start <= len(lower)-minLen; start++ {
			for length := minLen; start+length <= len(lower); length++ {
				// A temporary []byte-to-string conversion used only for a map
				// lookup does not escape, so Go can avoid allocating it.
				if _, exists := nltkWords[string(lower[start:start+length])]; exists {
					return true
				}
			}
		}
		return false
	}

	word = strings.ToLower(word)
	for start := 0; start <= len(word)-minLen; start++ {
		for length := minLen; start+length <= len(word); length++ {
			if _, exists := nltkWords[word[start:start+length]]; exists {
				return true
			}
		}
	}
	return false
}

func isASCII(word string) bool {
	for i := range word {
		if word[i] >= 0x80 {
			return false
		}
	}
	return true
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
