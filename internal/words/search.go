package words

import "strings"

// ContainsWord reports whether text contains a dictionary word of at least
// minLen bytes, ignoring case. Matches need not fall on word boundaries.
func ContainsWord(text string, minLen int) bool {
	wordsOnce.Do(loadWords)

	text = strings.ToLower(text)
	for start := 0; start <= len(text)-minLen; start++ {
		for length := minLen; start+length <= len(text); length++ {
			sub := text[start : start+length]
			if _, exists := nltkWords[sub]; exists {
				return true
			}
		}
	}
	return false
}
