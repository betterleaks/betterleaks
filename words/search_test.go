package words

import (
	"sort"
	"testing"
)

func TestHasMatchInList(t *testing.T) {
	tests := []struct {
		name   string
		word   string
		minLen int
		// want nil result
		wantNil bool
		// otherwise: expected unique words (order-independent)
		wantUniqueWords []string
		// and minimum number of total matches
		wantMinMatchCount int
	}{
		{
			name:    "empty string",
			word:    "",
			minLen:  3,
			wantNil: true,
		},
		{
			name:    "shorter than minLen",
			word:    "ab",
			minLen:  3,
			wantNil: true,
		},
		{
			name:    "no dictionary substring",
			word:    "xyzabc",
			minLen:  3,
			wantNil: true,
		},
		{
			name:              "exact word",
			word:              "pass",
			minLen:            3,
			wantUniqueWords:   []string{"ass", "pass"}, // "ass" is substring at index 1
			wantMinMatchCount: 2,
		},
		{
			name:              "prefix and middle matches",
			word:              "password",
			minLen:            3,
			wantUniqueWords:   []string{"ass", "pass", "password", "sword", "word"},
			wantMinMatchCount: 5,
		},
		{
			name:              "match in middle",
			word:              "xxwordxx",
			minLen:            3,
			wantUniqueWords:   []string{"word"},
			wantMinMatchCount: 1,
		},
		{
			name:              "minLen filters shorter",
			word:              "aba",
			minLen:            3,
			wantUniqueWords:   []string{"aba"},
			wantMinMatchCount: 1,
		},
		{
			name:    "minLen 4 excludes 3-char match",
			word:    "aba",
			minLen:  4,
			wantNil: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasMatchInList(tt.word, tt.minLen)
			if tt.wantNil {
				if got != nil {
					t.Errorf("HasMatchInList() = %v, want nil", got)
				}
				return
			}
			if got == nil || len(got) == 0 {
				t.Fatalf("HasMatchInList() = nil, want result with UniqueWords %v", tt.wantUniqueWords)
			}
			r := got[0]
			if r.WordCount < tt.wantMinMatchCount {
				t.Errorf("WordCount = %d, want at least %d", r.WordCount, tt.wantMinMatchCount)
			}
			sort.Strings(r.UniqueWords)
			wantSorted := make([]string, len(tt.wantUniqueWords))
			copy(wantSorted, tt.wantUniqueWords)
			sort.Strings(wantSorted)
			if len(r.UniqueWords) != len(wantSorted) {
				t.Errorf("UniqueWords = %v, want %v", r.UniqueWords, wantSorted)
			} else {
				for i := range wantSorted {
					if r.UniqueWords[i] != wantSorted[i] {
						t.Errorf("UniqueWords = %v, want %v", r.UniqueWords, wantSorted)
						break
					}
				}
			}
		})
	}
}
