package words

import "testing"

func TestContainsWord(t *testing.T) {
	tests := []struct {
		name   string
		word   string
		minLen int
		want   bool
	}{
		{
			name:   "empty string",
			word:   "",
			minLen: 3,
			want:   false,
		},
		{
			name:   "shorter than minLen",
			word:   "ab",
			minLen: 3,
			want:   false,
		},
		{
			name:   "no dictionary substring",
			word:   "xyzabc",
			minLen: 3,
			want:   false,
		},
		{
			name:   "exact word",
			word:   "pass",
			minLen: 3,
			want:   true,
		},
		{
			name:   "prefix and middle matches",
			word:   "password",
			minLen: 3,
			want:   true,
		},
		{
			name:   "match in middle",
			word:   "xxwordxx",
			minLen: 3,
			want:   true,
		},
		{
			name:   "minLen filters shorter",
			word:   "word",
			minLen: 4,
			want:   true,
		},
		{
			name:   "minLen 4 excludes 3-char match",
			word:   "aba",
			minLen: 4,
			want:   false,
		},
		{
			name:   "mixed case",
			word:   "xxPaSsWoRdxx",
			minLen: 5,
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsWord(tt.word, tt.minLen); got != tt.want {
				t.Errorf("ContainsWord(%q, %d) = %v, want %v", tt.word, tt.minLen, got, tt.want)
			}
		})
	}
}
