package detect

import (
	"strings"
	"testing"
)

func TestExtractContext(t *testing.T) {
	raw := "line0 aaa and some more text here padding\nline1 bbb with extra content after value\nline2 ccc followed by trailing characters\nline3 ddd plus additional context padding\nline4 SECRET_HERE eee some trailing content\nline5 fff more stuff beyond the match line\nline6 ggg yet another line with extra text\nline7 hhh continuing with padded out lines\nline8 iii almost done with trailing content\nline9 jjj final line with some extra filler"

	matchStr := "SECRET_HERE"
	matchStart := strings.Index(raw, matchStr)
	matchEnd := matchStart + len(matchStr)
	matchIndex := []int{matchStart, matchEnd}

	tests := []struct {
		name  string
		bytes int
		want  string
	}{
		{
			name:  "not set",
			bytes: 0,
			want:  "",
		},
		{
			name:  "small context around match",
			bytes: 10,
			want:  raw[matchStart-10 : matchEnd+10],
		},
		{
			name:  "large context includes everything",
			bytes: 10000,
			want:  raw,
		},
		{
			name:  "1 byte padding",
			bytes: 1,
			want:  raw[matchStart-1 : matchEnd+1],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContext(raw, matchIndex, tt.bytes)
			if got != tt.want {
				t.Errorf("extractContext() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestExtractContext_MatchAtStart(t *testing.T) {
	raw := "SECRET_HERE and some text after"
	matchEnd := len("SECRET_HERE")
	matchIndex := []int{0, matchEnd}

	got := extractContext(raw, matchIndex, 20)
	want := raw[:matchEnd+20]
	if got != want {
		t.Errorf("extractContext(start) =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractContext_MatchAtEnd(t *testing.T) {
	raw := "some text before and more padding here SECRET_HERE"
	matchStart := strings.Index(raw, "SECRET_HERE")
	matchIndex := []int{matchStart, len(raw)}

	got := extractContext(raw, matchIndex, 20)
	want := raw[matchStart-20:]
	if got != want {
		t.Errorf("extractContext(end) =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractContext_EmptyRaw(t *testing.T) {
	got := extractContext("", []int{0, 0}, 10)
	if got != "" {
		t.Errorf("extractContext(empty) = %q, want empty", got)
	}
}
