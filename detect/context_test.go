package detect

import (
	"strings"
	"testing"
)

func TestParseMatchContext(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    MatchContext
		wantErr bool
	}{
		{
			name: "empty string",
			spec: "",
			want: MatchContext{},
		},
		{
			name: "lines only - bare number",
			spec: "5",
			want: MatchContext{Lines: 5},
		},
		{
			name: "lines only - with L suffix",
			spec: "5L",
			want: MatchContext{Lines: 5},
		},
		{
			name: "lines and chars",
			spec: "5L250C",
			want: MatchContext{Lines: 5, Chars: 250},
		},
		{
			name: "one line",
			spec: "1",
			want: MatchContext{Lines: 1},
		},
		{
			name: "zero lines",
			spec: "0",
			want: MatchContext{Lines: 0},
		},
		{
			name: "whitespace trimmed",
			spec: "  3L100C  ",
			want: MatchContext{Lines: 3, Chars: 100},
		},
		{
			name:    "invalid spec - letters",
			spec:    "abc",
			wantErr: true,
		},
		{
			name:    "invalid spec - negative",
			spec:    "-1",
			wantErr: true,
		},
		{
			name:    "invalid spec - bad format",
			spec:    "5L250",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMatchContext(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMatchContext(%q) error = %v, wantErr %v", tt.spec, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseMatchContext(%q) = %+v, want %+v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestExtractContext(t *testing.T) {
	// Helper: create a raw string with numbered lines and compute newlineIndices + location.
	// Lines: "line0\nline1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9"
	lines := []string{
		"line0 aaa and some more text here padding",
		"line1 bbb with extra content after value",
		"line2 ccc followed by trailing characters",
		"line3 ddd plus additional context padding",
		"line4 SECRET_HERE eee some trailing content",
		"line5 fff more stuff beyond the match line",
		"line6 ggg yet another line with extra text",
		"line7 hhh continuing with padded out lines",
		"line8 iii almost done with trailing content",
		"line9 jjj final line with some extra filler",
	}
	raw := strings.Join(lines, "\n")
	newlineIndices := findNewlineIndices(raw)

	// The match is on line 4 (0-indexed). Find its byte offset.
	matchStr := "SECRET_HERE"
	matchStart := strings.Index(raw, matchStr)
	matchEnd := matchStart + len(matchStr)
	loc := location(newlineIndices, raw, []int{matchStart, matchEnd})

	tests := []struct {
		name string
		cfg  MatchContext
		want string
	}{
		{
			name: "not set",
			cfg:  MatchContext{},
			want: "",
		},
		{
			name: "2 lines context",
			cfg:  MatchContext{Lines: 2},
			want: strings.Join(lines[2:7], "\n"),
		},
		{
			name: "0 lines context (just the match line, but Lines=0 means IsSet is false)",
			cfg:  MatchContext{Lines: 0},
			want: "",
		},
		{
			name: "1 line context",
			cfg:  MatchContext{Lines: 1},
			want: strings.Join(lines[3:6], "\n"),
		},
		{
			name: "5 lines context (clamped at boundaries)",
			cfg:  MatchContext{Lines: 5},
			want: strings.Join(lines[0:10], "\n"),
		},
		{
			name: "100 lines context (clamped)",
			cfg:  MatchContext{Lines: 100},
			want: raw,
		},
		{
			name: "2 lines with char truncation",
			cfg:  MatchContext{Lines: 2, Chars: 20},
			want: "line2 ccc followed b\nline3 ddd plus addit\nline4 SECRET_HERE ee\nline5 fff more stuff\nline6 ggg yet anothe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContext(raw, newlineIndices, loc, tt.cfg)
			if got != tt.want {
				t.Errorf("extractContext() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestExtractContext_MatchOnFirstLine(t *testing.T) {
	raw := "SECRET_HERE\nline1\nline2"
	newlineIndices := findNewlineIndices(raw)
	matchStart := 0
	matchEnd := len("SECRET_HERE")
	loc := location(newlineIndices, raw, []int{matchStart, matchEnd})

	got := extractContext(raw, newlineIndices, loc, MatchContext{Lines: 2})
	want := "SECRET_HERE\nline1\nline2"
	if got != want {
		t.Errorf("extractContext(first line) =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractContext_MatchOnLastLine(t *testing.T) {
	raw := "line0\nline1\nSECRET_HERE"
	newlineIndices := findNewlineIndices(raw)
	matchStart := strings.Index(raw, "SECRET_HERE")
	matchEnd := matchStart + len("SECRET_HERE")
	loc := location(newlineIndices, raw, []int{matchStart, matchEnd})

	got := extractContext(raw, newlineIndices, loc, MatchContext{Lines: 2})
	want := "line0\nline1\nSECRET_HERE"
	if got != want {
		t.Errorf("extractContext(last line) =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractContext_SingleLine(t *testing.T) {
	raw := "only SECRET_HERE line"
	newlineIndices := findNewlineIndices(raw)
	matchStart := strings.Index(raw, "SECRET_HERE")
	matchEnd := matchStart + len("SECRET_HERE")
	loc := location(newlineIndices, raw, []int{matchStart, matchEnd})

	got := extractContext(raw, newlineIndices, loc, MatchContext{Lines: 3})
	want := "only SECRET_HERE line"
	if got != want {
		t.Errorf("extractContext(single line) =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractContext_EmptyRaw(t *testing.T) {
	got := extractContext("", nil, Location{}, MatchContext{Lines: 3})
	if got != "" {
		t.Errorf("extractContext(empty) = %q, want empty", got)
	}
}
