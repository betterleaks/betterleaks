package detect

import (
	"strings"
	"testing"
)

func TestParseMatchContext(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    MatchContextSpec
		wantErr bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  MatchContextSpec{},
		},
		{
			name:  "zero",
			input: "0",
			want:  MatchContextSpec{},
		},
		{
			name:  "plain number defaults to bytes",
			input: "100",
			want: MatchContextSpec{
				Mode:        ContextModeBytes,
				BytesBefore: 100,
				BytesAfter:  100,
			},
		},
		{
			name:  "100B explicit",
			input: "100B",
			want: MatchContextSpec{
				Mode:        ContextModeBytes,
				BytesBefore: 100,
				BytesAfter:  100,
			},
		},
		{
			name:  "asymmetric bytes",
			input: "-128B,+16B",
			want: MatchContextSpec{
				Mode:        ContextModeBytes,
				BytesBefore: 128,
				BytesAfter:  16,
			},
		},
		{
			name:  "10L symmetric lines",
			input: "10L",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 9,
				LinesAfter:  9,
			},
		},
		{
			name:  "asymmetric lines",
			input: "-10L,+2L",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 9,
				LinesAfter:  1,
			},
		},
		{
			name:  "box with columns",
			input: "-2C,+10L,-2L,+4C",
			want: MatchContextSpec{
				Mode:          ContextModeBox,
				LinesBefore:   1,
				LinesAfter:    9,
				ColumnsBefore: 2,
				ColumnsAfter:  4,
			},
		},
		{
			name:  "1L just the match line",
			input: "1L",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 0,
				LinesAfter:  0,
			},
		},
		{
			name:  "lines with byte limit",
			input: "10L,500B",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				BytesBefore: 500,
				BytesAfter:  500,
				LinesBefore: 9,
				LinesAfter:  9,
			},
		},
		{
			name:  "case insensitive",
			input: "10l",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 9,
				LinesAfter:  9,
			},
		},
		{
			name:  "one direction only sets other to 0",
			input: "+5L",
			want: MatchContextSpec{
				Mode:       ContextModeBox,
				LinesAfter: 4,
			},
		},
		{
			name:  "before direction only sets after to 0",
			input: "-5L",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 4,
			},
		},
		{
			name:  "undirected fills missing direction",
			input: "5L,+10L",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 4,
				LinesAfter:  9,
			},
		},
		{
			name:  "duplicate direction takes largest",
			input: "-5L,-10L",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 9,
			},
		},
		{
			name:  "only bytes before",
			input: "-50B",
			want: MatchContextSpec{
				Mode:        ContextModeBytes,
				BytesBefore: 50,
			},
		},
		{
			name:  "only bytes after",
			input: "+50B",
			want: MatchContextSpec{
				Mode:       ContextModeBytes,
				BytesAfter: 50,
			},
		},
		{
			name:  "whitespace trimming",
			input: "  10L  ",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				LinesBefore: 9,
				LinesAfter:  9,
			},
		},
		{
			name:    "invalid token",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "empty token in list",
			input:   "10L,,5C",
			wantErr: true,
		},
		{
			name:  "directional byte in box mode",
			input: "10L,-5B",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				BytesBefore: 5,
				LinesBefore: 9,
				LinesAfter:  9,
			},
		},
		{
			name:  "1L with byte limit",
			input: "1L,10B",
			want: MatchContextSpec{
				Mode:        ContextModeBox,
				BytesBefore: 10,
				BytesAfter:  10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMatchContext(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseMatchContext(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("ParseMatchContext(%q) =\n  %+v\nwant\n  %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractContext(t *testing.T) {
	raw := "line0 aaa and some more text here padding\nline1 bbb with extra content after value\nline2 ccc followed by trailing characters\nline3 ddd plus additional context padding\nline4 SECRET_HERE eee some trailing content\nline5 fff more stuff beyond the match line\nline6 ggg yet another line with extra text\nline7 hhh continuing with padded out lines\nline8 iii almost done with trailing content\nline9 jjj final line with some extra filler"

	matchStr := "SECRET_HERE"
	matchStart := strings.Index(raw, matchStr)
	matchEnd := matchStart + len(matchStr)
	matchIndex := []int{matchStart, matchEnd}

	tests := []struct {
		name string
		spec MatchContextSpec
		want string
	}{
		{
			name: "not set",
			spec: MatchContextSpec{},
			want: "",
		},
		{
			name: "small context around match (bytes)",
			spec: MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 10, BytesAfter: 10},
			want: raw[matchStart-10 : matchEnd+10],
		},
		{
			name: "large context includes everything (bytes)",
			spec: MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 10000, BytesAfter: 10000},
			want: raw,
		},
		{
			name: "1 byte padding",
			spec: MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 1, BytesAfter: 1},
			want: raw[matchStart-1 : matchEnd+1],
		},
		{
			name: "asymmetric bytes",
			spec: MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 5, BytesAfter: 20},
			want: raw[matchStart-5 : matchEnd+20],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContext(raw, matchIndex, tt.spec)
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

	got := extractContext(raw, matchIndex, MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 20, BytesAfter: 20})
	want := raw[:matchEnd+20]
	if got != want {
		t.Errorf("extractContext(start) =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractContext_MatchAtEnd(t *testing.T) {
	raw := "some text before and more padding here SECRET_HERE"
	matchStart := strings.Index(raw, "SECRET_HERE")
	matchIndex := []int{matchStart, len(raw)}

	got := extractContext(raw, matchIndex, MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 20, BytesAfter: 20})
	want := raw[matchStart-20:]
	if got != want {
		t.Errorf("extractContext(end) =\n%q\nwant\n%q", got, want)
	}
}

func TestExtractContext_EmptyRaw(t *testing.T) {
	got := extractContext("", []int{0, 0}, MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 10, BytesAfter: 10})
	if got != "" {
		t.Errorf("extractContext(empty) = %q, want empty", got)
	}
}

func TestExtractContext_BoxMode(t *testing.T) {
	raw := "line0 aaa\nline1 bbb\nline2 ccc\nline3 SECRET_HERE ddd\nline4 eee\nline5 fff\nline6 ggg"

	matchStr := "SECRET_HERE"
	matchStart := strings.Index(raw, matchStr)
	matchEnd := matchStart + len(matchStr)
	matchIndex := []int{matchStart, matchEnd}

	tests := []struct {
		name string
		spec MatchContextSpec
		want string
	}{
		{
			name: "1 line before and after",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 1},
			want: "line2 ccc\nline3 SECRET_HERE ddd\nline4 eee",
		},
		{
			name: "0 lines (just match line)",
			spec: MatchContextSpec{Mode: ContextModeBox},
			want: "line3 SECRET_HERE ddd",
		},
		{
			name: "asymmetric lines",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 2, LinesAfter: 1},
			want: "line1 bbb\nline2 ccc\nline3 SECRET_HERE ddd\nline4 eee",
		},
		{
			name: "more lines than available before",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 100, LinesAfter: 1},
			want: "line0 aaa\nline1 bbb\nline2 ccc\nline3 SECRET_HERE ddd\nline4 eee",
		},
		{
			name: "more lines than available after",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 100},
			want: "line2 ccc\nline3 SECRET_HERE ddd\nline4 eee\nline5 fff\nline6 ggg",
		},
		{
			name: "byte limit around match",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 2, LinesAfter: 2, BytesBefore: 10, BytesAfter: 10},
			want: raw[matchStart-10 : matchEnd+10],
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContext(raw, matchIndex, tt.spec)
			if got != tt.want {
				t.Errorf("extractContext() =\n%q\nwant\n%q", got, tt.want)
			}
		})
	}
}

func TestExtractContext_BoxModeWithColumns(t *testing.T) {
	raw := "aaaa SECRET_HERE bbbb\ncccc SECRET_XXXX dddd\neeee SECRET_YYYY ffff"

	matchStr := "SECRET_HERE"
	matchStart := strings.Index(raw, matchStr)
	matchEnd := matchStart + len(matchStr)
	matchIndex := []int{matchStart, matchEnd}

	spec := MatchContextSpec{
		Mode:          ContextModeBox,
		LinesBefore:   0,
		LinesAfter:    1,
		ColumnsBefore: 2,
		ColumnsAfter:  2,
	}

	got := extractContext(raw, matchIndex, spec)
	// Match is at column 5 on its line. Column window: [5-2:5+11+2] = [3:18]
	// Line 0 (match line): "aaaa SECRET_HERE bbbb"[3:18] = "a SECRET_HERE"
	// Line 1:              "cccc SECRET_XXXX dddd"[3:18] = "c SECRET_XXXX d"
	want := "a SECRET_HERE b\nc SECRET_XXXX d"
	if got != want {
		t.Errorf("extractContext(columns) =\n%q\nwant\n%q", got, want)
	}
}
