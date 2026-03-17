package detect

import (
	"reflect"
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
		// Zero / Empty states
		{"Empty string", "", MatchContextSpec{Mode: ContextModeNone}, false},
		{"Zero", "0", MatchContextSpec{Mode: ContextModeNone}, false},
		{"Spaces", "   ", MatchContextSpec{Mode: ContextModeNone}, false},

		// Cols Mode (C)
		{"Implicit cols", "100", MatchContextSpec{Mode: ContextModeCols, ColsBefore: 100, ColsAfter: 100}, false},
		{"Explicit cols", "100C", MatchContextSpec{Mode: ContextModeCols, ColsBefore: 100, ColsAfter: 100}, false},
		{"Directed cols", "-10C, +20C", MatchContextSpec{Mode: ContextModeCols, ColsBefore: 10, ColsAfter: 20}, false},
		{"Overriding cols", "10C, -50C", MatchContextSpec{Mode: ContextModeCols, ColsBefore: 50, ColsAfter: 10}, false},

		// Box Mode (L mixed with C for clipping)
		{"Lines only", "10L", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 9, LinesAfter: 9}, false},
		{"Directed lines", "-2L, +3L", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 2}, false},
		{"Lines and cols mixed (explicit)", "2L, 15C", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 1, ColsBefore: 15, ColsAfter: 15}, false},
		{"Lines and cols mixed (implicit C)", "15, 2L", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 1, ColsBefore: 15, ColsAfter: 15}, false},
		{"Directed mixed", "-2L, +10C", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, ColsAfter: 10}, false},

		// Errors
		{"Invalid token", "10X", MatchContextSpec{}, true},
		{"Malformed token", "10L-", MatchContextSpec{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMatchContext(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseMatchContext() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseMatchContext() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractContext(t *testing.T) {
	rawContent := `
L00|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
L01|bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
L02|cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
L03|dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
L04|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
L05|ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
L06|gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg
L07|hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh
L08|iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
L09|jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj
L10|kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkSECRET_KEY_VALUEkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
L11|llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll
L12|mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm
L13|nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn
L14|oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
L15|pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
L16|qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
L17|rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr
L18|ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss
L19|tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt
`
	lines := strings.Split(strings.Trim(rawContent, "\n"), "\n")

	const (
		matchCol = 60
		secret   = "SECRET_KEY_VALUE"
	)

	// Leading \n + each line is 150 chars + \n = 151. Match is on line 10 at column 60.
	matchStart := 1 + 10*151 + matchCol // 1571
	matchEnd := matchStart + len(secret)
	matchIdx := []int{matchStart, matchEnd}

	// Helpers for building expected values.
	joinLines := func(from, to int) string { return strings.Join(lines[from:to+1], "\n") }
	clipLine := func(line string, cs, ce int) string {
		if len(line) <= cs {
			cs = 0 // short line: show full content
		}
		return line[cs:min(ce, len(line))]
	}
	clipLines := func(from, to, cs, ce int) string {
		clipped := make([]string, to-from+1)
		for i := from; i <= to; i++ {
			clipped[i-from] = clipLine(lines[i], cs, ce)
		}
		return strings.Join(clipped, "\n")
	}

	tests := []struct {
		name string
		spec MatchContextSpec
		want string
	}{
		{
			name: "Zero spec",
			spec: MatchContextSpec{Mode: ContextModeNone},
			want: "",
		},
		{
			name: "Cols: 5 before, 5 after",
			spec: MatchContextSpec{Mode: ContextModeCols, ColsBefore: 5, ColsAfter: 5},
			want: rawContent[matchStart-5 : matchEnd+5],
		},
		{
			name: "Cols: directed -10, +5",
			spec: MatchContextSpec{Mode: ContextModeCols, ColsBefore: 10, ColsAfter: 5},
			want: rawContent[matchStart-10 : matchEnd+5],
		},
		{
			name: "Cols: out of bounds",
			spec: MatchContextSpec{Mode: ContextModeCols, ColsBefore: 10000, ColsAfter: 10000},
			want: rawContent,
		},
		{
			name: "Box: match line only",
			spec: MatchContextSpec{Mode: ContextModeBox},
			want: lines[10],
		},
		{
			name: "Box: 2 lines before, 3 lines after",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 2, LinesAfter: 3},
			want: joinLines(8, 13),
		},
		{
			name: "Box: match line, 10C clip",
			spec: MatchContextSpec{Mode: ContextModeBox, ColsBefore: 10, ColsAfter: 10},
			want: clipLine(lines[10], matchCol-10, matchCol+len(secret)+10),
		},
		{
			name: "Box: 3 lines before/after, 20C clip",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 3, LinesAfter: 3, ColsBefore: 20, ColsAfter: 20},
			want: clipLines(7, 13, matchCol-20, matchCol+len(secret)+20),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContext(rawContent, matchIdx, tt.spec)
			if got != tt.want {
				t.Errorf("extractContext()\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestExtractContextMultiLineMatch(t *testing.T) {
	// Multi-line match: column clipping should be skipped to avoid
	// corrupting the match on subsequent lines where the column offset
	// from the first line doesn't apply.
	raw := "aaa\nbbbSECRET_START\nSECRET_ENDccc\nddd"
	matchStart := strings.Index(raw, "SECRET_START")
	matchEnd := strings.Index(raw, "SECRET_END") + len("SECRET_END")
	matchIdx := []int{matchStart, matchEnd}

	tests := []struct {
		name string
		spec MatchContextSpec
		want string
	}{
		{
			name: "Box: multi-line match skips col clipping",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 1, ColsBefore: 2, ColsAfter: 2},
			// All 4 lines returned unclipped because the match spans lines.
			want: "aaa\nbbbSECRET_START\nSECRET_ENDccc\nddd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContext(raw, matchIdx, tt.spec)
			if got != tt.want {
				t.Errorf("extractContext()\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestExtractContextVaryingLineLengths(t *testing.T) {
	// Short lines mixed with long lines.
	// Tests that box mode column clipping shows short lines in full
	// rather than producing empty strings when the clip window exceeds the line length.
	rawContent := `
L00|aa
L01|bb
L02|cc
L03|dd
L04|ee
L05|ff
L06|gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg
L07|h
L08|iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
L09|jj
L10|kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkSECRET_KEY_VALUEkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
L11|lll
L12|m
L13|nn
L14|oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
L15|pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
L16|q
L17|rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr
L18|ssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss
L19|tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt
`
	lines := strings.Split(strings.Trim(rawContent, "\n"), "\n")

	const (
		matchCol = 60
		secret   = "SECRET_KEY_VALUE"
	)

	// Line lengths vary. Compute match offset by summing preceding line lengths + newlines.
	// Leading \n = 1, then lines 0-9 each contribute len+1 (\n).
	matchStart := 1
	for i := 0; i < 10; i++ {
		matchStart += len(lines[i]) + 1
	}
	matchStart += matchCol
	matchEnd := matchStart + len(secret)
	matchIdx := []int{matchStart, matchEnd}

	tests := []struct {
		name string
		spec MatchContextSpec
		want string
	}{
		{
			name: "Box: 3 lines before/after, 20C clip",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 3, LinesAfter: 3, ColsBefore: 20, ColsAfter: 20},
			want: "L07|h\n" +
				"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\n" +
				"L09|jj\n" +
				"kkkkkkkkkkkkkkkkkkkkSECRET_KEY_VALUEkkkkkkkkkkkkkkkkkkkk\n" +
				"L11|lll\n" +
				"L12|m\n" +
				"L13|nn",
		},
		{
			name: "Box: 5 lines before/after, 10C clip",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 5, LinesAfter: 5, ColsBefore: 10, ColsAfter: 10},
			want: "L05|ff\n" +
				"gggggggggggggggggggggggggggggggggggg\n" +
				"L07|h\n" +
				"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii\n" +
				"L09|jj\n" +
				"kkkkkkkkkkSECRET_KEY_VALUEkkkkkkkkkk\n" +
				"L11|lll\n" +
				"L12|m\n" +
				"L13|nn\n" +
				"oooooooooooooooooooooooooooooooooooo\n" +
				"pppppppppppppppppppppppppppppppppppp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContext(rawContent, matchIdx, tt.spec)
			if got != tt.want {
				t.Errorf("extractContext()\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}
