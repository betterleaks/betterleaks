package detect

import (
	"reflect"
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

		// Bytes Mode (B)
		{"Implicit bytes", "100", MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 100, BytesAfter: 100}, false},
		{"Explicit bytes", "100B", MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 100, BytesAfter: 100}, false},
		{"Directed bytes", "-10B, +20B", MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 10, BytesAfter: 20}, false},
		{"Overriding bytes", "10B, -50B", MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 50, BytesAfter: 10}, false},

		// Box Mode (L / C)
		{"Lines only", "10L", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 9, LinesAfter: 9}, false},
		{"Directed lines", "-2L, +3L", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 2}, false},
		{"Cols only", "50C", MatchContextSpec{Mode: ContextModeBox, ColsBefore: 50, ColsAfter: 50}, false},
		{"Directed cols", "-10C, +20C", MatchContextSpec{Mode: ContextModeBox, ColsBefore: 10, ColsAfter: 20}, false},
		{"Lines and Cols mixed", "2L, 15C", MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 1, ColsBefore: 15, ColsAfter: 15}, false},

		// Errors and Incompatibilities
		{"Mix B and L", "10L, 5B", MatchContextSpec{}, true},
		{"Mix B and C", "10C, 5B", MatchContextSpec{}, true},
		{"Mix implicit B and L", "10, 5L", MatchContextSpec{}, true},
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
	// Define test strings at the top using raw literals.
	// Flush-left prevents accidental indentation characters.
	rawContent := `0123456789
prefix_MATCH_HERE_suffix
klmnopqrst
`

	want1LineBefore := `0123456789
prefix_MATCH_HERE_suffix`

	want1LineAfter := `prefix_MATCH_HERE_suffix
klmnopqrst`

	wantLinesAndCols := `56789
x_MATCH_HERE_s
pqrst`

	// "MATCH_HERE" is 10 bytes long.
	// "prefix_" is 7 bytes.
	// Line 1 is 11 bytes (10 chars + \n).
	// Start index: 11 + 7 = 18.
	// End index: 18 + 10 = 28.
	matchIdx := []int{18, 28}

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
			name: "Bytes: 2 before, 2 after",
			spec: MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 2, BytesAfter: 2},
			want: "x_MATCH_HERE_s", // 2 before: "x_", 2 after: "_s"
		},
		{
			name: "Bytes: Out of bounds",
			spec: MatchContextSpec{Mode: ContextModeBytes, BytesBefore: 100, BytesAfter: 100},
			want: rawContent, // Should safely clamp to the entire string
		},
		{
			name: "Box: 0 lines, 0 cols (just the line)",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 0, LinesAfter: 0, ColsBefore: 0, ColsAfter: 0},
			want: "prefix_MATCH_HERE_suffix",
		},
		{
			name: "Box: 1 line before, 0 lines after",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 0, ColsBefore: 0, ColsAfter: 0},
			want: want1LineBefore,
		},
		{
			name: "Box: 0 lines before, 1 line after",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 0, LinesAfter: 1, ColsBefore: 0, ColsAfter: 0},
			want: want1LineAfter,
		},
		{
			name: "Box: 0 lines, 2 cols before/after",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 0, LinesAfter: 0, ColsBefore: 2, ColsAfter: 2},
			want: "x_MATCH_HERE_s", // Col clip: 2 cols around it on its line
		},
		{
			name: "Box: 1 line before/after, 2 cols before/after",
			spec: MatchContextSpec{Mode: ContextModeBox, LinesBefore: 1, LinesAfter: 1, ColsBefore: 2, ColsAfter: 2},
			want: wantLinesAndCols,
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
