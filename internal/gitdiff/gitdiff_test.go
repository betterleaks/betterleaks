package gitdiff

import (
	"strings"
	"testing"
)

func TestTextFragmentValidate(t *testing.T) {
	tests := map[string]struct {
		Fragment TextFragment
		Err      string
	}{
		"oldLines": {
			Fragment: TextFragment{
				OldPosition:     1,
				OldLines:        3,
				NewPosition:     1,
				NewLines:        2,
				LeadingContext:  1,
				TrailingContext: 0,
				LinesAdded:      1,
				LinesDeleted:    1,
				Lines: []Line{
					{Op: OpContext, Line: "line 1\n"},
					{Op: OpDelete, Line: "old line 2\n"},
					{Op: OpAdd, Line: "new line 2\n"},
				},
			},
			Err: "2 old lines",
		},
		"newLines": {
			Fragment: TextFragment{
				OldPosition:     1,
				OldLines:        2,
				NewPosition:     1,
				NewLines:        3,
				LeadingContext:  1,
				TrailingContext: 0,
				LinesAdded:      1,
				LinesDeleted:    1,
				Lines: []Line{
					{Op: OpContext, Line: "line 1\n"},
					{Op: OpDelete, Line: "old line 2\n"},
					{Op: OpAdd, Line: "new line 2\n"},
				},
			},
			Err: "2 new lines",
		},
		"leadingContext": {
			Fragment: TextFragment{
				OldPosition:     1,
				OldLines:        2,
				NewPosition:     1,
				NewLines:        2,
				LeadingContext:  0,
				TrailingContext: 0,
				LinesAdded:      1,
				LinesDeleted:    1,
				Lines: []Line{
					{Op: OpContext, Line: "line 1\n"},
					{Op: OpDelete, Line: "old line 2\n"},
					{Op: OpAdd, Line: "new line 2\n"},
				},
			},
			Err: "1 leading context lines",
		},
		"trailingContext": {
			Fragment: TextFragment{
				OldPosition:     1,
				OldLines:        4,
				NewPosition:     1,
				NewLines:        3,
				LeadingContext:  1,
				TrailingContext: 1,
				LinesAdded:      1,
				LinesDeleted:    2,
				Lines: []Line{
					{Op: OpContext, Line: "line 1\n"},
					{Op: OpDelete, Line: "old line 2\n"},
					{Op: OpAdd, Line: "new line 2\n"},
					{Op: OpContext, Line: "line 3\n"},
					{Op: OpDelete, Line: "old line 4\n"},
				},
			},
			Err: "0 trailing context lines",
		},
		"linesAdded": {
			Fragment: TextFragment{
				OldPosition:     1,
				OldLines:        4,
				NewPosition:     1,
				NewLines:        3,
				LeadingContext:  1,
				TrailingContext: 0,
				LinesAdded:      2,
				LinesDeleted:    2,
				Lines: []Line{
					{Op: OpContext, Line: "line 1\n"},
					{Op: OpDelete, Line: "old line 2\n"},
					{Op: OpAdd, Line: "new line 2\n"},
					{Op: OpContext, Line: "line 3\n"},
					{Op: OpDelete, Line: "old line 4\n"},
				},
			},
			Err: "1 added lines",
		},
		"linesDeleted": {
			Fragment: TextFragment{
				OldPosition:     1,
				OldLines:        4,
				NewPosition:     1,
				NewLines:        3,
				LeadingContext:  1,
				TrailingContext: 0,
				LinesAdded:      1,
				LinesDeleted:    1,
				Lines: []Line{
					{Op: OpContext, Line: "line 1\n"},
					{Op: OpDelete, Line: "old line 2\n"},
					{Op: OpAdd, Line: "new line 2\n"},
					{Op: OpContext, Line: "line 3\n"},
					{Op: OpDelete, Line: "old line 4\n"},
				},
			},
			Err: "2 deleted lines",
		},
		"fileCreation": {
			Fragment: TextFragment{
				OldPosition:     0,
				OldLines:        2,
				NewPosition:     1,
				NewLines:        1,
				LeadingContext:  0,
				TrailingContext: 0,
				LinesAdded:      1,
				LinesDeleted:    2,
				Lines: []Line{
					{Op: OpDelete, Line: "old line 1\n"},
					{Op: OpDelete, Line: "old line 2\n"},
					{Op: OpAdd, Line: "new line\n"},
				},
			},
			Err: "creation fragment",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.Fragment.Validate()
			if test.Err == "" && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
			if test.Err != "" && err == nil {
				t.Fatal("expected validation error, but got nil")
			}
			if !strings.Contains(err.Error(), test.Err) {
				t.Fatalf("incorrect validation error: %q is not in %q", test.Err, err.Error())
			}
		})
	}
}
