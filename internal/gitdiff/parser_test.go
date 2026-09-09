package gitdiff

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLineOperations(t *testing.T) {
	const content = "the first line\nthe second line\nthe third line\n"

	t.Run("read", func(t *testing.T) {
		p := newTestParser(content, false)

		for i, expected := range []string{
			"the first line\n",
			"the second line\n",
			"the third line\n",
		} {
			if err := p.Next(); err != nil {
				t.Fatalf("error advancing parser after line %d: %v", i, err)
			}
			if p.lineno != int64(i+1) {
				t.Fatalf("incorrect line number: expected %d, actual: %d", i+1, p.lineno)
			}

			line := p.Line(0)
			if line != expected {
				t.Fatalf("incorrect line %d: expected %q, was %q", i+1, expected, line)
			}
		}

		// reading after the last line should return EOF
		if err := p.Next(); err != io.EOF {
			t.Fatalf("expected EOF after end, but got: %v", err)
		}
		if p.lineno != 4 {
			t.Fatalf("incorrect line number: expected %d, actual: %d", 4, p.lineno)
		}

		// reading again returns EOF again and does not advance the line
		if err := p.Next(); err != io.EOF {
			t.Fatalf("expected EOF after end, but got: %v", err)
		}
		if p.lineno != 4 {
			t.Fatalf("incorrect line number: expected %d, actual: %d", 4, p.lineno)
		}
	})

	t.Run("peek", func(t *testing.T) {
		p := newTestParser(content, false)
		if err := p.Next(); err != nil {
			t.Fatalf("error advancing parser: %v", err)
		}

		line := p.Line(1)
		if line != "the second line\n" {
			t.Fatalf("incorrect peek line: %s", line)
		}

		if err := p.Next(); err != nil {
			t.Fatalf("error advancing parser after peek: %v", err)
		}

		line = p.Line(0)
		if line != "the second line\n" {
			t.Fatalf("incorrect read line: %s", line)
		}
	})

	t.Run("emptyInput", func(t *testing.T) {
		p := newTestParser("", false)
		if err := p.Next(); err != io.EOF {
			t.Fatalf("expected EOF on first Next(), but got: %v", err)
		}
	})
}

func TestParserInvariant_Advancement(t *testing.T) {
	tests := map[string]struct {
		Input   string
		Parse   func(p *parser) error
		EndLine string
	}{
		"ParseGitFileHeader": {
			Input: `diff --git a/dir/file.txt b/dir/file.txt
index 9540595..30e6333 100644
--- a/dir/file.txt
+++ b/dir/file.txt
@@ -1,2 +1,3 @@
context line
`,
			Parse: func(p *parser) error {
				_, err := p.ParseGitFileHeader()
				return err
			},
			EndLine: "@@ -1,2 +1,3 @@\n",
		},
		"ParseTraditionalFileHeader": {
			Input: `--- dir/file.txt
+++ dir/file.txt
@@ -1,2 +1,3 @@
context line
`,
			Parse: func(p *parser) error {
				_, err := p.ParseTraditionalFileHeader()
				return err
			},
			EndLine: "@@ -1,2 +1,3 @@\n",
		},
		"ParseTextFragmentHeader": {
			Input: `@@ -1,2 +1,3 @@
context line
`,
			Parse: func(p *parser) error {
				_, err := p.ParseTextFragmentHeader()
				return err
			},
			EndLine: "context line\n",
		},
		"ParseTextChunk": {
			Input: ` context line
-old line
+new line
 context line
@@ -1 +1 @@
`,
			Parse: func(p *parser) error {
				return p.ParseTextChunk(&TextFragment{OldLines: 3, NewLines: 3})
			},
			EndLine: "@@ -1 +1 @@\n",
		},
		"ParseTextFragments": {
			Input: `@@ -1,2 +1,2 @@
 context line
-old line
+new line
@@ -1,2 +1,2 @@
-old line
+new line
 context line
diff --git a/file.txt b/file.txt
`,
			Parse: func(p *parser) error {
				_, err := p.ParseTextFragments(&File{})
				return err
			},
			EndLine: "diff --git a/file.txt b/file.txt\n",
		},
		"ParseNextFileHeader": {
			Input: `not a header
diff --git a/file.txt b/file.txt
--- a/file.txt
+++ b/file.txt
@@ -1,2 +1,2 @@
`,
			Parse: func(p *parser) error {
				_, _, err := p.ParseNextFileHeader()
				return err
			},
			EndLine: "@@ -1,2 +1,2 @@\n",
		},
		"ParseBinaryMarker": {
			Input: `Binary files differ
diff --git a/file.txt b/file.txt
`,
			Parse: func(p *parser) error {
				_, _, err := p.ParseBinaryMarker()
				return err
			},
			EndLine: "diff --git a/file.txt b/file.txt\n",
		},
		"ParseBinaryFragmentHeader": {
			Input: `literal 0
HcmV?d00001
`,
			Parse: func(p *parser) error {
				_, err := p.ParseBinaryFragmentHeader()
				return err
			},
			EndLine: "HcmV?d00001\n",
		},
		"ParseBinaryChunk": {
			Input: "TcmZQzU|?i`" + `U?w2V48*Je09XJG

literal 0
`,
			Parse: func(p *parser) error {
				return p.ParseBinaryChunk(&BinaryFragment{Size: 20})
			},
			EndLine: "literal 0\n",
		},
		"ParseBinaryFragments": {
			Input: `GIT binary patch
literal 40
gcmZQzU|?i` + "`" + `U?w2V48*KJ%mKu_Kr9NxN<eH500b)lkN^Mx

literal 0
HcmV?d00001

diff --git a/file.txt b/file.txt
`,
			Parse: func(p *parser) error {
				_, err := p.ParseBinaryFragments(&File{})
				return err
			},
			EndLine: "diff --git a/file.txt b/file.txt\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestParser(test.Input, true)

			if err := test.Parse(p); err != nil {
				t.Fatalf("unexpected error while parsing: %v", err)
			}

			if test.EndLine != p.Line(0) {
				t.Errorf("incorrect position after parsing\nexpected: %q\n  actual: %q", test.EndLine, p.Line(0))
			}
		})
	}
}

func TestParseNextFileHeader(t *testing.T) {
	tests := map[string]struct {
		Input    string
		Output   *File
		Preamble string
		Err      bool
	}{
		"gitHeader": {
			Input: `commit 1acbae563cd6ef5750a82ee64e116c6eb065cb94
Author:	Morton Haypenny <mhaypenny@example.com>
Date:	Tue Apr 2 22:30:00 2019 -0700

    This is a sample commit message.

diff --git a/file.txt b/file.txt
index cc34da1..1acbae5 100644
--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,4 @@
`,
			Output: &File{
				OldName:      "file.txt",
				NewName:      "file.txt",
				OldMode:      os.FileMode(0100644),
				OldOIDPrefix: "cc34da1",
				NewOIDPrefix: "1acbae5",
			},
			Preamble: `commit 1acbae563cd6ef5750a82ee64e116c6eb065cb94
Author:	Morton Haypenny <mhaypenny@example.com>
Date:	Tue Apr 2 22:30:00 2019 -0700

    This is a sample commit message.

`,
		},
		"traditionalHeader": {
			Input: `
--- file.txt	2019-04-01 22:58:14.833597918 -0700
+++ file.txt	2019-04-01 22:58:14.833597918 -0700
@@ -1,3 +1,4 @@
`,
			Output: &File{
				OldName: "file.txt",
				NewName: "file.txt",
			},
			Preamble: "\n",
		},
		"noHeaders": {
			Input: `
this is a line
this is another line
--- could this be a header?
nope, it's just some dashes
`,
			Output:   nil,
			Preamble: "",
		},
		"detatchedFragmentLike": {
			Input: `
a wild fragment appears?
@@ -1,3 +1,4 ~1,5 @@
`,
			Output: nil,
		},
		"detatchedFragment": {
			Input: `
a wild fragment appears?
@@ -1,3 +1,4 @@
`,
			Err: true,
		},
		"mergeHeaderFollowedByNormalHeader": {
			Input: `commit f6ded7a51cf917bdb44097066fab608c0facde5b
Merge: b2cf1cd0de 0254477421
Author: BoloniniD <denis@bolonin.ru>
Date:   Thu Apr 7 01:07:38 2022 +0300

    Merge branch 'BLAKE3' of github.com:BoloniniD/ClickHouse into BLAKE3

commit 645e156af6b362145fad82d714f8e70a5b5a55a8
Author: Meena Renganathan <Meena.Renganathan@ibm.com>
Date:   Wed Apr 6 14:50:10 2022 -0700

    Updated the boringssl-cmake to match the latest broingssl module update

diff --git a/.gitmodules b/.gitmodules
index 6c9e66f9cb..9cee5f697e 100644
--- a/.gitmodules
+++ b/.gitmodules
@@ -207 +206,0 @@
-       branch = MergeWithUpstream
`,
			Output: &File{
				OldName:      ".gitmodules",
				NewName:      ".gitmodules",
				OldMode:      os.FileMode(0100644),
				OldOIDPrefix: "6c9e66f9cb",
				NewOIDPrefix: "9cee5f697e",
			},
			Preamble: `commit 645e156af6b362145fad82d714f8e70a5b5a55a8
Author: Meena Renganathan <Meena.Renganathan@ibm.com>
Date:   Wed Apr 6 14:50:10 2022 -0700

    Updated the boringssl-cmake to match the latest broingssl module update

`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestParser(test.Input, true)

			f, pre, err := p.ParseNextFileHeader()
			if test.Err {
				if err == nil || err == io.EOF {
					t.Fatalf("expected error parsing next file header, but got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error parsing next file header: %v", err)
			}

			if test.Preamble != pre {
				t.Errorf("incorrect preamble\nexpected: %q\n  actual: %q", test.Preamble, pre)
			}
			if !reflect.DeepEqual(test.Output, f) {
				t.Errorf("incorrect file\nexpected: %+v\n  actual: %+v", test.Output, f)
			}
		})
	}
}

func TestParse(t *testing.T) {
	textFragments := []*TextFragment{
		{
			OldPosition: 3,
			OldLines:    6,
			NewPosition: 3,
			NewLines:    8,
			Comment:     "fragment 1",
			Lines: []Line{
				{OpContext, "context line\n"},
				{OpDelete, "old line 1\n"},
				{OpDelete, "old line 2\n"},
				{OpContext, "context line\n"},
				{OpAdd, "new line 1\n"},
				{OpAdd, "new line 2\n"},
				{OpAdd, "new line 3\n"},
				{OpContext, "context line\n"},
				{OpDelete, "old line 3\n"},
				{OpAdd, "new line 4\n"},
				{OpAdd, "new line 5\n"},
			},
			LinesAdded:     5,
			LinesDeleted:   3,
			LeadingContext: 1,
		},
		{
			OldPosition: 31,
			OldLines:    2,
			NewPosition: 33,
			NewLines:    2,
			Comment:     "fragment 2",
			Lines: []Line{
				{OpContext, "context line\n"},
				{OpDelete, "old line 4\n"},
				{OpAdd, "new line 6\n"},
			},
			LinesAdded:     1,
			LinesDeleted:   1,
			LeadingContext: 1,
		},
	}

	textPreamble := `commit 5d9790fec7d95aa223f3d20936340bf55ff3dcbe
Author: Morton Haypenny <mhaypenny@example.com>
Date:   Tue Apr 2 22:55:40 2019 -0700

    A file with multiple fragments.

    The content is arbitrary.

`

	binaryPreamble := `commit 5d9790fec7d95aa223f3d20936340bf55ff3dcbe
Author: Morton Haypenny <mhaypenny@example.com>
Date:   Tue Apr 2 22:55:40 2019 -0700

    A binary file with the first 10 fibonacci numbers.

`
	tests := map[string]struct {
		InputFile string
		Output    []*File
		Preamble  string
		Err       bool
	}{
		"oneFile": {
			InputFile: "testdata/one_file.patch",
			Output: []*File{
				{
					PatchHeader: &PatchHeader{
						SHA: "5d9790fec7d95aa223f3d20936340bf55ff3dcbe",
						Author: &PatchIdentity{
							Name:  "Morton Haypenny",
							Email: "mhaypenny@example.com",
						},
						AuthorDate: asTime("2019-04-02T22:55:40-07:00"),
						Title:      "A file with multiple fragments.",
						Body:       "The content is arbitrary.",
					},
					OldName:       "dir/file1.txt",
					NewName:       "dir/file1.txt",
					OldMode:       os.FileMode(0100644),
					OldOIDPrefix:  "ebe9fa54",
					NewOIDPrefix:  "fe103e1d",
					TextFragments: textFragments,
				},
			},
			Preamble: textPreamble,
		},
		"twoFiles": {
			InputFile: "testdata/two_files.patch",
			Output: []*File{
				{
					PatchHeader: &PatchHeader{
						SHA: "5d9790fec7d95aa223f3d20936340bf55ff3dcbe",
						Author: &PatchIdentity{
							Name:  "Morton Haypenny",
							Email: "mhaypenny@example.com",
						},
						AuthorDate: asTime("2019-04-02T22:55:40-07:00"),
						Title:      "A file with multiple fragments.",
						Body:       "The content is arbitrary.",
					},
					OldName:       "dir/file1.txt",
					NewName:       "dir/file1.txt",
					OldMode:       os.FileMode(0100644),
					OldOIDPrefix:  "ebe9fa54",
					NewOIDPrefix:  "fe103e1d",
					TextFragments: textFragments,
				},
				{
					PatchHeader: &PatchHeader{
						SHA: "5d9790fec7d95aa223f3d20936340bf55ff3dcbe",
						Author: &PatchIdentity{
							Name:  "Morton Haypenny",
							Email: "mhaypenny@example.com",
						},
						AuthorDate: asTime("2019-04-02T22:55:40-07:00"),
						Title:      "A file with multiple fragments.",
						Body:       "The content is arbitrary.",
					},
					OldName:       "dir/file2.txt",
					NewName:       "dir/file2.txt",
					OldMode:       os.FileMode(0100644),
					OldOIDPrefix:  "417ebc70",
					NewOIDPrefix:  "67514b7f",
					TextFragments: textFragments,
				},
			},
			Preamble: textPreamble,
		},
		"newBinaryFile": {
			InputFile: "testdata/new_binary_file.patch",
			Output: []*File{
				{
					PatchHeader: &PatchHeader{
						SHA: "5d9790fec7d95aa223f3d20936340bf55ff3dcbe",
						Author: &PatchIdentity{
							Name:  "Morton Haypenny",
							Email: "mhaypenny@example.com",
						},
						AuthorDate: asTime("2019-04-02T22:55:40-07:00"),
						Title:      "A binary file with the first 10 fibonacci numbers.",
					},
					OldName:      "",
					NewName:      "dir/ten.bin",
					NewMode:      os.FileMode(0100644),
					OldOIDPrefix: "0000000000000000000000000000000000000000",
					NewOIDPrefix: "77b068ba48c356156944ea714740d0d5ca07bfec",
					IsNew:        true,
					IsBinary:     true,
					BinaryFragment: &BinaryFragment{
						Method: BinaryPatchLiteral,
						Size:   40,
						Data:   fib(10, binary.BigEndian),
					},
					ReverseBinaryFragment: &BinaryFragment{
						Method: BinaryPatchLiteral,
						Size:   0,
						Data:   []byte{},
					},
				},
			},
			Preamble: binaryPreamble,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			f, err := os.Open(test.InputFile)
			if err != nil {
				t.Fatalf("unexpected error opening input file: %v", err)
			}

			fileChan, err := Parse(f)
			if test.Err {
				if err == nil || err == io.EOF {
					t.Fatalf("expected error parsing patch, but got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error parsing patch: %v", err)
			}
			var files []*File
			for file := range fileChan {
				files = append(files, file)
			}

			if len(test.Output) != len(files) {
				t.Fatalf("incorrect number of parsed files: expected %d, actual %d", len(test.Output), len(files))
			}
			for i := range test.Output {
				if !reflect.DeepEqual(test.Output[i], files[i]) {
					exp, _ := json.MarshalIndent(test.Output[i], "", "  ")
					act, _ := json.MarshalIndent(files[i], "", "  ")
					t.Errorf("incorrect file at position %d\nexpected: %s\n  actual: %s", i, exp, act)
				}
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	var inputDiff string
	{
		builder := strings.Builder{}
		builder.WriteString(`commit 5d9790fec7d95aa223f3d20936340bf55ff3dcbe
Author: Morton Haypenny <mhaypenny@example.com>
Date:   Tue Apr 2 22:55:40 2019 -0700

    A file with multiple fragments.

    The content is arbitrary.

`)
		fileDiff := func(i int) string {
			return fmt.Sprintf(`diff --git a/dir/file%[1]d.txt b/dir/file%[1]d.txt
index ebe9fa54..fe103e1d 100644
--- a/dir/file%[1]d.txt
+++ b/dir/file%[1]d.txt
@@ -3,6 +3,8 @@ fragment 1
 context line
-old line 1
-old line 2
 context line
+new line 1
+new line 2
+new line 3
 context line
-old line 3
+new line 4
+new line 5
@@ -31,2 +33,2 @@ fragment 2
 context line
-old line 4
+new line 6
`, i)
		}
		for i := 0; i < 1000; i++ {
			_, err := builder.WriteString(fileDiff(i))
			if err != nil {
				panic(err)
			}
		}
		inputDiff = builder.String()
	}
	for i := 0; i < b.N; i++ {
		reader := io.NopCloser(strings.NewReader(inputDiff))
		ch, err := Parse(reader)
		if err != nil {
			panic(err)
		}
		for range ch {
		}
	}
}

func newTestParser(input string, init bool) *parser {
	p := newParser(bytes.NewBufferString(input))
	if init {
		_ = p.Next()
	}
	return p
}

func asTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
