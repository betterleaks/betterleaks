package gitdiff

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestApplierInvariants(t *testing.T) {
	binary := &BinaryFragment{
		Method: BinaryPatchLiteral,
		Size:   2,
		Data:   []byte("\xbe\xef"),
	}

	text := &TextFragment{
		NewPosition: 1,
		NewLines:    1,
		LinesAdded:  1,
		Lines: []Line{
			{Op: OpAdd, Line: "new line\n"},
		},
	}

	file := &File{
		TextFragments: []*TextFragment{text},
	}

	src := bytes.NewReader(nil)
	dst := ioutil.Discard

	assertInProgress := func(t *testing.T, kind string, err error) {
		if !errors.Is(err, errApplyInProgress) {
			t.Fatalf("expected in-progress error for %s apply, but got: %v", kind, err)
		}
	}

	t.Run("binaryFirst", func(t *testing.T) {
		a := NewApplier(src)
		if err := a.ApplyBinaryFragment(dst, binary); err != nil {
			t.Fatalf("unexpected error applying fragment: %v", err)
		}
		assertInProgress(t, "text", a.ApplyTextFragment(dst, text))
		assertInProgress(t, "binary", a.ApplyBinaryFragment(dst, binary))
		assertInProgress(t, "file", a.ApplyFile(dst, file))
	})

	t.Run("textFirst", func(t *testing.T) {
		a := NewApplier(src)
		if err := a.ApplyTextFragment(dst, text); err != nil {
			t.Fatalf("unexpected error applying fragment: %v", err)
		}
		// additional text fragments are allowed
		if err := a.ApplyTextFragment(dst, text); err != nil {
			t.Fatalf("unexpected error applying second fragment: %v", err)
		}
		assertInProgress(t, "binary", a.ApplyBinaryFragment(dst, binary))
		assertInProgress(t, "file", a.ApplyFile(dst, file))
	})

	t.Run("fileFirst", func(t *testing.T) {
		a := NewApplier(src)
		if err := a.ApplyFile(dst, file); err != nil {
			t.Fatalf("unexpected error applying file: %v", err)
		}
		assertInProgress(t, "text", a.ApplyTextFragment(dst, text))
		assertInProgress(t, "binary", a.ApplyBinaryFragment(dst, binary))
		assertInProgress(t, "file", a.ApplyFile(dst, file))
	})
}

func TestApplyTextFragment(t *testing.T) {
	tests := map[string]applyTest{
		"createFile": {Files: getApplyFiles("text_fragment_new")},
		"deleteFile": {Files: getApplyFiles("text_fragment_delete_all")},

		"addStart":    {Files: getApplyFiles("text_fragment_add_start")},
		"addMiddle":   {Files: getApplyFiles("text_fragment_add_middle")},
		"addEnd":      {Files: getApplyFiles("text_fragment_add_end")},
		"addEndNoEOL": {Files: getApplyFiles("text_fragment_add_end_noeol")},

		"changeStart":       {Files: getApplyFiles("text_fragment_change_start")},
		"changeMiddle":      {Files: getApplyFiles("text_fragment_change_middle")},
		"changeEnd":         {Files: getApplyFiles("text_fragment_change_end")},
		"changeExact":       {Files: getApplyFiles("text_fragment_change_exact")},
		"changeSingleNoEOL": {Files: getApplyFiles("text_fragment_change_single_noeol")},

		"errorShortSrcBefore": {
			Files: applyFiles{
				Src:   "text_fragment_error.src",
				Patch: "text_fragment_error_short_src_before.patch",
			},
			Err: io.ErrUnexpectedEOF,
		},
		"errorShortSrc": {
			Files: applyFiles{
				Src:   "text_fragment_error.src",
				Patch: "text_fragment_error_short_src.patch",
			},
			Err: io.ErrUnexpectedEOF,
		},
		"errorContextConflict": {
			Files: applyFiles{
				Src:   "text_fragment_error.src",
				Patch: "text_fragment_error_context_conflict.patch",
			},
			Err: &Conflict{},
		},
		"errorDeleteConflict": {
			Files: applyFiles{
				Src:   "text_fragment_error.src",
				Patch: "text_fragment_error_delete_conflict.patch",
			},
			Err: &Conflict{},
		},
		"errorNewFile": {
			Files: applyFiles{
				Src:   "text_fragment_error.src",
				Patch: "text_fragment_error_new_file.patch",
			},
			Err: &Conflict{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.run(t, func(w io.Writer, applier *Applier, file *File) error {
				if len(file.TextFragments) != 1 {
					t.Fatalf("patch should contain exactly one fragment, but it has %d", len(file.TextFragments))
				}
				return applier.ApplyTextFragment(w, file.TextFragments[0])
			})
		})
	}
}

func TestApplyBinaryFragment(t *testing.T) {
	tests := map[string]applyTest{
		"literalCreate":    {Files: getApplyFiles("bin_fragment_literal_create")},
		"literalModify":    {Files: getApplyFiles("bin_fragment_literal_modify")},
		"deltaModify":      {Files: getApplyFiles("bin_fragment_delta_modify")},
		"deltaModifyLarge": {Files: getApplyFiles("bin_fragment_delta_modify_large")},

		"errorIncompleteAdd": {
			Files: applyFiles{
				Src:   "bin_fragment_delta_error.src",
				Patch: "bin_fragment_delta_error_incomplete_add.patch",
			},
			Err: "incomplete add",
		},
		"errorIncompleteCopy": {
			Files: applyFiles{
				Src:   "bin_fragment_delta_error.src",
				Patch: "bin_fragment_delta_error_incomplete_copy.patch",
			},
			Err: "incomplete copy",
		},
		"errorSrcSize": {
			Files: applyFiles{
				Src:   "bin_fragment_delta_error.src",
				Patch: "bin_fragment_delta_error_src_size.patch",
			},
			Err: &Conflict{},
		},
		"errorDstSize": {
			Files: applyFiles{
				Src:   "bin_fragment_delta_error.src",
				Patch: "bin_fragment_delta_error_dst_size.patch",
			},
			Err: "insufficient or extra data",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.run(t, func(w io.Writer, applier *Applier, file *File) error {
				return applier.ApplyBinaryFragment(w, file.BinaryFragment)
			})
		})
	}
}

func TestApplyFile(t *testing.T) {
	tests := map[string]applyTest{
		"textModify": {
			Files: applyFiles{
				Src:   "file_text.src",
				Patch: "file_text_modify.patch",
				Out:   "file_text_modify.out",
			},
		},
		"textDelete": {
			Files: applyFiles{
				Src:   "file_text.src",
				Patch: "file_text_delete.patch",
				Out:   "file_text_delete.out",
			},
		},
		"textErrorPartialDelete": {
			Files: applyFiles{
				Src:   "file_text.src",
				Patch: "file_text_error_partial_delete.patch",
			},
			Err: &Conflict{},
		},
		"binaryModify": {
			Files: getApplyFiles("file_bin_modify"),
		},
		"modeChange": {
			Files: getApplyFiles("file_mode_change"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			test.run(t, func(w io.Writer, applier *Applier, file *File) error {
				return applier.ApplyFile(w, file)
			})
		})
	}
}

type applyTest struct {
	Files applyFiles
	Err   interface{}
}

func (at applyTest) run(t *testing.T, apply func(io.Writer, *Applier, *File) error) {
	src, patch, out := at.Files.Load(t)

	fileChan, err := Parse(io.NopCloser(bytes.NewReader(patch)))
	if err != nil {
		t.Fatalf("failed to parse patch file: %v", err)
	}
	var files []*File
	for file := range fileChan {
		files = append(files, file)
	}
	if len(files) != 1 {
		t.Fatalf("patch should contain exactly one file, but it has %d", len(files))
	}

	applier := NewApplier(bytes.NewReader(src))

	var dst bytes.Buffer
	err = apply(&dst, applier, files[0])
	if at.Err != nil {
		assertError(t, at.Err, err, "applying fragment")
		return
	}
	if err != nil {
		var aerr *ApplyError
		if errors.As(err, &aerr) {
			t.Fatalf("unexpected error applying: at %d: fragment %d at %d: %v", aerr.Line, aerr.Fragment, aerr.FragmentLine, err)
		} else {
			t.Fatalf("unexpected error applying: %v", err)
		}
	}

	if !bytes.Equal(out, dst.Bytes()) {
		t.Errorf("incorrect result after apply\nexpected:\n%q\nactual:\n%q", out, dst.Bytes())
	}
}

type applyFiles struct {
	Src   string
	Patch string
	Out   string
}

func getApplyFiles(name string) applyFiles {
	return applyFiles{
		Src:   name + ".src",
		Patch: name + ".patch",
		Out:   name + ".out",
	}
}

func (f applyFiles) Load(t *testing.T) (src []byte, patch []byte, out []byte) {
	load := func(name, kind string) []byte {
		d, err := ioutil.ReadFile(filepath.Join("testdata", "apply", name))
		if err != nil {
			t.Fatalf("failed to read %s file: %v", kind, err)
		}
		return d
	}

	if f.Src != "" {
		src = load(f.Src, "source")
	}
	if f.Patch != "" {
		patch = load(f.Patch, "patch")
	}
	if f.Out != "" {
		out = load(f.Out, "output")
	}
	return
}
