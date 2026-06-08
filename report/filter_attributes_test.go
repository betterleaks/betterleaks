package report

import "testing"

func TestFilterAttributesNoop(t *testing.T) {
	f := Finding{Attributes: map[string]string{"file": "main.go"}}
	got := f.FilterAttributes(nil, 0)
	if len(got.Attributes) != 1 || got.Attributes["file"] != "main.go" {
		t.Fatalf("expected attributes unchanged, got %v", got.Attributes)
	}
}

func TestFilterAttributesExcludeDoesNotMutateOriginal(t *testing.T) {
	f := Finding{Attributes: map[string]string{
		"file":   "main.go",
		"commit": "abc123",
		"email":  "a@b.com",
	}}
	exclude := map[string]struct{}{"commit": {}, "email": {}}

	got := f.FilterAttributes(exclude, 0)
	if _, ok := got.Attributes["commit"]; ok {
		t.Error("commit should have been excluded")
	}
	if _, ok := got.Attributes["email"]; ok {
		t.Error("email should have been excluded")
	}
	if got.Attributes["file"] != "main.go" {
		t.Errorf("file should remain, got %q", got.Attributes["file"])
	}
	// The original finding (and its map) must be untouched so reports are unaffected.
	if len(f.Attributes) != 3 {
		t.Errorf("original finding was mutated: %v", f.Attributes)
	}
}

func TestFilterAttributesMaxLen(t *testing.T) {
	f := Finding{Attributes: map[string]string{
		"short": "abc",
		"long":  "abcdefghij",
	}}
	got := f.FilterAttributes(nil, 5)
	if got.Attributes["short"] != "abc" {
		t.Errorf("value within the limit should be untouched, got %q", got.Attributes["short"])
	}
	if want := "abcde" + windowEllipsis; got.Attributes["long"] != want {
		t.Errorf("long value: got %q want %q", got.Attributes["long"], want)
	}
}

func TestFilterAttributesMaxLenCountsRunes(t *testing.T) {
	f := Finding{Attributes: map[string]string{"multi": "日本語テスト"}} // 6 runes, 18 bytes
	got := f.FilterAttributes(nil, 3)
	if want := "日本語" + windowEllipsis; got.Attributes["multi"] != want {
		t.Errorf("rune-aware truncation: got %q want %q", got.Attributes["multi"], want)
	}
}

func TestFilterAttributesNoAttributes(t *testing.T) {
	f := Finding{}
	got := f.FilterAttributes(map[string]struct{}{"x": {}}, 5)
	if got.Attributes != nil {
		t.Errorf("expected nil attributes, got %v", got.Attributes)
	}
}
