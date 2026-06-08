package cmd

import (
	"runtime"
	"sort"
	"testing"
)

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRemoveNestedPaths(t *testing.T) {
	// "a" appears twice (dedup to one), "a/sub" is nested under "a" (dropped),
	// "b" is unrelated (kept). Original strings and input order are preserved.
	got := removeNestedPaths([]string{"a", "a", "a/sub", "b"})
	if want := []string{"a", "b"}; !equalStringSlices(got, want) {
		t.Fatalf("removeNestedPaths = %v, want %v", got, want)
	}
}

func TestRemoveNestedPathsCaseInsensitiveOnWindows(t *testing.T) {
	got := removeNestedPaths([]string{"Foo", "foo/sub"})
	if runtime.GOOS == "windows" {
		if want := []string{"Foo"}; !equalStringSlices(got, want) {
			t.Fatalf("on Windows removeNestedPaths = %v, want %v", got, want)
		}
		return
	}
	// Case-sensitive filesystems treat them as distinct.
	sort.Strings(got)
	if want := []string{"Foo", "foo/sub"}; !equalStringSlices(got, want) {
		t.Fatalf("on case-sensitive FS removeNestedPaths = %v, want %v", got, want)
	}
}
