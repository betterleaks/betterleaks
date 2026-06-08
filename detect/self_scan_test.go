package detect

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks/sources"
)

func TestSamePathToleratesSeparators(t *testing.T) {
	// Native-separator config path vs the forward-slash fragment path the file
	// source produces must compare equal (the bug only bites on Windows, where
	// filepath.FromSlash yields backslashes).
	cfg := filepath.FromSlash("proj/sub/.betterleaks.toml")
	if !samePath("proj/sub/.betterleaks.toml", cfg) {
		t.Errorf("samePath(%q, %q) = false, want true", "proj/sub/.betterleaks.toml", cfg)
	}
	if samePath("proj/sub/other.toml", cfg) {
		t.Error("distinct files must not compare equal")
	}
}

func TestDetectFragmentSkipsConfigSelfScan(t *testing.T) {
	d, err := NewDetectorDefaultConfig()
	if err != nil {
		t.Fatalf("NewDetectorDefaultConfig: %v", err)
	}
	d.Config.Path = filepath.FromSlash("proj/.betterleaks.toml")

	// Deterministic, high-entropy github-pat token so the content would be
	// flagged if it were actually scanned.
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 36)
	for i := range b {
		b[i] = charset[(i*37+11)%len(charset)]
	}
	raw := `token = "ghp_` + string(b) + `"`

	// Sanity check: the same content at an ordinary path is flagged.
	if hits := d.detectFragment(context.Background(), sources.Fragment{
		Raw:        raw,
		Attributes: map[string]string{sources.AttrPath: "proj/app.go"},
	}); len(hits) == 0 {
		t.Fatal("expected the test token to be detectable at a normal path")
	}

	// The config file itself must be skipped, even though its fragment path uses
	// forward slashes while Config.Path uses the native separator.
	if hits := d.detectFragment(context.Background(), sources.Fragment{
		Raw:        raw,
		Attributes: map[string]string{sources.AttrPath: "proj/.betterleaks.toml"},
	}); len(hits) != 0 {
		t.Fatalf("config file should be skipped (self-scan guard), got %d finding(s)", len(hits))
	}
}
