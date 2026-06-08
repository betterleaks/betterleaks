package report

import (
	"testing"
	"unicode/utf8"
)

func TestRedactMasksCaptureGroups(t *testing.T) {
	f := Finding{
		Secret: "supersecret",
		Match:  "key=supersecret",
		Line:   "api key=supersecret here",
		CaptureGroups: map[string]string{
			"token": "supersecret",
			"user":  "alice",
		},
	}
	f.Redact(100)

	if f.CaptureGroups["token"] != "REDACTED" {
		t.Errorf("capture group holding the secret must be redacted, got %q", f.CaptureGroups["token"])
	}
	if f.CaptureGroups["user"] != "alice" {
		t.Errorf("non-secret capture group should be left intact, got %q", f.CaptureGroups["user"])
	}
}

func TestRedactPartiallyMasksCaptureGroups(t *testing.T) {
	f := Finding{
		Secret:        "abcdefghij",
		CaptureGroups: map[string]string{"t": "abcdefghij"},
	}
	f.Redact(50)
	if want := MaskSecret("abcdefghij", 50); f.CaptureGroups["t"] != want {
		t.Errorf("capture group should be partially masked to %q, got %q", want, f.CaptureGroups["t"])
	}
}

func TestMaskSecretMultibyteUTF8(t *testing.T) {
	secret := "日本語パスワード" // 8 runes, 24 bytes

	// At 70% the old byte-based slice cut at byte 7 — inside the 3rd rune —
	// producing invalid UTF-8. The rune-based mask keeps whole runes.
	got := MaskSecret(secret, 70)
	if !utf8.ValidString(got) {
		t.Fatalf("masked multi-byte secret is not valid UTF-8: %q", got)
	}
	if want := string([]rune(secret)[:2]) + "..."; got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
