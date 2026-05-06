package scm

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAuthCloneConfigs(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		token   string
		want    []GitConfig
		wantErr bool
	}{
		{
			name:   "https with token",
			remote: "https://github.com/owner/repo.git",
			token:  "ghp_abcdef",
			want: []GitConfig{{
				Key:   "http.https://github.com.extraHeader",
				Value: "Authorization: basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghp_abcdef")),
			}},
		},
		{
			name:   "http with token",
			remote: "http://example.com/repo.git",
			token:  "tkn",
			want: []GitConfig{{
				Key:   "http.http://example.com.extraHeader",
				Value: "Authorization: basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:tkn")),
			}},
		},
		{
			name:   "no token returns remote unchanged",
			remote: "https://github.com/owner/repo.git",
			token:  "",
			want:   nil,
		},
		{
			name:   "ssh remote returned unchanged",
			remote: "git@github.com:owner/repo.git",
			token:  "ghp_abcdef",
			want:   nil,
		},
		{
			name:   "enterprise host",
			remote: "https://github.enterprise.com/owner/repo.git",
			token:  "tkn",
			want: []GitConfig{{
				Key:   "http.https://github.enterprise.com.extraHeader",
				Value: "Authorization: basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:tkn")),
			}},
		},
		{
			name:    "malformed URL",
			remote:  "://bad",
			token:   "tkn",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authCloneConfigs(tc.remote, tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("authCloneConfigs() len = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("authCloneConfigs()[%d] = %#v, want %#v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestGitCloneEnv(t *testing.T) {
	env := gitCloneEnv([]GitConfig{{Key: "http.extraheader", Value: "Authorization: basic abc"}})
	joined := strings.Join(env, "\n")

	for _, want := range []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraheader",
		"GIT_CONFIG_VALUE_0=Authorization: basic abc",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("gitCloneEnv() missing %q in %q", want, joined)
		}
	}
}

func TestSanitizeOutput(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		token   string
		notWant []string // none of these substrings should appear in output
		want    string   // optional: exact expected output
	}{
		{
			name:    "redacts raw token",
			text:    "fatal: could not auth using ghp_secrettoken",
			token:   "ghp_secrettoken",
			notWant: []string{"ghp_secrettoken"},
		},
		{
			name:  "redacts URL userinfo even if token absent",
			text:  "fatal: cloning https://x-access-token:ghp_secret@github.com/foo/bar.git failed",
			token: "",
			want:  "fatal: cloning https://***@github.com/foo/bar.git failed",
		},
		{
			name:    "redacts URL userinfo when token also matches",
			text:    "cloning https://x-access-token:ghp_secret@github.com/foo/bar.git",
			token:   "ghp_secret",
			notWant: []string{"ghp_secret", "x-access-token:"},
		},
		{
			name:  "empty text",
			text:  "",
			token: "ghp_secret",
			want:  "",
		},
		{
			name:  "no token, no userinfo",
			text:  "fatal: not a git repository",
			token: "",
			want:  "fatal: not a git repository",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeOutput(tc.text, tc.token)
			for _, bad := range tc.notWant {
				if strings.Contains(got, bad) {
					t.Errorf("SanitizeOutput leaked %q in %q", bad, got)
				}
			}
			if tc.want != "" && got != tc.want {
				t.Errorf("SanitizeOutput() = %q, want %q", got, tc.want)
			}
		})
	}
}
