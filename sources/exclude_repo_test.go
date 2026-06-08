package sources

import "testing"

func TestGitHubIsExcluded(t *testing.T) {
	s := &GitHub{ExcludeRepos: []string{"owner/test-*", "Acme/Secret"}}
	cases := map[string]bool{
		"owner/test-foo": true,
		"owner/test-bar": true,
		"owner/prod":     false,
		"OWNER/TEST-FOO": true,  // GitHub names are case-insensitive
		"acme/secret":    true,  // case-folded against "Acme/Secret"
		"owner/test/sub": false, // '*' does not cross '/'
	}
	for in, want := range cases {
		if got := s.isExcluded(in); got != want {
			t.Errorf("GitHub.isExcluded(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGitLabIsExcluded(t *testing.T) {
	s := &GitLab{ExcludeRepos: []string{"group/test-*", "Group/Sub/Proj"}}
	cases := map[string]bool{
		"group/test-foo":   true,
		"group/prod":       false,
		"GROUP/TEST-FOO":   true,
		"group/sub/proj":   true, // case-folded against "Group/Sub/Proj"
		"group/sub/proj-2": false,
	}
	for in, want := range cases {
		if got := s.isExcluded(in); got != want {
			t.Errorf("GitLab.isExcluded(%q) = %v, want %v", in, got, want)
		}
	}
}
