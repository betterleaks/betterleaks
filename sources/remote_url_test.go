package sources

import "testing"

func TestSSHRemoteURLPattern(t *testing.T) {
	matches := map[string][2]string{ // input -> {host, path}
		"git@github.com:owner/repo.git":            {"github.com", "owner/repo"},
		"org-1234567@github.com:owner/repo.git":    {"github.com", "owner/repo"},
		"gitlab@gitlab.example.com:group/proj.git": {"gitlab.example.com", "group/proj"},
		"git@github.com:owner/repo":                {"github.com", "owner/repo"},
		"user.name@host.example.com:a/b/c.git":     {"host.example.com", "a/b/c"},
	}
	for in, want := range matches {
		m := sshUrlpat.FindStringSubmatch(in)
		if m == nil {
			t.Errorf("expected %q to match the scp pattern", in)
			continue
		}
		if m[1] != want[0] || m[2] != want[1] {
			t.Errorf("%q -> host=%q path=%q, want host=%q path=%q", in, m[1], m[2], want[0], want[1])
		}
	}

	for _, nonMatch := range []string{
		"https://github.com/owner/repo.git",
		"ftp://example.com/repo",
	} {
		if sshUrlpat.MatchString(nonMatch) {
			t.Errorf("%q should not match the scp pattern", nonMatch)
		}
	}
}
