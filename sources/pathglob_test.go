package sources

import "testing"

func TestShouldScanPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		include []string
		exclude []string
		want    bool
	}{
		{
			name:    "no filters",
			path:    "src/main.go",
			want:    true,
		},
		{
			name:    "exclude directory prefix",
			path:    "fixtures/keys/secret.txt",
			exclude: []string{"fixtures/keys/**"},
			want:    false,
		},
		{
			name:    "exclude does not match sibling",
			path:    "fixtures/other/secret.txt",
			exclude: []string{"fixtures/keys/**"},
			want:    true,
		},
		{
			name:    "include limits scan",
			path:    "pkg/a.go",
			include: []string{"src/**"},
			want:    false,
		},
		{
			name:    "include allows match",
			path:    "src/a.go",
			include: []string{"src/**"},
			want:    true,
		},
		{
			name:    "exclude wins over include",
			path:    "src/ignored.txt",
			include: []string{"src/**"},
			exclude: []string{"src/ignored.txt"},
			want:    false,
		},
		{
			name:    "glob file pattern",
			path:    "tmp/notes.txt",
			exclude: []string{"tmp/*.txt"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ShouldScanPath(tt.path, tt.include, tt.exclude)
			if got != tt.want {
				t.Fatalf("ShouldScanPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
