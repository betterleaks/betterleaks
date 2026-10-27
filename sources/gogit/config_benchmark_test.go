package gogit_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/gogit"
)

// BenchmarkRepositoryConfig measures opening a repository with many tracked
// branches. It catches quadratic config parsing without requiring Git or a
// large object corpus. This file can also run unchanged on the v6 baseline.
func BenchmarkRepositoryConfig(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			repo := b.TempDir()
			for _, dir := range []string{"objects", "refs/heads"} {
				if err := os.MkdirAll(filepath.Join(repo, ".git", dir), 0700); err != nil {
					b.Fatal(err)
				}
			}
			var cfg strings.Builder
			cfg.WriteString("[core]\nrepositoryformatversion = 0\n")
			for n := range count {
				fmt.Fprintf(&cfg, "[branch \"branch%d\"]\nremote = origin\nmerge = refs/heads/main\n", n)
			}
			for name, data := range map[string]string{"HEAD": "ref: refs/heads/main\n", "config": cfg.String()} {
				if err := os.WriteFile(filepath.Join(repo, ".git", name), []byte(data), 0600); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				s := &gogit.Source{RepoPath: repo} //nolint:exhaustruct // Benchmark the public defaults.
				if err := s.Fragments(b.Context(), func(_ sources.Fragment, err error) error { return err }); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
