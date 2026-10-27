//nolint:exhaustruct // Exercise the source with its public defaults.
package gogit_test

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/gogit"
)

// BenchmarkFragments measures the entire Git source, including tree decoding,
// rename scoring and patches, without the detector or report writer. The same
// benchmark can be copied unchanged into a baseline checkout for comparison.
func BenchmarkFragments(b *testing.B) {
	path := os.Getenv("BETTERLEAKS_GIT_BENCH_REPO")
	if path == "" {
		b.Skip("set BETTERLEAKS_GIT_BENCH_REPO to an existing repository")
	}
	b.ReportAllocs()
	for b.Loop() {
		var fragments, bytes atomic.Int64
		s := &gogit.Source{RepoPath: path}
		err := s.Fragments(b.Context(), func(f sources.Fragment, err error) error {
			if err == nil {
				fragments.Add(1)
				bytes.Add(int64(len(f.Raw)))
			}
			return err
		})
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(fragments.Load()), "fragments/op")
		b.ReportMetric(float64(bytes.Load()), "content-bytes/op")
	}
}
