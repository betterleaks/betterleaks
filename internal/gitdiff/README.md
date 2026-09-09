# Internal Git diff parser

This package is maintained as part of Betterleaks. It was copied from the
`gitdiff` package in `github.com/gitleaks/go-gitdiff` at **v0.9.1**, the version
previously required by Betterleaks. The upstream code is licensed under the
[MIT license](LICENSE), copyright Billy Keyes.

The import includes the parser, patch application support, tests, fixtures, and
benchmarks. Local changes include a synchronous `ParseFileHeader` entry point
that reads metadata directly from an existing string, without a goroutine,
channel, or buffered reader per file. The binary fixture helper uses the internal
import and the existing channel API. Parser fixes and optimizations belong here.
Scan orchestration and the streaming hunk reader remain in `sources/git.go` and
`sources/git_patch.go`.

Run the package tests and parser allocation benchmark with:

```sh
go test ./internal/gitdiff
go test ./internal/gitdiff -run '^$' -bench '^BenchmarkParse$' -benchmem
go test ./sources -run '^$' -bench '^(BenchmarkParseGitScanHeader|BenchmarkReadGitPatchManyFiles)$' -benchmem
```
