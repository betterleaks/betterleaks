# Internal Git diff parser

This package is maintained as part of Betterleaks. It was copied from the
`gitdiff` package in `github.com/gitleaks/go-gitdiff` at **v0.9.1**, the version
previously required by Betterleaks. The upstream code is licensed under the
[MIT license](LICENSE), copyright Billy Keyes.

This package contains the parser, its tests, fixtures, and benchmarks.
Local changes include a synchronous `ParseFileHeader` entry point
that reads metadata directly from an existing string, without a goroutine,
channel, or buffered reader per file. Parser fixes and optimizations belong here.
The `sources.GitDiff` source and streaming hunk reader live in
[`sources/git_patch.go`](../../sources/git_patch.go), used by `stdin --git-diff`.
Repository history scanning lives in [`sources/gogit`](../../sources/gogit) and
reads Git objects directly; it does not invoke Git or parse `git log` output.

Run the package tests and parser allocation benchmark with:

```sh
go test ./internal/gitdiff
go test ./internal/gitdiff -run '^$' -bench '^BenchmarkParse$' -benchmem
go test ./sources -run '^$' -bench '^(BenchmarkParseGitScanHeader|BenchmarkReadGitPatchManyFiles)$' -benchmem
```
