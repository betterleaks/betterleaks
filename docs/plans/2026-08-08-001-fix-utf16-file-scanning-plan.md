---
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
execution: code
product_contract_source: ce-plan-bootstrap
title: "fix: Scan UTF-16 encoded files correctly"
type: fix
---

# fix: Scan UTF-16 encoded files correctly

**Target repo:** betterleaks/betterleaks (working from fork `SomSamantray/betterleaks`)
**Origin:** https://github.com/betterleaks/betterleaks/issues/221

---

## Summary

`betterleaks dir` silently produces zero findings when scanning UTF-16 LE/BE encoded text files, even when they contain plaintext secrets a human (or the UTF-8 equivalent file) would trigger on. Fix by BOM-sniffing file content and transcoding UTF-16 to UTF-8 before it reaches the fragment/regex pipeline.

## Problem Frame

`sources/file.go`'s `fileFragments` reads raw file bytes into `Fragment.Raw`/`Fragment.Bytes` with no encoding awareness. Rule regexes (e.g. `generic-api-key`, `brave-search-api-key`) are byte/ASCII-oriented. UTF-16 encodes every ASCII character with an interleaved `0x00` byte, so no rule regex matches the raw byte stream — the scan completes "successfully" (files are read, bytes counted) but yields no leaks, which is worse than an error because it looks like a clean scan.

Confirmed still present at current `HEAD`: `sources/file.go:138` constructs the buffered reader directly from the raw content stream with no charset detection anywhere in the file or its callers. No BOM/`utf16`/`UTF16` handling exists anywhere in the non-test Go source. No open or merged PR touches this.

## Requirements

- R1: A UTF-16 LE encoded text file containing a matchable secret is scanned and the secret is reported, matching current UTF-8 behavior.
- R2: A UTF-16 BE encoded text file containing a matchable secret is scanned and the secret is reported.
- R3: Existing UTF-8/ASCII/Windows-1252/CP437 scanning behavior is unchanged (no regressions in encoding, findings, or reported byte counts for non-UTF-16 content).
- R4: The fix applies to the filesystem scan path (`betterleaks dir`, `sources/file.go`) — the reported bug's scope. Git-history scanning (`sources/git.go`) reads blob content through a separate path and is not touched by this plan (see Scope Boundaries).

## Key Technical Decisions

- **KTD1: Use `golang.org/x/text/encoding/unicode`'s `BOMOverride`, not a new dependency.** It is already an indirect dependency in `go.mod` (pulled in transitively) and is the standard library-adjacent way to do BOM-based encoding detection and transcoding in Go. Adding a new charset-detection library for this would violate the "use what's already installed" default — `BOMOverride` does exactly what's needed: detect a UTF-8/UTF-16LE/UTF-16BE BOM and decode accordingly, or pass bytes through unchanged when no BOM is present.
  - Alternative considered: heuristic null-byte-density detection (no BOM required). Rejected for this plan — it's a fuzzier, higher-risk heuristic (false positives on binary-ish text, needs tuning) whereas BOM detection is exact and covers the reported case (Windows tools that write UTF-16 files reliably emit a BOM). Documented as a known limitation, not silently promised.
- **KTD2: Wrap the stream once per top-level file, at the point immediately before `sources/file.go`'s `fileFragments` builds its buffered reader** (`sources/file.go:138`, the `br := getReader(stream)` line), not inside the read loop. `transform.Reader` is a streaming decoder — wrapping once here lets it see the BOM at the true start of the file and decode consistently across all subsequent chunked reads. This is also strictly after the archive-identification branch above it, so compressed/archive byte streams (which must stay untouched) are never passed through the text transcoder.
- **KTD3: No-BOM content is passed through unchanged via `transform.Nop`.** This guarantees R3: any file without a UTF-16/UTF-8 BOM (i.e., today's entire supported set) takes the identical byte path it does today.

## High-Level Technical Design

```
Fragments()
  ├─ archive? (archives.Identify) ──yes──> extractor/decompressor path (untouched)
  └─ no ──> stream = transform.NewReader(stream, unicode.BOMOverride(transform.Nop))
            └─ fileFragments(reader=getReader(stream), ...)
                 - BOM present (UTF-16LE/BE, UTF-8)  -> transcoded to UTF-8, BOM stripped
                 - no BOM                              -> bytes pass through unchanged (Nop)
```

## Scope Boundaries

### In scope
- BOM detection + UTF-16LE/UTF-16BE → UTF-8 transcoding for the filesystem scan path (`sources/file.go`).
- Regression coverage for existing non-UTF-16 encodings on the same code path.

### Out of scope / Non-goals
- UTF-16 files with no BOM (cannot be reliably distinguished from other binary/text content without a heuristic; not part of the reported issue).
- Other encodings not raised in the issue (e.g. UTF-32, EBCDIC).

### Deferred to Follow-Up Work
- Applying the same BOM-aware decoding to `sources/git.go`'s blob-reading path, if git-history scanning of UTF-16 files turns out to have the same problem — it reads content through a different, non-shared code path and needs its own investigation. Not requested by issue #221, which reproduces only via `betterleaks dir`.

## Implementation Units

### U1. BOM-aware transcoding in the file source

**Goal:** Detect a UTF-16LE/UTF-16BE/UTF-8 BOM on the file content stream and transcode to UTF-8 before fragments are built, leaving non-BOM content untouched.

**Requirements:** R1, R2, R3, R4

**Dependencies:** none

**Files:**
- `sources/file.go` — wrap `stream` with the BOM-aware transform reader at the point noted in KTD2, add the `golang.org/x/text/encoding/unicode` and `golang.org/x/text/transform` imports.
- `sources/file_test.go` — add test coverage (see Test scenarios).
- `go.mod` — `golang.org/x/text` moves from indirect to direct (run `go mod tidy` after the code change; no version bump needed, already at v0.38.0).

**Approach:** In `File.Fragments`, after the archive-identification branch has been ruled out (i.e. we're in the plain-file path that currently does `br := getReader(stream)`), wrap `stream` with `transform.NewReader(stream, unicode.BOMOverride(transform.Nop))` before passing it to `getReader`. `unicode.BOMOverride` inspects the first bytes for a UTF-8, UTF-16LE, or UTF-16BE BOM; if found, it strips the BOM and decodes the rest of the stream to UTF-8 using the matching decoder; if not found, it falls through to the given fallback transformer (`transform.Nop`), which passes bytes through unmodified. This keeps every currently-working encoding (ASCII, UTF-8, Windows-1252, CP437 — none of which carry a BOM in practice, or if UTF-8 does, `BOMOverride` already strips a UTF-8 BOM today's code doesn't strip) on its existing byte path.

**Patterns to follow:** The existing pooled-reader pattern (`getReader`/`putReader`) is unaffected — `transform.NewReader` just becomes the `io.Reader` passed into it, same as `stream` is today.

**Test scenarios:**
- Happy path: a byte slice with a UTF-16LE BOM (`0xFF 0xFE`) encoding text containing `BSA111222333444555666777888999000111` yields a fragment whose `Raw`/`Bytes` contain the plain UTF-8 secret string (matchable by the `brave-search-api-key` rule pattern).
- Happy path: the same content encoded UTF-16BE (`0xFE 0xFF` BOM) yields the same decoded result.
- Regression: a plain ASCII/UTF-8 (no BOM) file with the same secret still yields an identical fragment to current behavior (byte-for-byte unchanged `Raw`).
- Regression: a UTF-8 file that *does* start with a UTF-8 BOM (`0xEF 0xBB 0xBF`) has the BOM stripped and the remaining content still matches — confirm this doesn't newly break anything (UTF-8 BOM is rare but valid).
- Edge case: an empty file with just a BOM and no content produces no fragments/no error (matches current empty-file handling).
- Edge case: a UTF-16-encoded file that is large enough to span multiple internal buffer reads (`defaultBufferSize` / chunk boundaries) still decodes correctly across chunks — confirms `transform.NewReader`'s streaming behavior is being exercised, not just a single-read case.

**Verification:** `go test ./sources/...` passes, including the new UTF-16 cases; a manual `betterleaks dir` run against a UTF-16LE test file (mirroring the issue's repro steps) reports the finding instead of "no leaks found".

## Verification Contract

- `go build ./...` succeeds.
- `go test ./sources/... ./detect/...` passes with no regressions.
- Manual repro from issue #221 (write the Brave Search API key example to UTF-16LE and UTF-16BE `.txt` files, run `betterleaks dir`) now reports 1 leak for each, matching the UTF-8 case.

## Definition of Done

- [ ] U1 implemented and all listed test scenarios pass.
- [ ] No regression in existing `sources` package tests.
- [ ] Manual verification of the issue's exact repro steps confirms the fix.
