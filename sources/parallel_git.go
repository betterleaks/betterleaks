package sources

import (
	"context"
	"runtime"

	"github.com/fatih/semgroup"

	"github.com/betterleaks/betterleaks/sources/scm"
)

// ParallelGit is the compatibility entry point for parallel history scans.
//
// Deprecated: use Git with RepoPath and Workers.
type ParallelGit struct {
	RepoPath        string
	ShouldSkip      SkipFunc
	Platform        scm.Platform
	RemoteURL       string
	Sema            *semgroup.Group
	MaxArchiveDepth int
	LogOpts         string
	Workers         int // 0 means auto (min(NumCPU, 4))
	// TrustLocalGitConfig runs Git directly in RepoPath; see GitOptions.
	TrustLocalGitConfig bool
}

// Fragments delegates to Git, preserving automatic worker selection for v1 callers.
func (s *ParallelGit) Fragments(ctx context.Context, yield FragmentsFunc) error {
	workers := s.Workers
	if workers <= 0 {
		workers = min(runtime.NumCPU(), 4)
	}
	return (&Git{
		RepoPath: s.RepoPath, LogOpts: s.LogOpts, Workers: workers,
		TrustLocalGitConfig: s.TrustLocalGitConfig,
		ShouldSkip:          s.ShouldSkip, Platform: s.Platform, RemoteURL: s.RemoteURL,
		Sema: s.Sema, MaxArchiveDepth: s.MaxArchiveDepth,
	}).Fragments(ctx, yield)
}
