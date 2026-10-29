package scm

import "github.com/betterleaks/betterleaks/v2/sources/scm/platform"

// The platform names live in scm/platform so packages that only need them do not import go-git. These aliases keep
// the existing names working.
type Platform = platform.Platform

const (
	UnknownPlatform     = platform.UnknownPlatform
	NoPlatform          = platform.NoPlatform
	GitHubPlatform      = platform.GitHubPlatform
	GitLabPlatform      = platform.GitLabPlatform
	AzureDevOpsPlatform = platform.AzureDevOpsPlatform
	GiteaPlatform       = platform.GiteaPlatform
	BitbucketPlatform   = platform.BitbucketPlatform
)

var PlatformFromString = platform.PlatformFromString
