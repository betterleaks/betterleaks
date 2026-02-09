package git

import "github.com/betterleaks/betterleaks"

const (
	PatchContent  betterleaks.ResourceKind = "git_patch_content"
	CommitMessage betterleaks.ResourceKind = "git_commit_message"
	CommitBody    betterleaks.ResourceKind = "git_commit_body"
)

func init() {
	betterleaks.RegisterResourceKind(betterleaks.ResourceKindInfo{
		Kind:         PatchContent,
		IdentityKeys: []string{betterleaks.MetaCommitSHA, betterleaks.MetaPath},
		Source:       "git",
	})
	betterleaks.RegisterResourceKind(betterleaks.ResourceKindInfo{
		Kind:         CommitMessage,
		IdentityKeys: []string{betterleaks.MetaCommitSHA, betterleaks.MetaPath},
		Source:       "git",
	})
	betterleaks.RegisterResourceKind(betterleaks.ResourceKindInfo{
		Kind:         CommitBody,
		IdentityKeys: []string{betterleaks.MetaCommitSHA, betterleaks.MetaPath},
		Source:       "git",
	})
}
