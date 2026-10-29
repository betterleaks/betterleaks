package sources

import "github.com/betterleaks/betterleaks/v2/sources/sourcetypes"

// The shared types live in sourcetypes so packages that only need them (scan, report) do not import the
// git, archive and cloud sources in this package. These aliases keep the existing names working.
type (
	Fragment      = sourcetypes.Fragment
	FragmentsFunc = sourcetypes.FragmentsFunc
	PrefilterFunc = sourcetypes.PrefilterFunc
	Source        = sourcetypes.Source
)

const (
	InnerPathSeparator                = sourcetypes.InnerPathSeparator
	AttrPath                          = sourcetypes.AttrPath
	AttrURL                           = sourcetypes.AttrURL
	AttrResource                      = sourcetypes.AttrResource
	ResourceFileContent               = sourcetypes.ResourceFileContent
	ResourceURLContent                = sourcetypes.ResourceURLContent
	ResourceGitPatchContent           = sourcetypes.ResourceGitPatchContent
	ResourceGitCommitMessage          = sourcetypes.ResourceGitCommitMessage
	ResourceGitTagMessage             = sourcetypes.ResourceGitTagMessage
	ResourceGitReflogMessage          = sourcetypes.ResourceGitReflogMessage
	ResourceGitNote                   = sourcetypes.ResourceGitNote
	ResourceGitBlob                   = sourcetypes.ResourceGitBlob
	AttrGitSHA                        = sourcetypes.AttrGitSHA
	AttrGitAuthorName                 = sourcetypes.AttrGitAuthorName
	AttrGitAuthorEmail                = sourcetypes.AttrGitAuthorEmail
	AttrGitDate                       = sourcetypes.AttrGitDate
	AttrGitMessage                    = sourcetypes.AttrGitMessage
	AttrGitRemoteURL                  = sourcetypes.AttrGitRemoteURL
	AttrGitPlatform                   = sourcetypes.AttrGitPlatform
	AttrGitTagName                    = sourcetypes.AttrGitTagName
	AttrGitTagRef                     = sourcetypes.AttrGitTagRef
	AttrGitTaggerName                 = sourcetypes.AttrGitTaggerName
	AttrGitTaggerEmail                = sourcetypes.AttrGitTaggerEmail
	AttrGitCommitterName              = sourcetypes.AttrGitCommitterName
	AttrGitCommitterEmail             = sourcetypes.AttrGitCommitterEmail
	AttrGitCommitterDate              = sourcetypes.AttrGitCommitterDate
	AttrGitBlobSHA                    = sourcetypes.AttrGitBlobSHA
	AttrGitTagSHA                     = sourcetypes.AttrGitTagSHA
	AttrGitTagTarget                  = sourcetypes.AttrGitTagTarget
	AttrGitTagSourceRef               = sourcetypes.AttrGitTagSourceRef
	AttrGitTaggerDate                 = sourcetypes.AttrGitTaggerDate
	AttrGitNotesRef                   = sourcetypes.AttrGitNotesRef
	AttrGitNoteTarget                 = sourcetypes.AttrGitNoteTarget
	AttrGitReflogSelector             = sourcetypes.AttrGitReflogSelector
	AttrGitReflogRef                  = sourcetypes.AttrGitReflogRef
	AttrGitReflogActorName            = sourcetypes.AttrGitReflogActorName
	AttrGitReflogActorEmail           = sourcetypes.AttrGitReflogActorEmail
	AttrGitReflogDate                 = sourcetypes.AttrGitReflogDate
	AttrGitReflogOldSHA               = sourcetypes.AttrGitReflogOldSHA
	AttrGitReflogNewSHA               = sourcetypes.AttrGitReflogNewSHA
	AttrGitReflogLog                  = sourcetypes.AttrGitReflogLog
	AttrGitReflogLine                 = sourcetypes.AttrGitReflogLine
	AttrFSSymlink                     = sourcetypes.AttrFSSymlink
	AttrFSFirstFragment               = sourcetypes.AttrFSFirstFragment
	GitResourceTypeHistory            = sourcetypes.GitResourceTypeHistory
	GitResourceTypeMerges             = sourcetypes.GitResourceTypeMerges
	GitResourceTypeCommitMessages     = sourcetypes.GitResourceTypeCommitMessages
	GitResourceTypeNotes              = sourcetypes.GitResourceTypeNotes
	GitResourceTypeTagMessages        = sourcetypes.GitResourceTypeTagMessages
	GitResourceTypeReflogs            = sourcetypes.GitResourceTypeReflogs
	GitResourceTypeObjects            = sourcetypes.GitResourceTypeObjects
	GitResourceTypeUnreachableObjects = sourcetypes.GitResourceTypeUnreachableObjects
)
