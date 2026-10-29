// Package gitclone fetches HTTP(S) Git repositories into local bare repositories.
// It provides ref selection, authentication, temporary repository ownership,
// and pack indexing for Git-capable sources. SDK callers configure cloning
// through the sources' URL, Token, CloneRefs, and CloneAllRefs fields.
package gitclone
