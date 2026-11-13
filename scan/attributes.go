package scan

import (
	"maps"

	"github.com/betterleaks/betterleaks/v2/internal/confidence"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
)

// Source attributes are immutable after a fragment is yielded. Borrow them
// during detection so a dense fragment does not allocate a map per candidate.
// Filters receive their own map through exprAttributes; callers receive an
// owned map through ownFindingAttributes at the result handoff.
func borrowFindingAttributes(finding *report.Finding, attributes map[string]string) {
	finding.Attributes = attributes
	finding.Location.Path = attributes[sources.AttrPath]
	finding.Confidence = attributes[confidence.Attribute]
}

func ownFindingAttributes(finding *report.Finding) {
	finding.Attributes = maps.Clone(finding.Attributes)
	delete(finding.Attributes, sources.AttrPath)
	delete(finding.Attributes, confidence.Attribute)
	if link := findingSCMLink(*finding); link != "" {
		finding.SetAttr(sources.AttrURL, link)
	}
}

// Content findings get a line-specific link. Path-only findings have no line
// coordinates and retain the source URL. Compute links for filter evaluation
// and result handoff without modifying the borrowed source map.
func findingSCMLink(finding report.Finding) string {
	platform := finding.Attr(sources.AttrGitPlatform)
	remoteURL := finding.Attr(sources.AttrGitRemoteURL)
	if finding.Location.StartLine == 0 || platform == "" || remoteURL == "" {
		return ""
	}
	return createScmLink(platform, remoteURL, finding)
}
