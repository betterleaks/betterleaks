package scan

import (
	// "encoding/json"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/scm"
)

// samePath reports whether two file paths refer to the same location, tolerating
// OS separator differences. The file source normalizes fragment paths to forward
// slashes (filepath.ToSlash), whereas config/baseline paths keep the native
// separator, so a raw == comparison misses on Windows and the config or baseline
// file ends up being scanned against itself.
func samePath(a, b string) bool {
	return filepath.ToSlash(filepath.Clean(a)) == filepath.ToSlash(filepath.Clean(b))
}

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

func createScmLink(platform, remoteURL string, finding report.Finding) string {
	p, _ := scm.PlatformFromString(platform)
	commitSha := finding.Attr(sources.AttrGitSHA)
	path := finding.Location.Path
	location := finding.Location
	if p == scm.UnknownPlatform || p == scm.NoPlatform || commitSha == "" {
		return ""
	}
	if finding.Attr(sources.AttrResource) == sources.ResourceGitTagMessage {
		tag, ok := strings.CutPrefix(finding.Attr(sources.AttrGitTagRef), "refs/tags/")
		if !ok || tag == "" {
			return ""
		}
		tag = url.PathEscape(tag)
		switch p {
		case scm.GitHubPlatform, scm.GiteaPlatform:
			return fmt.Sprintf("%s/releases/tag/%s", remoteURL, tag)
		case scm.GitLabPlatform:
			return fmt.Sprintf("%s/-/tags/%s", remoteURL, tag)
		default:
			return ""
		}
	}
	if finding.Attr(sources.AttrResource) == sources.ResourceGitCommitMessage {
		switch p {
		case scm.GitHubPlatform, scm.AzureDevOpsPlatform, scm.GiteaPlatform:
			return fmt.Sprintf("%s/commit/%s", remoteURL, commitSha)
		case scm.GitLabPlatform:
			return fmt.Sprintf("%s/-/commit/%s", remoteURL, commitSha)
		case scm.BitbucketPlatform:
			return fmt.Sprintf("%s/commits/%s", remoteURL, commitSha)
		default:
			return ""
		}
	}
	if path == "" {
		return ""
	}

	// Clean the path.
	filePath, _, hasInnerPath := strings.Cut(path, sources.InnerPathSeparator)
	filePath = linkCleaner.Replace(filePath)

	switch p {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?plain=1"
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#L%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("-L%d", location.EndLine)
		}
		return link
	case scm.GitLabPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#L%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("-%d", location.EndLine)
		}
		return link
	case scm.AzureDevOpsPlatform:
		link := fmt.Sprintf("%s/commit/%s?path=/%s", remoteURL, commitSha, filePath)
		// Add line information if applicable
		if hasInnerPath {
			return link
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("&line=%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("&lineEnd=%d", location.EndLine)
		}
		// This is a bit dirty, but Azure DevOps does not highlight the line when the lineStartColumn and lineEndColumn are not provided
		link += "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files"
		return link
	case scm.GiteaPlatform:
		link := fmt.Sprintf("%s/src/commit/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?display=source"
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#L%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf("-L%d", location.EndLine)
		}
		return link
	case scm.BitbucketPlatform:
		link := fmt.Sprintf("%s/src/%s/%s", remoteURL, commitSha, filePath)
		if hasInnerPath {
			return link
		}
		if location.StartLine != 0 {
			link += fmt.Sprintf("#lines-%d", location.StartLine)
		}
		if location.EndLine != location.StartLine {
			link += fmt.Sprintf(":%d", location.EndLine)
		}
		return link
	default:
		// This should never happen.
		return ""
	}
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
// Another way to think about what this is doing is calculating the number of bits
// needed to on average encode the data. So, the higher the entropy, the more random the data, the
// more bits needed to encode that data.
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// findingIndex limits specificity comparisons to owners with a primary or
// component on the candidate's line. Component locations can differ from their
// owner's location, so indexing only the primary would change suppression.
type findingIndex struct {
	findings []report.Finding
	byLine   map[int][]int
}

func newFindingIndex(findings []report.Finding) *findingIndex {
	index := &findingIndex{findings: findings}
	for i := range findings {
		index.add(i)
	}
	return index
}

func (index *findingIndex) add(i int) {
	if index.byLine == nil {
		index.byLine = make(map[int][]int)
	}
	addLine := func(line int) {
		owners := index.byLine[line]
		// An owner can have several components on the same line. Insert it
		// once, preserving the original order of specificity comparisons.
		if len(owners) == 0 || owners[len(owners)-1] != i {
			index.byLine[line] = append(owners, i)
		}
	}
	f := &index.findings[i]
	addLine(f.Location.StartLine)
	for _, set := range f.ComponentSets {
		for _, component := range set.Components {
			addLine(component.Location.StartLine)
		}
	}
}

// containsAllowSignature checks whether the line contains an allow comment.
func containsAllowSignature(line string) bool {
	for _, signature := range allowSignatures {
		if strings.Contains(line, signature) {
			return true
		}
	}
	return false
}
