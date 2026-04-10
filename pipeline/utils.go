package pipeline

import (
	// "encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/betterleaks/betterleaks/sources/scm"
)

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

func createScmLink(platform, remoteURL string, finding report.Finding) string {
	p, _ := scm.PlatformFromString(platform)
	if p == scm.UnknownPlatform || p == scm.NoPlatform || finding.Commit == "" {
		return ""
	}

	// Clean the path.
	filePath, _, hasInnerPath := strings.Cut(finding.File, sources.InnerPathSeparator)
	filePath = linkCleaner.Replace(filePath)

	switch p {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, finding.Commit, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?plain=1"
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-L%d", finding.EndLine)
		}
		return link
	case scm.GitLabPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteURL, finding.Commit, filePath)
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-%d", finding.EndLine)
		}
		return link
	case scm.AzureDevOpsPlatform:
		link := fmt.Sprintf("%s/commit/%s?path=/%s", remoteURL, finding.Commit, filePath)
		// Add line information if applicable
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("&line=%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("&lineEnd=%d", finding.EndLine)
		}
		// This is a bit dirty, but Azure DevOps does not highlight the line when the lineStartColumn and lineEndColumn are not provided
		link += "&lineStartColumn=1&lineEndColumn=10000000&type=2&lineStyle=plain&_a=files"
		return link
	case scm.GiteaPlatform:
		link := fmt.Sprintf("%s/src/commit/%s/%s", remoteURL, finding.Commit, filePath)
		if hasInnerPath {
			return link
		}
		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".ipynb" || ext == ".md" {
			link += "?display=source"
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-L%d", finding.EndLine)
		}
		return link
	case scm.BitbucketPlatform:
		link := fmt.Sprintf("%s/src/%s/%s", remoteURL, finding.Commit, filePath)
		if hasInnerPath {
			return link
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#lines-%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf(":%d", finding.EndLine)
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

// filter will dedupe and redact findings
func filter(findings []report.Finding) []report.Finding {
	// Collect every required finding's (line, secret) so we can suppress
	// standalone duplicates that are already surfaced as components.
	requiredSet := make(map[string]struct{})
	for _, f := range findings {
		for _, set := range f.RequiredSets {
			for _, comp := range set.Components {
				requiredSet[fmt.Sprintf("%d:%s", comp.StartLine, comp.Secret)] = struct{}{}
			}
		}
	}

	var retFindings []report.Finding
	for _, f := range findings {
		include := true

		// Skip findings that are already surfaced as a required component
		// of another (composite) finding in this batch.
		if _, isRequired := requiredSet[fmt.Sprintf("%d:%s", f.StartLine, f.Secret)]; isRequired {
			redactedMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
			logging.Trace().Msgf("skipping %s finding (%s), already a required component of another finding", f.RuleID, redactedMatch)
			include = false
		} else if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
				if f.StartLine == fPrime.StartLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.ReplaceAll(f.Match, f.Secret, "REDACTED")
					betterMatch := strings.ReplaceAll(fPrime.Match, fPrime.Secret, "REDACTED")
					logging.Trace().Msgf("skipping %s finding (%s), %s rule takes precedence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

// lowercaseBufPool provides reusable byte buffers for lowercasing strings
// without allocating a new string via strings.ToLower each time.
var lowercaseBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 0, 128*1024)
		return &buf
	},
}

// getLowerBuf returns an ASCII-lowercased copy of s in a pooled byte buffer.
// Caller must call putLowerBuf when done with the returned slice.
func getLowerBuf(s string) (*[]byte, []byte) {
	bp := lowercaseBufPool.Get().(*[]byte)
	buf := *bp
	if cap(buf) < len(s) {
		buf = make([]byte, len(s))
	} else {
		buf = buf[:len(s)]
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + 32
		} else {
			buf[i] = c
		}
	}
	*bp = buf
	return bp, buf
}

func putLowerBuf(bp *[]byte) {
	lowercaseBufPool.Put(bp)
}

// findNewlineIndices returns the start indices of all newlines in s.
// This replaces the previous regex-based approach which was expensive
// when using go-re2 (WASM overhead for a literal \n search).
func findNewlineIndices(s string) [][]int {
	indices := make([][]int, 0, strings.Count(s, "\n"))
	offset := 0
	for {
		i := strings.IndexByte(s[offset:], '\n')
		if i == -1 {
			break
		}
		idx := offset + i
		indices = append(indices, []int{idx, idx + 1})
		offset = idx + 1
	}
	return indices
}

// containsAllowSignature checks if the line contains any of the allow signatures
func containsAllowSignature(line string) bool {
	for _, sig := range allowSignatures {
		if strings.Contains(line, sig) {
			return true
		}
	}
	return false
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func allTrue(bools []bool) bool {
	for _, check := range bools {
		if !check {
			return false
		}
	}
	return true
}

// stripEmptyMeta removes keys whose value is an empty string or nil.
func stripEmptyMeta(m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if v == nil {
			continue
		}
		out[k] = v
	}
	return out
}
