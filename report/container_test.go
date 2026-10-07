package report

import (
	"maps"
	"testing"

	"github.com/betterleaks/betterleaks/sources"
	"github.com/stretchr/testify/require"
)

func TestContainerFingerprintsIncludeProvenance(t *testing.T) {
	original := Finding{RuleID: "token", StartLine: 1, Attributes: map[string]string{
		sources.AttrPath: "/app.env", sources.AttrResource: "container.file",
		"container.image": "app:latest", "container.digest": "sha256:image",
		"container.layer_digest": "sha256:layer", "container.layer_index": "0",
		"container.platform": "linux/amd64",
	}}
	original.SetFingerprint()
	require.Contains(t, original.Fingerprint, "container:")
	for _, key := range []string{"container.image", "container.digest", "container.layer_digest", "container.layer_index", "container.platform", sources.AttrResource, sources.AttrPath} {
		t.Run(key, func(t *testing.T) {
			changed := original
			changed.Attributes = maps.Clone(original.Attributes)
			changed.Attributes[key] += "other"
			changed.SetFingerprint()
			require.NotEqual(t, original.Fingerprint, changed.Fingerprint)
		})
	}
	copy := original
	copy.Attributes = maps.Clone(original.Attributes)
	copy.Attributes["container.authors"] = "different maintainer"
	copy.SetFingerprint()
	require.Equal(t, original.Fingerprint, copy.Fingerprint)
	for _, commit := range []string{"", "commit"} {
		f := Finding{RuleID: "token", StartLine: 1, Attributes: map[string]string{sources.AttrPath: "app.env", sources.AttrGitSHA: commit}}
		f.SetFingerprint()
		expected := "app.env:token:1"
		if commit != "" {
			expected = commit + ":" + expected
		}
		require.Equal(t, expected, f.Fingerprint)
	}
}

func TestContainerMetadataEscapesTerminalControls(t *testing.T) {
	require.Equal(t, `Team\n\t\x1b[31m\r\x00`, escapeInline("Team\n\t\x1b[31m\r\x00"))
	require.Equal(t, "Team α", escapeInline("Team α"))
	require.Equal(t, `\xff`, escapeInline(string([]byte{0xff})))
}
