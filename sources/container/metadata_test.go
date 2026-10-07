package container

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

type metadataSource []byte

func (raw metadataSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	r := &session{s: &Source{}, yield: yield}
	return r.metadata(ctx, raw, "@config", ResourceConfig, nil)
}

func scanMetadataSource(t *testing.T, src sources.Source, rules ...config.Rule) []report.Finding {
	t.Helper()
	cfg := &config.Config{Rules: map[string]config.Rule{}}
	for _, rule := range rules {
		cfg.Rules[rule.RuleID] = rule
		cfg.NoKeywordRules = append(cfg.NoKeywordRules, rule.RuleID)
	}
	scanner := detect.NewDetector(cfg)
	scanner.MaxDecodeDepth = 2
	var findings []report.Finding
	for result := range scanner.Run(t.Context(), src) {
		require.NoError(t, result.Err)
		findings = append(findings, result.Finding)
	}
	return findings
}

func TestMetadataPreservesStructuredCredentialDetection(t *testing.T) {
	fs := scanMetadataSource(t, metadataSource(`{"id":"PAIR_ID","secret":"PAIR_SECRET"}`),
		config.Rule{RuleID: "pair", Regex: regexp.MustCompile(`"id":"PAIR_ID","secret":"(PAIR_SECRET)"`), SecretGroup: 1})
	require.Len(t, fs, 1)
	require.Equal(t, "PAIR_SECRET", fs[0].Secret)
	require.Equal(t, "@config", fs[0].File)
	require.Equal(t, "json", fs[0].Attr(AttrRepresentation))
}

func TestImageAttributionAndMetadataCoverage(t *testing.T) {
	f := newFixture(t)
	d := f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "file", content: "file-secret"})}, "tar")
	var manifest v1.Manifest
	require.NoError(t, json.Unmarshal(f.blobs[d.Digest.String()], &manifest))
	var cfg map[string]any
	require.NoError(t, json.Unmarshal(f.blobs[manifest.Config.Digest.String()], &cfg))
	labels := cfg["config"].(map[string]any)["Labels"].(map[string]any)
	labels["org.opencontainers.image.authors"] = "Team One <team@example.test>, Team Two"
	labels["org.opencontainers.image.source"] = "https://example.test/repository"
	labels["org.opencontainers.image.revision"] = "revision-one"
	manifest.Annotations["org.opencontainers.image.source"] = "https://example.test/less-specific"
	manifest.Config = f.blob(jsonBytes(t, cfg), types.OCIConfigJSON)
	d = f.blob(jsonBytes(t, manifest), types.OCIManifestSchema1)
	other := f.image("arm64", [][]byte{tarBytes(t, tarEntry{name: "other", content: "other-secret"})}, "tar")
	f.setIndex(d, other)
	fs := scanMetadataSource(t, &Source{Layouts: []string{f.directory()}, MaxArchiveDepth: 8}, config.Rule{RuleID: "token", Regex: regexp.MustCompile(`[a-z-]+secret`)})
	seen := map[string]bool{}
	for _, found := range fs {
		if found.Attr(AttrDigest) != d.Digest.String() {
			require.Empty(t, found.Attr(AttrAuthors), "attribution must not leak to sibling images or index metadata")
			continue
		}
		require.Equal(t, "Team One <team@example.test>, Team Two", found.Attr(AttrAuthors))
		require.Equal(t, "https://example.test/repository", found.Attr(AttrSourceURL))
		require.Equal(t, "revision-one", found.Attr(AttrRevision))
		seen[found.Secret] = true
		if found.Secret == "empty-history-secret" {
			require.Equal(t, ResourceHistory, found.Attr(sources.AttrResource))
			require.Equal(t, "1", found.Attr(AttrHistoryIndex))
			require.Empty(t, found.Attr(AttrLayerDigest))
		}
	}
	for _, value := range []string{"config-secret", "label-secret", "command-secret", "extension-secret", "history-secret", "empty-history-secret", "file-secret", "manifest-secret"} {
		require.True(t, seen[value], "missing %s", value)
	}
}

func TestImageAttributionFallbacks(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         v1.ConfigFile
		annotations map[string]string
		want        string
	}{
		{name: "manifest", annotations: map[string]string{"org.opencontainers.image.authors": " Team "}, want: "Team"},
		{name: "legacy", cfg: v1.ConfigFile{Config: v1.Config{Labels: map[string]string{"maintainer": " Legacy "}}}, want: "Legacy"},
		{name: "author", cfg: v1.ConfigFile{Author: " Author "}, want: "Author"},
		{name: "oversized", cfg: v1.ConfigFile{Author: strings.Repeat("a", 4097)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := map[string]string{}
			imageAttribution(attrs, tc.cfg, tc.annotations)
			require.Equal(t, tc.want, attrs[AttrAuthors])
		})
	}
}

func TestLayerBinaryContentsAreScanned(t *testing.T) {
	f := newFixture(t)
	f.setIndex(f.image("amd64", [][]byte{tarBytes(t, tarEntry{name: "document.pdf", content: "%PDF-1.7\nBINARY_SECRET"})}, "tar"))
	findings := scanMetadataSource(t, &Source{Layouts: []string{f.directory()}, MaxArchiveDepth: 8}, config.Rule{RuleID: "binary", Regex: regexp.MustCompile(`BINARY_SECRET`)})
	require.Len(t, findings, 1)
	require.Equal(t, "/document.pdf", findings[0].File)
}
