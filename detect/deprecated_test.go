package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/sources"
)

// TestDetectSource_ResetPerScanState is a regression test for betterleaks#86.
//
// Reusing the same Detector across multiple DetectSource calls previously
// returned accumulated findings from every prior scan because the internal
// findings slice, ValidationCounts map, TotalBytes counter, and commitMap
// were never cleared at the start of a new source scan. Each DetectSource
// invocation should return only the findings discovered in that scan, even
// when the Detector instance is reused.
func TestDetectSource_ResetPerScanState(t *testing.T) {
	// A PEM private key is a high-confidence match across the default rules
	// and avoids entropy-filter flakiness.
	const pemSecret = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7k3v8H4gZ0L2cP2l+9Pw6sbKfY9Y1fj3zKkQ3C0p8e7jYQ0o
-----END RSA PRIVATE KEY-----
`

	viper.SetConfigType("toml")
	require.NoError(t, viper.ReadConfig(strings.NewReader(config.DefaultConfig)))
	var vc config.ViperConfig
	require.NoError(t, viper.Unmarshal(&vc))
	cfg, err := vc.Translate()
	require.NoError(t, err)

	detector := NewDetector(cfg)

	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "secret.pem")
	require.NoError(t, os.WriteFile(secretPath, []byte(pemSecret), 0o600))

	newSource := func() *sources.Files {
		return &sources.Files{
			Path:   secretPath,
			Config: &detector.Config,
			Sema:   detector.Sema,
		}
	}

	first, err := detector.DetectSource(t.Context(), newSource())
	require.NoError(t, err)
	if len(first) == 0 {
		t.Fatalf("expected the PEM secret to be detected on the first scan, got 0 findings")
	}
	firstCount := len(first)
	firstBytes := detector.TotalBytes.Load()
	if firstBytes == 0 {
		t.Fatalf("expected TotalBytes > 0 after first scan, got 0")
	}

	second, err := detector.DetectSource(t.Context(), newSource())
	require.NoError(t, err)
	if len(second) != firstCount {
		t.Fatalf("second DetectSource must return only findings from the second scan; want %d, got %d (accumulating state from prior scan)",
			firstCount, len(second))
	}
	if detector.TotalBytes.Load() != firstBytes {
		t.Fatalf("second DetectSource must reset TotalBytes to this-scan-only; want %d, got %d",
			firstBytes, detector.TotalBytes.Load())
	}

	// Findings() should reflect only the most recent scan, not the sum of both.
	got := detector.Findings()
	if len(got) != firstCount {
		t.Fatalf("Findings() must return only results from the latest DetectSource; want %d, got %d",
			firstCount, len(got))
	}
}
