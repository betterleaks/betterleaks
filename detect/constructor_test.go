package detect

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/config"
)

func TestNewDetectorRequiresConfig(t *testing.T) {
	detector, err := NewDetector(t.Context(), nil, ValidationOptions{})
	require.Nil(t, detector)
	require.EqualError(t, err, "detect: config is required")
}

func TestNewDetectorReturnsPrefilterCompilationError(t *testing.T) {
	cfg := &config.Config{
		Rules:     make(map[string]config.Rule),
		Keywords:  make(map[string]struct{}),
		Prefilter: `attributes["path"] ==`,
	}

	detector, err := NewDetector(t.Context(), cfg, ValidationOptions{})
	require.Nil(t, detector)
	require.ErrorContains(t, err, "detect: compile filters")
}

func TestNewDetectorAcceptsNilContext(t *testing.T) {
	cfg := &config.Config{
		Rules:    make(map[string]config.Rule),
		Keywords: make(map[string]struct{}),
	}

	detector, err := NewDetector(nil, cfg, ValidationOptions{})
	require.NoError(t, err)
	require.NotNil(t, detector)
}
