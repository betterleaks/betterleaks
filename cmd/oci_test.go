package cmd

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources/oci"
	"github.com/stretchr/testify/require"
)

func cliOCIFixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0600))
	blob := func(media string, b []byte) (map[string]any, string) {
		hash := sha256.Sum256(b)
		digest := hex.EncodeToString(hash[:])
		name := filepath.Join(dir, "blobs", "sha256", digest)
		require.NoError(t, os.WriteFile(name, b, 0600))
		return map[string]any{"mediaType": media, "digest": "sha256:" + digest, "size": len(b)}, name
	}
	config, _ := blob("application/vnd.oci.image.config.v1+json", []byte(`{"os":"linux","architecture":"amd64","config":{"Env":["KEY=CONFIG_TOKEN"]}}`))
	var tarBytes bytes.Buffer
	tw := tar.NewWriter(&tarBytes)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "app/credentials", Mode: 0600, Size: int64(len("LAYER_TOKEN"))}))
	_, err := tw.Write([]byte("LAYER_TOKEN"))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	layer, layerPath := blob("application/vnd.oci.image.layer.v1.tar", tarBytes.Bytes())
	b, err := json.Marshal(map[string]any{"schemaVersion": 2, "config": config, "layers": []any{layer}})
	require.NoError(t, err)
	manifest, _ := blob("application/vnd.oci.image.manifest.v1+json", b)
	b, err = json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{manifest}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.json"), b, 0600))
	return dir, layerPath
}

func TestOCICommandReportsFindingsAndIncompleteScans(t *testing.T) {
	for _, test := range []string{"complete", "missing layer", "wrong platform", "layer limit"} {
		t.Run(test, func(t *testing.T) {
			dir, layer := cliOCIFixture(t)
			if test == "missing layer" {
				require.NoError(t, os.Remove(layer))
			}
			config := writeTestConfig(t, "[[rules]]\nid='token'\nregex='[A-Z]+_TOKEN'\n")
			root, stdout := newTestCLI(t)
			var exits []int
			root.runtime.exit = func(code int) { exits = append(exits, code) }
			args := []string{"oci", dir, "--config", config, "--no-banner", "--output=-", "--exit-code=7"}
			if test == "wrong platform" {
				args = append(args, "--platform=linux/arm64")
			}
			if test == "layer limit" {
				args = append(args, "--max-layer-size=1KiB")
			}
			root.SetArgs(args)
			require.NoError(t, root.Execute())
			metadata, findings := decodeScanJSON(t, stdout.Bytes())
			require.Equal(t, "oci", metadata.Source.Type)
			if test == "complete" {
				require.Equal(t, report.ScanStateComplete, metadata.State)
				require.Equal(t, []int{7}, exits)
				require.Len(t, findings, 2)
			} else {
				require.Equal(t, report.ScanStateIncomplete, metadata.State)
				require.Equal(t, []int{1}, exits)
			}
		})
	}
}
func TestOCICommandParsesLeadingFlags(t *testing.T) {
	cli, err := parseCLIForTest(t, "--platform=linux/arm64/v8", "--max-archive-depth=0", "oci", "layout", "--ref=built")
	require.NoError(t, err)
	require.Equal(t, "layout", cli.OCI.Path)
	require.Equal(t, "built", cli.OCI.Ref)
	require.Equal(t, "linux/arm64/v8", cli.OCI.Platform)
	require.Zero(t, cli.OCI.MaxArchiveDepth)
	require.EqualValues(t, oci.DefaultMaxLayerSize, cli.OCI.MaxLayerSize)
}

func TestOCICommandMaxLayerSize(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int64
	}{
		{"8GiB", 8 << 30},
		{"500MB", 500_000_000},
		{"4096", 4096},
		{"0", 0},
	} {
		t.Run(tc.value, func(t *testing.T) {
			cli, err := parseCLIForTest(t, "--max-layer-size="+tc.value, "oci", "layout")
			require.NoError(t, err)
			require.EqualValues(t, tc.want, cli.OCI.MaxLayerSize)
		})
	}
	for _, value := range []string{"-1", "invalid", "8EiB"} {
		_, err := parseCLIForTest(t, "oci", "layout", "--max-layer-size="+value)
		require.Error(t, err)
	}
}
