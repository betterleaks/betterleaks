package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/sources/container"
	"github.com/stretchr/testify/require"
)

func TestContainerCLIOptions(t *testing.T) {
	for _, command := range []string{"container", "docker"} {
		cli, err := parseCLIForTest(t, "--redact", command, "example.com/app:latest", "--platform", "linux/arm64", "--platform", "linux/amd64", "--archive", "image,one.tar", "--oci-layout", "layout", "--max-file-size", "1GiB")
		require.NoError(t, err)
		require.Equal(t, []string{"example.com/app:latest"}, cli.Container.Images)
		require.Equal(t, []string{"linux/arm64", "linux/amd64"}, cli.Container.Platform)
		require.Equal(t, []string{"image,one.tar"}, cli.Container.Archive)
		require.Equal(t, sizeFlag(1<<30), cli.Container.MaxFileSize)
		require.Equal(t, 8, cli.Container.MaxArchiveDepth)
		require.Equal(t, redactFlag(100), cli.Container.Redact)
		require.Empty(t, cli.Container.Daemon)
		require.False(t, cli.Container.source().CredentialHelpers)
	}
	for _, args := range [][]string{{"container"}, {"container", "--daemon", "--archive", "x"}, {"container", "image", "--platform", "amd64"}, {"container", "image", "--max-archive-depth", "-1"}, {"container", "image", "--status", "valid"}} {
		_, err := parseCLIForTest(t, args...)
		require.Error(t, err)
	}
}

func TestContainerCLICredentialHelpers(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		args := []string{"container", "registry.test/app:latest", "--credential-helpers"}
		if anonymous {
			args = append(args, "--anonymous")
		}
		cli, err := parseCLIForTest(t, args...)
		require.NoError(t, err)
		require.True(t, cli.Container.source().CredentialHelpers)
		require.Equal(t, anonymous, cli.Container.source().Anonymous)
	}
}

func TestContainerCLIDaemonSelection(t *testing.T) {
	for _, daemon := range []string{"docker", "podman"} {
		for _, flag := range [][]string{{"--daemon", daemon}, {"--daemon=" + daemon}} {
			args := append([]string{"container", "example:local"}, flag...)
			args = append(args, "--daemon-host=https://engine.example.test:2376")
			cli, err := parseCLIForTest(t, args...)
			require.NoError(t, err)
			require.Equal(t, daemon, cli.Container.source().Daemon)
			require.Equal(t, "https://engine.example.test:2376", cli.Container.source().DaemonHost)
			require.Equal(t, []string{"example:local"}, cli.Container.Images)
		}
	}
	for _, args := range [][]string{
		{"container", "example:local", "--daemon"},
		{"container", "example:local", "--daemon="},
		{"container", "--daemon", "example:local"},
		{"container", "example:local", "--daemon", "unknown"},
		{"container", "--daemon", "podman", "--archive", "image.tar"},
		{"container", "image", "--daemon-host", "http://engine.test"},
		{"container", "image", "--daemon", "docker", "--daemon-host="},
		{"container", "image", "--daemon", "docker", "--daemon-host", "ssh://engine.test"},
		{"container", "image", "--daemon", "docker", "--daemon-host", "http://user:secret@engine.test"},
	} {
		_, err := parseCLIForTest(t, args...)
		require.Error(t, err, "args: %v", args)
	}
}

func containerCLITar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, data := range files {
		require.NoError(t, w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}))
		_, err := w.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return b.Bytes()
}

func containerCLIArchive(t *testing.T) string {
	t.Helper()
	return containerCLIArchiveWithLayer(t, containerCLITar(t, map[string][]byte{"app.env": []byte("TOKEN=CONTAINER_TEST_SECRET\n")}))
}

func containerCLIArchiveWithLayer(t *testing.T, layer []byte) string {
	t.Helper()
	hash := sha256.Sum256(layer)
	config := []byte(fmt.Sprintf(`{"os":"linux","architecture":"arm64","rootfs":{"type":"layers","diff_ids":["sha256:%x"]},"config":{"Env":["TOKEN=CONTAINER_CONFIG_SECRET"],"Labels":{"org.opencontainers.image.authors":"Example Team","org.opencontainers.image.source":"https://example.test/app","org.opencontainers.image.revision":"revision-one"}}}`, hash))
	archive := containerCLITar(t, map[string][]byte{"manifest.json": []byte(`[{"Config":"config.json","Layers":["layer.tar"],"RepoTags":["example/app:latest"]}]`), "config.json": config, "layer.tar": layer})
	p := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, os.WriteFile(p, archive, 0600))
	return p
}

func TestContainerCLIReports(t *testing.T) {
	archive := containerCLIArchive(t)
	config := filepath.Join(t.TempDir(), "rules.toml")
	require.NoError(t, os.WriteFile(config, []byte("[[rules]]\nid='container-test'\nregex='CONTAINER_[A-Z_]+SECRET'\n"), 0600))
	for _, jsonl := range []bool{false, true} {
		for _, incomplete := range []bool{false, true} {
			t.Run(fmt.Sprintf("jsonl=%v/incomplete=%v", jsonl, incomplete), func(t *testing.T) {
				cli, out := newTestCLI(t)
				var exit int
				cli.runtime.exit = func(code int) { exit = code }
				args := []string{"container", "--archive", archive, "--config", config, "--output", "-", "--no-banner", "--redact", "--exit-code", "7"}
				if jsonl {
					args = append(args, "--jsonl")
				}
				if incomplete {
					args = append(args, "--archive", filepath.Join(t.TempDir(), "missing.tar"))
				}
				cli.SetArgs(args)
				require.NoError(t, cli.Execute())
				var metadata report.ScanMetadata
				var findings []report.Finding
				if jsonl {
					metadata, findings = decodeScanJSONL(t, out.Bytes())
				} else {
					metadata, findings = decodeScanJSON(t, out.Bytes())
				}
				require.Equal(t, "container", metadata.Source.Type)
				require.Len(t, findings, 2)
				if incomplete {
					require.Equal(t, report.ScanStateIncomplete, metadata.State)
					require.Equal(t, 1, exit)
				} else {
					require.Equal(t, report.ScanStateComplete, metadata.State)
					require.Equal(t, 7, exit)
				}
				for _, finding := range findings {
					require.Equal(t, "REDACTED", finding.Match.Value)
					require.Equal(t, "linux/arm64", finding.Attributes[container.AttrPlatform])
					require.NotEmpty(t, finding.Attributes[container.AttrConfigDigest])
					require.Equal(t, "Example Team", finding.Attributes[container.AttrAuthors])
					require.Equal(t, "https://example.test/app", finding.Attributes[container.AttrSourceURL])
					require.Equal(t, "revision-one", finding.Attributes[container.AttrRevision])
					require.NotEmpty(t, finding.Match.Fingerprint)
				}
				require.NotContains(t, out.String(), "CONTAINER_TEST_SECRET")
				require.NotContains(t, out.String(), "CONTAINER_CONFIG_SECRET")
			})
		}
	}
}

func TestContainerCLINestedCompressionCoverage(t *testing.T) {
	compress := func(data []byte) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, err := w.Write(data)
		require.NoError(t, err)
		require.NoError(t, w.Close())
		return b.Bytes()
	}
	cfg := writeTestConfig(t, "[[rules]]\nid='token'\nregex='(?:NESTED|AFTER)_TOKEN'\n")
	for _, corrupt := range []bool{false, true} {
		for _, jsonl := range []bool{false, true} {
			t.Run(fmt.Sprintf("corrupt=%v/jsonl=%v", corrupt, jsonl), func(t *testing.T) {
				payload := compress(compress([]byte("NESTED_TOKEN")))
				if corrupt {
					payload = compress(containerCLITar(t, map[string][]byte{"token.txt": []byte("NESTED_TOKEN")}))
					payload[len(payload)-8] ^= 0xff
				}
				archive := containerCLIArchiveWithLayer(t, containerCLITar(t, map[string][]byte{"payload": payload, "after.txt": []byte("AFTER_TOKEN")}))
				cli, out := newTestCLI(t)
				exit := 0
				cli.runtime.exit = func(code int) { exit = code }
				args := []string{"container", "--archive", archive, "--config", cfg, "--no-banner", "--output", "-", "--exit-code", "7"}
				if jsonl {
					args = append(args, "--jsonl")
				}
				cli.SetArgs(args)
				require.NoError(t, cli.Execute())
				var metadata report.ScanMetadata
				var findings []report.Finding
				if jsonl {
					metadata, findings = decodeScanJSONL(t, out.Bytes())
				} else {
					metadata, findings = decodeScanJSON(t, out.Bytes())
				}
				require.Len(t, findings, 2)
				if corrupt {
					require.Equal(t, report.ScanStateIncomplete, metadata.State)
					require.Equal(t, 1, exit)
				} else {
					require.Equal(t, report.ScanStateComplete, metadata.State)
					require.Equal(t, 7, exit)
				}
			})
		}
	}
}
