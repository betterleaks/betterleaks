package cmd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources/container"
)

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

func parseContainerForTest(t *testing.T, args ...string) (*container.Source, error) {
	t.Helper()
	cmd := newContainerCmd()
	cmd.Flags().Int("max-archive-depth", 8, "")
	cmd.Flags().Int("max-target-megabytes", 0, "")
	if args[0] != cmd.Name() {
		require.Contains(t, cmd.Aliases, args[0])
	}
	if err := cmd.ParseFlags(args[1:]); err != nil {
		return nil, err
	}
	return containerSource(cmd, cmd.Flags().Args())
}
func TestContainerCLIOptions(t *testing.T) {
	for _, alias := range []string{"container", "docker"} {
		src, err := parseContainerForTest(t, alias, "example/app:latest", "--platform", "linux/arm64", "--platform", "linux/amd64", "--archive", "image,one.tar", "--oci-layout", "layout", "--max-file-size", "1GiB")
		require.NoError(t, err)
		require.Equal(t, []string{"example/app:latest"}, src.Images)
		require.Equal(t, []string{"linux/arm64", "linux/amd64"}, src.Platforms)
		require.Equal(t, []string{"image,one.tar"}, src.Archives)
		require.Equal(t, int64(1<<30), src.MaxFileSize)
		require.Equal(t, 8, src.MaxArchiveDepth)
	}
	for _, runtime := range []string{"docker", "podman"} {
		src, err := parseContainerForTest(t, "container", "app:local", "--daemon", runtime)
		require.NoError(t, err)
		require.Equal(t, runtime, src.Daemon)
	}
	for _, args := range [][]string{
		{"container"}, {"container", "image", "--daemon"}, {"container", "image", "--daemon="},
		{"container", "image", "--daemon", "unknown"}, {"container", "--daemon", "docker", "--archive", "image.tar"},
		{"container", "image", "--platform", "amd64"}, {"container", "image", "--max-archive-depth", "-1"},
		{"container", "image", "--max-file-size", "-1"}, {"container", "image", "--max-archive-size", "99999999999999999999GiB"},
	} {
		_, err := parseContainerForTest(t, args...)
		require.Error(t, err, "args: %v", args)
	}
	src, err := parseContainerForTest(t, "container", "image", "--max-target-megabytes", "2")
	require.NoError(t, err)
	require.Equal(t, int64(2_000_000), src.MaxFileSize)
	src, err = parseContainerForTest(t, "container", "image", "--max-target-megabytes", "2", "--max-file-size", "0")
	require.NoError(t, err)
	require.Zero(t, src.MaxFileSize)
}

func TestContainerCLIHelperProcess(t *testing.T) {
	if os.Getenv("BETTERLEAKS_CONTAINER_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			rootCmd.SetArgs(os.Args[i+1:])
			break
		}
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}
func runContainerCLI(t *testing.T, args ...string) ([]byte, string, int) {
	t.Helper()
	command := exec.Command(os.Args[0], append([]string{"-test.run=^TestContainerCLIHelperProcess$", "--"}, args...)...)
	command.Env = append(os.Environ(), "BETTERLEAKS_CONTAINER_HELPER=1")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	code := 0
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit)
		code = exit.ExitCode()
	}
	return stdout.Bytes(), stderr.String(), code
}
func TestContainerCLIReports(t *testing.T) {
	archive := containerCLIArchive(t)
	config := filepath.Join(t.TempDir(), "rules.toml")
	require.NoError(t, os.WriteFile(config, []byte("[[rules]]\nid='container-test'\nregex='CONTAINER_[A-Z_]+SECRET'\n"), 0600))
	for _, incomplete := range []bool{false, true} {
		t.Run(fmt.Sprint(incomplete), func(t *testing.T) {
			args := []string{"container", "--archive", archive, "--config", config, "--report-path", "-", "--report-format", "json", "--no-banner", "--redact", "--exit-code", "7"}
			if incomplete {
				args = append(args, "--archive", filepath.Join(t.TempDir(), "missing.tar"))
			}
			output, stderr, code := runContainerCLI(t, args...)
			if incomplete {
				require.Equal(t, 1, code, stderr)
				require.Contains(t, stderr, "partial scan")
			} else {
				require.Equal(t, 7, code, stderr)
			}
			var findings []report.Finding
			require.NoError(t, json.Unmarshal(output, &findings), string(output))
			require.Len(t, findings, 2)
			for _, f := range findings {
				require.Equal(t, "REDACTED", f.Secret)
				require.Equal(t, "linux/arm64", f.Attributes[container.AttrPlatform])
				require.NotEmpty(t, f.Attributes[container.AttrConfigDigest])
				require.Equal(t, "Example Team", f.Attributes[container.AttrAuthors])
				require.Equal(t, "https://example.test/app", f.Attributes[container.AttrSourceURL])
				require.Equal(t, "revision-one", f.Attributes[container.AttrRevision])
				require.Contains(t, f.Fingerprint, "container:")
			}
			require.NotContains(t, string(output), "CONTAINER_TEST_SECRET")
			require.NotContains(t, string(output), "CONTAINER_CONFIG_SECRET")
		})
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
	config := filepath.Join(t.TempDir(), "rules.toml")
	require.NoError(t, os.WriteFile(config, []byte("[[rules]]\nid='token'\nregex='(?:NESTED|AFTER)_TOKEN'\n"), 0600))
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(corrupt), func(t *testing.T) {
			payload := compress(compress([]byte("NESTED_TOKEN")))
			if corrupt {
				payload = compress(containerCLITar(t, map[string][]byte{"token.txt": []byte("NESTED_TOKEN")}))
				payload[len(payload)-8] ^= 0xff
			}
			archive := containerCLIArchiveWithLayer(t, containerCLITar(t, map[string][]byte{"payload": payload, "after.txt": []byte("AFTER_TOKEN")}))
			out, stderr, code := runContainerCLI(t, "container", "--archive", archive, "--config", config, "--no-banner", "--report-path", "-", "--report-format", "json", "--exit-code", "7")
			if corrupt {
				require.Equal(t, 1, code, stderr)
				require.Contains(t, stderr, "partial scan")
			} else {
				require.Equal(t, 7, code, stderr)
			}
			var findings []report.Finding
			require.NoError(t, json.Unmarshal(out, &findings), string(out))
			require.Len(t, findings, 2)
		})
	}
}

func TestContainerRedactionIncludesRepeatedAttribution(t *testing.T) {
	secret := "CONTAINER_LABEL_SECRET"
	findings := []report.Finding{
		{Secret: secret, Attributes: map[string]string{"container.authors": secret}, Match: secret, MatchContext: "label=" + secret},
		{Secret: "CONTAINER_FILE_SECRET", Attributes: map[string]string{"container.authors": secret, "container.revision": "safe"}, MatchContext: secret + " CONTAINER_FILE_SECRET"},
	}
	redactContainerFindings(findings, 100)
	for i := range findings {
		findings[i].Redact(100)
	}
	output, err := json.Marshal(findings)
	require.NoError(t, err)
	require.NotContains(t, string(output), secret)
	require.NotContains(t, string(output), "CONTAINER_FILE_SECRET")
	require.Equal(t, "safe", findings[1].Attributes["container.revision"])
}

func TestContainerDisplayRedactionPreservesOriginal(t *testing.T) {
	for _, percent := range []uint{50, 100} {
		t.Run(fmt.Sprint(percent), func(t *testing.T) {
			original := report.Finding{
				Secret:        "PRIMARY_SECRET",
				Attributes:    map[string]string{"container.authors": "PRIMARY_SECRET COMPONENT_SECRET"},
				CaptureGroups: map[string]string{"token": "PRIMARY_SECRET"},
				MatchContext:  "PRIMARY_SECRET COMPONENT_SECRET",
				ComponentSets: []report.ComponentSet{{Components: []*report.ComponentFinding{{
					Secret: "COMPONENT_SECRET", Match: "COMPONENT_SECRET",
					CaptureGroups: map[string]string{"token": "COMPONENT_SECRET"},
				}}}},
			}
			before, err := json.Marshal(original)
			require.NoError(t, err)
			display := containerFindingForDisplay(original, percent)
			// Printing applies the normal percentage redaction to Secret.
			require.Equal(t, original.Secret, display.Secret)
			display.Redact(percent)
			output, err := json.Marshal(display)
			require.NoError(t, err)
			require.NotContains(t, string(output), "PRIMARY_SECRET")
			require.NotContains(t, string(output), "COMPONENT_SECRET")
			after, err := json.Marshal(original)
			require.NoError(t, err)
			require.Equal(t, string(before), string(after))
		})
	}
}

// The second archive never supplies data. A finding from the first archive
// must appear before that blocked scan can finish.
func TestContainerCLIVerboseStreamsBeforeScanCompletes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("named pipes require a Unix filesystem")
	}
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skip("mkfifo is unavailable")
	}
	archive := containerCLIArchive(t)
	config := filepath.Join(t.TempDir(), "rules.toml")
	require.NoError(t, os.WriteFile(config, []byte("[[rules]]\nid='container-test'\nregex='CONTAINER_TEST_SECRET'\n"), 0600))
	for _, tc := range []struct{ legacy, redact bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		t.Run(fmt.Sprintf("legacy=%v/redact=%v", tc.legacy, tc.redact), func(t *testing.T) {
			fifo := filepath.Join(t.TempDir(), "blocked.tar")
			require.NoError(t, exec.Command(mkfifo, fifo).Run())
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			args := []string{"-test.run=^TestContainerCLIHelperProcess$", "--", "container", "--archive", archive, "--archive", fifo, "--config", config, "--no-banner", "--no-color", "--verbose"}
			if tc.legacy {
				args = append(args, "--legacy-print")
			}
			marker := "CONTAINER_TEST_SECRET"
			if tc.redact {
				args = append(args, "--redact")
				marker = "REDACTED"
			}
			command := exec.CommandContext(ctx, os.Args[0], args...)
			command.Env = append(os.Environ(), "BETTERLEAKS_CONTAINER_HELPER=1")
			stdout, err := command.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, command.Start())
			found := make(chan struct{}, 1)
			readDone := make(chan struct{})
			var output strings.Builder
			go func() {
				defer close(readDone)
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					output.WriteString(scanner.Text())
					output.WriteByte('\n')
					if strings.Contains(scanner.Text(), marker) {
						select {
						case found <- struct{}{}:
						default:
						}
					}
				}
			}()
			defer func() {
				cancel()
				<-readDone
				_ = command.Wait()
				if tc.redact {
					require.NotContains(t, output.String(), "CONTAINER_TEST_SECRET")
				}
			}()
			select {
			case <-found:
			case <-ctx.Done():
				t.Fatal("verbose finding was buffered while the next archive blocked")
			}
		})
	}
}
