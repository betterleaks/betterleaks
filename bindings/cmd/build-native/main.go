// Command build-native builds target-specific C libraries and its manifest.
// Run from a Betterleaks checkout; cross builds require a target C toolchain.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type targetSpec struct {
	Target       string   `json:"target"`
	GOOS         string   `json:"goos"`
	GOARCH       string   `json:"goarch"`
	Libc         string   `json:"libc,omitempty"`
	Libraries    []string `json:"libraries"`
	MinimumMacOS string   `json:"minimum_macos_version,omitempty"`
}

type manifest struct {
	PackageVersion string `json:"package_version"`
	ABIVersion     int    `json:"abi_version"`
	Target         string `json:"target"`
	MinimumMacOS   string `json:"minimum_macos_version,omitempty"`
	ArchiveSHA256  string `json:"archive_sha256"`
	SharedLibrary  string `json:"shared_library"`
	SharedSHA256   string `json:"shared_sha256"`
	GoVersion      string `json:"go_version"`
	EngineVersion  string `json:"engine_version"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "build-native:", err)
		os.Exit(1)
	}
}

func run() error {
	target := flag.String("target", "", "Rust target triple (defaults to host; Linux defaults to glibc)")
	output := flag.String("output", "", "artifact directory (default: dist/native/<target>)")
	list := flag.Bool("list-targets", false, "list Rust targets and exit")
	flag.Parse()
	if flag.NArg() > 1 || (flag.NArg() == 1 && *output != "") {
		return errors.New("supply at most one output directory")
	}
	if flag.NArg() == 1 { // Preserve the original shell entry point's argument.
		*output = flag.Arg(0)
	}
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	catalog, err := os.ReadFile(filepath.Join(root, "bindings/rust/sys/targets.json"))
	if err != nil {
		return err
	}
	var targets []targetSpec
	if err := json.Unmarshal(catalog, &targets); err != nil {
		return err
	}
	if *list {
		for _, spec := range targets {
			fmt.Println(spec.Target)
		}
		return nil
	}
	spec, err := selectTarget(targets, *target, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	goVersion, err := commandOutput(root, "go", "env", "GOVERSION")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(goVersion, "go1.26.") {
		return fmt.Errorf("use Go 1.26.x for native artifacts; got %s (runtime compatibility is pinned)", goVersion)
	}
	if (spec.GOOS != runtime.GOOS || spec.GOARCH != runtime.GOARCH) && os.Getenv("CC") == "" {
		return fmt.Errorf("cross-building %s requires an explicit target C compiler in CC", spec.Target)
	}
	if *output == "" {
		*output = filepath.Join(root, "dist/native", spec.Target)
	}
	out, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(out), ".native-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	engineVersion, err := commandOutput(root, "git", "describe", "--tags", "--match", "v2.*", "--always", "--dirty")
	if err != nil {
		engineVersion = "dev"
	}
	// -ldflags is tokenized again by Go. A tag must not introduce linker flags.
	if strings.ContainsAny(engineVersion, " \t\r\n\"'\\") {
		return errors.New("engine version contains unsupported characters")
	}
	sharedName := "libbetterleaks_ffi.so"
	if spec.GOOS == "darwin" {
		sharedName = "libbetterleaks_ffi.dylib"
	}
	archive := filepath.Join(stage, "libbetterleaks.a")
	shared := filepath.Join(stage, sharedName)
	build := func(mode, path string) (string, error) {
		linkerFlags := "-X github.com/betterleaks/betterleaks/v2/version.Version=" + engineVersion
		if mode == "c-shared" && spec.GOOS == "darwin" {
			linkerFlags += " -extldflags=-Wl,-install_name,@rpath/" + sharedName
		}
		cmd := exec.Command("go", "build", "-mod=readonly", "-trimpath", "-tags", "betterleaks_ffi", "-buildmode="+mode,
			"-ldflags", linkerFlags,
			"-o", path, "./bindings/c")
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = root, targetEnvironment(spec), os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("build %s %s: %w", spec.Target, mode, err)
		}
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer file.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", hash.Sum(nil)), nil
	}
	archiveHash, err := build("c-archive", archive)
	if err != nil {
		return err
	}
	sharedHash, err := build("c-shared", shared)
	if err != nil {
		return err
	}
	metadata := manifest{
		PackageVersion: "0.1.0", ABIVersion: 1, Target: spec.Target, MinimumMacOS: spec.MinimumMacOS,
		ArchiveSHA256: archiveHash, SharedLibrary: sharedName, SharedSHA256: sharedHash,
		GoVersion: goVersion, EngineVersion: engineVersion,
	}
	encoded, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	for source, destination := range map[string]string{
		archive:                                  filepath.Join(out, "lib/libbetterleaks.a"),
		shared:                                   filepath.Join(out, "lib", sharedName),
		filepath.Join(stage, "libbetterleaks.h"): filepath.Join(out, "include/cgo-generated.h"),
		filepath.Join(root, "bindings/c/betterleaks.h"): filepath.Join(out, "include/betterleaks.h"),
		filepath.Join(root, "LICENSE"):                  filepath.Join(out, "LICENSE"),
	} {
		if err := copyFile(source, destination); err != nil {
			return err
		}
	}
	// Write the manifest last; partially copied artifacts cannot pass the hash check.
	if err := os.WriteFile(filepath.Join(out, "lib/betterleaks-native.json"), append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("Built %s\nUse BETTERLEAKS_LIB_DIR=%s when building the Rust crate.\n", out, filepath.Join(out, "lib"))
	return nil
}

func selectTarget(targets []targetSpec, requested, hostOS, hostArch string) (targetSpec, error) {
	if strings.HasSuffix(requested, "-linux-musl") {
		return targetSpec{}, errors.New("musl targets are unsupported by the native artifact build")
	}
	for _, spec := range targets {
		if requested == spec.Target || (requested == "" && spec.GOOS == hostOS && spec.GOARCH == hostArch) {
			return spec, nil
		}
	}
	return targetSpec{}, fmt.Errorf("unsupported target %q (host %s/%s); use -list-targets", requested, hostOS, hostArch)
}

func targetEnvironment(spec targetSpec) []string {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	values["GOOS"], values["GOARCH"], values["CGO_ENABLED"] = spec.GOOS, spec.GOARCH, "1"
	if spec.MinimumMacOS != "" {
		values["MACOSX_DEPLOYMENT_TARGET"] = spec.MinimumMacOS
	}
	if spec.Libc == "gnu" {
		values["CGO_CPPFLAGS"] += " -DBL_LIBC_GNU"
	}
	env := make([]string, 0, len(values))
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func repositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "bindings/c/betterleaks.h")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("run from a Betterleaks checkout")
		}
		dir = parent
	}
}

func commandOutput(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.Output()
	return strings.TrimSpace(string(output)), err
}

func copyFile(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	sourceInfo, err := in.Stat()
	if err != nil {
		return err
	}
	if destinationInfo, err := os.Stat(destination); err == nil && os.SameFile(sourceInfo, destinationInfo) {
		return fmt.Errorf("source and destination are the same file: %s", destination)
	}
	out, err := os.Create(destination)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	return errors.Join(err, out.Close())
}
