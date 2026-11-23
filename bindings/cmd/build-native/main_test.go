package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalog(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "bindings/rust/sys/targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var specs []targetSpec
	if err := json.Unmarshal(data, &specs); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"aarch64-apple-darwin": true, "x86_64-apple-darwin": true,
		"aarch64-unknown-linux-gnu": true, "x86_64-unknown-linux-gnu": true,
	}
	for _, spec := range specs {
		if !want[spec.Target] {
			t.Fatalf("unexpected or duplicated target %s", spec.Target)
		}
		delete(want, spec.Target)
		selected, err := selectTarget(specs, spec.Target, "darwin", "arm64")
		if err != nil || selected.Target != spec.Target {
			t.Fatalf("explicit cross target not selected: %s: %v", spec.Target, err)
		}
		if len(spec.Libraries) == 0 || spec.GOOS == "" || spec.GOARCH == "" {
			t.Fatalf("incomplete target %s", spec.Target)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing targets: %v", want)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		selected, err := selectTarget(specs, "", "linux", arch)
		if err != nil || selected.Libc != "gnu" || selected.GOARCH != arch {
			t.Fatalf("wrong Linux default: %+v: %v", selected, err)
		}
	}
	if _, err := selectTarget(specs, "", "windows", "amd64"); err == nil {
		t.Fatal("Windows must remain explicitly unsupported")
	}
	if _, err := selectTarget(specs, "aarch64-unknown-linux-musl", "linux", "arm64"); err == nil || !strings.Contains(err.Error(), "musl") {
		t.Fatalf("musl must be rejected with the runtime limitation: %v", err)
	}
}

func TestTargetEnvironment(t *testing.T) {
	t.Setenv("CC", "target-cc")
	t.Setenv("GOOS", "windows")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("CGO_CPPFLAGS", "-DUSER_FLAG")
	spec := targetSpec{GOOS: "linux", GOARCH: "arm64", Libc: "gnu"}
	env := map[string]string{}
	for _, entry := range targetEnvironment(spec) {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	if env["GOOS"] != "linux" || env["GOARCH"] != "arm64" || env["CGO_ENABLED"] != "1" || env["CC"] != "target-cc" {
		t.Fatalf("wrong target environment: GOOS=%q GOARCH=%q CGO_ENABLED=%q CC=%q", env["GOOS"], env["GOARCH"], env["CGO_ENABLED"], env["CC"])
	}
	if !strings.Contains(env["CGO_CPPFLAGS"], "-DUSER_FLAG") || !strings.Contains(env["CGO_CPPFLAGS"], "-DBL_LIBC_GNU") {
		t.Fatal("libc check must preserve caller CPPFLAGS")
	}
}

func TestCopyFileCannotTruncateItsSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LICENSE")
	if err := os.WriteFile(path, []byte("keep this"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(path, path); err == nil {
		t.Fatal("copying onto the source must fail")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "keep this" {
		t.Fatalf("source was changed: %q: %v", data, err)
	}
}
