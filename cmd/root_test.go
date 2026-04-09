package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/betterleaks/betterleaks/sources"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestInitConfigUsesSiblingConfigForFileTarget(t *testing.T) {
	t.Helper()

	projectDir := t.TempDir()
	configPath := filepath.Join(projectDir, ".betterleaks.toml")
	targetPath := filepath.Join(projectDir, "input.txt")

	if err := os.WriteFile(configPath, []byte(`
title = "custom"

[[rules]]
id = "custom-secret"
description = "Custom secret"
regex = '''MYSECRET'''
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(targetPath, []byte("MYSECRET\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	viper.Reset()
	t.Cleanup(viper.Reset)

	oldBannerPrinted := bannerPrinted
	bannerPrinted = false
	t.Cleanup(func() {
		bannerPrinted = oldBannerPrinted
	})

	oldRootCmd := rootCmd
	rootCmd = &cobra.Command{}
	rootCmd.Flags().Bool("no-banner", false, "")
	rootCmd.Flags().String("config", "", "")
	t.Cleanup(func() {
		rootCmd = oldRootCmd
	})

	if err := rootCmd.Flags().Set("no-banner", "true"); err != nil {
		t.Fatalf("set no-banner: %v", err)
	}

	initConfig(targetPath)

	cmd := &cobra.Command{}
	cmd.Flags().String("config", "", "")

	cfg := Config(cmd)
	if cfg.Path != configPath {
		t.Fatalf("cfg.Path = %q, want %q", cfg.Path, configPath)
	}
	if _, ok := cfg.Rules["custom-secret"]; !ok {
		t.Fatalf("custom rule was not loaded from discovered config")
	}
}

func TestDetectorLoadsSiblingIgnoreForFileTarget(t *testing.T) {
	t.Helper()

	projectDir := t.TempDir()
	configPath := filepath.Join(projectDir, ".betterleaks.toml")
	targetPath := filepath.Join(projectDir, "input.txt")
	ignorePath := filepath.Join(projectDir, ".betterleaksignore")
	isolatedIgnoreDir := t.TempDir()

	if err := os.WriteFile(configPath, []byte(`
title = "custom"

[[rules]]
id = "custom-secret"
description = "Custom secret"
regex = '''MYSECRET'''
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(targetPath, []byte("MYSECRET\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.WriteFile(ignorePath, []byte(filepath.Clean(targetPath)+":custom-secret:1\n"), 0o600); err != nil {
		t.Fatalf("write ignore: %v", err)
	}

	viper.Reset()
	t.Cleanup(viper.Reset)

	oldBannerPrinted := bannerPrinted
	bannerPrinted = false
	t.Cleanup(func() {
		bannerPrinted = oldBannerPrinted
	})

	oldRootCmd := rootCmd
	rootCmd = &cobra.Command{}
	rootCmd.Flags().Bool("no-banner", false, "")
	rootCmd.Flags().String("config", "", "")
	t.Cleanup(func() {
		rootCmd = oldRootCmd
	})

	if err := rootCmd.Flags().Set("no-banner", "true"); err != nil {
		t.Fatalf("set no-banner: %v", err)
	}
	if err := rootCmd.Flags().Set("config", configPath); err != nil {
		t.Fatalf("set config: %v", err)
	}

	initConfig(targetPath)

	cmd := &cobra.Command{}
	cmd.Flags().String("config", configPath, "")
	cmd.Flags().String("gitleaks-ignore-path", isolatedIgnoreDir, "")
	cmd.Flags().Bool("no-color", false, "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Uint("redact", 0, "")
	cmd.Flags().Int("max-target-megabytes", 0, "")
	cmd.Flags().Bool("ignore-gitleaks-allow", false, "")
	cmd.Flags().String("match-context", "", "")
	cmd.Flags().String("baseline-path", "", "")
	cmd.Flags().StringSlice("enable-rule", nil, "")
	cmd.Flags().Int("max-decode-depth", 5, "")
	cmd.Flags().Int("max-archive-depth", 0, "")
	cmd.Flags().Bool("validation", false, "")
	cmd.Flags().String("validation-status", "", "")
	cmd.Flags().Duration("validation-timeout", 0, "")
	cmd.Flags().Bool("validation-debug", false, "")
	cmd.Flags().Int("validation-workers", 0, "")
	cmd.Flags().Bool("validation-extract-empty", false, "")
	cmd.Flags().String("report-path", "", "")
	cmd.Flags().String("report-format", "", "")
	cmd.Flags().String("report-template", "", "")
	cmd.SetContext(context.Background())

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, targetPath)

	findings, err := detector.DetectSource(context.Background(), &sources.Files{
		Config:          &cfg,
		Path:            targetPath,
		Sema:            detector.Sema,
		MaxArchiveDepth: detector.MaxArchiveDepth,
	})
	if err != nil {
		t.Fatalf("scan file: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected ignored scan to yield no findings, got %d", len(findings))
	}
}

func TestDirectoryScanSkipsAutoDiscoveredBetterleaksConfigFile(t *testing.T) {
	t.Helper()

	projectDir := t.TempDir()
	configPath := filepath.Join(projectDir, ".betterleaks.toml")
	targetPath := filepath.Join(projectDir, "input.txt")
	isolatedIgnoreDir := t.TempDir()

	if err := os.WriteFile(configPath, []byte(`
title = "custom"

[[rules]]
id = "custom-secret"
description = "Custom secret"
regex = '''MYSECRET'''
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(targetPath, []byte("MYSECRET\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	viper.Reset()
	t.Cleanup(viper.Reset)

	oldBannerPrinted := bannerPrinted
	bannerPrinted = false
	t.Cleanup(func() {
		bannerPrinted = oldBannerPrinted
	})

	oldRootCmd := rootCmd
	rootCmd = &cobra.Command{}
	rootCmd.Flags().Bool("no-banner", false, "")
	rootCmd.Flags().String("config", "", "")
	t.Cleanup(func() {
		rootCmd = oldRootCmd
	})

	if err := rootCmd.Flags().Set("no-banner", "true"); err != nil {
		t.Fatalf("set no-banner: %v", err)
	}

	initConfig(projectDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("config", "", "")
	cmd.Flags().String("gitleaks-ignore-path", isolatedIgnoreDir, "")
	cmd.Flags().Bool("no-color", false, "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Uint("redact", 0, "")
	cmd.Flags().Int("max-target-megabytes", 0, "")
	cmd.Flags().Bool("ignore-gitleaks-allow", false, "")
	cmd.Flags().String("match-context", "", "")
	cmd.Flags().String("baseline-path", "", "")
	cmd.Flags().StringSlice("enable-rule", nil, "")
	cmd.Flags().Int("max-decode-depth", 5, "")
	cmd.Flags().Int("max-archive-depth", 0, "")
	cmd.Flags().Bool("validation", false, "")
	cmd.Flags().String("validation-status", "", "")
	cmd.Flags().Duration("validation-timeout", 0, "")
	cmd.Flags().Bool("validation-debug", false, "")
	cmd.Flags().Int("validation-workers", 0, "")
	cmd.Flags().Bool("validation-extract-empty", false, "")
	cmd.Flags().String("report-path", "", "")
	cmd.Flags().String("report-format", "", "")
	cmd.Flags().String("report-template", "", "")
	cmd.SetContext(context.Background())

	cfg := Config(cmd)
	detector := Detector(cmd, cfg, projectDir)

	findings, err := detector.DetectSource(context.Background(), &sources.Files{
		Config:          &cfg,
		Path:            projectDir,
		Sema:            detector.Sema,
		MaxArchiveDepth: detector.MaxArchiveDepth,
	})
	if err != nil {
		t.Fatalf("scan directory: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one finding from the target file, got %d", len(findings))
	}
	if findings[0].File != targetPath {
		t.Fatalf("finding file = %q, want %q", findings[0].File, targetPath)
	}
}
