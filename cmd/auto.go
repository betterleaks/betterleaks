package cmd

import (
	"errors"
	"net/http"
	"net/url"
	"os"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/sources/auto"
)

type AutoCmd struct {
	ScanFlags          `embed:""`
	MaxArchiveDepth    int      `group:"scanning" name:"max-archive-depth" default:"8" help:"Allow scanning into nested archives up to this depth."`
	MaxTargetMegabytes int      `group:"scanning" name:"max-target-megabytes" help:"Files larger than this will be skipped."`
	FollowSymlinks     bool     `group:"scanning" name:"follow-symlinks" help:"Follow symlinks when scanning local paths."`
	Targets            []string `arg:"" optional:"" name:"target" help:"Local paths or a single remote URL to scan."`
}

func (cmd *AutoCmd) Run(cli *CLI, runtime *commandRuntime, parsed *kong.Context) error {
	targets := cmd.Targets
	if len(targets) == 0 {
		targets = []string{"."}
	}
	directory := DirectoryCmd{
		ScanFlags:          cmd.ScanFlags,
		MaxArchiveDepth:    cmd.MaxArchiveDepth,
		MaxTargetMegabytes: cmd.MaxTargetMegabytes,
		FollowSymlinks:     cmd.FollowSymlinks,
		Paths:              targets,
	}
	if len(targets) > 1 {
		for _, target := range targets {
			if _, err := os.Stat(target); err != nil {
				return errors.New("multiple targets must all be existing local paths; scan one remote URL at a time")
			}
		}
		runtime.Logger().InfoContext(runtime.Context, "auto: selected source", "source", "filesystem", "targets", len(targets))
		return directory.Run(cli, runtime)
	}
	target := targets[0]
	// Reject local-only flags before discovery makes a request.
	if flagWasSet(parsed, "follow-symlinks") {
		if _, err := os.Stat(target); err != nil {
			return errors.New("--follow-symlinks requires an existing filesystem target")
		}
	}
	opts := []auto.AutoOption{auto.WithAutoLogger(runtime.Logger())}
	if token := remoteGitToken(target); token != "" {
		u, _ := url.Parse(target)
		opts = append(opts, auto.WithAutoHTTPClient(&http.Client{
			Transport: gitAutoTransport{host: u.Host, token: token},
		}))
	}
	kind, err := auto.Auto(runtime.Context, target, opts...)
	if err != nil {
		return err
	}
	if flagWasSet(parsed, "max-target-megabytes") && kind != auto.FilesystemKind && kind != auto.URLKind {
		return errors.New("--max-target-megabytes requires a filesystem target or a single downloadable URL")
	}
	// Copy the parsed commands to retain their defaults without changing CLI state.
	switch kind {
	case auto.FilesystemKind:
		return directory.Run(cli, runtime)
	case auto.GitKind:
		command := cli.Git
		command.MaxArchiveDepth = cmd.MaxArchiveDepth
		command.ScanFlags, command.Repo = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case auto.URLKind:
		command := cli.URL
		command.MaxTargetMegabytes = cmd.MaxTargetMegabytes
		command.MaxArchiveDepth = cmd.MaxArchiveDepth
		command.ScanFlags, command.URL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case auto.GitHubKind:
		command := cli.GitHub
		command.MaxArchiveDepth = cmd.MaxArchiveDepth
		command.ScanFlags, command.TargetURL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case auto.GitLabKind:
		command := cli.GitLab
		command.MaxArchiveDepth = cmd.MaxArchiveDepth
		command.ScanFlags, command.TargetURL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case auto.HuggingFaceKind:
		command := cli.HuggingFace
		command.MaxArchiveDepth = cmd.MaxArchiveDepth
		command.ScanFlags, command.TargetURL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case auto.S3Kind:
		command := cli.S3
		command.MaxArchiveDepth = cmd.MaxArchiveDepth
		command.ScanFlags, command.URL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	default:
		return errors.New("could not determine source type; select a source command explicitly")
	}
}
