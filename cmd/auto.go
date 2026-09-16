package cmd

import (
	"errors"
	"net/http"
	"net/url"
	"os"

	"github.com/alecthomas/kong"
	"github.com/betterleaks/betterleaks/v2/sources"
)

type AutoCmd struct {
	ScanFlags      `embed:""`
	FollowSymlinks bool     `name:"follow-symlinks" help:"Follow symlinks when scanning local paths."`
	Targets        []string `arg:"" optional:"" name:"target" help:"Local paths or a single remote URL to scan."`
}

func (cmd *AutoCmd) Run(cli *CLI, runtime *commandRuntime, parsed *kong.Context) error {
	targets := cmd.Targets
	if len(targets) == 0 {
		targets = []string{"."}
	}
	directory := DirectoryCmd{ScanFlags: cmd.ScanFlags, FollowSymlinks: cmd.FollowSymlinks, Paths: targets}
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
	opts := []sources.AutoOption{sources.WithAutoLogger(runtime.Logger())}
	if token := remoteGitToken(target); token != "" {
		u, _ := url.Parse(target)
		opts = append(opts, sources.WithAutoHTTPClient(&http.Client{
			Transport: gitAutoTransport{host: u.Host, token: token},
		}))
	}
	kind, err := sources.Auto(runtime.Context, target, opts...)
	if err != nil {
		return err
	}
	// Copy the parsed commands to retain their defaults without changing CLI state.
	switch kind {
	case sources.FilesystemKind:
		return directory.Run(cli, runtime)
	case sources.GitKind:
		command := cli.Git
		command.ScanFlags, command.Repo = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case sources.URLKind:
		command := cli.URL
		command.ScanFlags, command.URL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case sources.GitHubKind:
		command := cli.GitHub
		command.ScanFlags, command.TargetURL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case sources.GitLabKind:
		command := cli.GitLab
		command.ScanFlags, command.TargetURL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case sources.HuggingFaceKind:
		command := cli.HuggingFace
		command.ScanFlags, command.TargetURL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	case sources.S3Kind:
		command := cli.S3
		command.ScanFlags, command.URL = cmd.ScanFlags, target
		return command.Run(cli, runtime)
	default:
		return errors.New("could not determine source type; select a source command explicitly")
	}
}
