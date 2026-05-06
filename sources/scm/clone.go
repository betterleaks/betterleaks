package scm

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// userinfoRedactor matches `<scheme>://<userinfo>@` in URLs so we can replace
// the userinfo with "***" without parsing every URL we might log.
var userinfoRedactor = regexp.MustCompile(`(https?)://[^/\s@]+@`)

// CloneOptions configures a CloneAuthed call. Zero value is valid: full
// (non-bare, non-mirror) clone with no extra options.
type CloneOptions struct {
	// Bare clones with --bare (no working tree). Recommended for scanning
	// since we only need objects.
	Bare bool

	// Mirror clones with --mirror (implies bare). Useful when the caller
	// wants the full set of refs (e.g. PR refs, tags) without further
	// configuration.
	Mirror bool

	// SingleBranch limits the clone to the default branch only.
	SingleBranch bool

	// Depth, if > 0, requests a shallow clone of that many commits.
	Depth int

	// Configs are extra git config key/value pairs applied only to this clone.
	Configs []GitConfig
}

// GitConfig is a single git config entry applied to a command invocation.
type GitConfig struct {
	Key   string
	Value string
}

// CloneAuthed clones remote into dest. If token is non-empty and the remote
// is HTTPS, it is passed via a temporary git config entry so the clone can
// authenticate without mutating the remote URL. The token is stripped from any
// returned error message via SanitizeOutput.
//
// The intent is to let multiple SCM sources (GitHub today, GitLab/Bitbucket
// later) share one clone helper.
func CloneAuthed(ctx context.Context, remote, token, dest string, opts CloneOptions) error {
	if remote == "" {
		return fmt.Errorf("scm.CloneAuthed: empty remote")
	}
	if dest == "" {
		return fmt.Errorf("scm.CloneAuthed: empty dest")
	}

	authConfigs, err := authCloneConfigs(remote, token)
	if err != nil {
		return fmt.Errorf("clone auth config: %w", err)
	}

	args := []string{"clone", "--quiet"}
	if opts.Mirror {
		args = append(args, "--mirror")
	} else if opts.Bare {
		args = append(args, "--bare")
	}
	if opts.SingleBranch {
		args = append(args, "--single-branch")
	}
	if opts.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", opts.Depth))
	}
	args = append(args, remote, dest)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = gitCloneEnv(append(opts.Configs, authConfigs...))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone %s: %w: %s",
			SanitizeOutput(remote, token),
			err,
			SanitizeOutput(string(out), token))
	}
	return nil
}

// CloneToTempDir clones a remote into a temporary directory, invokes fn with
// the cloned repo path, and removes the directory afterwards.
func CloneToTempDir(ctx context.Context, remote, token, tempDirPattern string, opts CloneOptions, fn func(repoPath string) error) error {
	if tempDirPattern == "" {
		tempDirPattern = "betterleaks-git-*"
	}
	tmpDir, err := os.MkdirTemp("", tempDirPattern)
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := CloneAuthed(ctx, remote, token, tmpDir, opts); err != nil {
		return err
	}
	return fn(tmpDir)
}

func authCloneConfigs(remote, token string) ([]GitConfig, error) {
	if token == "" {
		return nil, nil
	}
	// SSH-style remotes ("git@host:owner/repo") are not parseable by net/url.
	// We can't authenticate them with a token anyway, so pass through.
	if isSSHRemote(remote) {
		return nil, nil
	}
	u, err := url.Parse(remote)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil
	}
	cred := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	key := fmt.Sprintf("http.%s://%s.extraHeader", u.Scheme, u.Host)
	return []GitConfig{{Key: key, Value: "Authorization: basic " + cred}}, nil
}

// isSSHRemote reports whether s looks like the scp-style SSH remote that
// GitHub and friends emit (e.g. "git@github.com:owner/repo.git"). Such URLs
// are not parseable as RFC 3986 URLs.
func isSSHRemote(s string) bool {
	if strings.HasPrefix(s, "ssh://") {
		return true
	}
	at := strings.Index(s, "@")
	if at <= 0 {
		return false
	}
	colon := strings.Index(s[at:], ":")
	if colon <= 0 {
		return false
	}
	// Reject http(s)://user:pass@host: forms.
	return !strings.Contains(s[:at], "://")
}

func gitCloneEnv(configs []GitConfig) []string {
	var nullDevice string
	if runtime.GOOS == "windows" {
		nullDevice = "NUL"
	} else {
		nullDevice = "/dev/null"
	}
	overrides := map[string]string{
		"GIT_CONFIG_GLOBAL":      nullDevice,
		"GIT_CONFIG_NOSYSTEM":    "1",
		"GIT_CONFIG_SYSTEM":      nullDevice,
		"GIT_NO_REPLACE_OBJECTS": "1",
		"GIT_TERMINAL_PROMPT":    "0",
	}

	if len(configs) > 0 {
		overrides["GIT_CONFIG_COUNT"] = fmt.Sprintf("%d", len(configs))
		for i, cfg := range configs {
			overrides[fmt.Sprintf("GIT_CONFIG_KEY_%d", i)] = cfg.Key
			overrides[fmt.Sprintf("GIT_CONFIG_VALUE_%d", i)] = cfg.Value
		}
	}

	env := os.Environ()
	for i, e := range env {
		for k, v := range overrides {
			if strings.HasPrefix(e, k+"=") {
				env[i] = k + "=" + v
				delete(overrides, k)
			}
		}
	}
	for k, v := range overrides {
		env = append(env, k+"="+v)
	}
	return env
}

// SanitizeOutput redacts the token (and any URL-encoded form of it) from text.
// It also strips userinfo from any URL that looks like https://user:pass@host.
// Use it whenever you log or wrap text that may have come from a `git` invocation.
func SanitizeOutput(text, token string) string {
	if text == "" {
		return text
	}
	if token != "" {
		text = strings.ReplaceAll(text, token, "***")
		if encoded := url.QueryEscape(token); encoded != token {
			text = strings.ReplaceAll(text, encoded, "***")
		}
	}
	return userinfoRedactor.ReplaceAllString(text, "$1://***@")
}
