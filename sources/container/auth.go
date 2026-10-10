package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/docker/docker-credential-helpers/credentials"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// The default upstream keychain executes configured docker-credential helpers.
// Resolve file credentials by default. Explicit helper opt-in uses a bounded,
// cancellable command; the upstream default keychain ignores its context.
type registryKeychain struct{ allowHelpers bool }

func (k registryKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	return k.ResolveContext(context.Background(), target)
}

func (k registryKeychain) ResolveContext(ctx context.Context, target authn.Resource) (authn.Authenticator, error) {
	home, _ := os.UserHomeDir()
	var paths []string
	if path := dockerConfigPath(); path != "" {
		paths = append(paths, path)
	}
	if file := os.Getenv("REGISTRY_AUTH_FILE"); file != "" {
		paths = append(paths, file)
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		paths = append(paths, filepath.Join(dir, "containers", "auth.json"))
	}
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" && home != "" {
		configDir = filepath.Join(home, ".config")
	}
	if configDir != "" {
		paths = append(paths, filepath.Join(configDir, "containers", "auth.json"))
	}
	// As with the previous keychain, use the first existing config file, rather
	// than mixing credentials from independent stores.
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := readConfigFile(ctx, path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read registry credential file: %w", err)
		}
		return k.credentials(ctx, data, target)
	}
	return authn.Anonymous, nil
}

func dockerConfigPath() string {
	dir := os.Getenv("DOCKER_CONFIG")
	if dir == "" {
		home, _ := os.UserHomeDir()
		if home == "" {
			return ""
		}
		dir = filepath.Join(home, ".docker")
	}
	return filepath.Join(dir, "config.json")
}

func readConfigFile(ctx context.Context, path string) ([]byte, error) {
	const maxConfigFileSize = 16 << 20
	f, err := openRegularFile(ctx, nil, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, maxConfigFileSize+1))
	if len(data) > maxConfigFileSize {
		return nil, errors.New("container configuration file exceeds 16 MiB")
	}
	return data, err
}

func (k registryKeychain) credentials(ctx context.Context, data []byte, target authn.Resource) (authn.Authenticator, error) {
	var config struct {
		Auths   map[string]json.RawMessage `json:"auths"`
		Store   string                     `json:"credsStore"`
		Helpers map[string]string          `json:"credHelpers"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("invalid registry credential file: %w", err)
	}
	host := target.RegistryStr()
	keys := []string{target.String(), host, "https://" + host + "/v1/", "https://" + host, "https://" + host + "/", "http://" + host + "/v1/", "http://" + host, "http://" + host + "/"}
	helper := config.Store
	server := host
	if host == name.DefaultRegistry {
		server = authn.DefaultAuthKey
	}
	for _, key := range keys {
		if configured := config.Helpers[key]; configured != "" {
			helper = configured
			break
		}
	}
	if helper != "" && k.allowHelpers {
		return helperCredentials(ctx, helper, server)
	}
	// Older Docker files may key credentials by a registry URL with an API
	// path. Keep exact keys first and make legacy fallback deterministic. Do
	// not broaden repository-scoped keys or match another host by prefix.
	for _, key := range slices.Sorted(maps.Keys(config.Auths)) {
		u, err := url.Parse(key)
		if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host == host && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" {
			keys = append(keys, key)
		}
	}
	var emptyAuth authn.AuthConfig
	for _, key := range keys {
		if raw, ok := config.Auths[key]; ok {
			var auth authn.AuthConfig
			if err := json.Unmarshal(raw, &auth); err != nil {
				return nil, fmt.Errorf("invalid registry credentials for %s: %w", host, err)
			}
			if auth != emptyAuth {
				return authn.FromConfig(auth), nil
			}
		}
	}
	if helper != "" {
		return nil, fmt.Errorf("registry %s relies on a credential helper; automatic helper execution is disabled: use --credential-helpers to opt in, file-based credentials, --anonymous for public images, or an explicit SDK Keychain", host)
	}
	return authn.Anonymous, nil
}

func helperCredentials(ctx context.Context, helper, server string) (authn.Authenticator, error) {
	if helper == "" || strings.ContainsAny(helper, "/\\\x00") {
		return nil, errors.New("credential helper must be a configured executable suffix, not a path")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output := new(helperOutput)
	output.cancel = cancel
	// This is the only built-in container subprocess path and requires opt-in.
	// No shell is involved; the registry is sent on stdin, never as a command.
	cmd := exec.CommandContext(ctx, "docker-credential-"+helper, "get")
	cmd.Stdin = strings.NewReader(server)
	cmd.Stdout, cmd.Stderr = output, io.Discard
	// A descendant holding a pipe open must not indefinitely block Wait after
	// the helper exits or its context is canceled.
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if output.overflow {
		return nil, errors.New("credential helper response exceeds 1 MiB")
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("credential helper for %s: %w", server, ctx.Err())
	}
	if err != nil {
		if credentials.IsErrCredentialsNotFoundMessage(output.buffer.String()) {
			return authn.Anonymous, nil
		}
		// Helpers can print credentials even on failure; never include output.
		return nil, fmt.Errorf("credential helper for %s failed: %w", server, err)
	}
	var value struct {
		Username string
		Secret   *string
	}
	if json.Unmarshal(output.buffer.Bytes(), &value) != nil || value.Username == "" || value.Secret == nil {
		return nil, errors.New("invalid credential helper response (expected Username and Secret JSON fields)")
	}
	var auth authn.AuthConfig
	if value.Username == "<token>" {
		auth.IdentityToken = *value.Secret
	} else {
		auth.Username, auth.Password = value.Username, *value.Secret
	}
	return authn.FromConfig(auth), nil
}

type helperOutput struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	overflow bool
}

func (w *helperOutput) Write(p []byte) (int, error) {
	if len(p) > (1<<20)-w.buffer.Len() {
		w.overflow = true
		w.cancel()
		return 0, errors.New("credential helper response exceeds 1 MiB")
	}
	return w.buffer.Write(p)
}
