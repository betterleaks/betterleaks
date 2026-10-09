package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func parseDaemonHost(host string) (*url.URL, error) {
	u, err := url.Parse(host)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid daemon host: use a unix://, http:// or https:// endpoint without credentials, query or fragment")
	}
	switch u.Scheme {
	case "unix":
		if u.Host != "" || !filepath.IsAbs(u.Path) || strings.ContainsRune(u.Path, 0) {
			return nil, errors.New("daemon Unix socket must use unix:///absolute/path")
		}
	case "http", "https":
		if u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("daemon HTTP endpoint must specify a host without a path")
		}
	default:
		return nil, errors.New("unsupported daemon host scheme: use unix://, http:// or https://; SSH, tcp:// and named-pipe connections are not supported")
	}
	return u, nil
}

func (s *Source) daemonHost(ctx context.Context) (*url.URL, error) {
	host := s.DaemonHost
	if host == "" {
		if s.Daemon == "docker" {
			// Do not silently ignore CLI settings and connect to another engine.
			if os.Getenv("DOCKER_CONTEXT") != "" {
				return nil, errors.New("docker contexts are not resolved; set --daemon-host to the engine endpoint")
			}
			if os.Getenv("DOCKER_TLS_VERIFY") != "" || os.Getenv("DOCKER_CERT_PATH") != "" || os.Getenv("DOCKER_TLS") != "" {
				return nil, errors.New("docker TLS environment settings are not loaded; set an explicit HTTPS daemon host and configure DaemonTransport for custom certificates")
			}
			host = os.Getenv("DOCKER_HOST")
			if host == "" {
				if path := dockerConfigPath(); path != "" {
					data, err := readConfigFile(ctx, path)
					if err != nil && !errors.Is(err, os.ErrNotExist) {
						return nil, fmt.Errorf("read Docker configuration: %w", err)
					}
					if err == nil {
						var config struct {
							CurrentContext string `json:"currentContext"`
						}
						if err := json.Unmarshal(data, &config); err != nil {
							return nil, fmt.Errorf("invalid Docker configuration: %w", err)
						}
						if config.CurrentContext != "" && config.CurrentContext != "default" {
							return nil, errors.New("saved Docker contexts are not resolved; set --daemon-host to the engine endpoint")
						}
					}
				}
			}
			if host == "" && runtime.GOOS != "windows" {
				host = "unix:///var/run/docker.sock"
			}
		} else {
			host = os.Getenv("CONTAINER_HOST")
			if host == "" && os.Getenv("CONTAINER_CONNECTION") != "" {
				return nil, errors.New("podman connections are not resolved; set --daemon-host to the engine endpoint")
			}
			if host == "" && runtime.GOOS == "linux" {
				if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
					var socketURL url.URL
					socketURL.Scheme = "unix"
					socketURL.Path = filepath.Join(dir, "podman", "podman.sock")
					host = socketURL.String()
				} else if os.Geteuid() == 0 {
					host = "unix:///run/podman/podman.sock"
				}
			}
		}
	}
	if host == "" {
		return nil, errors.New("set --daemon-host to the engine API endpoint; the API service must be available")
	}
	return parseDaemonHost(host)
}

func (r *session) daemon(ctx context.Context, ref string) error {
	if strings.TrimSpace(ref) == "" {
		return errors.New("daemon image reference must not be empty")
	}
	endpoint, err := r.s.daemonHost(ctx)
	if err != nil {
		return err
	}
	transport := r.s.DaemonTransport
	if transport == nil {
		var dialer net.Dialer
		dialer.Timeout, dialer.KeepAlive = 30*time.Second, 30*time.Second
		t := new(http.Transport)
		t.DialContext = dialer.DialContext
		t.TLSHandshakeTimeout = 10 * time.Second
		t.MaxResponseHeaderBytes = 64 << 10
		t.DisableCompression = true
		if endpoint.Scheme == "unix" {
			socket := endpoint.Path
			t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socket)
			}
		}
		defer t.CloseIdleConnections()
		transport = t
	}
	if endpoint.Scheme == "unix" {
		endpoint.Scheme, endpoint.Host = "http", "localhost"
	}
	// Escape the entire reference: slashes, query punctuation and shell syntax
	// are image-name data, never a request to a different endpoint or a command.
	// Both engines support this unversioned export route. Its response is an
	// archive we already validate; no engine-specific JSON schema is needed.
	endpoint.Path = "/images/" + ref + "/get"
	endpoint.RawPath = "/images/" + url.PathEscape(ref) + "/get"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/x-tar")
	client := &http.Client{Transport: transport, Jar: nil, Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	r.debug(ctx, "exporting local container image", "runtime", r.s.Daemon, "image", ref)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s image export: %w", r.s.Daemon, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s image export: HTTP %d: %w", r.s.Daemon, resp.StatusCode, daemonResponseError(resp.Body))
	}
	return r.unpack(ctx, resp.Body, "daemon:"+r.s.Daemon+":"+ref)
}

func daemonResponseError(body io.Reader) error {
	const limit = 16 << 10
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return err
	}
	truncated := len(data) > limit
	data = data[:min(len(data), limit)]
	message := strings.TrimSpace(string(data))
	var envelope struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &envelope) == nil && envelope.Message != "" {
		message = envelope.Message
	}
	if truncated {
		message += " [truncated]"
	}
	return errors.New(message)
}
