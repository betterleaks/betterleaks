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
	"path"
	"strings"
	"time"
)

func parseDaemonHost(host string) (*url.URL, error) {
	u, err := url.Parse(host)
	if err == nil && u.Scheme == "ssh" {
		return nil, errors.New("SSH engine connections are not supported; set --daemon-host to a forwarded Unix socket or a TCP/TLS API endpoint")
	}
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid daemon host: endpoint must not contain credentials, query or fragment")
	}
	switch u.Scheme {
	case "unix":
		if u.Host != "" || !path.IsAbs(u.Path) || strings.ContainsRune(u.Path, 0) {
			return nil, errors.New("daemon Unix socket must use unix:///absolute/path")
		}
	case "http", "https", "tcp":
		if u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
			return nil, errors.New("daemon HTTP endpoint must specify a host without a path")
		}
	case "npipe":
		name := strings.TrimPrefix(u.Path, "//./pipe/")
		if u.Host != "" || name == u.Path || name == "" || strings.ContainsAny(name, "/\\\x00") || name == "." || name == ".." {
			return nil, errors.New("daemon named pipe must use npipe:////./pipe/name (local pipes only)")
		}
	default:
		return nil, errors.New("unsupported daemon host scheme: use unix://, npipe://, tcp://, http:// or https://")
	}
	return u, nil
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
		t.ResponseHeaderTimeout = 30 * time.Second
		t.MaxResponseHeaderBytes = 64 << 10
		t.DisableCompression = true
		t.TLSClientConfig = endpoint.tls
		if endpoint.Scheme == "unix" {
			socket := endpoint.Path
			t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socket)
			}
		}
		if endpoint.Scheme == "npipe" {
			pipe := strings.ReplaceAll(endpoint.Path, "/", "\\")
			t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				return dialDaemonPipe(dialCtx, pipe)
			}
		}
		defer t.CloseIdleConnections()
		transport = t
	}
	if endpoint.Scheme == "unix" || endpoint.Scheme == "npipe" {
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
