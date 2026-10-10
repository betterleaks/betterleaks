package container

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
)

// Keep endpoint selection separate from transport ownership. A caller-provided
// transport remains responsible for its own TLS and connection settings.
type daemonEndpoint struct {
	*url.URL
	tls *tls.Config
}

func (s *Source) daemonHost(ctx context.Context) (*daemonEndpoint, error) {
	if s.DaemonHost != "" {
		return loadDaemonEndpoint(ctx, s.DaemonHost, "", false, false)
	}
	if s.Daemon == "docker" {
		return dockerEndpoint(ctx)
	}
	host, err := podmanHost(ctx)
	if err != nil {
		return nil, err
	}
	return loadDaemonEndpoint(ctx, host, "", false, false)
}

func dockerEndpoint(ctx context.Context) (*daemonEndpoint, error) {
	configPath := dockerConfigPath()
	contextName := os.Getenv("DOCKER_CONTEXT")
	host := os.Getenv("DOCKER_HOST")
	// DOCKER_CONTEXT overrides DOCKER_HOST per Docker's documented CLI contract.
	if contextName == "" && host == "" && configPath != "" {
		data, err := readConfigFile(ctx, configPath)
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
			contextName = config.CurrentContext
		}
	}
	if contextName != "" && contextName != "default" {
		if configPath == "" {
			return nil, errors.New("cannot locate Docker context configuration; set DOCKER_CONFIG or --daemon-host")
		}
		id := fmt.Sprintf("%x", sha256.Sum256([]byte(contextName)))
		root := filepath.Join(filepath.Dir(configPath), "contexts")
		data, err := readConfigFile(ctx, filepath.Join(root, "meta", id, "meta.json"))
		if err != nil {
			return nil, fmt.Errorf("read Docker context %q: %w", contextName, err)
		}
		var metadata struct {
			Name      string
			Endpoints map[string]struct {
				Host          string
				SkipTLSVerify bool
			}
		}
		if err := json.Unmarshal(data, &metadata); err != nil {
			return nil, fmt.Errorf("invalid Docker context %q: %w", contextName, err)
		}
		endpoint, ok := metadata.Endpoints["docker"]
		if metadata.Name != contextName || !ok || endpoint.Host == "" {
			return nil, fmt.Errorf("docker context %q has no valid docker endpoint", contextName)
		}
		return loadDaemonEndpoint(ctx, endpoint.Host, filepath.Join(root, "tls", id, "docker"), false, endpoint.SkipTLSVerify)
	}
	enableTLS := os.Getenv("DOCKER_TLS") != "" || os.Getenv("DOCKER_TLS_VERIFY") != ""
	if host == "" {
		switch {
		case enableTLS:
			host = "tcp://localhost:2376"
		case runtime.GOOS == "windows":
			host = "npipe:////./pipe/docker_engine"
		default:
			host = "unix:///var/run/docker.sock"
		}
	}
	certDir := ""
	if enableTLS {
		certDir = os.Getenv("DOCKER_CERT_PATH")
		if certDir == "" && configPath != "" {
			certDir = filepath.Dir(configPath)
		}
	}
	return loadDaemonEndpoint(ctx, host, certDir, enableTLS, enableTLS && os.Getenv("DOCKER_TLS_VERIFY") == "")
}

func loadDaemonEndpoint(ctx context.Context, host, certDir string, enableTLS, skipVerify bool) (*daemonEndpoint, error) {
	u, err := parseDaemonHost(host)
	if err != nil {
		return nil, err
	}
	endpoint := &daemonEndpoint{URL: u, tls: nil}
	if u.Scheme == "unix" || u.Scheme == "npipe" {
		return endpoint, nil
	}
	var ca, cert, key []byte
	if certDir != "" {
		for name, dest := range map[string]*[]byte{"ca.pem": &ca, "cert.pem": &cert, "key.pem": &key} {
			data, err := readConfigFile(ctx, filepath.Join(certDir, name))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("read engine TLS %s: %w", name, err)
			}
			if err == nil {
				if len(data) == 0 {
					return nil, fmt.Errorf("empty engine TLS %s", name)
				}
				*dest = data
			}
		}
	}
	enableTLS = enableTLS || skipVerify || ca != nil || cert != nil || key != nil || u.Scheme == "https"
	if u.Scheme == "tcp" && u.Port() == "" {
		port := "2375"
		if enableTLS {
			port = "2376"
		}
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	if enableTLS {
		if u.Scheme == "http" {
			return nil, errors.New("engine TLS configuration conflicts with http://; use tcp:// or https://")
		}
		cfg := new(tls.Config)
		cfg.MinVersion = tls.VersionTLS12
		cfg.InsecureSkipVerify = skipVerify // Explicit Docker context/DOCKER_TLS setting; never inferred from a failure.
		if ca != nil {
			cfg.RootCAs = x509.NewCertPool()
			if !cfg.RootCAs.AppendCertsFromPEM(ca) {
				return nil, errors.New("invalid engine TLS ca.pem")
			}
		}
		if (cert == nil) != (key == nil) {
			return nil, errors.New("engine TLS requires both cert.pem and key.pem")
		}
		if cert != nil {
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				return nil, fmt.Errorf("invalid engine TLS client certificate: %w", err)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
		endpoint.tls = cfg
		u.Scheme = "https"
	} else if u.Scheme == "tcp" {
		u.Scheme = "http"
	}
	return endpoint, nil
}

func podmanHost(ctx context.Context) (string, error) {
	name := os.Getenv("CONTAINER_CONNECTION")
	if host := os.Getenv("CONTAINER_HOST"); name == "" && host != "" {
		return host, nil
	}
	configPath := os.Getenv("PODMAN_CONNECTIONS_CONF")
	if configPath == "" {
		dir := os.Getenv("XDG_CONFIG_HOME")
		if dir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			dir = filepath.Join(home, ".config")
		}
		configPath = filepath.Join(dir, "containers", "podman-connections.json")
	}
	data, err := readConfigFile(ctx, configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read Podman connections: %w", err)
	}
	if err == nil {
		var config struct {
			Connection struct {
				Default     string
				Connections map[string]struct{ URI, TLSCert, TLSKey, TLSCA string }
			}
		}
		if err := json.Unmarshal(data, &config); err != nil {
			return "", fmt.Errorf("invalid Podman connections: %w", err)
		}
		if name == "" {
			name = config.Connection.Default
		}
		if name != "" {
			connection, ok := config.Connection.Connections[name]
			if !ok || connection.URI == "" {
				return "", fmt.Errorf("podman connection %q has no URI in podman-connections.json; for containers.conf connections use --daemon-host", name)
			}
			if connection.TLSCert != "" || connection.TLSKey != "" || connection.TLSCA != "" {
				return "", errors.New("podman connection TLS files are not supported; use --daemon-host with an SDK DaemonTransport for custom TLS")
			}
			return connection.URI, nil
		}
	}
	if name != "" {
		return "", fmt.Errorf("podman connection %q not found; for containers.conf connections use --daemon-host", name)
	}
	if runtime.GOOS == "linux" {
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			var u url.URL
			u.Scheme, u.Path = "unix", filepath.Join(dir, "podman", "podman.sock")
			return u.String(), nil
		}
		if os.Geteuid() == 0 {
			return "unix:///run/podman/podman.sock", nil
		}
	}
	return "", errors.New("set --daemon-host to the engine API endpoint; the API service must be available")
}
