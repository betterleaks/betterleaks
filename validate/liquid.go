package validate

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/osteele/liquid"
)

// TemplateEngine wraps a Liquid engine with custom filters for secret
// validation templates.
type TemplateEngine struct {
	engine *liquid.Engine
}

// NewTemplateEngine creates a TemplateEngine with all registered filters.
func NewTemplateEngine() *TemplateEngine {
	e := liquid.NewEngine()
	registerFilters(e)
	return &TemplateEngine{engine: e}
}

// Render parses and renders a Liquid template string with the given variables.
// Dotted keys like "test.rule" are expanded into nested maps so that Liquid's
// property access syntax ({{ test.rule }}) works correctly. Flat keys (e.g.
// "secret", "my-rule") are kept as-is.
func (t *TemplateEngine) Render(tmpl string, vars map[string]string) (string, error) {
	bindings := buildBindings(vars)
	out, err := t.engine.ParseAndRenderString(tmpl, bindings)
	if err != nil {
		return "", fmt.Errorf("liquid render: %w", err)
	}
	return out, nil
}

// buildBindings converts a flat string map into a nested map suitable for
// Liquid. Keys containing dots are expanded: "a.b.c" -> {"a": {"b": {"c": val}}}.
// Non-dotted keys are set directly.
func buildBindings(vars map[string]string) map[string]any {
	bindings := make(map[string]any, len(vars))
	for k, v := range vars {
		if !strings.Contains(k, ".") {
			bindings[k] = v
			continue
		}
		parts := strings.Split(k, ".")
		cur := bindings
		for i, p := range parts {
			if i == len(parts)-1 {
				cur[p] = v
			} else {
				next, ok := cur[p]
				if !ok {
					m := make(map[string]any)
					cur[p] = m
					cur = m
				} else if m, ok := next.(map[string]any); ok {
					cur = m
				} else {
					// Conflict: a scalar already occupies this key.
					// Wrap it in a map, preserving the scalar as a special key.
					m := map[string]any{"_value": next}
					cur[p] = m
					cur = m
				}
			}
		}
	}
	return bindings
}

// RenderMap renders all values in a map through the Liquid engine.
func (t *TemplateEngine) RenderMap(m map[string]string, vars map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(m))
	for k, v := range m {
		rendered, err := t.Render(v, vars)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k, err)
		}
		out[k] = rendered
	}
	return out, nil
}

// Parse validates template syntax without rendering.
func (t *TemplateEngine) Parse(tmpl string) error {
	_, err := t.engine.ParseString(tmpl)
	return err
}

func registerFilters(e *liquid.Engine) {
	e.RegisterFilter("b64enc", func(input string) string {
		return base64.StdEncoding.EncodeToString([]byte(input))
	})

	e.RegisterFilter("b64dec", func(input string) string {
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return input
		}
		return string(decoded)
	})

	e.RegisterFilter("url_encode", func(input string) string {
		return url.QueryEscape(input)
	})

	e.RegisterFilter("sha256", func(input string) string {
		h := sha256.Sum256([]byte(input))
		return hex.EncodeToString(h[:])
	})

	e.RegisterFilter("hmac_sha1", func(input string, key string) string {
		mac := hmac.New(sha1.New, []byte(key))
		mac.Write([]byte(input))
		return base64.StdEncoding.EncodeToString(mac.Sum(nil))
	})

	e.RegisterFilter("hmac_sha256", func(input string, key string) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(input))
		return hex.EncodeToString(mac.Sum(nil))
	})

	e.RegisterFilter("unix_timestamp", func(_ string) string {
		return strconv.FormatInt(time.Now().Unix(), 10)
	})

	e.RegisterFilter("iso_timestamp", func(_ string) string {
		return time.Now().UTC().Format(time.RFC3339)
	})

	e.RegisterFilter("json_escape", func(input string) string {
		b, err := json.Marshal(input)
		if err != nil {
			return input
		}
		// json.Marshal wraps in quotes; strip them
		return string(b[1 : len(b)-1])
	})

	e.RegisterFilter("uuid", func(_ string) string {
		return uuid.New().String()
	})

	e.RegisterFilter("prefix", func(input string, n int) string {
		if n >= len(input) {
			return input
		}
		return input[:n]
	})

	e.RegisterFilter("suffix", func(input string, n int) string {
		if n >= len(input) {
			return input
		}
		return input[len(input)-n:]
	})
}
