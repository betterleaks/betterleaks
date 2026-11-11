// Command gen renders the default rules into config/betterleaks.toml.
package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/rules"
)

//go:embed config.tmpl
var configTemplate string

// tomlKeyQuote quotes a TOML key if it contains characters that require quoting
// (e.g. dots, spaces). Bare keys only allow [A-Za-z0-9_-].
func tomlKeyQuote(key string) string {
	if strings.ContainsAny(key, ". \t") {
		return fmt.Sprintf("%q", key)
	}
	return key
}

// tomlQuote returns a TOML-safe quoted string. Values containing liquid
// template syntax ({{ ... }}) use TOML literal strings (single quotes) to
// avoid escaping inner double quotes used by filters like append/b64enc.
func tomlQuote(s string) string {
	if strings.Contains(s, "{{") {
		return "'" + s + "'"
	}
	return fmt.Sprintf("%q", s)
}

func tomlValue(v any) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, tomlValue(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprintf("%q", fmt.Sprintf("%v", v))
	}
}

func main() {
	if len(os.Args) != 2 {
		_, _ = os.Stderr.WriteString("usage: gen path/to/betterleaks.toml\n")
		os.Exit(2)
	}
	path := os.Args[1]

	cfg, err := rules.Config()
	if err != nil {
		logging.Fatal("Invalid rules", "error", err)
	}

	funcMap := template.FuncMap{
		"tomlQuote": tomlQuote,
		"tomlExpr": func(s string) string {
			// Always use TOML multi-line literal strings for filter/prefilter
			// expressions. This avoids quoting issues and improves readability.
			return "'''\n" + s + "\n'''"
		},
		"tomlInlineTable": func(m map[string]string) string {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s = %s", tomlKeyQuote(k), tomlQuote(m[k])))
			}
			return "{ " + strings.Join(parts, ", ") + " }"
		},
		"tomlInlineTableAny": func(m map[string]any) string {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s = %s", tomlKeyQuote(k), tomlValue(m[k])))
			}
			return "{ " + strings.Join(parts, ", ") + " }"
		},
	}
	tmpl, err := template.New("config").Funcs(funcMap).Parse(configTemplate)
	if err != nil {
		logging.Fatal("Failed to parse template", "error", err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, cfg); err != nil {
		logging.Fatal("Failed to render config", "error", err)
	}

	// Leave an unchanged file untouched.
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, out.Bytes()) {
		return
	}
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		logging.Fatal("Failed to write config", "error", err, "path", path)
	}
}
