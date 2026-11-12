// Command gen renders the default rules into config/betterleaks.toml.
package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"text/template"

	"github.com/betterleaks/betterleaks/v2/internal/logging"
	"github.com/betterleaks/betterleaks/v2/internal/rulebuilder"
	_ "github.com/betterleaks/betterleaks/v2/rules"
)

//go:embed config.tmpl
var configTemplate string

func main() {
	if len(os.Args) != 2 {
		_, _ = os.Stderr.WriteString("usage: gen path/to/betterleaks.toml\n")
		os.Exit(2)
	}
	path := os.Args[1]

	cfg, err := rulebuilder.Config()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	funcMap := template.FuncMap{
		// Expressions are always TOML multi-line literal strings, which need
		// no escaping and keep multi-line expressions readable.
		"tomlExpr": func(s string) string { return "'''\n" + s + "\n'''" },
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
