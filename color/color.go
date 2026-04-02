package color

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"
)

// isTTY is evaluated once at init and caches whether stdout is a terminal.
var isTTY = isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())

// Style holds ANSI formatting attributes for terminal output.
type Style struct {
	fg   string // ANSI color escape (empty = no color)
	bold bool
	italic bool
}

// New returns a new empty Style.
func New() Style { return Style{} }

// Foreground sets the foreground color from a hex string like "#f05c07".
func (s Style) Foreground(hex string) Style {
	s.fg = hexToANSI(hex)
	return s
}

// Bold enables bold text.
func (s Style) Bold() Style {
	s.bold = true
	return s
}

// Italic enables italic text.
func (s Style) Italic() Style {
	s.italic = true
	return s
}

// Render wraps text with the configured ANSI escape sequences.
// If stdout is not a TTY (e.g. piped or redirected), codes are suppressed.
func (s Style) Render(text string) string {
	if !isTTY {
		return text
	}
	var codes []string
	if s.bold {
		codes = append(codes, "1")
	}
	if s.italic {
		codes = append(codes, "3")
	}
	if s.fg != "" {
		codes = append(codes, s.fg)
	}
	if len(codes) == 0 {
		return text
	}
	return fmt.Sprintf("\033[%sm%s\033[0m", strings.Join(codes, ";"), text)
}

// hexToANSI converts a hex color like "#f05c07" to a 24-bit ANSI escape code.
func hexToANSI(hex string) string {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return ""
	}
	r, _ := strconv.ParseUint(hex[0:2], 16, 8)
	g, _ := strconv.ParseUint(hex[2:4], 16, 8)
	b, _ := strconv.ParseUint(hex[4:6], 16, 8)
	return fmt.Sprintf("38;2;%d;%d;%d", r, g, b)
}
