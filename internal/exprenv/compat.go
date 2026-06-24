package exprenv

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	celRawStringRe = regexp.MustCompile(`r"""([\s\S]*?)"""`)
	celOptArrayRe  = regexp.MustCompile(`([A-Za-z0-9_.]+)\.\?([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]\.\?([A-Za-z_][A-Za-z0-9_]*)\.orValue\(([^()]*)\)`)
	celOptIndexRe  = regexp.MustCompile(`\[\?"([^"]+)"\]`)
	celOrValueRe   = regexp.MustCompile(`([A-Za-z0-9_\]\)"\?\.]+(?:\[[^\]]+\])?)\.orValue\(([^()]*)\)`)
	celOptionalRe  = regexp.MustCompile(`\.\?([A-Za-z_][A-Za-z0-9_]*)`)
	envAliasRe     = regexp.MustCompile(`\benv\(`)
)

// RewriteCELCompat rewrites the CEL-shaped expression syntax used by existing
// configs into Expr syntax. It is intentionally narrow; unsupported CEL syntax
// should fail at Expr compile with both original and rewritten expressions.
func RewriteCELCompat(input string) (string, error) {
	out := input
	var err error
	for strings.Contains(out, "cel.bind(") {
		out, err = rewriteFirstBind(out)
		if err != nil {
			return "", err
		}
	}

	out = celRawStringRe.ReplaceAllString(out, "`$1`")
	out = celOptArrayRe.ReplaceAllString(out, `getPath($1, "$2.$3.$4", $5)`)
	out = celOptIndexRe.ReplaceAllString(out, `["$1"]`)
	out = celOptionalRe.ReplaceAllString(out, `?.$1`)
	for {
		next := celOrValueRe.ReplaceAllString(out, `($1 ?? $2)`)
		if next == out {
			break
		}
		out = next
	}
	out, err = rewriteMethodCalls(out, "contains", "contains")
	if err != nil {
		return "", err
	}
	out, err = rewriteMethodCalls(out, "replace", "replace")
	if err != nil {
		return "", err
	}
	out, err = rewriteMethodCalls(out, "substring", "substring")
	if err != nil {
		return "", err
	}
	out, err = rewriteMethodCalls(out, "lastIndexOf", "lastIndexOf")
	if err != nil {
		return "", err
	}
	out = strings.ReplaceAll(out, "string(time.now_unix())", "time.now_unix()")
	out = envAliasRe.ReplaceAllString(out, "env.get(")
	out = stripTopLevelLetParens(out)
	return out, nil
}

func NeedsCELCompat(s string) bool {
	return strings.Contains(s, "cel.bind(") ||
		strings.Contains(s, `r"""`) ||
		strings.Contains(s, ".?") ||
		strings.Contains(s, "[?\"") ||
		strings.Contains(s, ".orValue(") ||
		strings.Contains(s, ".contains(") ||
		strings.Contains(s, ".replace(") ||
		strings.Contains(s, ".substring(") ||
		strings.Contains(s, ".lastIndexOf(") ||
		strings.Contains(s, "string(time.now_unix())") ||
		envAliasRe.MatchString(s)
}

func rewriteMethodCalls(s, method, fn string) (string, error) {
	needle := "." + method + "("
	for {
		idx := strings.Index(s, needle)
		if idx < 0 {
			return s, nil
		}
		recvStart := receiverStart(s, idx)
		if recvStart < 0 {
			return "", fmt.Errorf("compat rewrite could not find receiver for .%s", method)
		}
		argsStart := idx + len(needle)
		argsEnd, err := matchingParen(s, argsStart-1)
		if err != nil {
			return "", err
		}
		receiver := strings.TrimSpace(s[recvStart:idx])
		args := strings.TrimSpace(s[argsStart:argsEnd])
		var repl string
		if method == "contains" {
			repl = "(" + receiver + " contains " + args + ")"
		} else {
			repl = fn + "(" + receiver
			if args != "" {
				repl += ", " + args
			}
			repl += ")"
		}
		s = s[:recvStart] + repl + s[argsEnd+1:]
	}
}

func receiverStart(s string, dot int) int {
	i := dot - 1
	for i >= 0 && strings.ContainsRune(" \t\r\n", rune(s[i])) {
		i--
	}
	for i >= 0 {
		switch s[i] {
		case ')':
			open, err := matchingOpen(s, i, '(', ')')
			if err != nil {
				return -1
			}
			i = open - 1
		case ']':
			open, err := matchingOpen(s, i, '[', ']')
			if err != nil {
				return -1
			}
			i = open - 1
		default:
			if isReceiverChar(s[i]) {
				i--
				continue
			}
			return i + 1
		}
	}
	return 0
}

func matchingOpen(s string, close int, openCh, closeCh byte) (int, error) {
	depth := 0
	var quote byte
	for i := close; i >= 0; i-- {
		c := s[i]
		if quote != 0 {
			if c == quote && (i == 0 || s[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case closeCh:
			depth++
		case openCh:
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unmatched %c in expression", closeCh)
}

func isReceiverChar(c byte) bool {
	return c == '_' || c == '.' || c == '?' || c == '"' || c == '\'' ||
		(c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func stripTopLevelLetParens(s string) string {
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "(let ") || !strings.HasSuffix(trimmed, ")") {
		return s
	}
	end, err := matchingParen(trimmed, 0)
	if err != nil || end != len(trimmed)-1 {
		return s
	}
	inner := trimmed[1 : len(trimmed)-1]
	prefixLen := len(s) - len(strings.TrimLeft(s, " \t\r\n"))
	suffixLen := len(s) - len(strings.TrimRight(s, " \t\r\n"))
	return s[:prefixLen] + inner + s[len(s)-suffixLen:]
}

func rewriteFirstBind(s string) (string, error) {
	idx := strings.Index(s, "cel.bind(")
	if idx < 0 {
		return s, nil
	}
	startArgs := idx + len("cel.bind(")
	end, err := matchingParen(s, startArgs-1)
	if err != nil {
		return "", err
	}
	args, err := splitTopLevelArgs(s[startArgs:end])
	if err != nil {
		return "", err
	}
	if len(args) != 3 {
		return "", fmt.Errorf("cel.bind compatibility rewrite expected 3 args, got %d", len(args))
	}
	name := strings.TrimSpace(args[0])
	if name == "" {
		return "", fmt.Errorf("cel.bind compatibility rewrite found empty binding name")
	}
	repl := "(let " + name + " = " + strings.TrimSpace(args[1]) + "; " + strings.TrimSpace(args[2]) + ")"
	return s[:idx] + repl + s[end+1:], nil
}

func matchingParen(s string, open int) (int, error) {
	depth := 0
	var quote rune
	for i := open; i < len(s); i++ {
		r := rune(s[i])
		if quote != 0 {
			if r == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '"', '\'', '`':
			quote = r
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unmatched parenthesis in expression")
}

func splitTopLevelArgs(s string) ([]string, error) {
	var args []string
	start, depthParen, depthBrace, depthBracket := 0, 0, 0, 0
	var quote rune
	for i := 0; i < len(s); i++ {
		r := rune(s[i])
		if quote != 0 {
			if r == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '"', '\'', '`':
			quote = r
		case '(':
			depthParen++
		case ')':
			depthParen--
		case '{':
			depthBrace++
		case '}':
			depthBrace--
		case '[':
			depthBracket++
		case ']':
			depthBracket--
		case ',':
			if depthParen == 0 && depthBrace == 0 && depthBracket == 0 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
		if depthParen < 0 || depthBrace < 0 || depthBracket < 0 {
			return nil, fmt.Errorf("unbalanced expression while splitting cel.bind")
		}
	}
	args = append(args, s[start:])
	return args, nil
}
