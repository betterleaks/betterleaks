package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ansiRed      = 31
	ansiGreen    = 32
	ansiYellow   = 33
	ansiBlue     = 34
	ansiCyan     = 36
	ansiDarkGray = 90
)

// ConsoleOptions configures the human-readable slog handler used by commands.
type ConsoleOptions struct {
	Level   slog.Leveler
	NoColor bool
}

// NewConsole returns a logger that writes compact, human-readable records.
func NewConsole(w io.Writer, options ConsoleOptions) *slog.Logger {
	return slog.New(&consoleHandler{
		state: &consoleState{
			writer: w,
		},
		level:   options.Level,
		noColor: options.NoColor,
	})
}

type consoleState struct {
	mu     sync.Mutex
	writer io.Writer
}

type consoleHandler struct {
	state   *consoleState
	level   slog.Leveler
	noColor bool
	attrs   []consoleAttr
	groups  []string
}

type consoleAttr struct {
	key   string
	value slog.Value
}

func (h *consoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	minimum := slog.LevelInfo
	if h.level != nil {
		minimum = h.level.Level()
	}
	return level >= minimum
}

func (h *consoleHandler) Handle(_ context.Context, record slog.Record) error {
	var line bytes.Buffer
	colors := !h.noColor && os.Getenv("NO_COLOR") == ""

	timestamp := record.Time
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	line.WriteString(colorize(timestamp.Format(time.Kitchen), ansiDarkGray, false, colors))
	line.WriteByte(' ')
	line.WriteString(colorize(shortLevel(record.Level), levelColor(record.Level), false, colors))

	if record.Message != "" {
		line.WriteByte(' ')
		line.WriteString(colorize(record.Message, 0, record.Level >= slog.LevelInfo, colors))
	}

	attrs := make(map[string]slog.Value, len(h.attrs)+record.NumAttrs())
	for _, attr := range h.attrs {
		attrs[attr.key] = attr.value
	}
	record.Attrs(func(attr slog.Attr) bool {
		appendConsoleAttrs(attrs, h.groups, attr)
		return true
	})
	writeConsoleAttrs(&line, attrs, colors)
	line.WriteByte('\n')

	// A logger is shared by scanners running concurrently. Keep each record in
	// one critical section so writers without their own synchronization remain
	// safe and individual lines cannot interleave.
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	_, err := h.state.writer.Write(line.Bytes())
	return err
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := h.clone()
	flattened := make(map[string]slog.Value, len(attrs))
	for _, attr := range attrs {
		appendConsoleAttrs(flattened, clone.groups, attr)
	}
	keys := sortedAttrKeys(flattened)
	for _, key := range keys {
		clone.attrs = append(clone.attrs, consoleAttr{key: key, value: flattened[key]})
	}
	return clone
}

func (h *consoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := h.clone()
	clone.groups = append(clone.groups, name)
	return clone
}

func (h *consoleHandler) clone() *consoleHandler {
	clone := *h
	clone.attrs = append([]consoleAttr(nil), h.attrs...)
	clone.groups = append([]string(nil), h.groups...)
	return &clone
}

func appendConsoleAttrs(dst map[string]slog.Value, groups []string, attr slog.Attr) {
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		nestedGroups := groups
		if attr.Key != "" {
			nestedGroups = append(append([]string(nil), groups...), attr.Key)
		}
		for _, nested := range value.Group() {
			appendConsoleAttrs(dst, nestedGroups, nested)
		}
		return
	}
	if attr.Equal(slog.Attr{}) {
		return
	}

	keyParts := make([]string, 0, len(groups)+1)
	keyParts = append(keyParts, groups...)
	if attr.Key != "" {
		keyParts = append(keyParts, attr.Key)
	}
	if len(keyParts) == 0 {
		return
	}
	dst[strings.Join(keyParts, ".")] = value
}

func writeConsoleAttrs(line *bytes.Buffer, attrs map[string]slog.Value, colors bool) {
	for _, key := range sortedAttrKeys(attrs) {
		line.WriteByte(' ')
		line.WriteString(colorize(key+"=", ansiCyan, false, colors))
		value := formatValue(attrs[key])
		if key == "error" {
			line.WriteString(colorize(value, ansiRed, true, colors))
		} else {
			line.WriteString(value)
		}
	}
}

func sortedAttrKeys(attrs map[string]slog.Value) []string {
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 1 {
		for i, key := range keys {
			if key == "error" {
				copy(keys[1:i+1], keys[:i])
				keys[0] = key
				break
			}
		}
	}
	return keys
}

func formatValue(value slog.Value) string {
	value = value.Resolve()
	switch value.Kind() {
	case slog.KindString:
		return quoteValue(value.String())
	case slog.KindBool:
		return strconv.FormatBool(value.Bool())
	case slog.KindInt64:
		return strconv.FormatInt(value.Int64(), 10)
	case slog.KindUint64:
		return strconv.FormatUint(value.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.FormatFloat(value.Float64(), 'g', -1, 64)
	case slog.KindDuration:
		return value.Duration().String()
	case slog.KindTime:
		return value.Time().Format(time.RFC3339Nano)
	case slog.KindAny:
		return formatAny(value.Any())
	default:
		return quoteValue(value.String())
	}
}

func formatAny(value any) string {
	if value == nil {
		return "null"
	}
	if err, ok := value.(error); ok {
		return quoteValue(err.Error())
	}
	if stringer, ok := value.(fmt.Stringer); ok {
		return quoteValue(stringer.String())
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return quoteValue(fmt.Sprint(value))
	}
	return string(encoded)
}

func quoteValue(value string) string {
	for i := range len(value) {
		char := value[i]
		if char < 0x20 || char > 0x7e || char == ' ' || char == '\\' || char == '"' {
			return strconv.Quote(value)
		}
	}
	return value
}

func shortLevel(level slog.Level) string {
	switch {
	case level < slog.LevelDebug:
		return "TRC"
	case level < slog.LevelInfo:
		return "DBG"
	case level < slog.LevelWarn:
		return "INF"
	case level < slog.LevelError:
		return "WRN"
	case level < LevelFatal:
		return "ERR"
	default:
		return "FTL"
	}
}

func levelColor(level slog.Level) int {
	switch {
	case level < slog.LevelDebug:
		return ansiBlue
	case level < slog.LevelInfo:
		return 0
	case level < slog.LevelWarn:
		return ansiGreen
	case level < slog.LevelError:
		return ansiYellow
	default:
		return ansiRed
	}
}

func colorize(value string, color int, bold, enabled bool) string {
	if !enabled || (!bold && color == 0) {
		return value
	}
	var codes string
	if bold {
		codes = "1"
	}
	if color != 0 {
		if codes != "" {
			codes += ";"
		}
		codes += strconv.Itoa(color)
	}
	return "\x1b[" + codes + "m" + value + "\x1b[0m"
}
