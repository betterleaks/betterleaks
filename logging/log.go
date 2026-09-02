package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

const (
	// LevelTrace is lower than slog.LevelDebug so verbose tracing remains
	// separately selectable.
	LevelTrace = slog.LevelDebug - 4
	// LevelFatal is higher than slog.LevelError so --log-level=fatal continues
	// to suppress non-fatal errors.
	LevelFatal = slog.LevelError + 4
)

func Trace(msg string, args ...any) {
	slog.Default().Log(context.Background(), LevelTrace, msg, args...)
}

func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}

func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

func Error(msg string, args ...any) {
	slog.Error(msg, args...)
}

// Fatal logs an error and terminates the process. It is intended for command
// entry points; reusable packages should return errors instead.
func Fatal(msg string, args ...any) {
	slog.Default().Log(context.Background(), LevelFatal, msg, args...)
	os.Exit(1)
}

// Panic logs an error and then panics with msg.
func Panic(msg string, args ...any) {
	slog.Error(msg, args...)
	panic(fmt.Sprint(msg))
}
