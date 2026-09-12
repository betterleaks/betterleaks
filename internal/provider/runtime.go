package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
)

// RuntimeOptions configures provider execution for scans and direct checks.
type RuntimeOptions struct {
	Debug                   bool
	Timeout                 time.Duration
	MaxRequestsPerTarget    int
	RequestsPerSecond       float64
	RequestsPerSecondByRule map[string]float64
	EnvVars                 []string
}

// NewRuntime validates options and creates an independent request budget.
func NewRuntime(options RuntimeOptions) (*exprruntime.Runtime, error) {
	runtime, err := exprruntime.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create provider runtime: %w", err)
	}
	if err := ConfigureRuntime(runtime, options); err != nil {
		return nil, err
	}
	return runtime, nil
}

// ConfigureRuntime applies provider options before a runtime is used.
func ConfigureRuntime(runtime *exprruntime.Runtime, options RuntimeOptions) error {
	if options.Timeout < 0 {
		return errors.New("provider timeout must be non-negative")
	}
	runtime.AllowedEnv = exprruntime.ParseValidationEnvAllowlist(options.EnvVars)
	if options.Timeout > 0 {
		runtime.SetHTTPClient(&http.Client{Timeout: options.Timeout})
	}
	if err := runtime.SetValidationRequestLimits(exprruntime.ValidationRequestLimits{
		MaxRequestsPerTarget:    options.MaxRequestsPerTarget,
		RequestsPerSecond:       options.RequestsPerSecond,
		RequestsPerSecondByRule: options.RequestsPerSecondByRule,
	}); err != nil {
		return fmt.Errorf("invalid provider request limits: %w", err)
	}
	return nil
}

// NewConfiguredPool creates workers with their own runtime and request limits.
func NewConfiguredPool(ctx context.Context, workers int, options RuntimeOptions) (*Pool, error) {
	runtime, err := NewRuntime(options)
	if err != nil {
		return nil, err
	}
	pool := NewPoolContext(ctx, workers, runtime)
	pool.Debug = options.Debug
	return pool, nil
}
