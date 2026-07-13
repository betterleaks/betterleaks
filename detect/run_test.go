package detect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
)

type fragmentsSource func(context.Context, sources.FragmentsFunc) error

func (s fragmentsSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	return s(ctx, yield)
}

func runFindings(t *testing.T, workers int, source sources.Source) []report.Finding {
	t.Helper()
	d := NewDetector(loadTestConfig(t, "simple"))
	d.FragmentWorkers = workers
	var findings []report.Finding
	for result := range d.Run(t.Context(), source) {
		require.NoError(t, result.Err)
		findings = append(findings, result.Finding)
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].File < findings[j].File })
	return findings
}

func TestRunFragmentWorkers(t *testing.T) {
	makeSource := func() sources.Source {
		return fragmentsSource(func(ctx context.Context, yield sources.FragmentsFunc) error {
			attrs := map[string]string{}
			for i := range 100 {
				attrs[sources.AttrPath] = fmt.Sprintf("%03d", i)
				if err := yield(sources.Fragment{Raw: "AKIAIOSFODNN7EXAMPLE", Attributes: attrs}, nil); err != nil {
					return err
				}
			}
			return nil
		})
	}

	one := runFindings(t, 1, makeSource())
	ten := runFindings(t, 10, makeSource())
	require.Len(t, one, 100)
	require.Equal(t, one, ten)
}

func TestRunFragmentWorkersSourceErrorAndCancellation(t *testing.T) {
	t.Run("source error", func(t *testing.T) {
		want := errors.New("source failed")
		d := NewDetector(loadTestConfig(t, "simple"))
		for result := range d.Run(t.Context(), fragmentsSource(func(ctx context.Context, yield sources.FragmentsFunc) error {
			return yield(sources.Fragment{}, want)
		})) {
			require.ErrorIs(t, result.Err, want)
		}
	})

	t.Run("consumer cancellation", func(t *testing.T) {
		done := make(chan struct{})
		d := NewDetector(loadTestConfig(t, "simple"))
		for range d.Run(t.Context(), fragmentsSource(func(ctx context.Context, yield sources.FragmentsFunc) error {
			defer close(done)
			for {
				if err := yield(sources.Fragment{Raw: "AKIAIOSFODNN7EXAMPLE"}, nil); err != nil {
					return err
				}
			}
		})) {
			break
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("source did not stop after consumer cancellation")
		}
	})
}

func TestRunFragmentWorkersValidation(t *testing.T) {
	cfg := loadTestConfig(t, "simple")
	rule := cfg.Rules["aws-access-key"]
	rule.ValidateExpr = `{"result": "valid"}`
	cfg.Rules[rule.RuleID] = rule
	d := NewDetectorContext(t.Context(), cfg, ValidationOptions{Enabled: true, Workers: 2})
	d.FragmentWorkers = 10

	findings := 0
	for result := range d.Run(t.Context(), fragmentsSource(func(ctx context.Context, yield sources.FragmentsFunc) error {
		for range 20 {
			if err := yield(sources.Fragment{Raw: "AKIAIOSFODNN7EXAMPLE"}, nil); err != nil {
				return err
			}
		}
		return nil
	})) {
		require.NoError(t, result.Err)
		require.Equal(t, report.ValidationStatusValid, result.Finding.ValidationStatus)
		findings++
	}
	require.Equal(t, 20, findings)
}
