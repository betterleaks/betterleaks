package sources

import (
	"context"
)

// FragmentsFunc receives a fragment or a source error. When err is non-nil,
// Scanner records the error instead of scanning the fragment and may continue
// consuming the source. A non-nil return value asks the source to stop.
type FragmentsFunc func(fragment Fragment, err error) error

// PrefilterFunc evaluates source attributes before scanning content.
// It returns true to skip the input, false to keep it.
type PrefilterFunc func(attrs map[string]string) bool

// Source yields content and metadata for scanning.
type Source interface {
	// Fragments yields content until exhausted, canceled, or stopped by yield.
	// Skippable input failures, such as corrupt archives or unreadable files,
	// should be logged as warnings and skipped, rather than yielded as errors.
	// Yielded errors report unsuccessful work while allowing the source to
	// continue; the returned error reports why the source could not finish.
	//
	// A source must stop producing when yield returns an error and propagate
	// that error. It may call yield concurrently, but every call must finish
	// before Fragments returns. It must not mutate a fragment or its attributes
	// after yield accepts it.
	//
	// Yield may block. Bound readers and queues so a slow consumer stops further
	// read-ahead, including API pagination. Sources choose their own concurrency.
	Fragments(ctx context.Context, yield FragmentsFunc) error
}
