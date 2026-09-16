package sources_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/github"
	"github.com/betterleaks/betterleaks/v2/sources/gitlab"
	"github.com/betterleaks/betterleaks/v2/sources/huggingface"
	"github.com/stretchr/testify/require"
)

func TestProviderTargetLogRedaction(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Exercise startup diagnostics without making external requests.
	for _, provider := range []string{"github", "gitlab", "huggingface"} {
		t.Run(provider, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			var source sources.Source
			switch provider {
			case "github":
				source = &github.Source{URL: "https://user:fixture-password@github.com/owner/repo/issues/1?description=with spaces&token=fixture-query#fixture-fragment", Token: "fixture-auth", Logger: logger}
			case "gitlab":
				source = &gitlab.Source{URL: "https://user:fixture-password@gitlab.com/group/repo/-/issues/1?description=with spaces&token=fixture-query#fixture-fragment", Token: "fixture-auth", Logger: logger}
			case "huggingface":
				source = &huggingface.Source{URL: "https://user:fixture-password@huggingface.co/owner?description=with spaces&token=fixture-query#fixture-fragment", Token: "fixture-auth", Logger: logger}
			}
			require.Error(t, source.Fragments(ctx, func(sources.Fragment, error) error { return nil }))
			require.Contains(t, logs.String(), "starting")
			for _, secret := range []string{"fixture-password", "fixture-query", "fixture-fragment", "fixture-auth"} {
				require.NotContains(t, logs.String(), secret)
			}
		})
	}
}
