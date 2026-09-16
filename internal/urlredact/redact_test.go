package urlredact

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactDiagnostics(t *testing.T) {
	for _, text := range []string{
		`git clone https://user:password@example.com/repo.git?access_token=query-secret#fragment-secret: failed`,
		`fatal: unable to access 'https://user:password@example.com/repo.git?access_token=query-secret/': HTTP 403`,
		`Get "https://example.com/file?token=query-secret": failed`,
		`parse "https://user:pa'ssword@example.com/%zz?token=query-secret": invalid escape`,
		`hf://user:password@buckets/owner/bucket?token=query-secret#fragment-secret`,
	} {
		got := Redact(text)
		for _, secret := range []string{"password", "pa'ssword", "query-secret", "fragment-secret", "access_token="} {
			require.NotContains(t, got, secret)
		}
	}
	u, err := url.Parse("https://user:password@example.com/a%2Fb?token=query-secret#fragment-secret")
	require.NoError(t, err)
	require.Equal(t, "https://example.com/a%2Fb", Public(u))
	require.NotNil(t, u.User, "do not modify the request URL")
	require.Equal(t, "https://example.com/file", PublicString("https://user:password@example.com/file?description=with spaces&token=query-secret"))
}

func TestRedactedErrorPreservesCause(t *testing.T) {
	cause := &url.Error{Op: "Get", URL: "https://user:password@example.com/file?description=with spaces&token=query-secret", Err: context.Canceled}
	err := Error(fmt.Errorf("download failed: %w", cause))
	require.ErrorIs(t, err, context.Canceled)
	var urlErr *url.Error
	require.True(t, errors.As(err, &urlErr))
	require.Same(t, cause, urlErr)
	require.NotContains(t, err.Error(), "password")
	require.NotContains(t, err.Error(), "query-secret")
	require.Nil(t, Error(nil))
}
