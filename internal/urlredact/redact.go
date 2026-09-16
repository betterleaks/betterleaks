// Package urlredact removes sensitive URL components from diagnostics and attributes.
package urlredact

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Public removes credentials and non-path components from a URL attribute.
func Public(u *url.URL) string {
	public := *u
	public.User = nil
	public.RawQuery = ""
	public.ForceQuery = false
	public.Fragment = ""
	public.RawFragment = ""
	return public.String()
}

// PublicString sanitizes a complete target URL, including unescaped query spaces.
func PublicString(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	return Public(u)
}

var urls = regexp.MustCompile(`(?i)\b(?:https?|s3|hf)://[^\s<>]+`)

// Redact removes userinfo, queries, and fragments from URLs in diagnostic text.
// It also handles malformed URLs in parser errors and subprocess output.
func Redact(text string) string {
	return urls.ReplaceAllStringFunc(text, func(raw string) string {
		// Quotes and punctuation often surround URLs in subprocess errors.
		trimmed := strings.TrimRight(raw, "\"'),.;:")
		suffix := raw[len(trimmed):]
		raw = trimmed
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			raw = raw[:i]
		}
		start := strings.Index(raw, "://") + 3
		end := len(raw)
		if i := strings.IndexByte(raw[start:], '/'); i >= 0 {
			end = start + i
		}
		if i := strings.LastIndexByte(raw[start:end], '@'); i >= 0 {
			raw = raw[:start] + "***@" + raw[start+i+1:]
		}
		return raw + suffix
	})
}

// Error sanitizes error text while preserving errors.Is/errors.As behavior.
func Error(err error) error {
	if err == nil {
		return nil
	}
	return redactedError{err}
}

type redactedError struct{ err error }

func (e redactedError) Error() string {
	text := e.err.Error()
	var requestErr *url.Error
	if errors.As(e.err, &requestErr) && requestErr.URL != "" {
		public := PublicString(requestErr.URL)
		text = strings.ReplaceAll(text, strconv.Quote(requestErr.URL), strconv.Quote(public))
		text = strings.ReplaceAll(text, requestErr.URL, public)
	}
	return Redact(text)
}
func (e redactedError) Unwrap() error { return e.err }
