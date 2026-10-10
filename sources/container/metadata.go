package container

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/betterleaks/betterleaks/v2/sources"
)

// Preserve JSON for rules matching structured credentials. When escaping occurs,
// also scan JSON-pointer=value records with decoded strings, so escaped and
// multiline credentials are visible without losing multipart field context.
func (r *session) metadata(ctx context.Context, raw []byte, location, resource string, attrs map[string]string) error {
	if len(raw) > maxMetadataSize {
		return fmt.Errorf("metadata exceeds %d MiB limit", maxMetadataSize>>20)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing data in container JSON metadata")
	}
	a := maps.Clone(attrs)
	if a == nil {
		a = make(map[string]string)
	}
	a[sources.AttrResource], a[sources.AttrPath] = resource, location
	a[AttrRepresentation] = "json"
	s := sources.Reader{Content: bytes.NewReader(raw), Attributes: a, Prefilter: r.s.Prefilter}
	if err := s.Fragments(ctx, r.yield); err != nil {
		return err
	}
	if !bytes.ContainsRune(raw, '\\') {
		return nil
	}
	text, err := decodedMetadata(ctx, value)
	if err != nil {
		return err
	}
	a = maps.Clone(a)
	a[sources.AttrPath], a[AttrRepresentation] = location+"#decoded", "decoded"
	s = sources.Reader{Content: strings.NewReader(text), Attributes: a, Prefilter: r.s.Prefilter}
	return s.Fragments(ctx, r.yield)
}

// decodedMetadata bounds the representation, not just its JSON input. Keep
// pointer segments separately: concatenating every ancestor at each level can
// allocate quadratic memory even before the first leaf is emitted.
func decodedMetadata(ctx context.Context, value any) (string, error) {
	var text strings.Builder
	write := func(value string) error {
		if len(value) > maxMetadataSize-text.Len() {
			return fmt.Errorf("decoded metadata exceeds %d MiB limit", maxMetadataSize>>20)
		}
		text.WriteString(value)
		return nil
	}
	var render func(any, []string) error
	render = func(value any, pointer []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch v := value.(type) {
		case map[string]any:
			for _, k := range slices.Sorted(maps.Keys(v)) {
				segment := strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
				if err := render(v[k], append(pointer, segment)); err != nil {
					return err
				}
			}
		case []any:
			for i, item := range v {
				if err := render(item, append(pointer, strconv.Itoa(i))); err != nil {
					return err
				}
			}
		default:
			for _, segment := range pointer {
				if err := write("/"); err != nil {
					return err
				}
				if err := write(segment); err != nil {
					return err
				}
			}
			if err := write("="); err != nil {
				return err
			}
			if v != nil {
				if err := write(fmt.Sprint(v)); err != nil {
					return err
				}
			}
			if err := write("\n"); err != nil {
				return err
			}
		}
		return nil
	}
	if err := render(value, nil); err != nil {
		return "", err
	}
	return text.String(), nil
}
