package container

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
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
	if err := ctx.Err(); err != nil {
		return err
	}
	// Validate without constructing an object graph. A compact JSON array of
	// small objects can otherwise consume many times its input size in heap.
	if !json.Valid(raw) {
		return errors.New("invalid container JSON metadata")
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
	a = maps.Clone(a)
	a[sources.AttrPath], a[AttrRepresentation] = location+"#decoded", "decoded"
	// Pipe decoded records through the normal fragment reader, retaining neither
	// a parsed tree nor a complete decoded copy. Closing the reader interrupts
	// the producer if scanning stops early; wait for it before releasing raw.
	reader, writer := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := bufio.NewWriterSize(writer, 32<<10)
		err := decodedMetadata(ctx, raw, buffer)
		if err == nil {
			err = buffer.Flush()
		}
		writer.CloseWithError(err)
	}()
	defer func() {
		reader.Close()
		<-done
	}()
	s = sources.Reader{Content: reader, Attributes: a, Prefilter: r.s.Prefilter}
	return s.Fragments(ctx, func(f sources.Fragment, err error) error {
		if err != nil {
			return err
		}
		return r.yield(f, nil)
	})
}

// decodedMetadata emits JSON-pointer=value records in document order, including
// duplicate keys. Keep pointer segments separately to avoid quadratic memory
// from concatenating every ancestor at each level. raw must be valid JSON.
func decodedMetadata(ctx context.Context, raw []byte, out io.Writer) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	written := 0
	write := func(value string) error {
		if len(value) > maxMetadataSize-written {
			return fmt.Errorf("decoded metadata exceeds %d MiB limit", maxMetadataSize>>20)
		}
		n, err := io.WriteString(out, value)
		written += n
		return err
	}
	var render func([]string) error
	render = func(pointer []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := decoder.Token()
		if err != nil {
			return err
		}
		switch value {
		case json.Delim('{'):
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				k := key.(string) // Object keys in validated JSON are strings.
				segment := strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
				if err := render(append(pointer, segment)); err != nil {
					return err
				}
			}
			_, err := decoder.Token() // Closing brace.
			return err
		case json.Delim('['):
			for i := 0; decoder.More(); i++ {
				if err := render(append(pointer, strconv.Itoa(i))); err != nil {
					return err
				}
			}
			_, err := decoder.Token() // Closing bracket.
			return err
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
			if value != nil {
				if err := write(fmt.Sprint(value)); err != nil {
					return err
				}
			}
			if err := write("\n"); err != nil {
				return err
			}
		}
		return nil
	}
	return render(nil)
}
