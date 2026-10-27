//nolint:exhaustruct // Object fields are populated incrementally by the decoders.
package gitobj

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

type Commit struct {
	Hash, TreeHash    Hash
	ParentHashes      []Hash
	Author, Committer object.Signature
	Message           string
}
type Tag struct {
	Hash, Target  Hash
	TargetType    ObjectType
	Name, Message string
	Tagger        object.Signature
}
type TreeEntry struct {
	Name string
	Mode filemode.FileMode
	Hash Hash
}
type Tree struct {
	Hash    Hash
	Entries []TreeEntry
	store   ObjectReader
}
type ChangeEntry struct {
	Name      string
	Tree      *Tree
	TreeEntry TreeEntry
}
type Change struct{ From, To ChangeEntry }
type Changes []*Change

// Raw text is already immutable in the scanner's object cache. Avoid copying
// whole objects when decoding trees and metadata.
func objectText(o EncodedObject) (string, error) {
	if o, ok := o.(interface{ Text() string }); ok {
		return o.Text(), nil
	}
	r, err := o.Reader()
	if err != nil {
		return "", err
	}
	defer r.Close()
	var b strings.Builder
	_, err = io.Copy(&b, r)
	return b.String(), err
}

func parseID(s string, size int) (Hash, error) {
	if len(s) != size*2 || !IsHash(s) {
		return Hash{}, errors.New("malformed Git object ID")
	}
	return NewHash(s), nil
}

func DecodeCommit(_ ObjectReader, o EncodedObject) (*Commit, error) {
	if o.Type() != CommitObject {
		return nil, ErrObjectNotFound
	}
	raw, err := objectText(o)
	if err != nil {
		return nil, err
	}
	c := &Commit{Hash: o.Hash()}
	header, message, _ := strings.Cut(raw, "\n\n")
	c.Message = message
	state := 0
	for line := range strings.SplitSeq(header, "\n") {
		key, value, _ := strings.Cut(line, " ")
		if state == 0 {
			if key != "tree" {
				return nil, errors.New("malformed Git commit: tree header must be first")
			}
			c.TreeHash, err = parseID(value, c.Hash.Size())
			if err != nil {
				return nil, err
			}
			state = 1
			continue
		}
		if state == 1 {
			if key == "parent" {
				id, err := parseID(value, c.Hash.Size())
				if err != nil {
					return nil, err
				}
				c.ParentHashes = append(c.ParentHashes, id)
				continue
			}
			state = 2
		}
		if state == 2 {
			state = 3
			if key == "author" {
				c.Author.Decode([]byte(value))
				continue
			}
		}
		if state == 3 {
			state = 4
			if key == "committer" {
				c.Committer.Decode([]byte(value))
			}
		}
	}
	return c, nil
}

func DecodeTag(_ ObjectReader, o EncodedObject) (*Tag, error) {
	if o.Type() != TagObject {
		return nil, ErrObjectNotFound
	}
	raw, err := objectText(o)
	if err != nil {
		return nil, err
	}
	t := &Tag{Hash: o.Hash()}
	header, message, _ := strings.Cut(raw, "\n\n")
	t.Message = message
	state := 0
	for line := range strings.SplitSeq(header, "\n") {
		key, value, _ := strings.Cut(line, " ")
		switch state {
		case 0:
			if key != "object" {
				return nil, errors.New("malformed Git tag: object header must be first")
			}
			t.Target, err = parseID(value, t.Hash.Size())
		case 1:
			if key != "type" {
				return nil, errors.New("malformed Git tag: type header must follow object")
			}
			t.TargetType, err = parseType(value)
		case 2:
			if key != "tag" {
				return nil, errors.New("malformed Git tag: tag header must follow type")
			}
			t.Name = value
		case 3:
			if key == "tagger" {
				t.Tagger.Decode([]byte(value))
			}
		}
		if err != nil {
			return nil, err
		}
		state++
	}
	if state < 3 {
		return nil, errors.New("malformed Git tag: missing header")
	}
	// Like go-git, a trailing armored signature is metadata, not tag text.
	last := -1
	for pos := 0; pos < len(message); {
		line, _, _ := strings.Cut(message[pos:], "\n")
		for _, marker := range []string{"-----BEGIN PGP SIGNATURE-----", "-----BEGIN PGP MESSAGE-----", "-----BEGIN SIGNED MESSAGE-----", "-----BEGIN SSH SIGNATURE-----"} {
			if strings.HasPrefix(line, marker) {
				last = pos
				break
			}
		}
		pos += len(line) + 1
	}
	if last >= 0 {
		t.Message = message[:last]
	}

	return t, nil
}

func parseType(s string) (ObjectType, error) {
	switch s {
	case "commit":
		return CommitObject, nil
	case "tree":
		return TreeObject, nil
	case "blob":
		return BlobObject, nil
	case "tag":
		return TagObject, nil
	}
	return AnyObject, fmt.Errorf("invalid Git object type %q", s)
}

func DecodeTree(store ObjectReader, o EncodedObject) (*Tree, error) {
	if o.Type() != TreeObject {
		return nil, ErrObjectNotFound
	}
	raw, err := objectText(o)
	if err != nil {
		return nil, err
	}
	t := &Tree{Hash: o.Hash(), store: store}
	for len(raw) > 0 {
		mode, rest, ok := strings.Cut(raw, " ")
		if !ok {
			return nil, errors.New("malformed Git tree mode")
		}
		name, rest, ok := strings.Cut(rest, "\x00")
		if !ok || name == "" || len(rest) < t.Hash.Size() {
			return nil, errors.New("malformed Git tree entry")
		}
		n, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return nil, err
		}
		id := FromObjectFormat(SHA1)
		id.ResetBySize(t.Hash.Size())
		id.Write([]byte(rest[:id.Size()]))
		t.Entries = append(t.Entries, TreeEntry{Name: strings.Clone(name), Mode: canonicalMode(filemode.FileMode(n)), Hash: id})
		raw = rest[id.Size():]
	}
	return t, nil
}

func (t *Tree) Encode(o EncodedObject) error {
	o.SetType(TreeObject)
	w, err := o.Writer()
	if err != nil {
		return err
	}
	defer w.Close()
	for _, e := range t.Entries {
		if _, err := fmt.Fprintf(w, "%o %s\x00", e.Mode, e.Name); err != nil {
			return err
		}
		if _, err := w.Write(e.Hash.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// Git canonicalizes historical mode bits when interpreting a tree.
func canonicalMode(mode filemode.FileMode) filemode.FileMode {
	switch mode & 0o170000 {
	case 0o040000:
		return filemode.Dir
	case 0o100000:
		if mode&0o111 != 0 {
			return filemode.Executable
		}
		return filemode.Regular
	case 0o120000:
		return filemode.Symlink
	default:
		return filemode.Submodule
	}
}
