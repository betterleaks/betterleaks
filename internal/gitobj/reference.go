package gitobj

import (
	"fmt"
	"io"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
)

// ValidateReferenceName validates a fully qualified ref, including existing
// names that v5 incorrectly rejects: an @ component or a leading - in a branch
// or tag. Those are accepted by Git's check-ref-format and go-git v6. Normalize
// only those components for v5's validator; keep every other naming check.
func ValidateReferenceName(name ReferenceName) error {
	parts := strings.Split(name.String(), "/")
	for n, part := range parts {
		if part == "@" {
			parts[n] = "x"
		}
		if n == 2 && (name.IsBranch() || name.IsTag()) && strings.HasPrefix(part, "-") {
			parts[n] = "x" + part
		}
	}
	if err := plumbing.ReferenceName(strings.Join(parts, "/")).Validate(); err != nil {
		return fmt.Errorf("%w: %q", err, name)
	}
	return nil
}

type Reference struct {
	name   ReferenceName
	target ReferenceName
	id     Hash
	kind   ReferenceType
}

func NewHashReference(name ReferenceName, id Hash) *Reference {
	return &Reference{name: name, id: id, kind: HashReference, target: ""}
}
func NewSymbolicReference(name, target ReferenceName) *Reference {
	return &Reference{name: name, target: target, kind: SymbolicReference, id: ZeroHash}
}
func (r *Reference) Name() ReferenceName   { return r.name }
func (r *Reference) Target() ReferenceName { return r.target }
func (r *Reference) Hash() Hash            { return r.id }
func (r *Reference) Type() ReferenceType   { return r.kind }

type ReferenceIter struct {
	refs []*Reference
	pos  int
}

func NewReferenceIter(refs []*Reference) *ReferenceIter { return &ReferenceIter{refs: refs, pos: 0} }
func (*ReferenceIter) Close()                           {}
func (i *ReferenceIter) Next() (*Reference, error) {
	if i.pos == len(i.refs) {
		return nil, io.EOF
	}
	r := i.refs[i.pos]
	i.pos++
	return r, nil
}
func ResolveReference(s interface {
	Reference(name ReferenceName) (*Reference, error)
}, name ReferenceName) (*Reference, error) {
	for range 64 {
		r, err := s.Reference(name)
		if err != nil {
			return nil, err
		}
		if r.Type() != SymbolicReference {
			return r, nil
		}
		name = r.Target()
	}
	return nil, fmt.Errorf("symbolic reference cycle at %s", name)
}
