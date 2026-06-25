package regexp

import (
	"testing"

	"github.com/betterleaks/betterleaks/regexp/internal"
)

type countingEngine struct {
	compiles int
}

func (e *countingEngine) Compile(str string) (internal.CompiledRegexp, error) {
	e.compiles++
	return Stdlib{}.Compile(str)
}

func (e *countingEngine) Version() string { return "counting" }

func TestCompileIsLazy(t *testing.T) {
	previous := currentEngine
	defer SetEngine(previous)

	engine := &countingEngine{}
	SetEngine(engine)

	re, err := Compile(`(foo)(bar)?`)
	if err != nil {
		t.Fatal(err)
	}
	if engine.compiles != 0 {
		t.Fatalf("Compile compiled regex eagerly")
	}
	if re.String() != `(foo)(bar)?` {
		t.Fatalf("String changed pattern: %q", re.String())
	}
	if re.NumSubexp() != 2 {
		t.Fatalf("NumSubexp = %d, want 2", re.NumSubexp())
	}
	if engine.compiles != 0 {
		t.Fatalf("metadata access compiled regex eagerly")
	}

	if !re.MatchString("foobar") {
		t.Fatal("MatchString returned false")
	}
	if engine.compiles != 1 {
		t.Fatalf("compiles = %d, want 1", engine.compiles)
	}
	_ = re.FindString("foobar")
	if engine.compiles != 1 {
		t.Fatalf("regex compiled more than once")
	}
}
