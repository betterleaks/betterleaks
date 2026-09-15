package scan

import (
	"sync"

	"github.com/betterleaks/betterleaks/v2/internal/exprruntime"
)

// lazyFilter belongs to one immutable rule. After the first compilation, the
// hot path needs neither a cache-key lookup nor a shared mutex. Errors are also
// memoized so malformed filters are not recompiled for every candidate.
type lazyFilter struct {
	once    sync.Once
	program exprruntime.Program
	err     error
}

func (f *lazyFilter) compile(runtime *exprruntime.LocalRuntime, expression string) (exprruntime.Program, error) {
	f.once.Do(func() { f.program, f.err = runtime.CompileFilter(expression, nil) })
	return f.program, f.err
}
