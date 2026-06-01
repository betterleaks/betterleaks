package celenv

import (
	"strconv"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func timeBindings() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("time.nowUnix",
			cel.Overload("time_now_unix_camel",
				[]*cel.Type{},
				cel.StringType,
				cel.FunctionBinding(timeNowUnixBinding()),
			),
		),
		// Deprecated: use time.nowUnix.
		cel.Function("time.now_unix",
			cel.Overload("time_now_unix",
				[]*cel.Type{},
				cel.StringType,
				cel.FunctionBinding(timeNowUnixBinding()),
			),
		),
	}
}

func timeNowUnixBinding() functions.FunctionOp {
	return func(args ...ref.Val) ref.Val {
		return types.String(strconv.FormatInt(time.Now().Unix(), 10))
	}
}
