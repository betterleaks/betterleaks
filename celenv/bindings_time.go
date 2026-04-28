package celenv

import (
	"strconv"
	"time"

	"github.com/google/cel-go/common/functions"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

func timeNowUnixBinding() functions.FunctionOp {
	return func(args ...ref.Val) ref.Val {
		return types.String(strconv.FormatInt(time.Now().Unix(), 10))
	}
}
