package exprruntime

import (
	"strconv"
	"time"
)

func timeNamespace() map[string]any {
	return map[string]any{
		"nowUnix":    timeNowUnix,
		"now_unix":   timeNowUnix,
		"nowRFC3339": timeNowRFC3339,
	}
}

func timeNowUnix() string { return strconv.FormatInt(time.Now().Unix(), 10) }

func timeNowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }
