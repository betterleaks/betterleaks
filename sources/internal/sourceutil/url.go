package sourceutil

import "strings"

func SingleSlashJoin(left, right string) string {
	if left == "" {
		left = "/"
	}
	if !strings.HasSuffix(left, "/") {
		left += "/"
	}
	right = strings.TrimPrefix(right, "/")
	return left + right
}
