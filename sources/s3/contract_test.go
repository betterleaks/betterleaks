package s3_test

import (
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/s3"
)

var _ sources.Source = (*s3.Source)(nil)
