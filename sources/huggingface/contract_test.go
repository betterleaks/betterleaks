package huggingface_test

import (
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/huggingface"
)

var _ sources.Source = (*huggingface.Source)(nil)
