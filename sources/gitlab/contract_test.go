package gitlab_test

import (
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/gitlab"
)

var _ sources.Source = (*gitlab.Source)(nil)
