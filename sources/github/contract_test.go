package github_test

import (
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/github"
)

var _ sources.Source = (*github.Source)(nil)
