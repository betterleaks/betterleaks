package github_test

import (
	"fmt"

	"github.com/betterleaks/betterleaks/v2/sources/github"
)

func ExampleSource() {
	src := &github.Source{
		URL:       "https://github.com/example/project",
		Resources: github.ResourceSet{github.ResourceTypeRepos: true},
	}
	// Pass src to detector.Scan(ctx, src, handler) to scan the repository.
	fmt.Println(src.URL)
	fmt.Println(github.AttrOwner, github.ResourceRepo)
	// Output:
	// https://github.com/example/project
	// github.owner github.repository
}
