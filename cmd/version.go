package cmd

import (
	"fmt"

	"github.com/betterleaks/betterleaks/version"
)

type VersionCmd struct{}

func (*VersionCmd) Run(runtime *commandRuntime) error {
	_, _ = fmt.Fprintln(runtime.stdout, version.Version)
	return nil
}
