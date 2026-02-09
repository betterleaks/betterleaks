package file

import "github.com/betterleaks/betterleaks"

const Content betterleaks.ResourceKind = "file_content"

func init() {
	betterleaks.RegisterResourceKind(betterleaks.ResourceKindInfo{
		Kind:         Content,
		IdentityKeys: []string{betterleaks.MetaPath},
		Source:       "file",
	})
}
