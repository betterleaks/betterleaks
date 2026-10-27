package gogit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRepositoryConfigMergeValues(t *testing.T) {
	raw := `[core]
	repositoryformatversion = 0
[url "https://github.com/"]
	insteadOf = gh:
[remote "review"]
	url = gh:example/review
	fetch = +refs/pull/*/head:refs/remotes/review/*
[branch "topic"]
	remote = review
	merge = refs/heads/main
	MeRgE = refs/pull/83/head
	rebase = interactive
	description = "review\nwith \"quotes\" and \\backslashes"
[branch "ordinary"]
	merge = refs/heads/main
[custom]
	value = "a # comment; tab\tand newline\n"
`
	cfg, err := parseRepositoryConfig(raw)
	require.NoError(t, err)
	branch := cfg.Branches["topic"]
	require.Equal(t, "review", branch.Remote)
	require.Equal(t, "refs/pull/83/head", branch.Merge.String())
	require.Equal(t, "interactive", branch.Rebase)
	require.Equal(t, "review\nwith \"quotes\" and \\backslashes", branch.Description)
	require.Equal(t, []string{"refs/heads/main", "refs/pull/83/head"}, cfg.Raw.Section("branch").Subsection("topic").Options.GetAll("merge"))
	require.Equal(t, "refs/heads/main", cfg.Branches["ordinary"].Merge.String())
	require.Equal(t, []string{"https://github.com/example/review"}, cfg.Remotes["review"].URLs)
	require.Equal(t, "+refs/pull/*/head:refs/remotes/review/*", cfg.Remotes["review"].Fetch[0].String())
	require.Equal(t, "a # comment; tab\tand newline\n", cfg.Raw.Section("custom").Option("value"))
}

func TestRepositoryConfigMergeDoesNotHideErrors(t *testing.T) {
	for name, extra := range map[string]string{
		"syntax":        "[unterminated\n",
		"branch name":   "[branch \"bad..name\"]\nremote = origin\n",
		"rebase":        "[branch \"topic\"]\nrebase = invalid\n",
		"pack window":   "[pack]\nwindow = invalid\n",
		"protocol":      "[protocol]\nversion = 3\n",
		"fetch refspec": "[remote \"origin\"]\nfetch = refs/heads/*:refs/remotes/origin/main\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseRepositoryConfig("[branch \"topic\"]\nmerge = refs/pull/83/head\n" + extra)
			require.Error(t, err)
		})
	}
	cfg, err := parseRepositoryConfig("[branch \"topic\"]\nmerge = refs/pull/83/head\n[extensions]\nunknown = true\n")
	require.NoError(t, err)
	require.ErrorContains(t, checkExtensions(cfg), "unknown extension")
}

func TestRepositoryURLRewrites(t *testing.T) {
	for _, tc := range []struct{ name, rules, want string }{
		{"multiple", "[url \"https://github.com/\"]\ninsteadOf = short:\ninsteadOf = another:\n", "https://github.com/example/project"},
		{"tie", "[url \"https://github.com/\"]\ninsteadOf = short:\n[url \"https://gitlab.com/\"]\ninsteadOf = short:\n", "https://github.com/example/project"},
		{"longest", "[url \"https://github.com/\"]\ninsteadOf = short:\n[url \"https://gitlab.com/group/\"]\ninsteadOf = short:example/\n", "https://gitlab.com/group/project"},
		{"empty", "[url \"https://github.com/\"]\ninsteadOf = \n", "short:example/project"},
		{"push only", "[url \"https://github.com/\"]\npushInsteadOf = short:\n", "short:example/project"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, merge := range []string{"refs/heads/main", "refs/pull/83/head"} {
				cfg, err := parseRepositoryConfig("[branch \"topic\"]\nmerge = " + merge + "\n[remote \"origin\"]\nurl = short:example/project\n" + tc.rules)
				require.NoError(t, err)
				require.Equal(t, []string{tc.want}, cfg.Remotes["origin"].URLs)
			}
		})
	}
}

func TestRepositoryExistingBranchNames(t *testing.T) {
	for _, name := range []string{"@", "-existing", "topic/@/child"} {
		cfg, err := parseRepositoryConfig("[branch \"" + name + "\"]\nremote = origin\nmerge = refs/heads/main\n")
		require.NoError(t, err, name)
		require.Equal(t, "origin", cfg.Branches[name].Remote)
	}
}

func TestRepositoryConfigSectionIdentity(t *testing.T) {
	cfg, err := parseRepositoryConfig(`[Branch "Topic"]
remote = wrong
[branch "topic"]
remote = lower
[BRANCH "Topic"]
remote = upper
merge = refs/pull/83/head
[remote "upper"]
url = https://github.com/example/upper
[REMOTE "lower"]
url = https://github.com/example/lower
[include]
path = /must/not/be/read
`)
	require.NoError(t, err)
	require.Len(t, cfg.Branches, 2)
	require.Equal(t, "upper", cfg.Branches["Topic"].Remote)
	require.Equal(t, "lower", cfg.Branches["topic"].Remote)
	require.Len(t, cfg.Remotes, 2)
	require.Equal(t, []string{"https://github.com/example/upper"}, cfg.Remotes["upper"].URLs)
	require.Equal(t, []string{"wrong", "upper"}, cfg.Raw.Section("branch").Subsection("Topic").Options.GetAll("remote"))
}

func FuzzRepositoryConfig(f *testing.F) {
	for _, raw := range []string{
		"",
		"[core]\nrepositoryformatversion = 1\n[extensions]\nobjectformat = sha256\n",
		"[branch \"topic\"]\nremote = review\nmerge = refs/pull/83/head\n",
		"[Branch \"Topic\"]\nremote = a\n[branch \"Topic\"]\nremote = b\n",
		"[url \"https://github.com/\"]\ninsteadOf = gh:\n[remote \"origin\"]\nurl = gh:example/repo\n",
		"[unterminated\n",
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 65536 {
			t.Skip()
		}
		cfg, err := parseRepositoryConfig(raw)
		if err == nil {
			require.NotNil(t, cfg.Raw)
			_ = checkExtensions(cfg)
		}
	})
}
