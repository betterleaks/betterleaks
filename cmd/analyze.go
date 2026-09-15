package cmd

type AnalyzeCmd struct {
	CredentialFlags `embed:""`
}

func (*AnalyzeCmd) Help() string {
	return "Validates a known credential, then resolves its identity and permissions when valid. The rule must define analysis; use config show ids --analysis to see supported rules. When the secret is omitted, it is read from piped or redirected stdin. Supply multipart credential components explicitly with --component."
}

func (cmd *AnalyzeCmd) Run(cli *CLI, runtime *commandRuntime) error {
	return runCredential(runtime, &cli.GlobalFlags, &cmd.CredentialFlags, credentialAnalysis)
}
