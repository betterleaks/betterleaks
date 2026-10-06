package cmd

type AnalyzeCmd struct {
	CredentialFlags `embed:""`
}

func (*AnalyzeCmd) Help() string {
	return `Checks whether a credential is valid, then reports available identity, permissions, capabilities, and derived severity.

Use --rule <rule-id> or --rule=<rule-id> to select the credential type.
When the secret is omitted, it is read from piped or redirected stdin.

Analysis runs only after successful validation.
List supported rules with betterleaks config show ids --analysis.
Supply multipart credential components with --component rule-id=secret and required captures with --capture name=value.`
}

func (cmd *AnalyzeCmd) Run(cli *CLI, runtime *commandRuntime) error {
	return runCredential(runtime, &cli.GlobalFlags, &cmd.CredentialFlags, credentialAnalysis)
}
