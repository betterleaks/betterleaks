package cmd

type RevokeCmd struct {
	CredentialFlags `embed:""`
}

func (*RevokeCmd) Help() string {
	return "Runs the rule's revoke expression to invalidate a known credential. Revocation may make multiple provider requests and only runs through this command, never during scans, validation, or analysis. Use config show ids --revocation to find supported rules. When the secret is omitted, it is read from piped or redirected stdin. Supply multipart credential components explicitly with --component."
}

func (cmd *RevokeCmd) Run(cli *CLI, runtime *commandRuntime) error {
	return runCredential(runtime, &cli.GlobalFlags, &cmd.CredentialFlags, credentialRevocation)
}
