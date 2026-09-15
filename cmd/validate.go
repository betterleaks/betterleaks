package cmd

type ValidateCmd struct {
	CredentialFlags `embed:""`
}

func (*ValidateCmd) Help() string {
	return "Checks credential liveness. Use analyze to also resolve identity and permissions. When the secret is omitted, it is read from piped or redirected stdin. Supply multipart credential components explicitly with --component."
}

func (cmd *ValidateCmd) Run(cli *CLI, runtime *commandRuntime) error {
	return runCredential(runtime, &cli.GlobalFlags, &cmd.CredentialFlags, false)
}
