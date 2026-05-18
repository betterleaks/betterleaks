You are working on the Betterleaks project.
This file has a few guidelines to make ensure a consistent style and shape to the code.

General information:
- Betterleaks is a secrets scanner
- CEL is used for validation and filtering logic
- Sources yield fragments, the detector scans fragments and returns a stream of findings.
- CLI options + config determine scanning behavior.
- Prefer simple solutions over clever ones even at the expense of more LOCs.

If you're adding a new source:
- Keep the source to a single file in `sources`.
- Prefix resources used _in the new source_ file as {NewSource}ResourceWhatever
- No magic strings
- Set fragment Attributes as needed
- Call SkipFunc to prevent unecessary and expensive operations

If you're adding a new rule:
- Look at examples like https://github.com/betterleaks/betterleaks/blob/296fee33358904c47d094fa6716347b223b2c13f/config/betterleaks.toml#L2771-L2803.
- New rules should have a `validate` field.
- Do not commit real keys used for testing.
- Do not directly modify `../config/betterleaks.toml`. Instead, create a rule generator. See examples in `../cmd/generate/config/rules/github.go`
