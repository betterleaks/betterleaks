# Betterleaks

Betterleaks is a secrets scanner that supports many sources. It's fast, easy to use, and highly configurable. Betterleaks builds on the legacy of Gitleaks, it just does secrets scanner _better_.

```
➜  ~/code(master) betterleaks git -v


  ○
  ○
  ●
  ○  betterleaks v0.0.0

```

Note: if you're looking for the true drop-in replacement for Gitleaks, check out [this branch](https://github.com/betterleaks/betterleaks/tree/gitleaks-v8.x.x-compat).

## Pre-receive hook

Use `betterleaks git --pre-receive` as a server-side [Git pre-receive
hook](https://git-scm.com/docs/githooks#pre-receive). It reads ref updates from
stdin, scans commits introduced by those updates, and exits non-zero to reject
a push when leaks are found.

- Updated refs scan the `<old>..<new>` range, including commits already
  reachable from another ref.
- New refs exclude history already reachable in the repository.
- Annotated tags are peeled to commits; tags on blobs or trees are skipped.
- Deleted refs contribute nothing, so deletion-only pushes are allowed.
- Object lookup failures reject the push rather than allowing an unscanned update.

`--pre-receive` cannot be combined with `--pre-commit`, `--staged`, or
`--log-opts`.

Install an executable `hooks/pre-receive` in the server repository:

```sh
#!/bin/sh
exec betterleaks git --pre-receive --no-banner \
	--pre-receive-error-message "Push rejected on ${CI_PROJECT}: secrets detected. Contact ${SECURITY_TEAM}."
```

The optional error message is printed to stderr only when leaks are found.
`$VAR` and `${VAR}` references are expanded from the hook environment.
