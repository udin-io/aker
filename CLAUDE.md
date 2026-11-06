# ex_licence

A public Hex library. Every file, commit message, issue and PR here is public.

- No private key, no real root key and no customer data ever goes in. Tests
  make their keys during the run; no key file is checked in.
- No path from a developer's machine (home folders, temporary folders,
  worktrees), no machine name and no email address. `bin/hygiene` fails on
  these, and `bin/ci` runs it.
- `lib/` names no product. An app passes its product name, its version and the
  root public keys it trusts.
- `bin/ci` runs every CI step. Run it before every push.
- The TPM tests need `swtpm` and `tpm2-tools`: `mix test --only tpm`. CI's
  `tpm` job runs them.
