# Contributing

`nlnt` is a member of the piekstra CLI family and conforms to the
`piekstra-cli/1` spec. The spec, not this repo, is the source of truth for the
command surface: see [`cli-common/DESIGN.md`](https://github.com/piekstra/cli-common/blob/main/DESIGN.md)
and `conformance.md`.

## Setup

```sh
make deps     # toolchain components (rustfmt, clippy)
make dev      # debug build, then dev-sign it (see below)
make verify   # fmt-check + lint + test + smoke — the CI gate
```

## The gate

`make verify` must be green before anything merges. It runs:

| Step | Command |
|---|---|
| `fmt-check` | `cargo fmt --all -- --check` |
| `lint` | `cargo clippy --all-targets -- -D warnings` |
| `test` | `cargo test` (offline; see below) |
| `smoke` | builds and exercises `--help`, `info`, `completions` on the real binary |

## Tests are offline. Always.

No test may contact Nelnet. This is not a performance preference:

- We have exactly one set of credentials for a **federal student-loan servicer**,
  and a test that hit the live API would spend the household's real session.
- Auth is a browser-captured OAuth bundle; MFA happens once in the browser, not
  in the CLI, so the CLI cannot spend a code or lock the account (see
  `SECURITY.md`). Tests stay offline so CI needs no keychain or network and
  never touches a real federal servicer.
- No test launches Chrome either. The `auth login --browser` tests stop at the
  flag check, before the keychain or a window, and set `NLNT_CHROME` to a path
  that does not exist so a regression fails fast instead of opening one.

So: no network in tests, no mocking library either. `tests/fixture_shapes.rs`
asserts parser behavior against committed fixtures; `tests/cli_surface.rs`
black-boxes the binary with `assert_cmd`. If you need new provider data, capture
it during a real owner session (see `docs/api.md`), scrub it, and commit the
scrubbed copy.

## Fixtures

Read `tests/fixtures/README.md` before adding one. The rules:

- Preserve **structure** exactly — keys, nesting, types, null-vs-absent. That is
  the whole value; a fixture that "looks about right" tests nothing.
- Replace every identifying or financial value with an obvious dummy.
- Never commit a raw capture. Document download URLs are frequently pre-signed
  and are live credentials.
- `fixture_shapes.rs` enforces the scrubbing policy **positively** — identity
  fields must match a known dummy shape. It is deliberately not a denylist of
  real names, because a denylist publishes exactly what it exists to keep out.

## macOS signing

`cargo install` ad-hoc signs the binary, minting a new code identity each time,
and macOS scopes keychain "Always Allow" grants to that identity — so every
reinstall silently revokes the grant and the next run re-prompts. Both `make dev`
and `make install` therefore re-sign with a stable identity.

Create the identity once:

```sh
~/Dev/cli-common/scripts/setup-dev-signing.sh
```

Verify: `codesign -dv $(which nlnt)` should show `pk-cli-codesign`, not
`Signature=adhoc`. Changing the identity invalidates the old grant, so expect
exactly one more prompt after fixing it.

## Adding a command

1. Reuse first. Grep `cli-common/crates` before writing a helper — dates,
   output/table rendering, range args, paging, auth, secrets, config and
   self-update are all already provided, and each has been re-implemented by
   accident at least once.
2. `--json` is mandatory on every command, emitting exactly one schema-tagged
   DTO on stdout. Diagnostics go to stderr.
3. Validate arguments **before** touching the keychain or the network, so
   `--help` and bad input never prompt, hang, or hit the provider.
4. Map failures onto the shared exit codes (0/2/3/4/5/6) via `CliError`.
5. Add the `--help` render to `tests/cli_surface.rs`. That test is what catches a
   subcommand flag colliding with a global like `-q`.
6. If the change touches an endpoint, update `docs/api.md` in the same commit,
   and refresh the scrubbed fixture in `tests/fixtures/` so `fixture_shapes.rs`
   still pins the real shape.

## Honesty rules for provider code

These are paid for in lost hours elsewhere in the family and apply here:

- **Never report success from a status code alone.** Portals answer `200` with
  an HTML login page when the session has expired. Require a positive
  confirmation signal — for a document download, the `%PDF` magic bytes.
- **Expiry is rarely a 401.** Treat "landed on a login URL" and "HTML where JSON
  was expected" as auth failures (exit 3).
- **Observe traffic; never infer the request from the markup.** A rendered
  `<form>` is often not what gets submitted.
- **Chase the small anomaly.** A blank field in an otherwise working response is
  usually the failure reporting itself.
