# AGENTS.md — working on `nelnet-cli`

Canonical guide for anyone (human or agent) changing this repo.

## What this is

`nlnt`: a read-only CLI over the Nelnet federal student-loan servicing portal,
member of the piekstra CLI family, conforming to `piekstra-cli/1`. The shared
surface and libraries live in
[`cli-common`](https://github.com/piekstra/cli-common) — **read `DESIGN.md`
there before changing the command surface**; do not reconstruct the spec from
this repo's code, it drifts.

Every `pk-cli-*` crate is pinned to the same `cli-common` revision, **v0.29.0**
(see `Cargo.toml`); never mix versions. `auth login --browser` uses `pk-cli-browser`,
whose kept profile needs cli-common v0.16.0 or later and whose site-storage
clearing and `profile_exists` need v0.19.0. Renewals take `pk-cli-auth`'s
`refresh_lock`, which needs Rust 1.89.

## The single most important fact

**The endpoint map and field names are CONFIRMED-LIVE** (2026-08-12): captured
from the real federal account and replayed against `mmaapi.nelnet.studentaid.gov`.
The scrubbed responses are in `tests/fixtures/`, and `docs/api.md` records the
map, the auth flow, and the traps.

Consequences for you:

- Auth is **OAuth2 Bearer**, not a cookie. The CLI replays a browser-captured
  token bundle and refreshes it via the OAuth refresh grant. `auth login
  --browser` reads the bundle out of a Chrome window the owner signs in
  through; `auth login --stdin` / `--from-env` take the same value copied out of
  DevTools. Both go through `Session::parse_captured`, one verifying read and
  the keychain. A read that can't tell stores a session from the window, with a
  warning (`keep_finished_sign_in`), because it can't be read again, and stores
  nothing from a pipe. There is no password and no MFA in the CLI.
- The fixtures are **scrubbed real captures**: preserve structure exactly and
  replace only values (see `tests/fixtures/README.md`). A rename in a real
  response must fail `fixture_shapes.rs`, not silently empty a column.
- A parse failure naming a missing field is the *designed* behavior, not a bug
  to paper over with a default value.

## Build, test, lint

```sh
make verify   # fmt-check + lint + test + smoke — the gate. Must be green.
make dev      # debug build, dev-signed
make install  # install to ~/.cargo/bin, dev-signed
```

## Layout

| Path | Owns |
| --- | --- |
| `src/main.rs` | clap tree, `auth`/`config` commands, exit-code mapping |
| `src/lib.rs` | module wiring, `BIN`/`REPO` constants |
| `src/client.rs` | Bearer HTTP session, sentinel headers, token refresh, the auth/bot guards, `%PDF` check, **the endpoint map** |
| `src/browser.rs` | the `auth login --browser` capture: start URL, the one host it reads, the `localStorage` expression, the profile choice |
| `src/parse.rs` | responses → DTOs; all provider field knowledge |
| `src/parse/checked.rs` | the same fields for `nlnt mcp`, where an unreadable answer is an error rather than an empty list or a `0.00` |
| `src/mcp.rs` | `nlnt mcp`: five read-only tools over a `Reads` seam with `get_text` and nothing else, asking only for `&'static str` paths (`LiveSource` on the portal, fixtures in `src/mcp/tests.rs`) |
| `packaging/mcpb/manifest.json` | the Claude Desktop extension; `tests/packaging.rs` holds it to the binary |
| `src/model.rs` | `LoanSummary`, `Loan`, `Transaction`, `TaxInfo` DTOs |
| `src/config.rs` | non-secret settings, keychain account names |
| `src/commands/` | one module per command group, plus `Ctx` and the reauth wiring |
| `scripts/nlnt-capture.mjs` | reference capture script for unattended re-login (see `docs/api.md` § Unattended re-login) |
| `tests/` | offline surface + fixture tests |
| `docs/api.md` | the reverse-engineering record and its traps |

## Conventions (do not break these)

- **Reuse before you write.** Grep `cli-common/crates` first. Dates, money,
  output/table rendering, `Paged`, `RangeArgs`, auth, secrets, config,
  self-update, `with_reauth` and HTML scanning are all already provided. Each
  has been re-implemented by accident somewhere in the family at least once.
- **`--json` on every command**, exactly one schema-tagged DTO on stdout.
  Diagnostics to stderr. Never emit a second JSON document — if a DTO already
  went out and a nonzero exit is needed, exit directly.
- **Validate arguments before touching the keychain or the network.** `--help`
  and bad input must never prompt, hang, or hit the provider. The pure policy
  function `download_blocked` exists for this.
- **Exit codes** 0/1/2/3/4/5/6 per SPEC §1.5, via `CliError`.
- **ISO `YYYY-MM-DD`** on every date flag and in every DTO. Provider date
  dialects are converted in `parse` and never escape it.
- **Money is `Money`** (string decimal). No floats, no bare cents.
- **Field/column order is insertion order** — lead with identifying fields.

## Portal-specific gotchas

- **Akamai keys on client-hint headers.** `client::sentinel_headers` (UA +
  `sec-ch-ua*` + `Sec-Fetch-*`) is what gets a plain reqwest client past the bot
  wall; drop half of it and every call 403s. A 403 whose body is the Akamai
  denial is **upstream (exit 5)**, not auth — it happens before the token is read.
- **`currentBalance` is inverted between endpoints.** On `/api/1/loan/overview`
  it is the total and principal is `outstandingPrincipal`; on a loan group it is
  the principal and the total is `outstandingBalance`. `parse::summary` and
  `parse::loans` read different keys for this reason.
- **Refresh tokens rotate.** `Portal::refresh` writes the new bundle back to the
  keychain; skipping the write-back breaks the *next* refresh.
- **The download check is the only positive signal.** `client::pdf_error`
  requires `%PDF-` within the first kilobyte. Never relax it.
- **Money is JSON numbers** (except the tax dictionary's comma strings), and
  `loanType` is space-padded. `parse::money` and `as_text` handle both.

## Credentials

MFA happens in the browser during sign-in, **not** in the CLI's normal paths.
The CLI replays a Bearer token and exchanges a refresh token, so day-to-day it
cannot spend a code or lock the account. Still:

- The test suite is fully offline. No test, lint or CI job may contact Nelnet
  or launch Chrome. The `--browser` tests stop at the flag check and point
  `NLNT_CHROME` at a path that does not exist, so a regression fails fast
  instead of opening a window.
- **`auth login --browser` reads `nelnet.studentaid.gov` only.** Never evaluate
  in, read from or navigate to `auth.nelnet.studentaid.gov` programmatically:
  it is the Akamai-protected identity host, and the owner's own clicks are the
  only traffic it should see from the window. `docs/api.md` § How the CLI gets
  the initial bundle records the capture.
- **The browser profile is kept on disk** (`--fresh-profile` skips it for one
  sign-in), so **the launch keeps `clear_site_storage` on and the expression only
  reads**. A bundle left in the profile goes stale at the CLI's next refresh, and
  handing it over or letting the SPA present it breaks the single-holder rule
  below. The crate may evaluate the expression more than once, so a write in it
  could lose the bundle. `auth logout` removes the profile last, through `logout_browser`'s
  closure: the binary binds `pk_cli_browser::forget_profile`, tests bind
  `forget_profile_in` under a temp dir. **No test may reach the owner's real
  profile.** It is a full Chrome profile that outlives even a failed sign-in
  (SECURITY.md lists its contents). Every browser sign-in goes through
  `browser::sign_in`, including the step that parses, verifies and stores the
  session, so any failure after the window opens names the profile
  (`failed_sign_in`). Logout attempts every step, keychain first and profile last,
  then names what was cleared and what remains (`incomplete_logout`). The config is
  read only in the arms that use it, so a broken file doesn't stop logout; `dispatch`
  takes the logout as a seam so a test can run it with neither keychain nor profile.
  `auth status` reports the profile through `browser_profile_status`'s closure: the
  binary binds `profile_exists`, tests bind `profile_exists_in`. Don't recompute its
  path here.
- `with_reauth` retries **once** and never loops. The recovery step is
  `client::refresh_or_relogin`: exchange the refresh token, and only if that is
  dead run the configured `refresh_command` (the reference capture script in
  `scripts/nlnt-capture.mjs`) for a fresh bundle.
- **Single-holder rule.** Duende rotates refresh tokens with reuse detection:
  presenting an already-rotated token revokes the whole family. So the CLI must
  be the sole holder of a captured bundle — don't refresh concurrently against a
  live browser session on the same account. See `docs/api.md` § Token lifetimes.
  Two `nlnt` processes cannot race each other: `client::refresh_or_relogin` posts
  its grant under `pk_cli_auth::refresh_lock::RefreshLock`
  (`~/.config/nlnt/token-refresh.lock`, holding nothing), re-reads the session
  once it holds the lock, and posts no grant if the stored session (access or
  refresh token) differs from the one it presented.
  A login and a logout hold it around their keychain write only, never across the
  sign-in: `before_signin` first, `store_signin` for the write, and a logout's
  delete runs with or without it (`forget_for_binary`).
- **One capture at a time.** The capture command can spend a one-time code, so
  `capture_once` runs it under a second empty file, `token-capture.lock`, outside
  the refresh lock so a login or logout never waits on a capture. A process that
  finds it held waits, uses what that capture stored, and if nothing was stored
  fails rather than spending another code. A capture is stopped after 5 minutes,
  SIGTERM then SIGKILL 20 s later, though anything it started may keep running; it
  stays in `nlnt`'s process group so Ctrl-C reaches all of it. The reference script
  gives up after 4 minutes and stops Chrome on SIGTERM, so its teardown runs first. A sign-in's or logout's result stands over a capture
  that finishes later.
- The unattended full-login path burns a real MFA code; the capture script
  prefers silent renewal (persistent profile) precisely to avoid that.

## Safety & privacy (treat this repo as public)

It is private today. Assume it will not always be.

- Secrets only via prompt / `--stdin` / `--from-env`, only into the keychain
  (`piekstra.nlnt`). Never argv, never a file, never a log. The token bundle
  (access + refresh token) is the secret.
- `--verbose` must never print tokens or full account numbers. Account
  identifiers are masked by `parse::mask`.
- **Statement-download paths stay out of DTOs.** `fixture_shapes.rs` asserts this.
- **Never commit a PDF.** A 1098-E carries an SSN; `.gitignore` excludes them.
- Fixtures are scrubbed real captures — structure real, values dummied; see
  `tests/fixtures/README.md`, enforced by the hygiene test.

## Definition of done

`make verify` green, CI green, `docs/api.md` matching reality, `--json` and human
output in sync, and no secrets or personal data anywhere in the diff — fixtures
included. Dogfood through the **installed** binary against the live account for
any change that touches provider behavior.
