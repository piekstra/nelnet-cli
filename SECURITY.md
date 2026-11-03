# Security policy

## Reporting

This is a private, single-household tool. Report anything sensitive directly to
the repository owner rather than opening a public issue.

## What this tool handles

`nlnt` talks to a **federal student-loan servicer** on behalf of one household.
The data it touches — loan balances, accrued interest, payment history, SSN-bearing
1098-E tax forms — is financial PII. The invariants below are not stylistic.

## Invariants

- **Secrets never enter via argv.** Credentials come from the browser sign-in
  (`auth login --browser`), an interactive prompt, `--stdin`, or
  `--from-env <VAR>`. A password on a command line lands in shell history and in
  every `ps` listing on the machine.
- **The browser sign-in window is short-lived and private.** `auth login
  --browser` runs Chrome on an owner-only (`0700`) profile, reads the session
  over the DevTools protocol from `nelnet.studentaid.gov` pages only, closes the
  tab the moment it has the session, then stops Chrome on every exit, Ctrl-C
  included. The DevTools port has no authentication, so while the window is
  open any local process that can reach it can read the window's session; the
  window stays open only for the sign-in.
- **The browser profile is kept on disk between sign-ins.** It lives at
  `~/Library/Application Support/piekstra.nlnt/browser-profile` on macOS and
  under `$XDG_DATA_HOME` or `~/.local/share` on Linux, and a launch is refused
  when it is a symlink, another user's or not `0700`. It holds the identity
  host's cookies (`idsrv`, the remembered device), which is the trade for fewer
  sign-ins. Chrome encrypts its cookies at rest (on macOS with the "Chrome Safe
  Storage" key in the login keychain). `localStorage` is protected only by the
  directory's mode, so the capture removes the token bundle from it as it reads
  it: the profile is not meant to hold a refresh token after a sign-in. A window
  killed before Chrome writes that removal can leave one, and `auth logout`
  removes it with the profile. While `idsrv` lasts (observed ~1 hour), anyone
  who can run a browser in this profile can mint a new session.
- **`auth logout` removes the kept profile**, that directory and nothing else, as
  its last step. It refuses (exit 1, with the keychain session already cleared)
  while a sign-in or a Chrome is using the profile, or when the path is a symlink
  or another user's. `auth login --browser --fresh-profile` runs one sign-in in a
  scratch profile instead (`0700`, created exclusively under an unpredictable
  name in the temp dir, removed when the window closes), leaving the kept one
  alone. `scripts/nlnt-capture.mjs` keeps its own separate profile
  (`NLNT_CAPTURE_PROFILE`), which `auth logout` does not touch.
- **Secrets live only in the macOS keychain**, service `piekstra.nlnt`. Never a
  dotfile, never the config file (`~/.config/nlnt/config.json`), never an
  environment variable written to disk.
- **The OAuth token bundle is the secret.** The access token *and* the refresh
  token are stored in the keychain under the same service and are never logged,
  never printed by `--verbose`, and never written to a fixture. A refresh token
  is a durable credential — it re-mints access tokens on its own.
- **The portal password**, when supplied for unattended re-login, comes from the
  keychain (`piekstra.nlnt`, account `password`) or — as a less-preferred
  alternative for non-keychain environments — the `$NLNT_PASSWORD` env var, read
  by the capture script at point of use. Never argv, never config, never a log.
  Storing it is opt-in; normal token-replay operation never needs it.
- **`--verbose` never emits** access or refresh tokens, `Authorization` headers,
  full account/loan numbers, or SSNs.
- **Downloaded documents are PII.** A 1098-E carries a Social Security Number.
  `.gitignore` excludes `*.pdf` for this reason. Do not commit one, ever, not
  even "redacted".
- **Fixtures are scrubbed real captures.** `tests/fixtures/` preserves the real
  response *structure* with every identifying and financial value replaced by an
  obvious dummy, enforced by a hygiene test (marker present, no token/cookie/SSN
  shapes, dummy UUIDs). Raw provider captures are never committed.
- **This repo is written as if public.** It is private today; treat every commit
  as though it were not.

## Multi-factor authentication

Nelnet's login presents a one-time passcode challenge, but it is completed **in
the browser** during the one-time sign-in — the CLI never submits a code.
`nlnt` only replays a Bearer token and exchanges a refresh token, so it cannot
spend a code or lock the account. The test suite is nonetheless **fully
offline** — no test, CI job, or lint has ever contacted the provider. Do not add
one.

## Threat model, briefly

The realistic risks are (1) a credential leaking into git history or a log, and
(2) a downloaded tax form being committed. Both are addressed above. This tool
is **read-only** against the provider: it holds no payment surface, so a bug
cannot move money. That claim must change in the same commit as the first write
operation.
