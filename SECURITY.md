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
  --browser` runs Chrome on a throwaway profile created `0700` under an
  unpredictable name, reads the session over the DevTools protocol from
  `nelnet.studentaid.gov` pages only, closes the tab the moment it has the
  session, then stops Chrome and deletes the profile on every exit, Ctrl-C
  included. The DevTools port has no authentication, so while the window is
  open any local process that can reach it can read the window's session; the
  window stays open only for the sign-in.
- **A hard-killed capture can leave a browser behind.** `nlnt` stops a capture
  command after 5 minutes, and the reference script stops its Chrome first. If the
  script is killed outright, its Chrome stays up on the signed-in profile with an
  unauthenticated debugging port, which any local process can read the token bundle
  through. `docs/api.md` § Unattended re-login says how to find and stop it.
- **Secrets live only in the macOS keychain**, service `piekstra.nlnt`. Never a
  dotfile, never the config file (`~/.config/nlnt/config.json`), never an
  environment variable written to disk. `~/.config/nlnt/token-refresh.lock` is an
  empty file that `nlnt` processes hold while renewing the session, so two never
  present one rotating refresh token once all are 0.1.2 or later.
  `token-capture.lock` beside it keeps two capture commands from running at once.
  Neither holds anything.
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
