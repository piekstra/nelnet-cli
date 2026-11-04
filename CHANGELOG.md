# Changelog

Earlier releases are described on the GitHub releases page.

## v0.4.0 — 2026-11-03

- Windows: releases attach `nlnt-x86_64-pc-windows-msvc.tar.gz`, and the `.mcpb` runs there.
  A session too long for one Windows credential is split and read back as one.
- `nelnet_payments` and `nelnet_documents` page by position, so a row that arrives between
  pages repeats nothing and skips nothing. Rows of the same day now run in a fixed order of
  their own. A cursor from an earlier version still works, as the count of rows it holds.
- The tools read what a failure means from the error's reason, not its wording.
- `auth logout --forget` says what a removed connector token does not end: a running
  `nlnt mcp --http` keeps the token it started with.
- A refresh token stays on the host it was for. reqwest re-sends a body on a 307 or 308, so
  the token request refuses a redirect to another host, and other requests refuse one that
  leaves https.
- A network error no longer quotes the URL it was reading.
- cli-common v0.27.0, up from v0.21.0.

## v0.3.0 — 2026-11-03

- `nlnt mcp`: read-only tools for Claude, `nelnet_loans`, `nelnet_payments`,
  `nelnet_repayment`, `nelnet_tax` and `nelnet_documents`. They run over stdio for
  Claude Code and Claude Desktop, and with `--http` on 127.0.0.1 behind a bearer token
  for Claude on the web and mobile through your own Cloudflare Worker and tunnel. No
  tool can make a payment or change anything at Nelnet, and a test holds every request
  a tool makes to a list of nine reads.
- A server reads the config and keychain on each call and renews under the same
  `RefreshLock` as every other `nlnt`. A tool never signs in, and does not run
  `refresh_command`.
- A tool says what it does not know: an answer of the wrong shape is an error, a figure
  Nelnet did not state is absent rather than `0.00`, and no document title or account
  number appears in a result.
- Releases attach `nlnt-<version>.mcpb`, a Claude Desktop extension, for macOS and Linux.
  There is no Windows build; `SECURITY.md` says why.
- `auth logout --forget` also removes the `mcp --http` bearer token.
- `Portal::refresh` writes the stored session back before it spends the refresh token,
  so a keychain prompt or refusal comes while that token can still be used.
- `self-update` says to restart a running `nlnt mcp --http` and to install the new
  `.mcpb`.
- A failure that got no answer from the portal no longer prints its URL.
- `documents list --tax-year` no longer reads a year out of a longer run of digits in a
  title.
- cli-common v0.21.0, up from v0.20.0.

## v0.2.3 — 2026-11-03

- An edge block no longer offers a new sign-in as the first fix, because the block is
  on this client rather than the session. The stored-unverified warning and the errors
  for an HTML `403` or an HTML answer say a new sign-in may not clear it, and to wait
  or try another network, before naming `nlnt auth login --browser --overwrite`. The
  Akamai denial on an ordinary read names no sign-in at all. Exit codes are unchanged.
- The verifying read reports an HTML page as an edge block rather than as no data.
- Moves to cli-common v0.20.0, and builds the `auth-login/v1` result with its `AuthLogin`. The output is unchanged.

## v0.2.2 — 2026-11-03

- `nlnt auth login --json` and `nlnt auth set-credential --json` print a result,
  schema `auth-login/v1`, once the session is stored. `verified` is always there:
  `true` when a read accepted the session, `false` when its read could not tell or
  `--no-verify` skipped it. The exit code stays 0.

## v0.2.1 — 2026-11-03

- `nlnt auth login --browser` keeps a finished sign-in when the read that checks it
  can't tell: a `429`, a `5xx`, a `404`, a dropped connection, a body with no data or
  an edge block. The session is stored, exit 0, with a warning even under `-q` that
  it is unverified, naming `nlnt auth login --browser --overwrite` if reads keep
  failing. These used to store nothing, and
  the owner had to sign in again. A definite refusal still stores nothing. `--stdin`,
  `--from-env` and `auth set-credential` are unchanged.
- A refused verifying read keeps the portal's answer in its message.
- A `403` with an HTML page is an edge block on every read, exit 5 with its own
  reason and the same way out. It used to read as an expired token, and spent a
  refresh token on a retry. No such page has been observed yet.

## v0.2.0 — 2026-11-03

cli-common v0.19.0, which needs Rust 1.89: the browser sign-in keeps its Chrome
profile (v0.16.0) and clears its site storage (v0.19.0).

- `nlnt auth login --browser` runs Chrome in a profile `nlnt` keeps on disk
  (`<data dir>/piekstra.nlnt/browser-profile`, owner-only), where it used to run
  in a scratch profile deleted after every sign-in. Nelnet's cookies carry over,
  so a later sign-in may need less input. The trade is a full Chrome profile on
  disk: cookies, and history with query strings and the HTTP cache,
  which Chrome's cookie encryption does not cover, and on Linux with no desktop
  keyring that encryption uses a publicly known key (SECURITY.md). How much input
  it saves is unverified against the live portal.
- Any sign-in that fails once the window has opened now says the kept profile
  stays, possibly with a live session, and that `nlnt auth logout` removes it.
- The sign-in turns on `Launch::clear_site_storage`: site storage is removed before
  Chrome starts and again once it has stopped, keeping the cookies. Refresh tokens
  rotate with reuse detection, so a copy left in the kept profile could revoke the
  CLI's session (docs/api.md § Token lifetimes). The token no longer stays on disk
  between runs, except after a crash, which the next launch clears. The capture's
  expression still only reads.
- The crate now asks Chrome to quit over its debug port, so a persistent cookie set
  just before the close reaches disk for the next sign-in. Measured by cli-common in
  headless Chrome 156 only.
- `nlnt auth status` reports whether the kept profile exists (`browser_profile`),
  not whether it is signed in.
- `nlnt auth login --browser --fresh-profile` signs in once through a scratch
  profile, deleted afterwards, leaving the kept one alone. A failed login's
  retry command repeats the flag.
- `nlnt auth logout` also removes the kept profile, as its last step. It attempts
  every step even when one fails. If one fails, or a sign-in or a Chrome window is
  using the profile, it exits with the first failure's code, and the message says
  what was cleared, what remains and how to finish. A config file that can't be
  parsed no longer stops it, and `--forget` clears that file.
- The verifying read at login must return data. An empty body, `null` or `{}` is now
  exit 5 with nothing stored, since a stale session could get one.
