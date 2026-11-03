# Security policy

## Reporting

This is a single-household tool. Report anything sensitive directly to
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
  when it is a symlink, another user's or not `0700`. It is a full Chrome
  profile, which is the trade for fewer sign-ins. It holds:
  - the identity host's cookies (`idsrv`, the remembered device);
  - browsing history with full URLs, query strings included;
  - the HTTP cache, for whatever the responses allow: loan balances and payment
    history among it, if those pages load in the window;
  - any password you let Chrome save.

  Chrome encrypts its cookies at rest, but how well depends on the platform. On
  macOS the key is "Chrome Safe Storage" in the login keychain. On Linux it is
  the desktop keyring; with no keyring Chrome falls back to a fixed, publicly
  known key, so there the directory's `0700` mode is all that protects the
  session cookie. Encryption does not cover the history or the HTTP cache on any
  platform, so `0700` is their only protection. The directory sits where ordinary
  user-level backups usually look, so exclude it from any backup you don't want
  holding this.
- **What this portal leaves in the history.** The sign-in's OIDC redirects stay
  there with their query strings, the one-time authorization code and state
  among them, until `auth logout`. The window closes as soon as the session is
  read, which limits what else loads in it; a statement opened there would stay
  in the cache too, and a statement can carry an SSN. Use `--fresh-profile` to
  view anything in that window.
- **The refresh token.** The token bundle sits in `localStorage` only while the
  window is open, unencrypted on disk. The crate removes the profile's site storage
  (`localStorage`, IndexedDB and the rest) before Chrome starts and again once it
  has stopped, keeping the cookies, so the profile holds no refresh token between
  runs. A crash or a second Ctrl-C skips the second removal, as does a Chrome still
  running in the profile once the spawned process has ended, with a warning. A
  bundle can then stay on disk until the next launch's removal or `auth logout`.
  While `idsrv` lasts (observed ~1
  hour), anyone who can run a browser in this profile can mint a new session.
- **A finished sign-in can be stored unverified.** The read that checks it runs after
  the window, when the page's copy is gone, so a read that can't tell (a `429`, a
  `5xx`, a dropped connection, a body with no data, an edge block) stores the session
  anyway, with a warning even under `-q` and `verified: false` in the `--json` result.
  It can only be this sign-in's, because site
  storage is cleared before Chrome starts, and it can't replace a stored session
  without `--overwrite`, which login checks before the window opens. With `--overwrite`
  it does replace it. A `401` or the API's own `403` stores nothing. A later read
  settles an outage, but not an answer that repeats: an HTML `403` and a 2xx with no
  data can come back for this session on every read. Nothing renews on those, and
  `auth status` makes no request, so a bad session stays stored until a new sign-in
  (`nlnt auth login --browser --overwrite`). For an edge block the warning first says a
  new sign-in may not clear it and to wait or try another network, because the block is
  on this client rather than the session.
- **The profile outlives a failed sign-in.** Any failure once the window has
  opened (a timeout, a closed window, Ctrl-C, a refused verifying read, a bundle
  the parser refuses, a failed keychain write) leaves the profile with what the
  sign-in got as far as, possibly a live `idsrv` session. Every such error says
  so and names `nlnt auth logout`. `auth status` says whether the profile exists
  (`browser_profile`), not what is in it or whether it is signed in.
- **`auth logout` removes the kept profile**, that directory and nothing else, as
  its last step; it clears the stored session too, and there is no way to remove
  the profile alone. Every step is attempted even when an earlier one fails, so a
  denied keychain prompt or an unwritable config does not leave the profile behind.
  A config file that can't be parsed doesn't stop it either, and `--forget` clears
  that file.
  The removal refuses while a sign-in or a Chrome is using the profile, or when the
  path is a symlink or another user's. Any failure exits non-zero with the first
  failure's exit code, and the message says what was cleared, what remains and how
  to finish. If a renewal in another process outlasts the lock's wait, the session is
  deleted but may be stored again, so that message says so and to wait a minute and
  rerun.
- `auth login --browser --fresh-profile` runs one sign-in in a
  scratch profile instead (`0700`, created exclusively under an unpredictable
  name in the temp dir, removed when the window closes), leaving the kept one
  alone. `scripts/nlnt-capture.mjs` keeps its own separate profile
  (`NLNT_CAPTURE_PROFILE`), which `auth logout` does not touch.
- **A hard-killed capture can leave a browser behind.** `nlnt` stops a capture
  command after 5 minutes, and the reference script stops its Chrome first. If the
  script is killed outright, its Chrome stays up on the signed-in profile with an
  unauthenticated debugging port, which any local process can read the token bundle
  through. `docs/api.md` § Unattended re-login says how to find and stop it.
- **Secrets live only in the macOS keychain**, service `piekstra.nlnt`. Never a
  dotfile, never the config file (`~/.config/nlnt/config.json`), never an
  environment variable written to disk. The bearer token of `nlnt mcp --http` is
  there too (account `mcp-http-token`), or in `$NLNT_MCP_TOKEN`; see
  [The MCP server](#the-mcp-server). `~/.config/nlnt/token-refresh.lock` is an
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
- **This repo is public.** Treat every commit accordingly.

## Multi-factor authentication

Nelnet's login presents a one-time passcode challenge, but it is completed **in
the browser** during the one-time sign-in — the CLI never submits a code.
`nlnt` only replays a Bearer token and exchanges a refresh token, so it cannot
spend a code or lock the account. The test suite is nonetheless **fully
offline** — no test, CI job, or lint has ever contacted the provider. Do not add
one.

## The MCP server

`nlnt mcp` serves five read-only tools to an MCP client (Claude Code, Claude Desktop)
over stdio; the server opens no port unless run with `--http` (below). **What the tools
return goes to Claude on every path**, as part of your conversation: balances, accrued
interest, loan types and rates, payments and their split, the repayment plan and next
payment, autopay enrollment and the bank's name, income-driven applications, the 1098-E
figure, and documents' dates and categories, with the school's name in detailed format.
No tool returns an account number, a bank account's digits, a routing number, an SSN, a
name, an address, or a document's title, which embeds an identifier.

No tool can make a payment or change anything at Nelnet. A tool reaches Nelnet only
through a seam with `get_text` and nothing else, and asks for `&'static str` paths, so
what a model passes cannot name another endpoint, even for a read. `--allow-writes` adds
nothing, since every tool is read-only. `src/mcp/tests.rs` holds this to the requests
the tools send.

**A tool never signs in.** `tools/list` touches no credential and no file. A call reads
the config and the `session` keychain item afresh, and renews with the stored refresh
token under `token-refresh.lock`, the lock every other `nlnt` holds, so two running
copies never present one rotating token. A tool does not run `refresh_command`, even
where one is configured: it drives a browser and may spend a one-time code, and a model
must not be able to start that. A dead session is an error naming the command for a
person to run.

On macOS a call can raise a keychain prompt, and a server left unattended waits on it,
holding `token-refresh.lock` if it was renewing, so other `nlnt` processes wait too.
Before a renewal spends the refresh token, `Portal::refresh` writes the stored session
back to the keychain, so a program macOS has not granted is asked, or refused, while the
token is unspent. Refresh tokens rotate, and one lost after the POST can revoke the whole
family at the next use.

`nlnt auth logout` removes the session and does not touch `mcp-http-token` or stop `nlnt
mcp --http`: after a later sign-in, whatever holds that bearer token can read through the
tunnel again. `nlnt auth logout --forget` removes `mcp-http-token` too, and a server already
running keeps the copy it read until it stops. To end the connector's access, run `nlnt mcp
--new-token --overwrite` and restart the server (`launchctl kickstart -k gui/$(id -u)/com.piekstra.nlnt-mcp-http`);
the old token works until the restart. To stop serving, run `launchctl bootout
gui/$(id -u)/com.piekstra.nlnt-mcp-http`, stop the tunnel and delete `HOME_NELNET_TOKEN`.

There is no Windows build. The session is one credential-store item holding an access
token, a refresh token and an id token, and Windows limits an item to 2,560 bytes
(1,280 UTF-16 units), with `pk-cli-secrets` not splitting one. The size of a real bundle
has not been measured against that limit, and a bundle that outgrew it at a renewal
would lose the rotated refresh token.

**`nlnt mcp --http`** is the path for Claude on the web and mobile. It binds 127.0.0.1
only, and is reached through a Cloudflare Tunnel and a Worker in your own account,
deployed from [cli-common's `connector/`](https://github.com/piekstra/cli-common/tree/main/connector),
whose README has the threat model. It refuses to start without a bearer token of at
least 32 bytes, from `$NLNT_MCP_TOKEN` or the keychain item `mcp-http-token`, and refuses
any request without it, whose `Host` is not loopback, or that carries an `Origin`. The
Nelnet session never leaves your computer, but on this path tool results also cross
Cloudflare on their way to Claude, in plaintext to your Worker. Anyone holding the bearer
token and able to reach the port can read everything the tools return, and cannot do
more. Rotate it with `nlnt mcp --new-token`, then update `HOME_NELNET_TOKEN`.

A call waits at most 45 seconds for the call before it and stops asking Nelnet after 110,
so a call the client has stopped waiting for ends. Nothing is cached between calls, and
results are not logged.

## Threat model, briefly

The realistic risks are (1) a credential leaking into git history or a log, and
(2) a downloaded tax form being committed. Both are addressed above. This tool
is **read-only** against the provider, `nlnt mcp` included: it holds no payment
surface, so a bug cannot move money. That claim must change in the same commit as the first write
operation.
