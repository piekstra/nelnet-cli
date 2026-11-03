# nelnet-cli (`nlnt`)

Nelnet federal student-loan servicing from the command line — balances,
**accrued interest**, payment history, and the yearly 1098-E.

Conforms to `piekstra-cli/1`. **Read-only. Unofficial.** Not affiliated with,
endorsed by, or supported by Nelnet.

> ### How auth works
>
> Nelnet's login is an **OAuth2/OIDC** flow (Duende IdentityServer at
> `auth.nelnet.studentaid.gov`) behind **Akamai** bot protection, and the API at
> `mmaapi.nelnet.studentaid.gov` takes a **Bearer token, not a cookie**. So the
> CLI does not replay a password. You sign in once in a Chrome window that
> `nlnt auth login --browser` opens, on Nelnet's own pages; `nlnt` reads the
> session the portal stores, closes the window, and from then on replays the
> Bearer token — sending the Chrome client-hint headers Akamai requires — and
> **refreshes it itself** using the session's refresh token. No browser after
> the first sign-in. Full record, including the header-bypass finding, in
> [`docs/api.md`](docs/api.md).

## Why this exists

The household is paying down **accrued interest during a $0-payment IDR
window**. In that situation the number a servicer's dashboard leads with — the
amount due — is `$0.00` and tells you nothing. What matters is:

- how much interest has accrued and not yet capitalized,
- whether extra payments are outrunning the accrual,
- and the 1098-E at tax time.

`nlnt summary` is built around exactly those, and `nlnt tax` surfaces the
yearly 1098-E deductible-interest figure as data instead of a portal expedition.

## Install

```sh
git clone https://github.com/piekstra/nelnet-cli
cd nelnet-cli
make install
```

macOS users: run `~/Dev/cli-common/scripts/setup-dev-signing.sh` once first, so
keychain "Always Allow" grants survive reinstalls. See
[CONTRIBUTING.md](CONTRIBUTING.md#macos-signing).

## Quick start

```sh
nlnt auth login --browser           # sign in in the Chrome window; verified with a live read, then stored
nlnt summary                        # balances + accrued interest
nlnt tax                            # the 1098-E deductible-interest figure
nlnt transactions list --since 2026-01-01
nlnt documents list                 # statements (real PDFs)
nlnt documents download <id> -o ~/Documents/statement.pdf
```

`auth login --browser` opens Chrome at `https://nelnet.studentaid.gov`. Sign in
there — username, password and the one-time code go to Nelnet, never through
`nlnt`. Once the portal has stored its session, `nlnt` reads it from the page and
closes the window. If the read that checks it can't tell, for example during an
outage, the session is kept with a warning that it is unverified, so the sign-in
isn't wasted. A session the portal refuses is not stored. Chrome is found at the standard install paths; set
`NLNT_CHROME` to use another binary.

The window runs in a Chrome profile `nlnt` **keeps on disk** between sign-ins
(owner-only, `~/Library/Application Support/piekstra.nlnt/browser-profile` on
macOS, `$XDG_DATA_HOME/piekstra.nlnt/browser-profile` or
`~/.local/share/piekstra.nlnt/browser-profile` on Linux), so Nelnet's cookies
carry over and a later sign-in may need less input: no one-time code on a device
Nelnet remembers. `nlnt auth login --browser --fresh-profile` signs in once
through a scratch profile, deleted afterwards, and leaves the kept one alone.

The trade is more than cookies. `nlnt` clears the page's storage, the token bundle
with it, before Chrome starts and once it stops; after a crash, the next launch
clears it. But this is a full Chrome profile, so it also keeps browsing history with
full URLs, query strings included, and the HTTP cache, for whatever loads in that
window. Chrome's cookie encryption does not cover those,
and on Linux with no desktop keyring it uses a fixed, publicly known key, which
protects the session cookie no better. The directory's `0700` mode is then the
only protection, and ordinary backups usually include the directory
([`SECURITY.md`](SECURITY.md)). The sign-in's OIDC
redirects stay in the history, query strings and all. **Use `--fresh-profile` if
you view loan or statement pages in that window.**

The profile stays after a failed sign-in too, possibly with a live session, and
the error says so. `nlnt auth status` says whether the profile exists
(`browser_profile`), not whether it is signed in. `nlnt auth logout` removes it and clears the stored session with it.
It attempts every step even when one fails. If one fails, or a sign-in or a Chrome
window is using the profile, it exits non-zero and says what was cleared, what
remains and how to finish.

The session carries a refresh token, so this is a **one-time sign-in**: `nlnt`
renews the short-lived access token itself (`nlnt auth refresh`, or
automatically on expiry). Sign in again only when the refresh token's own
lifetime lapses (`nlnt auth login --browser --overwrite`).

**Without Chrome**, sign in at `https://nelnet.studentaid.gov` in any browser,
copy the session out of DevTools → Console, and pipe it in. It is parsed and
verified as the browser path does, and stored only if the read proves it:

```sh
# in the browser console:
copy(localStorage['oidc.user:https://auth.nelnet.studentaid.gov:mma'])

# in the terminal:
pbpaste | nlnt auth login --stdin
```

**Fully unattended (optional):** point `nlnt` at a capture command and it
re-logs-in on its own when the refresh token dies — no paste, no browser in the
common case:

```sh
nlnt config set username you@example.com
# Store the portal password WITHOUT putting it on argv — omit -w so `security`
# prompts, reads it on stdin, and it never lands in shell history or `ps`:
security add-generic-password -U -s piekstra.nlnt -a password
nlnt auth refresh --command "node $(pwd)/scripts/nlnt-capture.mjs" --save
```

The reference script (`scripts/nlnt-capture.mjs`) drives real Chrome with its own
persistent profile (`auth logout` does not touch that one): it silently renews with no MFA **while the identity session
lives (observed ~1 hour)**, and after that does a full username/password login —
needing an MFA code unless the device is trusted. If it can't get a fresh
session it **errors clearly rather than storing a dead token**. So "unattended"
is reliable for the silent window and password-only re-logins; a full login
whose code lands in an unreadable channel still needs a human. See
[`docs/api.md`](docs/api.md) § Auth for the honest durability details.

The 1098-E is **not** downloadable — Nelnet publishes no such file. `nlnt tax`
gives the deductible-interest figure as data; the January statement carries the
same interest total and *is* a real PDF.

## Commands

| Command | What it does |
| --- | --- |
| `nlnt summary` | Principal, **accrued interest**, payoff, plan, next due (`loan-summary/v1`) |
| `nlnt loans list` (`ls`) | Every loan with its balance and rate (`loan-list/v1`) |
| `nlnt loans get <ID>` | One loan (`loan/v1`) |
| `nlnt transactions list` | Payment/activity history with the principal-vs-interest split; `--scheduled` for upcoming payments |
| `nlnt repayment` | Repayment status + income-driven-repayment application tracking (`repayment/v1`) |
| `nlnt autopay` | Auto-debit enrollment and next-cycle detail, banking PII masked (`autopay/v1`) |
| `nlnt tax` | The 1098-E deductible-interest figure as data (`tax-info/v1`) |
| `nlnt documents list` | Statements; `--tax` / `--tax-year YYYY` filters |
| `nlnt documents download <ID> -o <PATH>` | Download one statement; `--all -o <DIR>` for all |
| `nlnt auth login --browser` | Sign in through a Chrome window and store the session (`--stdin` takes one copied from DevTools) |
| `nlnt auth refresh\|status\|logout\|set-credential` | Session refresh, state, and credential management |
| `nlnt config path\|show\|set\|unset` | Non-secret settings |
| `nlnt api GET <PATH>` | Raw read-only passthrough |
| `nlnt mcp` | Serve read-only tools to Claude over MCP; see [Use with Claude](#use-with-claude) |
| `nlnt info` | Machine discovery (`cli-info/v1`) |
| `nlnt self-update [--check]` | Update from GitHub releases |
| `nlnt completions <shell>` | Shell completions |

Every command takes `--json`, `-v/--verbose`, `-q/--quiet`, `--no-color`.
Lists take `--limit N`, `--since YYYY-MM-DD`, `--until YYYY-MM-DD`.

## Examples

```sh
# Is the extra payment outrunning the accrual?
nlnt summary --json | jq '{principal: .principal_balance.amount, accrued: .accrued_interest.amount}'

# Every payment this year, with how much landed on interest
nlnt transactions list --since 2026-01-01 --json | jq '.items[] | {date, amount: .amount.amount, interest: .interest.amount}'

# This year's 1098-E, by tax year rather than publication date
nlnt documents list --tax-year 2025 --json
```

`documents list --tax-year 2025` matches the year in the **title**, not the
publication date — a 1098-E for tax year 2025 is published in January 2026, so
filtering by date returns the wrong form.

## Configuration

`~/.config/nlnt/config.json`, via `nlnt config set <key> <value>`:

| Key | Meaning |
| --- | --- |
| `account` | Servicer account number, if more than one. Env `NLNT_ACCOUNT`. |
| `username` | Portal username (only for unattended full-login). Env `NLNT_USERNAME`. |
| `base_url` | API host override (`mmaapi.nelnet.studentaid.gov`). |
| `auth_url` | Identity host override (`auth.nelnet.studentaid.gov`). |
| `auto_refresh` | Refresh the access token automatically on expiry (default on). |
| `refresh_command` | Capture command for unattended re-login. Env `NLNT_REFRESH_COMMAND`. |

Secrets are **never** stored here — the OAuth token bundle (access + refresh
token) and the portal password live in the macOS keychain under `piekstra.nlnt`,
as does the bearer token of `nlnt mcp --http`, which can also come from
`$NLNT_MCP_TOKEN`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | generic error |
| 2 | usage error |
| 3 | auth required / session expired |
| 4 | not found |
| 5 | upstream / provider error (incl. a download that was not a PDF), or another `nlnt` process holding a token lock past the wait |
| 6 | confirmation required (or a write refused — this CLI is read-only) |

## Read-only, and how that is enforced

`nlnt` implements no write operation. `nlnt api` refuses any method but `GET`
with exit 6, and `nlnt mcp` serves read-only tools alone. On a loan servicer the write endpoints move real money, so that
refusal is policy rather than an unfinished feature. If a write is ever added,
this claim must change in the same commit.

A statement download only reports success when the bytes actually begin with
`%PDF-`. Without that check an error body (JSON, or an edge interstitial) would
be written to disk under a `.pdf` name with a "Saved" message — feeding a
non-document into an archive.

## Use with Claude

`nlnt mcp` serves five read-only tools over MCP, so Claude can answer questions about
your own student loans. There is no hosted service: the tools run on your computer, in
your copy of `nlnt`, and call Nelnet with the session in your OS keychain.

| Tool | Answers |
| --- | --- |
| `nelnet_loans` | What do I owe? Total principal, accrued interest and payoff, and each loan group's type, status, rate and balances, narrowed by `loan_type` |
| `nelnet_payments` | What did I pay, and how much reached principal? Payments by `since`/`until`, or upcoming ones with `scheduled` |
| `nelnet_repayment` | What is due next? Status, plan, next payment, recertification date, autopay enrollment and income-driven applications |
| `nelnet_tax` | What goes on the 1098-E line? Nelnet's running total of deductible interest, with its as-of date |
| `nelnet_documents` | Has a statement arrived? Published documents by date and category, with no file contents; `nlnt documents download <id>` saves one |

No tool can make or schedule a payment, change autopay or a repayment plan, or change
anything at Nelnet: there is no such tool, the tools have no verb but `GET`, they ask
only for fixed paths, and `--allow-writes` adds nothing.

Results are concise by default (`response_format: "detailed"` adds ids and provider
detail), 25 records a page with a cursor for more, and never larger than about 32,000
characters. No result carries an account number or a bank account's tail, and a document
goes by date and category because Nelnet's titles embed an identifier. A figure Nelnet
did not state is absent rather than `0.00`, and an answer the tools cannot read is an
error rather than an empty list. `nelnet_repayment` still answers when Nelnet does not
answer for autopay or income-driven applications, and its `note` says which. Text in a
result comes from Nelnet; the server tells Claude to treat it as data, not instructions.

The tools are worded for a model, so they differ from `--json` in two ways. Amounts are
plain decimal strings where `--json` has `Money` objects. And a payment's `type` is
Nelnet's payment type only, where `nlnt transactions list --json` falls back to the
benefit status for `kind`.

**Sign in first.** Sign-in is through a browser, so no settings form can hold it. Run
`nlnt auth login --browser` in a terminal. Both ways of connecting Claude below then use
that session from the OS keychain (service `piekstra.nlnt`), and renew the access token
in place, as the commands do, under the same lock as every other `nlnt`. When the refresh
token dies, the tools say so and ask you to run `nlnt auth login --browser --overwrite`
in a terminal. They never sign in by themselves, and they do not run `refresh_command`,
because that would drive a browser on a model's call. A running command still does.

**Claude Code.** Add the `nelnet-cli` plugin from the
[piekstra plugin marketplace](https://github.com/piekstra/claude-plugins):

```console
$ claude plugin marketplace add piekstra/claude-plugins
$ claude plugin install nelnet-cli@piekstra-plugins
```

**Claude Desktop.** Download `nlnt-<version>.mcpb` from the
[latest release](https://github.com/piekstra/nelnet-cli/releases/latest) and open it.
It asks for nothing: the bundled `nlnt` reads what your installed `nlnt` stored. On
macOS the bundled binary is a different program to the keychain, so its first call
raises a keychain prompt for the `piekstra.nlnt` session; choose **Always Allow**, or
every call will ask again.

Any other MCP client that launches a local server can run `nlnt mcp`.

**Claude on the web and mobile.** claude.ai reaches tools through a remote connector,
and your Nelnet session stays on your computer, so `nlnt` serves the same tools from
your computer to a connector you deploy into your own Cloudflare account:

```console
$ nlnt mcp --new-token            # once: a bearer token, saved in the keychain and printed for the Worker
$ nlnt mcp --http --port 8737     # serve on 127.0.0.1 only
```

The connector, [cli-common's `connector/`](https://github.com/piekstra/cli-common/tree/main/connector#tools-from-your-computer-home-modules),
reaches that port through a Cloudflare Tunnel in your account; its README walks through
the tunnel, the VPC service, a launchd agent that keeps the server running, and the
`HOME_NELNET_TOKEN` secret, with the threat model. `--http` binds 127.0.0.1 only,
refuses to start without the token, refuses any request whose `Host` is not loopback
or that carries an `Origin`, and serves the read-only tools only. The Nelnet session
never leaves your computer, but tool results do: your balances, payments and repayment
details pass through Cloudflare and reach Claude ([`SECURITY.md`](SECURITY.md)). While
the computer sleeps, the tools answer that it is offline.

After `nlnt self-update`, restart the server: a running one keeps the old code, and its
launchd agent restarts it only when it exits. Its start line names the version.

```console
$ launchctl kickstart -k gui/$(id -u)/com.piekstra.nlnt-mcp-http
```

`self-update` does not reach a Claude Desktop extension, which runs its own copy.
Install the new release's `.mcpb` too.

## Development

```sh
make verify   # fmt-check + lint + test + smoke — the CI gate
```

The test suite is **fully offline** and never touches the keychain. See
[CONTRIBUTING.md](CONTRIBUTING.md) for why that is a hard rule here, and
[docs/api.md](docs/api.md) for the reverse-engineering record.

## License

MIT OR Apache-2.0.
