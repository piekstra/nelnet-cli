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

`auth login --browser` opens Chrome with a throwaway profile at
`https://nelnet.studentaid.gov`. Sign in there — username, password and the
one-time code go to Nelnet, never through `nlnt`. Once the portal has stored its
session, `nlnt` reads it, closes the window and deletes the profile. Chrome is
found at the standard install paths; set `NLNT_CHROME` to use another binary.

The session carries a refresh token, so this is a **one-time sign-in**: `nlnt`
renews the short-lived access token itself (`nlnt auth refresh`, or
automatically on expiry). Sign in again only when the refresh token's own
lifetime lapses (`nlnt auth login --browser --overwrite`).

**Without Chrome**, sign in at `https://nelnet.studentaid.gov` in any browser,
copy the session out of DevTools → Console, and pipe it in. It is parsed,
verified and stored exactly as the browser path does:

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

The reference script (`scripts/nlnt-capture.mjs`) drives real Chrome with a
persistent profile: it silently renews with no MFA **while the identity session
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
token) and the portal password live in the macOS keychain under `piekstra.nlnt`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | generic error |
| 2 | usage error |
| 3 | auth required / session expired |
| 4 | not found |
| 5 | upstream / provider error (incl. a download that was not a PDF) |
| 6 | confirmation required (or a write refused — this CLI is read-only) |

## Read-only, and how that is enforced

`nlnt` implements no write operation. `nlnt api` refuses any method but `GET`
with exit 6. On a loan servicer the write endpoints move real money, so that
refusal is policy rather than an unfinished feature. If a write is ever added,
this claim must change in the same commit.

A statement download only reports success when the bytes actually begin with
`%PDF-`. Without that check an error body (JSON, or an edge interstitial) would
be written to disk under a `.pdf` name with a "Saved" message — feeding a
non-document into an archive.

## Development

```sh
make verify   # fmt-check + lint + test + smoke — the CI gate
```

The test suite is **fully offline** and never touches the keychain. See
[CONTRIBUTING.md](CONTRIBUTING.md) for why that is a hard rule here, and
[docs/api.md](docs/api.md) for the reverse-engineering record.

## License

MIT OR Apache-2.0.
