# Nelnet — endpoint map and reverse-engineering record

Unofficial. Nelnet publishes no public API for borrower servicing data. This
file records the API this CLI drives, **how it was confirmed**, and the traps
that cost hours to find.

`nlnt api GET <PATH>` is the escape hatch for probing once a session exists.

---

## Provenance

Everything below is **CONFIRMED-LIVE 2026-08-12**: captured by logging into the
real federal account in a browser, reading the SPA's own XHRs, and replaying
each request against the API host. The scrubbed responses are in
`tests/fixtures/`. Where a caveat remains it is called out inline.

---

## Hosts

| Host | Role |
| --- | --- |
| `nelnet.studentaid.gov` | The Angular SPA (borrower portal). Serves the app bundles; makes no data API calls itself. Keeps the token bundle in its `localStorage`, where `auth login --browser` reads it. |
| `mmaapi.nelnet.studentaid.gov` | **The data API.** Every `/api/N/...` call goes here. This is `base_url` / `DEFAULT_BASE_URL`. |
| `auth.nelnet.studentaid.gov` | **Duende IdentityServer** (OAuth2/OIDC). `/connect/token` is the refresh endpoint. This is `auth_url`. |
| `secure.nelnet.com` | **No DNS record.** Was an early wrong guess; do not reinstate it. |

`sloanservicing.com` runs the same platform for commercial FFEL loans and is out
of scope. Nelnet Bank and Campus Commerce are separate products.

## Auth — OAuth2/OIDC Bearer, refreshed by the CLI

Login is an **authorization-code + PKCE** flow at Duende IdentityServer. The
observed authorize request:

```
client_id=mma  response_type=code  code_challenge_method=S256
scope=openid offline_access mma.api.read mma.api.write
nds_client_id=1  nds_application_id=1        (1 = the federal client)
```

MFA (email/SMS 6-digit code) happens **in the browser**, once. The SPA stores
the resulting token bundle in `localStorage` under the key
`oidc.user:https://auth.nelnet.studentaid.gov:mma`:

```json
{ "access_token": "…", "refresh_token": "…", "id_token": "…",
  "token_type": "Bearer", "expires_at": <unix>, "scope": "…" }
```

The API authenticates with `Authorization: Bearer <access_token>` — **no
cookie**. The access token lives **15 minutes** (`expires_in: 900`). The bundle
carries a **refresh token** (`offline_access`), so the CLI renews the access
token itself via:

```
POST auth.nelnet.studentaid.gov/connect/token
  grant_type=refresh_token  client_id=mma  refresh_token=<rt>
```

**Refresh tokens rotate**: every refresh returns a new one and invalidates the
old. The CLI writes the new bundle back to the keychain after each refresh — a
refresh followed by not persisting the result breaks the *next* refresh. This is
the same hazard as a rotating cookie jar.

### How the CLI gets the initial bundle

The CLI never replays a password and never drives the identity host's login
pages. The owner signs in once, in a browser, and the CLI reads the bundle the
SPA stores. Both ways in below end in the same code: `Session::parse_captured`
(the bundle, or a bare `Bearer` token), one live read of `/api/1/loan/overview`
to prove it works, and one keychain item. From then on `auth refresh` (and
automatic refresh on a 401) keep it alive with no further browser interaction,
until the refresh token's own lifetime lapses — then sign in again.

#### `nlnt auth login --browser` (the primary path)

Built on cli-common's `pk-cli-browser` (`DESIGN.md` §2.2). `src/browser.rs`
holds the capture:

| | |
| --- | --- |
| Launch URL | `https://nelnet.studentaid.gov`, in a Chrome started with the owner-only (`0700`) profile the CLI keeps (`--fresh-profile`: a throwaway one), a DevTools port Chrome picks itself, and no automation flags |
| Sign-in | by the owner, on Nelnet's own pages: the SPA sends them to `auth.nelnet.studentaid.gov` for username, password and the one-time code |
| Read from | pages on exactly `nelnet.studentaid.gov` (`HostRule::exact`): an `https` page on the default port, matched label for label, whose document's own `location.hostname` matches too |
| Never touched | `auth.nelnet.studentaid.gov` (Akamai, the bot checks): the CLI evaluates nothing there and navigates nothing there; the owner's own sign-in passes through it in the window. `mmaapi` is reached only by the verifying read afterwards, over the CLI's HTTP client |
| What is read | `localStorage['oidc.user:https://auth.nelnet.studentaid.gov:mma']`, the value the DevTools fallback copies. No cookies |
| Ready when | the value contains `access_token`; before that the expression answers `null` |
| Then | the tab is closed at once and Chrome is stopped. The crate then removes the profile's site storage (`Launch::clear_site_storage`). The profile stays on disk with its cookies |

The expression (`browser::expression`, pinned by a unit test):

```js
(() => { const v = localStorage.getItem("oidc.user:https://auth.nelnet.studentaid.gov:mma"); return v && v.includes('access_token') ? v : null; })()
```

What follows from it:

- **The CLI is the sole holder from the start.** The tab closes before the SPA
  can renew the token it just stored. `Launch::clear_site_storage` removes the
  profile's site storage before Chrome starts and again once it has stopped, so
  between runs the kept profile holds no copy of the refresh-token family for a
  later window to hand over or for the SPA to present. A bundle the capture sees
  is therefore this sign-in's, so the expression writes nothing and checks no
  expiry. The single-holder rule in § Token lifetimes holds without the owner
  doing anything; on the DevTools path it is theirs to keep (close the tab).
- **After a crash the bundle can stay on disk until the next launch.** A crash or
  a second Ctrl-C skips the removal after Chrome stops, as does a Chrome still
  running in the profile once the spawned process has ended, with a warning. The
  next launch's removal covers each, before Chrome starts, and `auth logout`
  removes it with the profile.
- **A later sign-in can need less input (UNVERIFIED-LIVE).** The kept profile
  (`<data dir>/piekstra.nlnt/browser-profile`) keeps the identity host's cookies
  but no bundle. While `idsrv` lasts (~1 hour, § Token lifetimes) the SPA should
  get a new bundle with no password or code; after that, a device Nelnet
  remembers (`SaveTrustedDevice`) should skip only the code. Each sign-in mints
  a new token family. The crate asks Chrome to quit over its debug port and waits
  up to 5 s, so a persistent cookie set just before the close reaches disk;
  cli-common measured that in headless Chrome 156 only, so a visible window is
  **UNVERIFIED-LIVE**. `--fresh-profile` signs in through a scratch profile,
  removed when the window closes, so that sign-in is an unknown device and asks
  for the code.
- **The profile keeps more than cookies.** It is a full Chrome profile, so the
  history keeps the sign-in's OIDC redirects with their query strings, beside the
  HTTP cache; SECURITY.md lists what it holds, and its exact
  contents for this portal are **UNVERIFIED-LIVE**. Any sign-in that fails once
  the window has opened leaves it in place (a timeout, a closed window, Ctrl-C, a
  refused verifying read, a bundle the parser refuses, a failed keychain write),
  and the error says so and names `nlnt auth logout`. `auth status` reports whether it exists
  (`browser_profile`), not whether it is signed in. A profile needing repair leaves
  the field out, with a warning naming the path and the fix, unless `-q`.
- The verifying read must return data. An empty body, `null`, `{}` or anything else
  that isn't JSON with something in it doesn't prove the session, since a stale one
  could get it. It is exit 5 with nothing stored on a piped route, and a warning on
  a sign-in from the window (below).
- If a renewal in another process outlasts the lock's wait, `auth logout` exits 5
  saying the session is deleted but may be stored again, and to wait a minute and
  rerun.
- `auth logout` removes the kept profile as its last step, and attempts every step
  even when one fails, or when the config can't be parsed (`--forget` clears that
  file). A failed step, or a sign-in or a Chrome using the profile,
  exits non-zero with the first failure's code, naming what was cleared, what
  remains and how to finish. The capture script's profile below is a
  separate one, which logout does not touch.
- A captured value the parser refuses is exit 5: the portal changed what it
  stores, which is not a usage mistake.
- **A finished sign-in is kept unless the portal refuses it.** The verifying read
  runs after the window: Chrome has stopped and its site storage is cleared, so not
  storing the session would cost another sign-in.
  - A `401`, or a `403` that isn't an HTML page or the Akamai denial, is the portal
    refusing the session: exit 3, nothing stored, and the error keeps what it
    answered.
  - Anything else says nothing about the session: a `429`, a `5xx`, a `404`, a dropped
    connection, a 2xx with no data or a body that isn't JSON, or an edge block (the
    Akamai denial, or any `403` with an HTML page). The session is stored, exit 0,
    with a warning on stderr, even under `-q`, that it is unverified and that if reads
    keep failing, the way out is `nlnt auth login --browser --overwrite`. For an edge
    block it says first that a new sign-in may not clear it, because the block is on
    this client rather than the session, and to wait or try another network. `--json`
    prints `{"schema":"auth-login/v1","stored":true,"verified":false}`. `verified` is
    always there, and is `true` when a read accepted the session. `auth login` and
    `auth set-credential` print the same result, and `set-credential` always verifies.
  - A later read settles a `429`, a `5xx` or a dropped connection once the outage
    ends. It can't settle an answer that repeats: an HTML `403` and a 2xx with no data
    can come back for this session on every read, as can a `404` or the Akamai
    denial. Those reads exit 5 (a `404`, exit 4) and nothing renews, so a bad session
    stays stored until that new sign-in. `auth status` makes no request and reports a
    session with a refresh token as valid, so it settles nothing either.
  - Storing it can't mix up sessions. Site storage is cleared before Chrome starts, so
    the session can only be this sign-in's. A session already stored can't be replaced
    by accident: login refuses before the window opens without `--overwrite`. With
    `--overwrite`, an unverified session does replace it.
  - `auth login --stdin`, `--from-env` and `auth set-credential` don't do this. The
    value can be supplied again, so anything but a proven read stores nothing.
- Chrome is found at the standard install paths (Chrome, Chromium, Edge on
  macOS and Linux), or `NLNT_CHROME` names the binary, the same variable
  `scripts/nlnt-capture.mjs` reads. Windows has no standard path here, so it needs
  `NLNT_CHROME`. With no Chrome, the error points at the fallback below.
- The wait is 10 minutes. A timeout or a closed window is exit 3, Ctrl-C
  cancels (Chrome is stopped, a `--fresh-profile` scratch profile removed), and
  `-q` silences the status lines. `--fresh-profile` without `--browser` is exit 2. `--browser` refuses `--stdin`, `--from-env`, `--no-verify` and
  `--non-interactive` with exit 2, before the keychain is read or a window
  opens.

#### The DevTools fallback (`--stdin`)

For a machine without Chrome: sign in at `nelnet.studentaid.gov` in any
browser, copy the same value out by hand, and pipe it in:

```
# in the browser DevTools console, signed in at nelnet.studentaid.gov:
copy(localStorage['oidc.user:https://auth.nelnet.studentaid.gov:mma'])
# then:
pbpaste | nlnt auth login --stdin
```

Reloading the SPA while the IdP session cookie (`idsrv`) is still valid
silently mints a fresh bundle with no re-login or MFA, which is the easy way to
re-capture on this path.

### Unattended re-login (the capture-command hook)

For a hands-off setup, point the CLI at a **capture command** whose stdout is a
fresh bundle. When the stored refresh token is dead (or nothing is stored),
`auth refresh` — and automatic refresh on a 401 — run it instead of failing:

```
nlnt config set username you@example.com
# Omit -w so `security` prompts for the password on stdin — keeping it off argv
# (and out of shell history / `ps`), per SECURITY.md:
security add-generic-password -U -s piekstra.nlnt -a password
nlnt auth refresh --command "node /path/to/scripts/nlnt-capture.mjs" --save
```

`scripts/nlnt-capture.mjs` (reference implementation) drives the **real** Google
Chrome binary over CDP — not Playwright's Chromium, which Akamai rejects — using
a **persistent profile**. It tries the cheap path first:

1. **Silent renewal:** reload the SPA; while the `idsrv` cookie is valid,
   oidc-client mints a fresh bundle with no password and no MFA. This costs
   nothing — **but the window is short. Observed ~1 hour**, not the "remember
   this device" ~90 days (those are different cookies; see below). So this covers
   the next hour of use, not indefinitely.
2. **Full login:** once the `idsrv` session lapses — fill username/password, and
   an MFA code *unless the device is trusted* (`SaveTrustedDevice`, which the
   script ticks so future logins skip it). The code comes from
   `$NLNT_OTP_COMMAND` — a command that prints it. The script itself does **not**
   read email: pulling a code out of a mailbox is a cross-cutting concern (email
   + any CLI) that lives in a higher-level skill (`mfa-via-mail`, a gro-based
   reader), not in this provider's script. If no code can be obtained, the script
   **errors clearly rather than emitting a stale token** — it never lies about
   success.

> **Honesty about durability:** the "unattended" claim holds for the ~1 h silent
> window and, if the device-trust cookie is live, for password-only re-logins
> after that. Beyond that — or if the MFA code lands somewhere the OTP command
> can't read (e.g. the account holder's separate mailbox / an SMS) — a human
> must supply a code. The script fails loudly in that case; it does not return a
> dead token.

The command runner is provider-agnostic: any command that prints a bundle (or a
bare Bearer token) on stdout works. The password comes from the keychain or, as a
less-preferred fallback, `$NLNT_PASSWORD` — never argv; the reference script
writes only the bundle to stdout and all diagnostics to stderr. See the script
header for the full env knobs (`NLNT_USERNAME`, `NLNT_PASSWORD`,
`NLNT_KEYCHAIN_SERVICE`, `NLNT_KEYCHAIN_ACCOUNT`, `NLNT_CAPTURE_PROFILE`,
`NLNT_CAPTURE_HEADED`, `NLNT_CHROME`, `NLNT_PLAYWRIGHT_DIR`, `NLNT_OTP_COMMAND`).

**Stopping a capture.** `nlnt` stops a capture command after 5 minutes: SIGTERM, then
SIGKILL 20 s later. The reference script stays inside that: it gives up after 4
minutes, limits each `$NLNT_OTP_COMMAND` run to 15 s, and stops Chrome on SIGTERM. A
hard kill still skips its teardown, as does a `refresh_command` that is more than one
command, where only the shell gets the signal. That can leave its Chrome running on
the signed-in profile with the debugging port open (9455 unless
`NLNT_CAPTURE_PORT` says otherwise), so any local process can read the token bundle,
and its page can renew as a second holder of the family. Find it with
`lsof -iTCP:9455 -sTCP:LISTEN` and stop that process.

### Token lifetimes — what's measured, what isn't

| Value | How long | Provenance |
| --- | --- | --- |
| Access token | **900 s (15 min)** | MEASURED — `expires_in` from `/connect/token`, matches the bundle's `expires_at`. |
| Refresh token | rotates on every use; new one replaces the old | MEASURED — each refresh returns a fresh `refresh_token` and invalidates the prior. |
| Refresh token absolute lifetime | **not yet pinned** — see below | Duende defaults are 30 d absolute / 15 d sliding (REPORTED-typical, not confirmed for this deployment). |
| IdP session (`idsrv`) — the silent-renewal window | **~1 hour** | MEASURED — a capture ~1 h after login found the session lapsed (silent renewal returned only a stale token). This is what silent renewal depends on. |
| "Remember this device" (`SaveTrustedDevice`) — skips the MFA step on a full login | unknown; community guesses ~90 d | REPORTED. A **different** cookie from `idsrv`: it doesn't keep you silently renewing, it lets a password re-login skip the code. |

The refresh-token **absolute** lifetime can't be measured in one sitting. One
observation exists — a refresh token, minted and left unused, was rejected
(`invalid_grant`) about **an hour** later — but it is **not trustworthy** as the
lifetime, because two other holders of the same token *family* were in play
(the browser SPA doing its own silent renew, plus a reinstall in between).
Duende rotation ships with **refresh-token reuse detection**: presenting an
already-rotated token revokes the whole family, which would kill an otherwise
healthy token. So that hour is more likely a reuse-revocation than a TTL.

This is corroborated by a clean single-holder test: capturing a fresh bundle and
letting the CLI be the only holder, `auth refresh` and the capture-command
fallback both work — so the earlier hour was almost certainly a family
revocation from the competing browser, not the token's own TTL.

**Operational rule that follows:** after capture, the CLI should be the *sole*
holder of the bundle. Don't run `nlnt` refreshes concurrently against a browser
session still logged into the same account, or reuse detection can revoke the
family. Two `nlnt` processes cannot do this to each other: a grant runs under an
exclusive lock on `~/.config/nlnt/token-refresh.lock` (an empty file;
`pk_cli_auth::refresh_lock`), reads the session again once it holds the lock, and
posts no grant if another process already renewed. A wait is bounded at 75 s, then
exit 5 naming the lock, with nothing sent. A capture command runs outside that lock,
under `token-capture.lock` beside it, so one runs at a time and a login or logout
never waits on one. A process that finds it held waits for that capture and uses its
session; if it stored none, that process fails rather than spending another one-time
code. A capture is stopped after 5 minutes, exit 5, though anything it started may keep
running (§ Unattended re-login). The unattended capture script
sidesteps this by re-minting from the browser only when asked (a short-lived
headless launch that exits), rather than holding a competing refresh token; and
when a revocation *does* happen, the next command's capture-command fallback
silently re-mints, so it self-heals.

**On pinning the absolute number:** a background probe that refreshes on a timer
is deliberately **not** run here. Alongside normal `nlnt` use it would
occasionally race a real refresh and trip reuse detection, and each such
revocation looks exactly like an expiry — so the "measurement" would mostly
measure its own interference on a live account. A trustworthy number needs a
dedicated idle window with the CLI as sole holder; until someone runs that, the
absolute lifetime stays REPORTED-from-Duende-defaults. In practice it is moot:
with `refresh_command` configured the session self-heals regardless.

## The Akamai bot wall — it keys on client-hint headers

**CONFIRMED-LIVE, and the single most useful finding.** Both `mmaapi` and the
SPA host are fronted by Akamai. A plain HTTP client (curl, reqwest) gets a bare
`403 Access denied` **before the token is read** — a Chrome `User-Agent` alone
is not enough, and *even a real headless Chrome driven by Playwright is blocked*
(the automation fingerprint trips it).

But the wall is **not** TLS-fingerprint or cookie gated. It admits any client
that sends Chrome's **client-hint headers**. The minimal set, established by
bisection:

```
User-Agent: …Chrome/<major>…            (must match sec-ch-ua's version)
sec-ch-ua: "Chromium";v="<major>", …
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "macOS"
Sec-Fetch-Site: same-site               (same-origin for the token endpoint)
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
```

`sec-ch-ua` **and** `Sec-Fetch-*` must both be present; either alone is refused.
Cookies are not needed at all. `client::sentinel_headers` sends this set on every
request, so a plain reqwest client sails through. Consequences baked into the
code:

- A **403 whose body is the Akamai denial** (`Access denied`, `Reference #`) is
  reported as **upstream (exit 5)**, never as an auth failure — it happens before
  the token is considered, so "re-authenticate" would be wrong advice. So is any
  other 403 with an HTML page, whichever vendor's wording it uses, on the reasoning
  that the API answers JSON; no such page has been observed (**UNVERIFIED-LIVE**).
  An HTML 403 from the portal itself would read the same, so its error also says
  to run `nlnt auth login --browser --overwrite` if reads still fail after waiting
  or trying another network.
- Do **not** try to defeat this with a real browser at runtime; the header set is
  the sanctioned, tested path.

## Endpoint map — CONFIRMED-LIVE

Versioning is `/api/1`. Host is `mmaapi.nelnet.studentaid.gov`.

| Constant | Path | Feeds | Key fields |
| --- | --- | --- | --- |
| `OVERVIEW` | `/api/1/loan/overview` | `summary` | `outstandingPrincipal`, `accruedInterest`, `currentBalance`, `lastBumpDate` |
| `LOAN_SUMMARY` | `/api/1/loan/summary` | `summary` (enrich), `loans` | `federalAccounts[].borrowerGroupPayments[]` |
| `PAYMENT_HISTORY` | `/api/1/payment/history` | `transactions` | `paymentHistoryList[]` (`sumOfPaymentAmount/Principal/Interest/Fees`, `effectiveDate`) |
| `PAYMENT_SCHEDULED` | `/api/1/payment/scheduled` | `transactions --scheduled` | `scheduledPaymentsList[]` (same item shape, no applied split) |
| `REPAYMENT_OVERVIEW` | `/api/1/borrower/repayment/overview` | `repayment` | `statusDesc`, `hasOnlyInSchoolLoans`, `currentSchool`, `separationDate` |
| `IDR_STATUSES` | `/api/1/borrower/idr-application-statuses` | `repayment` | `[]` of `{requestDateTime, status, type}` |
| `AUTO_DEBIT` | `/api/1/auto-debit/summary` | `autopay` | `achFlag`, `nextCycleAmount/Date`, `standardAmount`, `bankName`, `processingStatus` (SSN/routing/full-account **not** surfaced) |
| `STATEMENTS` | `/api/1/statements` | `documents` | `statementList[]` (`documentId`, `documentTitle`, `docReceivedDate`, `letterType`, `isDirect`) |
| `statement_pdf(id, isDirect)` | `/api/1/statements/pdf/{documentId}/{isDirect}` | `documents download` | `application/pdf` (a real file) |
| `TAX_INFO` | `/api/1/tax/account-tax-info` | `tax` | `edServicerAccount.taxInfoDictionary.TaxDeductibleInterest` |

Other observed, unused paths: `/api/1/web-account` (profile, **not** balances —
an early wrong guess), `/api/1/loan/account-numbers`,
`/api/1/borrower/with-accounts`, `/api/1/borrower/profile/overview`,
`/api/1/payment/overview/true`, `/api/1/payment/methods`,
`/api/1/notification/*`. (The `borrower/repayment/overview`,
`borrower/idr-application-statuses`, and `auto-debit/summary` paths are now
**used** — see the table above.)

## The 1098-E is not a PDF — CONFIRMED

**Nelnet publishes no 1098-E file.** The portal's "Tax Info" page fills an HTML
template client-side from `/api/1/tax/account-tax-info` and calls
`window.print()`. There is no PDF and no filename convention.

`nlnt tax` surfaces the real figure as data:
`edServicerAccount.taxInfoDictionary.TaxDeductibleInterest` (a comma-grouped
string, e.g. `"1,812.34"`; the sibling numeric `taxDeductibleInterest` agrees).
It is a **running total as of `refreshDate`**, not a discrete-year form — for a
completed tax year the finalized 1098-E (end of January) is authoritative, and
the January billing statement carries the same total *and is a real PDF*.

The federal Direct Loan recipient/lender TIN is **52-1198289** (U.S. Department
of Education); `nlnt tax` prints it for filing. `commands::documents::undownloadable`
routes a request to download a 1098-E to `nlnt tax` rather than a failed file
fetch.

---

## Traps

Recorded so nobody re-derives them.

### `currentBalance` is inverted between endpoints

- On **`/api/1/loan/overview`**: `currentBalance` is the **total** (principal +
  accrued), and principal is `outstandingPrincipal`.
- On a **loan group** (`borrowerGroupPayments[]`): `currentBalance` is the
  **principal**, and the total is `outstandingBalance`.

Verified by the arithmetic (`currentBalance + accruedInterest == outstandingBalance`
at the group level). `parse::summary` and `parse::loans` therefore read
*different* keys for the same DTO field. A fixture test pins the invariant
`principal + accrued == payoff`.

### Money is JSON numbers; the tax dictionary is strings

Balances come back as JSON numbers (`1234.56`). The `taxInfoDictionary` uses
comma-grouped strings (`"1,812.34"`). `parse::money` accepts both. `loanType`
strings are space-padded (`"DIRECT SUB     "`) and must be trimmed.

### A 200 is not always success; a 403 is not always auth

The auth guard maps: Akamai-denial or HTML 403 (**UNVERIFIED-LIVE**) → upstream (5); other 401/403 → auth (3),
which triggers one refresh-and-retry; HTML where JSON was promised → upstream.

### The statement download needs `%PDF-`

`client::pdf_error` requires the `%PDF-` magic within the first kilobyte. Without
it an error/JSON body would be written to disk under a `.pdf` name with a "Saved"
message. Statements are real PDFs; the 1098-E is not a document at all.

### Refresh tokens rotate — persist the new bundle

Covered above. `Portal::refresh` writes the rotated bundle back before returning.

### One-time codes are spent in the browser, not by the CLI

MFA happens during the browser sign-in. The CLI never submits a code and cannot
lock the account: it only ever replays a Bearer token and exchanges a refresh
token. (The old cookie-form login, its MFA-parking machinery, and the lockout
hazard are gone.)

---

## Writes — catalogued, not implemented

`nlnt` is read-only. **No Nelnet write endpoint has been mapped, called, or
implemented**, `nlnt api` refuses any method but GET with exit 6, and `nlnt mcp`'s
tools read only the paths in `client::paths`. On a
federal student loan the write surface (make a payment, change autopay, change a
repayment plan, submit IDR recertification) moves real money and affects loan
terms. Anything implementing one must confirm its contract against live traffic
first, and must flip the read-only claims in `README.md`, `AGENTS.md`,
`CLAUDE.md` and `SECURITY.md` in the same commit.

## Re-capturing a fixture

`nlnt api GET <path> --json` once logged in prints the live response. Scrub it
per `tests/fixtures/README.md` (structure exact, values dummied, arrays trimmed,
`_fixture` marker kept) and move it in with the same commit that updates this
file.
