# Fixtures

## Scrubbed captures — real shapes, dummy values

Each file here mirrors the **structure** of a real authenticated response from
`mmaapi.nelnet.studentaid.gov` (captured 2026-08-12, see `docs/api.md`), or of
the session the SPA stores (`oidc_user.json`), with
**every identifying or financial value replaced by an obvious dummy**. The
structure is the value: keys, nesting, types and null-vs-absent are preserved so
a provider rename fails loudly in `fixture_shapes.rs` instead of silently
emptying a column. The numbers are fictional and prove nothing about any real
account.

The large repeating arrays in the real responses (16 loan groups, 17 loans, 13
payments) are trimmed to one or two representative entries — enough to exercise
the list parsers without carrying bulk.

| File | Stands in for | Read by |
| --- | --- | --- |
| `overview.json` | `/api/1/loan/overview` | `parse::summary` (core figures) |
| `loan_summary.json` | `/api/1/loan/summary` | `parse::summary` (enrichment), `parse::loans` |
| `payment_history.json` | `/api/1/payment/history` | `parse::transactions` |
| `statements.json` | `/api/1/statements` | `parse::documents` |
| `tax_info.json` | `/api/1/tax/account-tax-info` | `parse::tax` |
| `repayment_overview.json` | `/api/1/borrower/repayment/overview` | `parse::repayment` |
| `idr_statuses.json` | `/api/1/borrower/idr-application-statuses` | `parse::repayment` |
| `auto_debit.json` | `/api/1/auto-debit/summary` | `parse::autopay` (banking PII → dummies) |
| `payment_scheduled.json` | `/api/1/payment/scheduled` | `parse::scheduled_payments` |
| `oidc_user.json` | the SPA's `localStorage['oidc.user:…']` value that `auth login --browser` captures (keys as recorded in `docs/api.md` § Auth) | `client::Session::parse_captured`, via the `browser` unit tests |

Every fixture carries the literal marker `SYNTHETIC-FIXTURE-NOT-A-REAL-CAPTURE`
(a JSON `_fixture` key). `tests/fixture_shapes.rs` asserts its presence in every
file, so a raw capture dropped in here fails the suite immediately rather than
being committed. Parsers ignore the extra key.

## Scrubbing policy

Preserve structure exactly; replace with obvious dummies:

- Names, emails, phone numbers, addresses → `JANE`, `DOE`, `user@example.com`,
  `000 EXAMPLE ST`, `000-000-0000`.
- Account numbers, borrower ids, group ids → `000000000000`, `0000000001`.
- Every UUID (e.g. `documentId`) → must start with `00000000-`. The test
  enforces this **positively**: any UUID not starting with eight zeros fails, so
  a real one cannot slip through.
- All dollar amounts → repdigit values (`11111.11`, `222.22`) that are obviously
  synthetic at a glance, while preserving the arithmetic invariants a parser
  asserts (principal + accrued == payoff).
- The `tax_info.json` `SSN` → a masked non-numeric dummy (`XXX-XX-0000`). The
  real servicer already masks it, and the hygiene test rejects any `ddd-dd-dddd`
  shape outright. **Never commit a 1098-E PDF**, scrubbed or not.

Never commit:

- A raw capture, "just to scrub it later." `.gitignore` excludes `*.raw.json`,
  `*.raw.html`, `*.har` as a backstop.
- `Authorization: Bearer …` values, `Set-Cookie` headers, or a real OAuth token
  bundle — these are live credentials. `oidc_user.json` keeps the bundle's keys
  with every token a `DUMMY-…` placeholder; the hygiene test requires that of
  every `*_token` value and rejects anything JWT-shaped (`eyJ…`).
- A statement or 1098-E PDF download from a live session.

The scrub test is written as **patterns and positive shape rules**, never as a
denylist of the household's real names and account numbers — a denylist would
publish in the repo exactly what it exists to keep out. Extend it whenever a new
kind of identifier appears.

## Refreshing a fixture

1. Capture during a real session (DevTools → Network → the `mmaapi` XHR, or
   `nlnt api GET <path>` once logged in). Save it **outside** the repo.
2. Scrub per the rules above; keep the `_fixture` marker; trim bulky arrays.
3. Move it in, run `cargo test`, and update the table above plus `docs/api.md`
   in the same commit.
