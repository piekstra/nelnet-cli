# CLAUDE.md

The canonical guide for this repo is **[AGENTS.md](AGENTS.md)**. Read it first.

Five things that bite hardest here:

1. **`make verify` is the gate** — fmt-check, lint, test, smoke. Green before
   anything merges.
2. **Tests are offline, always.** No test may touch the network or the keychain.
   MFA happens in the browser during the one-time token capture; the CLI only
   replays a Bearer token and refreshes it, so it cannot spend a code or lock the
   account. Dogfood live changes through the **installed** binary.
3. **Endpoints and field names are CONFIRMED-LIVE** (`docs/api.md`), and the
   fixtures are scrubbed real captures. Do not "fix" a parse failure by
   defaulting the missing figure to zero — a fabricated `$0.00` accrued interest
   reads as good news in the very workflow this CLI exists for. Watch the
   `currentBalance` inversion between `/loan/overview` and a loan group.
4. **Read-only is enforced in three places that must stay in agreement**: the
   `api` non-GET guard (exit 6), the absence of any write command, and the
   claims in README/AGENTS/SECURITY. Change them together or not at all.
5. **Auth is OAuth2 Bearer behind Akamai.** `client::sentinel_headers` is what
   passes the bot wall; an Akamai-denial 403 is upstream (5), not auth (3).
   Refresh tokens rotate — persist the new bundle. The `%PDF-` check in
   `client::pdf_error` is the download's only positive confirmation; never relax it.
