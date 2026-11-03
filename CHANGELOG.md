# Changelog

Earlier releases are described on the GitHub releases page.

## v0.2.0 — 2026-11-03

cli-common v0.17.0, which needs Rust 1.89: the browser sign-in keeps its Chrome
profile (v0.16.0).

- `nlnt auth login --browser` runs Chrome in a profile `nlnt` keeps on disk
  (`<data dir>/piekstra.nlnt/browser-profile`, owner-only), where it used to run
  in a scratch profile deleted after every sign-in. Nelnet's cookies carry over,
  so a later sign-in may need less input. The trade is a full Chrome profile on
  disk: cookies, and history with query strings, HTTP cache and site storage,
  which Chrome's cookie encryption does not cover, and on Linux with no desktop
  keyring that encryption uses a publicly known key (SECURITY.md). How much input
  it saves is unverified against the live portal.
- Any sign-in that fails once the window has opened now says the kept profile
  stays, possibly with a live session, and that `nlnt auth logout` removes it.
- The capture now removes the token bundle from `localStorage` as it reads it,
  and removes without reading one already past its `expires_at`. Refresh tokens
  rotate with reuse detection, so a copy left in the kept profile could revoke
  the CLI's session (docs/api.md § Token lifetimes).
- `nlnt auth login --browser --fresh-profile` signs in once through a scratch
  profile, deleted afterwards, leaving the kept one alone. A failed login's
  retry command repeats the flag.
- `nlnt auth logout` also removes the kept profile, as its last step. It attempts
  every step even when one fails. If one fails, or a sign-in or a Chrome window is
  using the profile, it exits with the first failure's code, and the message says
  what was cleared, what remains and how to finish.
