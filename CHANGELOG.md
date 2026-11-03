# Changelog

Earlier releases are described on the GitHub releases page.

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
