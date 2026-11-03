//! `auth login --browser`: the portal session read out of a sign-in window
//! (`pk-cli-browser`, cli-common DESIGN.md §2.2).
//!
//! The owner signs in at the SPA in a Chrome running in the profile the crate
//! keeps for this CLI, so the identity host's cookies (its remembered device,
//! its session) carry over to the next sign-in. The password and the one-time
//! code go to Nelnet's own pages, the Akamai-protected identity host included;
//! this module never reads from or navigates to that host. Once the SPA has
//! stored its token bundle, the capture reads it from the SPA host's
//! `localStorage` (the value the DevTools fallback copies by hand) and closes
//! the tab before the SPA can renew, and so rotate, the refresh token it just
//! handed over. The value then takes the same path as a `--stdin` import:
//! `Session::parse_captured`, one verifying read, the keychain.
//!
//! The read also **removes the bundle from `localStorage`**, because the
//! profile outlives the window. Refresh tokens rotate with reuse detection
//! (`docs/api.md` § Token lifetimes): a copy left in the profile goes stale at
//! the CLI's next refresh, and the next window would hand it over, or the SPA
//! would present it and revoke the CLI's whole token family.
//!
//! That covers the bundle and nothing else. It is a full Chrome profile, kept
//! until `auth logout`, a failed sign-in included: besides the cookies it holds
//! browsing history with full URLs, query strings included (so the sign-in's
//! OIDC redirects, with their authorization code and state), the HTTP cache and
//! site storage. Chrome's cookie encryption does not cover those, so `0700` is
//! their only protection. On Linux with no desktop keyring Chrome encrypts
//! cookies with a fixed, publicly known key, so there `0700` is all that protects
//! the `idsrv` cookie too.

use pk_cli_browser::{BrowserError, Capture, HostRule, Launch, DEFAULT_TIMEOUT};
use pk_cli_core::CliError;
use pk_cli_secrets::Secret;

use crate::BIN;

/// What a failed sign-in leaves behind, for its error. The kept profile stays
/// with whatever the sign-in got as far as. The later the failure, the likelier
/// that is a live session: a refused verifying read or a failed keychain write
/// comes after the owner signed in.
const PROFILE_STAYS: &str = "The browser profile stays on disk with what this sign-in left in it, \
                             possibly a live session; `nlnt auth logout` removes it and clears \
                             any stored session with it, and `--fresh-profile` signs in without \
                             it.";

/// The page the sign-in window opens at. The SPA sends the owner on to the
/// identity host to sign in and stores the bundle once it is back.
pub const START_URL: &str = "https://nelnet.studentaid.gov";

/// The one host the capture reads from: the SPA, whose origin holds the
/// bundle. Never the identity host, where the bot checks run.
pub const SPA_HOST: &str = "nelnet.studentaid.gov";

/// The `localStorage` key the SPA's OIDC client keeps the token bundle under:
/// `oidc.user:<authority>:<client id>`.
pub const SESSION_STORAGE_KEY: &str = "oidc.user:https://auth.nelnet.studentaid.gov:mma";

/// The in-page expression: the stored bundle once it holds an access token,
/// `null` before. Signed out, the key is absent, so the token is the
/// readiness signal (the tab is closed the moment a value is read, so a
/// premature read could not be retried).
///
/// It takes the bundle out of `localStorage` as it reads it, so the kept
/// profile holds no copy of the token family (the module docs say why). A
/// bundle already past its `expires_at` is one an earlier sign-in left, so it
/// is removed and not handed over, and the wait goes on for a new one. A value
/// that is not JSON is handed over for `Session::parse_captured` to refuse by
/// name.
pub fn expression() -> String {
    let key = serde_json::to_string(SESSION_STORAGE_KEY).expect("a str serializes");
    format!(
        "(() => {{ const v = localStorage.getItem({key}); \
         if (!v || !v.includes('access_token')) return null; \
         localStorage.removeItem({key}); \
         let exp; try {{ exp = JSON.parse(v).expires_at; }} catch {{}} \
         return typeof exp === 'number' && exp * 1000 <= Date.now() ? null : v; }})()"
    )
}

/// What the browser login reads: [`expression`] in pages on [`SPA_HOST`].
pub fn session_capture() -> Result<Capture, BrowserError> {
    Ok(Capture::new("Nelnet", HostRule::exact(SPA_HOST)?)
        .expression(expression())
        .hint("username, password and the one-time code"))
}

/// The whole browser sign-in: open the window, read the bundle, and hand it to
/// `store` to parse, verify and keep. The only way in, so that any failure from
/// the window opening onwards, `store`'s included, goes through
/// [`failed_sign_in`].
pub fn sign_in(
    quiet: bool,
    fresh_profile: bool,
    login_hint: &str,
    store: impl FnOnce(&Secret) -> Result<(), CliError>,
) -> Result<(), CliError> {
    finish_sign_in(fresh_profile, || {
        let raw = capture_session(quiet, fresh_profile, login_hint)?;
        store(&raw).map_err(BrowserError::Handler)
    })
}

/// Run a sign-in, turning any failure into the error [`failed_sign_in`] words.
pub fn finish_sign_in<T>(
    fresh_profile: bool,
    sign_in: impl FnOnce() -> Result<T, BrowserError>,
) -> Result<T, CliError> {
    sign_in().map_err(|e| failed_sign_in(e, fresh_profile))
}

/// Open the sign-in window at [`START_URL`], wait for the owner to sign in,
/// and return the captured bundle, unparsed. `fresh_profile` signs in through
/// a scratch profile rather than the kept one; `login_hint` is the command the
/// timeout and closed-window errors tell the owner to re-run.
fn capture_session(
    quiet: bool,
    fresh_profile: bool,
    login_hint: &str,
) -> Result<Secret, BrowserError> {
    let captured = pk_cli_browser::capture(
        Launch::new(BIN)
            .url(START_URL)
            .fresh_profile(fresh_profile)
            .quiet(quiet)
            .login_hint(login_hint),
        &session_capture()?,
        DEFAULT_TIMEOUT,
    )?;
    captured.into_value().ok_or_else(|| {
        BrowserError::Handler(CliError::Other(
            "the browser capture read no session".into(),
        ))
    })
}

/// The family's error for a failed sign-in, with [`PROFILE_STAYS`] added when
/// the failure leaves a kept profile. A scratch profile is gone by now. The
/// refusals from before Chrome runs leave nothing new, and `auth logout` could
/// not remove a profile needing repair. A new crate error gets the note. The
/// exit code is unchanged. Without Chrome, it points at the manual path instead
/// of a dead end.
fn failed_sign_in(error: BrowserError, fresh_profile: bool) -> CliError {
    let refused_before_the_window = match &error {
        BrowserError::ChromeNotFound(m) => {
            return CliError::Other(format!(
                "{m}; or sign in at {START_URL} in any browser and import the session by hand \
                 (`{BIN} auth login --help`)"
            ))
        }
        BrowserError::Invalid(_) | BrowserError::Profile(_) | BrowserError::ProfileInUse(_) => true,
        _ => false,
    };
    let cli_error = CliError::from(error);
    if fresh_profile || refused_before_the_window {
        return cli_error;
    }
    let noted = |m: String| {
        let stop = if m.ends_with('.') { " " } else { ". " };
        format!("{m}{stop}{PROFILE_STAYS}")
    };
    match cli_error {
        CliError::Usage(m) => CliError::Usage(noted(m)),
        CliError::Auth(m) => CliError::Auth(noted(m)),
        CliError::NotFound(m) => CliError::NotFound(noted(m)),
        CliError::Upstream(m) => CliError::Upstream(noted(m)),
        CliError::ConfirmationRequired(m) => CliError::ConfirmationRequired(noted(m)),
        CliError::Keychain(m) => CliError::Keychain(noted(m)),
        CliError::Other(m) => CliError::Other(noted(m)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Session, OAUTH_CLIENT_ID};
    use crate::config::DEFAULT_AUTH_URL;

    #[test]
    fn the_capture_is_well_formed() {
        session_capture()
            .expect("the host rule parses")
            .validate()
            .expect("the capture validates");
    }

    #[test]
    fn the_capture_reads_the_spa_host_only() {
        let rule = HostRule::exact(SPA_HOST).unwrap();
        assert!(!rule.includes_subdomains());
        assert!(rule.matches_url(START_URL));
        assert!(rule.matches_url("https://nelnet.studentaid.gov/dashboard"));
        // The identity host (Akamai, the bot checks) and the API host are
        // never read from.
        assert!(!rule.matches_url("https://auth.nelnet.studentaid.gov/Account/Login"));
        assert!(!rule.matches_url("https://mmaapi.nelnet.studentaid.gov/api/1/loan/overview"));
        assert!(!rule.matches_url("http://nelnet.studentaid.gov/"));
    }

    /// The key is the SPA's OIDC client's: its authority and client id are
    /// the identity host and the client id the refresh grant uses.
    #[test]
    fn the_storage_key_names_the_identity_host_and_client() {
        assert_eq!(
            SESSION_STORAGE_KEY,
            format!("oidc.user:{DEFAULT_AUTH_URL}:{OAUTH_CLIENT_ID}")
        );
    }

    #[test]
    fn the_expression_takes_the_key_and_waits_for_a_live_token() {
        assert_eq!(
            expression(),
            "(() => { const v = localStorage.getItem(\
             \"oidc.user:https://auth.nelnet.studentaid.gov:mma\"); \
             if (!v || !v.includes('access_token')) return null; \
             localStorage.removeItem(\
             \"oidc.user:https://auth.nelnet.studentaid.gov:mma\"); \
             let exp; try { exp = JSON.parse(v).expires_at; } catch {} \
             return typeof exp === 'number' && exp * 1000 <= Date.now() ? null : v; })()"
        );
    }

    #[test]
    fn a_missing_chrome_points_at_the_manual_path() {
        let e = failed_sign_in(
            BrowserError::ChromeNotFound("no Chrome found".into()),
            false,
        );
        assert_eq!(e.exit_code(), 1);
        let m = e.to_string();
        assert!(m.starts_with("no Chrome found"), "{m}");
        assert!(m.contains("nlnt auth login --help"), "{m}");
    }

    #[test]
    fn a_timeout_keeps_the_family_exit_code() {
        let e = failed_sign_in(BrowserError::TimedOut("timed out.".into()), true);
        assert_eq!(e.exit_code(), 3);
        // A scratch profile is already gone, so there is nothing to mention.
        assert_eq!(e.to_string(), "timed out.");
    }

    /// Every failure from the window opening onwards, each with its own exit
    /// code: the crate's and the store step's.
    fn failures_after_the_window_opens() -> Vec<(BrowserError, i32)> {
        vec![
            (BrowserError::TimedOut("timed out.".into()), 3),
            (BrowserError::WindowClosed("closed.".into()), 3),
            (BrowserError::Canceled, 1),
            (BrowserError::Launch("Chrome stalled".into()), 1),
            (BrowserError::Handler(CliError::Auth("refused".into())), 3),
            (
                BrowserError::Handler(CliError::Upstream("HTTP 503".into())),
                5,
            ),
            (
                BrowserError::Handler(CliError::Keychain("store failed".into())),
                1,
            ),
        ]
    }

    #[test]
    fn a_failed_sign_in_says_the_kept_profile_stays() {
        for (error, code) in failures_after_the_window_opens() {
            let e = finish_sign_in(false, || -> Result<(), _> { Err(error) }).unwrap_err();
            assert_eq!(e.exit_code(), code, "{e}");
            let m = e.to_string();
            assert!(m.contains("browser profile stays on disk"), "{m}");
            assert!(m.contains("possibly a live session"), "{m}");
            assert!(m.contains("`nlnt auth logout` removes it"), "{m}");
        }
    }

    #[test]
    fn a_fresh_profile_failure_does_not_mention_the_kept_profile() {
        for (error, code) in failures_after_the_window_opens() {
            let e = finish_sign_in(true, || -> Result<(), _> { Err(error) }).unwrap_err();
            assert_eq!(e.exit_code(), code, "{e}");
            assert!(!e.to_string().contains("stays on disk"), "{e}");
        }
    }

    /// Refused before Chrome ran, so nothing new was left. `auth logout` could
    /// not remove a profile needing repair, so the note would be wrong for it.
    #[test]
    fn a_refusal_before_the_window_does_not_mention_the_kept_profile() {
        let refusals = [
            BrowserError::Invalid("bad capture".into()),
            BrowserError::ChromeNotFound("no Chrome".into()),
            BrowserError::Profile("x is a symlink".into()),
            BrowserError::ProfileInUse("x is in use".into()),
        ];
        for refusal in refusals {
            let e = failed_sign_in(refusal, false);
            assert!(!e.to_string().contains("stays on disk"), "{e}");
        }
    }

    #[test]
    fn a_finished_sign_in_passes_through() {
        assert_eq!(finish_sign_in(false, || Ok(7)).unwrap(), 7);
    }

    /// The readiness signal and the parser agree: what the expression lets
    /// through (a bundle holding `access_token`) is what `parse_captured`
    /// accepts, and it yields the tokens and expiry the CLI stores.
    #[test]
    fn a_captured_bundle_goes_through_the_stdin_parser() {
        let path = format!(
            "{}/tests/fixtures/oidc_user.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).expect("fixture");
        assert!(raw.contains("access_token"));
        let s = Session::parse_captured(&raw).expect("the bundle parses");
        assert_eq!(s.access_token, "DUMMY-ACCESS-TOKEN");
        assert_eq!(s.refresh_token.as_deref(), Some("DUMMY-REFRESH-TOKEN"));
        assert_eq!(s.id_token.as_deref(), Some("DUMMY-ID-TOKEN"));
        assert_eq!(s.expires_at, Some(2_000_000_000));
    }
}
