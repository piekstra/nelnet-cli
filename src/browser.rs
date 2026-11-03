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
//! would present it and revoke the CLI's whole token family. So the profile
//! keeps the cookies and never the tokens.

use pk_cli_browser::{BrowserError, Capture, HostRule, Launch, DEFAULT_TIMEOUT};
use pk_cli_core::CliError;
use pk_cli_secrets::Secret;

use crate::BIN;

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
pub fn session_capture() -> Result<Capture, CliError> {
    Ok(Capture::new("Nelnet", HostRule::exact(SPA_HOST)?)
        .expression(expression())
        .hint("username, password and the one-time code"))
}

/// Open the sign-in window at [`START_URL`], wait for the owner to sign in,
/// and return the captured bundle, unparsed. `fresh_profile` signs in through
/// a scratch profile rather than the kept one; `login_hint` is the command the
/// timeout and closed-window errors tell the owner to re-run.
pub fn capture_session(
    quiet: bool,
    fresh_profile: bool,
    login_hint: &str,
) -> Result<Secret, CliError> {
    let captured = pk_cli_browser::capture(
        Launch::new(BIN)
            .url(START_URL)
            .fresh_profile(fresh_profile)
            .quiet(quiet)
            .login_hint(login_hint),
        &session_capture()?,
        DEFAULT_TIMEOUT,
    )
    .map_err(browser_error)?;
    captured
        .into_value()
        .ok_or_else(|| CliError::Other("the browser capture read no session".into()))
}

/// Without Chrome, point at the manual path instead of a dead end.
fn browser_error(e: BrowserError) -> CliError {
    match e {
        BrowserError::ChromeNotFound(m) => CliError::Other(format!(
            "{m}; or sign in at {START_URL} in any browser and import the session by hand \
             (`{BIN} auth login --help`)"
        )),
        other => other.into(),
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
        let e = browser_error(BrowserError::ChromeNotFound("no Chrome found".into()));
        assert_eq!(e.exit_code(), 1);
        let m = e.to_string();
        assert!(m.starts_with("no Chrome found"), "{m}");
        assert!(m.contains("nlnt auth login --help"), "{m}");
    }

    #[test]
    fn a_timeout_keeps_the_family_exit_code() {
        let e = browser_error(BrowserError::TimedOut("timed out".into()));
        assert_eq!(e.exit_code(), 3);
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
