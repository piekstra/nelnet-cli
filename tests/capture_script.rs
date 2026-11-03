//! `scripts/nlnt-capture.mjs` runs only against a real browser and a real login,
//! so these hold its text to the two rules that keep a credential off stderr.

const SCRIPT: &str = include_str!("../scripts/nlnt-capture.mjs");

/// The text from `start` up to the next top-level `function`.
fn function_body(start: &str) -> &'static str {
    let from = SCRIPT
        .find(start)
        .unwrap_or_else(|| panic!("{start} is gone from the script"));
    let rest = &SCRIPT[from + start.len()..];
    let end = rest.find("\nasync function ").unwrap_or(rest.len());
    &rest[..end]
}

/// `execSync` puts the whole command in its error's message, its stack and its
/// `cmd`, and `$NLNT_OTP_COMMAND` is the owner's own command line. The handler's
/// code is pinned, so any other use of the error fails this.
#[test]
fn the_otp_commands_error_message_is_not_logged() {
    let body = function_body("async function fetchOtp");
    let (_, after_catch) = body.split_once("catch (e) {").expect("fetchOtp's catch");
    let (handler, _) = after_catch.split_once('}').expect("the catch's end");
    let code: Vec<&str> = handler
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .collect();
    assert_eq!(
        code,
        ["log('otp command failed:', e.status ?? e.signal ?? e.code ?? 'unknown');"]
    );
}

/// `main` logs the message of whatever reaches it, and the password and the
/// one-time code go through this `fill`. A handler that takes no argument can't
/// rethrow Playwright's error.
#[test]
fn a_failed_fill_does_not_reach_main_with_playwrights_message() {
    let body = function_body("async function fullLogin");
    assert!(
        body.contains(
            "await el.fill(value).catch(() => {\n          throw new Error(`could not fill ${s}`);"
        ),
        "{body}"
    );
}
