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

/// `execSync` puts the whole command in its error's message, and
/// `$NLNT_OTP_COMMAND` is the owner's own command line.
#[test]
fn the_otp_commands_error_message_is_not_logged() {
    let body = function_body("async function fetchOtp");
    assert!(body.contains("catch (e)"), "{body}");
    assert!(!body.contains("e.message"), "{body}");
}

/// `main` logs the message of whatever reaches it, and the password and the
/// one-time code go through this `fill`.
#[test]
fn a_failed_fill_does_not_reach_main_with_playwrights_message() {
    let body = function_body("async function fullLogin");
    assert!(body.contains("el.fill(value).catch("), "{body}");
    assert!(!body.contains("await el.fill(value);"), "{body}");
}
