//! Black-box tests over the built binary.
//!
//! Every test here is **offline and keychain-free**. That is not incidental:
//! reaching the keychain would prompt, and reaching Nelnet needs a captured
//! session token. Each case below is chosen because it fails (or renders)
//! *before* any credential or network access — which is itself the property
//! being tested, since SPEC requires argument validation to happen first.

use assert_cmd::Command;

fn nlnt() -> Command {
    Command::cargo_bin("nlnt").expect("binary builds")
}

/// Every top-level command. Reused by three tests, so a rename trips them.
const COMMANDS: &[&str] = &[
    "auth",
    "config",
    "summary",
    "loans",
    "transactions",
    "repayment",
    "autopay",
    "tax",
    "documents",
    "api",
    "self-update",
    "completions",
    "info",
];

#[test]
fn top_level_help_lists_the_surface() {
    let out = nlnt().arg("--help").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    for cmd in COMMANDS {
        assert!(stdout.contains(cmd), "`--help` does not mention `{cmd}`");
    }
}

/// Rendering a subcommand's help forces clap's debug assertions to run over
/// that subtree, which is what catches a subcommand flag colliding with a
/// global like `-q`/`--quiet`.
#[test]
fn every_subcommand_help_renders() {
    for cmd in COMMANDS {
        nlnt().args([cmd, "--help"]).assert().success();
    }
}

#[test]
fn nested_subcommand_help_renders() {
    let nested = [
        ("auth", "login"),
        ("auth", "refresh"),
        ("auth", "status"),
        ("auth", "logout"),
        ("auth", "set-credential"),
        ("config", "path"),
        ("config", "show"),
        ("config", "set"),
        ("config", "unset"),
        ("loans", "list"),
        ("loans", "get"),
        ("transactions", "list"),
        ("documents", "list"),
        ("documents", "download"),
    ];
    for (group, sub) in nested {
        nlnt().args([group, sub, "--help"]).assert().success();
    }
}

#[test]
fn list_subcommands_all_have_the_ls_alias() {
    for group in ["loans", "transactions", "documents"] {
        let out = nlnt().args([group, "--help"]).assert().success();
        let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
        assert!(
            stdout.contains("ls"),
            "`{group} list` is missing the `ls` alias"
        );
    }
}

#[test]
fn version_prints_the_crate_version() {
    let out = nlnt().arg("--version").assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn unknown_command_is_a_usage_error() {
    nlnt().arg("definitely-not-a-command").assert().code(2);
}

#[test]
fn info_reports_the_cli_contract() {
    let out = nlnt().arg("info").assert().success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("info emits JSON");
    assert_eq!(v["schema"], "cli-info/v1");
    assert_eq!(v["name"], "nlnt");
    assert_eq!(v["spec"], "piekstra-cli/1");
    assert_eq!(v["auth"]["required"], true);
    assert_eq!(v["auth"]["method"], "browser-session");
    assert_eq!(v["auth"]["login_hint"], "nlnt auth login --browser");

    let caps: Vec<String> = v["capabilities"]
        .as_array()
        .expect("capabilities is an array")
        .iter()
        .map(|c| c.as_str().unwrap_or_default().to_string())
        .collect();
    for expected in [
        "summary",
        "loans",
        "transactions",
        "repayment",
        "autopay",
        "tax",
        "documents",
    ] {
        assert!(caps.iter().any(|c| c == expected), "missing cap {expected}");
    }

    // The documents/v1 profile is what lets the archiver call this CLI with no
    // per-provider adapter, so the declaration is part of the contract.
    let profiles: Vec<String> = v["profiles"]
        .as_array()
        .expect("profiles is an array")
        .iter()
        .map(|c| c.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(profiles.iter().any(|p| p == "documents/v1"));
}

#[test]
fn completions_render_for_every_supported_shell() {
    for shell in ["bash", "zsh", "fish"] {
        nlnt().args(["completions", shell]).assert().success();
    }
}

#[test]
fn no_color_in_the_environment_never_fails_a_command() {
    // Any non-empty NO_COLOR disables color, per no-color.org; read as a
    // clap boolean, NO_COLOR=1 was a usage error on every command.
    for v in ["1", "true", "0", ""] {
        nlnt()
            .env("NO_COLOR", v)
            .args(["completions", "bash"])
            .assert()
            .success();
    }
}

// ---------------------------------------------------------------------------
// Argument validation happens before any keychain or network access
// ---------------------------------------------------------------------------

#[test]
fn inverted_date_range_is_a_usage_error() {
    for group in ["loans", "transactions", "documents"] {
        nlnt()
            .args([
                group,
                "list",
                "--since",
                "2026-06-01",
                "--until",
                "2026-01-01",
            ])
            .assert()
            .code(2);
    }
}

#[test]
fn non_iso_dates_are_a_usage_error() {
    nlnt()
        .args(["transactions", "list", "--since", "06/01/2026"])
        .assert()
        .code(2);
}

#[test]
fn an_implausible_tax_year_is_a_usage_error() {
    nlnt()
        .args(["documents", "list", "--tax-year", "1200"])
        .assert()
        .code(2);
}

#[test]
fn download_without_an_id_or_all_is_a_usage_error() {
    nlnt().args(["documents", "download"]).assert().code(2);
}

#[test]
fn batch_download_to_stdout_is_a_usage_error() {
    nlnt()
        .args(["documents", "download", "--all", "-o", "-"])
        .assert()
        .code(2);
}

#[test]
fn json_and_stdout_download_conflict_is_a_usage_error() {
    nlnt()
        .args(["--json", "documents", "download", "abc", "-o", "-"])
        .assert()
        .code(2);
}

/// The read-only promise: `api` refuses to mutate, with exit 6 to say the
/// refusal is policy rather than a syntax mistake. Lowercased too, so casing
/// is not a bypass.
#[test]
fn api_refuses_to_write() {
    for method in ["POST", "post", "PUT", "DELETE"] {
        let out = nlnt().args(["api", method, "/anything"]).assert().code(6);
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        assert!(
            stderr.contains("read-only"),
            "the refusal should say why: {stderr}"
        );
    }
}

// ---------------------------------------------------------------------------
// auth login --browser
// ---------------------------------------------------------------------------

/// `nlnt` with a Chrome that cannot exist, so a regression that got as far as
/// launching one fails fast instead of opening a window.
fn nlnt_without_chrome() -> Command {
    let mut cmd = nlnt();
    cmd.env("NLNT_CHROME", "/nonexistent/nlnt-test-chrome");
    cmd
}

#[test]
fn login_help_leads_with_the_browser() {
    let out = nlnt().args(["auth", "login", "--help"]).assert().success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    // The flag, with the family's description of it.
    assert!(stdout.contains("--browser"), "{stdout}");
    assert!(
        stdout.contains("Sign in through a Chrome window"),
        "{stdout}"
    );
    // The browser path is the primary one; the DevTools paste is the fallback.
    let browser = stdout
        .find("nlnt auth login --browser")
        .expect("the help shows the browser login");
    let stdin = stdout
        .find("nlnt auth login --stdin")
        .expect("the help keeps the DevTools fallback");
    assert!(
        browser < stdin,
        "the browser path should come first:\n{stdout}"
    );
    assert!(stdout.contains("oidc.user:https://auth.nelnet.studentaid.gov:mma"));

    let short = nlnt().args(["auth", "login", "-h"]).assert().success();
    let short = String::from_utf8_lossy(&short.get_output().stdout).to_string();
    assert!(short.contains("--browser"), "{short}");
    assert!(short.contains("--fresh-profile"), "{short}");
}

/// `--fresh-profile` chooses the browser's profile, so it means nothing without
/// `--browser`: a usage error before the keychain is read or a window opens.
#[test]
fn fresh_profile_requires_the_browser() {
    let out = nlnt_without_chrome()
        .args(["auth", "login", "--fresh-profile"])
        .write_stdin("")
        .assert()
        .code(2);
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(stderr.contains("--browser"), "{stderr}");
    assert!(!stderr.contains("NLNT_CHROME"), "{stderr}");
}

/// `--browser` takes the session from the window, always verifies it and
/// waits on a person, so another source, `--no-verify` and
/// `--non-interactive` are usage errors, refused before the keychain is read
/// or a window opens.
#[test]
fn browser_login_refuses_conflicting_flags() {
    let cases: [&[&str]; 4] = [
        &["--stdin"],
        &["--from-env", "NLNT_TEST_SESSION"],
        &["--no-verify"],
        &["--non-interactive"],
    ];
    for extra in cases {
        let mut args = vec!["auth", "login", "--browser"];
        args.extend_from_slice(extra);
        let out = nlnt_without_chrome()
            .args(&args)
            .write_stdin("")
            .assert()
            .code(2);
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        assert!(
            stderr.contains("--browser"),
            "`{args:?}` should explain the conflict: {stderr}"
        );
        assert!(
            !stderr.contains("NLNT_CHROME"),
            "`{args:?}` got as far as looking for Chrome: {stderr}"
        );
    }
}

#[test]
fn browser_login_conflict_is_one_json_error_dto() {
    let out = nlnt_without_chrome()
        .args(["--json", "auth", "login", "--browser", "--stdin"])
        .write_stdin("")
        .assert()
        .code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is one JSON document");
    assert_eq!(v["error"]["code"], "usage");
}

#[test]
fn unknown_config_key_is_a_usage_error() {
    nlnt()
        .args(["config", "set", "not-a-key", "value"])
        .assert()
        .code(2);
}

#[test]
fn config_path_needs_no_session() {
    nlnt().args(["config", "path"]).assert().success();
}

// ---------------------------------------------------------------------------
// Output contract
// ---------------------------------------------------------------------------

#[test]
fn json_mode_emits_exactly_one_error_dto_on_failure() {
    let out = nlnt()
        .args(["--json", "transactions", "list", "--since", "nonsense"])
        .assert()
        .code(2);
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).to_string();

    // Exactly one JSON document — a second would break every consumer.
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is one JSON document");
    assert_eq!(v["error"]["code"], "usage");
    assert!(v["error"]["message"].is_string());

    // The human message goes to stderr, not stdout.
    let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
    assert!(stderr.contains("error:"));
}

/// Error messages routinely name a command to run next. A rename that misses
/// one sends the user to a command that does not exist.
#[test]
fn error_messages_only_reference_real_commands() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["documents", "download"],
        vec!["documents", "download", "--all", "-o", "-"],
        vec!["api", "POST", "/x"],
        vec!["config", "set", "nope", "v"],
        vec!["transactions", "list", "--since", "nope"],
        vec!["auth", "login", "--browser", "--stdin"],
        vec!["auth", "login", "--browser", "--no-verify"],
    ];
    for args in cases {
        let out = nlnt_without_chrome().args(&args).assert().failure();
        let stderr = String::from_utf8_lossy(&out.get_output().stderr).to_string();
        for mention in stderr.split("nlnt ").skip(1) {
            let suggested: String = mention
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-')
                .collect();
            if suggested.is_empty() {
                continue;
            }
            assert!(
                COMMANDS.contains(&suggested.as_str()),
                "error for `{args:?}` suggests `nlnt {suggested}`, which is not a command:\n{stderr}"
            );
        }
    }
}
