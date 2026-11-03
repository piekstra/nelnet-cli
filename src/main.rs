//! `nlnt` — the Nelnet federal student-loan servicing portal from the command
//! line. Conforms to `piekstra-cli/1`. Read-only. Unofficial.

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserArgs, BrowserError};
use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{output, CliError, CommonArgs};
use pk_cli_http::ApiArgs;
use pk_cli_secrets::CredentialStore;
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};

use nlnt::client::{self, Session};
use nlnt::commands::{autopay, documents, loans, repayment, summary, tax, transactions, Ctx};
use nlnt::config::{Config, SESSION_ACCOUNT};
use nlnt::{BIN, REPO};

/// Nelnet student-loan servicing from the command line — balances, accrued
/// interest, payment history, and the yearly 1098-E. Read-only. Unofficial.
#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Session token capture, refresh, status, and credential management.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Non-secret settings.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Balances and accrued interest — the paydown-tracking view.
    Summary,
    /// Individual loans and their balances.
    #[command(subcommand)]
    Loans(loans::Cmd),
    /// Payment and activity history (--scheduled for upcoming payments).
    #[command(subcommand)]
    Transactions(transactions::Cmd),
    /// Repayment status and income-driven-repayment application tracking.
    Repayment,
    /// Auto-debit (autopay) enrollment and next-cycle detail.
    Autopay,
    /// The 1098-E student-loan-interest figure, as data.
    Tax,
    /// Published documents: statements (and where the 1098-E data lives).
    #[command(subcommand, visible_alias = "docs")]
    Documents(documents::Cmd),
    /// Raw portal passthrough (read-only: GET requests only).
    Api(ApiArgs),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// Sign in and store the session, verified with one live read.
    ///
    /// Nelnet's login is an OAuth2/OIDC flow behind Akamai bot protection, so
    /// the CLI does not replay a password. With `--browser` (the primary path) a
    /// Chrome window opens at https://nelnet.studentaid.gov. Sign in there: the
    /// username, password and one-time code go to Nelnet's own pages, never
    /// through this CLI. Once the portal has stored its session, `nlnt` takes it
    /// from the page and closes the window:
    ///
    ///   nlnt auth login --browser
    ///
    /// The window's Chrome profile stays on disk for the next sign-in, so Nelnet
    /// can remember the device; `--fresh-profile` signs in through a scratch one
    /// instead, and `auth logout` removes the kept one.
    ///
    /// Chrome is found at the standard install paths; `NLNT_CHROME` points at
    /// another binary.
    ///
    /// Without Chrome, log in at https://nelnet.studentaid.gov in any browser,
    /// then in DevTools → Console run:
    ///
    ///   copy(localStorage['oidc.user:https://auth.nelnet.studentaid.gov:mma'])
    ///
    /// and pipe the clipboard in:
    ///
    ///   pbpaste | nlnt auth login --stdin
    ///
    /// Both paths parse, verify and store the session the same way. It carries a
    /// refresh token, so this is a one-time sign-in: the CLI renews the
    /// short-lived access token itself. A session enters via the browser,
    /// `--stdin` or `--from-env <VAR>`; there is no token flag. See
    /// `docs/api.md` § Auth.
    Login(LoginCmd),
    /// Refresh the session now.
    ///
    /// Exchanges the stored refresh token (no browser). If that token is dead
    /// and a capture command is configured (`refresh_command`, or `--command`),
    /// runs it for a whole fresh bundle — so re-login is unattended. See the
    /// reference script in `scripts/` and `docs/api.md` § Auth.
    Refresh(RefreshArgs),
    /// Report credential and session state (auth-status/v1).
    Status,
    /// Clear the cached session and remove the kept browser profile; --forget
    /// also clears saved settings.
    Logout(LogoutArgs),
    /// Write a session bundle to the keychain (rotation / scripted setup).
    ///
    /// Verifies with a live read before storing, like `auth login`. For a
    /// genuinely offline write, use `auth login --stdin --no-verify` instead.
    SetCredential(SetCredentialArgs),
}

/// The standard login flags plus the family's `--browser`, flattened beside
/// `LoginArgs` as cli-common's example-cli does.
#[derive(Args, Debug)]
struct LoginCmd {
    #[command(flatten)]
    login: LoginArgs,
    #[command(flatten)]
    browser: BrowserArgs,
}

#[derive(Args, Debug)]
struct RefreshArgs {
    /// Capture command to run when the refresh token is dead (overrides the
    /// `refresh_command` config and `$NLNT_REFRESH_COMMAND`).
    #[arg(long, value_name = "CMD")]
    command: Option<String>,
    /// Persist `--command` to config as `refresh_command` for future refreshes.
    #[arg(long)]
    save: bool,
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Print the resolved config file path.
    Path,
    /// Show the effective configuration.
    Show,
    /// Set a config key (base_url, auth_url, account, username, auto_refresh,
    /// refresh_command).
    Set { key: String, value: String },
    /// Remove a config key.
    Unset { key: String },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        std::process::exit(output::fail(&e, cli.common.json));
    }
}

fn run(cli: &Cli) -> Result<(), CliError> {
    let store = ConfigStore::new(BIN);
    let creds = CredentialStore::for_binary(BIN);
    let cfg: Config = store.load()?;
    let ctx = Ctx {
        common: &cli.common,
        cfg: &cfg,
        creds: &creds,
    };

    match &cli.command {
        Command::Auth(cmd) => auth(cli, cmd, &store, &creds, &cfg),
        Command::Config(cmd) => config(cli, cmd, &store),
        Command::Summary => summary::run(&ctx),
        Command::Loans(cmd) => loans::run(&ctx, cmd),
        Command::Transactions(cmd) => transactions::run(&ctx, cmd),
        Command::Repayment => repayment::run(&ctx),
        Command::Autopay => autopay::run(&ctx),
        Command::Tax => tax::run(&ctx),
        Command::Documents(cmd) => documents::run(&ctx, cmd),
        Command::Api(args) => api(&ctx, args),
        Command::SelfUpdate(args) => Updater {
            repo: REPO.into(),
            binary: BIN.into(),
            target: env!("BUILD_TARGET").into(),
            current: env!("CARGO_PKG_VERSION").into(),
        }
        .run(args, cli.common.json, cli.common.quiet),
        Command::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            Ok(())
        }
        Command::Info => {
            let info = CliInfo::new(
                BIN,
                env!("CARGO_PKG_VERSION"),
                &format!("https://github.com/{REPO}"),
                AuthInfo {
                    required: true,
                    method: "browser-session".into(),
                    login_hint: Some(format!("{BIN} auth login --browser")),
                },
                &[
                    "summary",
                    "loans",
                    "transactions",
                    "repayment",
                    "autopay",
                    "tax",
                    "documents",
                    "api",
                ],
            )
            .with_profiles(&[pk_cli_documents::PROFILE]);
            output::json(&serde_json::to_value(&info).unwrap());
            Ok(())
        }
    }
}

/// Raw passthrough, restricted to reads.
///
/// The CLI is read-only, and on a loan servicer the write endpoints move real
/// money. Refusing non-GET here keeps `api` from being a hole in that promise;
/// exit 6 (confirmation required) says "this is deliberate policy", not "your
/// syntax was wrong".
fn api(ctx: &Ctx, args: &ApiArgs) -> Result<(), CliError> {
    let method = args.parsed_method()?;
    if method != reqwest::Method::GET {
        return Err(CliError::ConfirmationRequired(format!(
            "`{BIN}` is read-only: `api` performs GET requests only (asked for {method}). \
             Nelnet's write endpoints move real money and this CLI deliberately implements none."
        )));
    }
    if args.data.is_some() {
        return Err(CliError::Usage(
            "--data has no meaning for a GET request".into(),
        ));
    }
    let body = ctx.read(|portal| portal.get_text(&args.path))?;
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(v) if ctx.common.json => output::json(&v),
        Ok(v) => output::render(&v),
        Err(_) => println!("{body}"),
    }
    Ok(())
}

fn auth(
    cli: &Cli,
    cmd: &AuthCmd,
    store: &ConfigStore,
    creds: &CredentialStore,
    cfg: &Config,
) -> Result<(), CliError> {
    match cmd {
        AuthCmd::Login(args) => login(cli, args, creds, cfg),
        AuthCmd::Refresh(args) => refresh(cli, args, store, creds, cfg),
        AuthCmd::Status => {
            let stored = creds.get(SESSION_ACCOUNT)?;
            let has_session = stored.is_some();
            let mut status = AuthStatus::new(true, has_session, AuthMethod::BrowserSession);
            status.account = cfg.account();
            status.credential_in_keychain = Some(has_session);
            status.session_valid = Some(has_session);
            // Surface the access-token expiry, and report the session as valid
            // when the token is fresh OR still refreshable — an expired access
            // token with a refresh token is usable, since the next read renews it.
            if let Some(secret) = &stored {
                if let Ok(session) = serde_json::from_str::<Session>(secret.expose()) {
                    status.expires_at = session.expires_at.map(pk_cli_core::dates::fmt_rfc3339);
                    let fresh = !session.is_expired(client::now_secs(), 0);
                    status.session_valid = Some(fresh || session.refresh_token.is_some());
                }
            }
            status.emit(cli.common.json);
            Ok(())
        }
        AuthCmd::Logout(args) => {
            creds.delete(SESSION_ACCOUNT)?;
            if args.forget {
                store.clear()?;
            }
            // Last, so a refusal (its window still open) leaves the rest done.
            let line = logout_browser(|| pk_cli_browser::forget_profile(BIN))?;
            if !cli.common.quiet {
                eprintln!("{line}");
            }
            Ok(())
        }
        AuthCmd::SetCredential(args) => {
            if creds.get(SESSION_ACCOUNT)?.is_some() && !args.overwrite {
                return Err(CliError::Usage(
                    "a session is already stored; pass --overwrite to replace it".into(),
                ));
            }
            let secret = args.source.read(None)?;
            let session = Session::parse_captured(secret.expose())?;
            // Verify with a live read before storing, same as `auth login`:
            // storing an unexercised token is how a keychain entry ends up
            // failing on the next unrelated command instead of here. The offline
            // path (headless, no network) is `auth login --stdin --no-verify`.
            client::establish_session(cfg, creds, session, true, cli.common.verbose)?;
            if !cli.common.quiet {
                eprintln!(
                    "session verified and stored in the OS keychain ({})",
                    creds.service()
                );
            }
            Ok(())
        }
    }
}

/// `auth logout`'s browser step. The profile `auth login --browser` keeps holds
/// the identity host's cookies (its remembered device and session), so a logout
/// removes it too and the next sign-in starts signed out. The removal is passed
/// in: the binary binds it to `forget_profile(BIN)`, the tests to
/// `forget_profile_in` under a temp dir, so a test never removes the owner's
/// real profile. Returns the status line.
fn logout_browser(forget: impl FnOnce() -> Result<bool, BrowserError>) -> Result<String, CliError> {
    let removed = forget()?;
    Ok(format!(
        "logged out{}",
        if removed {
            "; browser profile removed"
        } else {
            ""
        }
    ))
}

/// Refuse a flag combination `--browser` cannot honor. Runs before anything
/// reads the keychain or opens a window, so a bad combination is exit 2 with
/// no side effect.
fn check_login_flags(args: &LoginCmd) -> Result<(), CliError> {
    let login = &args.login;
    if !args.browser.browser {
        return Ok(());
    }
    if login.source.stdin || login.source.from_env.is_some() {
        return Err(CliError::Usage(
            "--browser takes the session from the browser; drop --stdin and --from-env".into(),
        ));
    }
    if login.no_verify {
        return Err(CliError::Usage(
            "--browser always verifies the captured session with one read; drop --no-verify".into(),
        ));
    }
    if login.non_interactive {
        return Err(CliError::Usage(
            "--browser waits for you to sign in in a Chrome window; it cannot run with \
             --non-interactive"
                .into(),
        ));
    }
    Ok(())
}

fn login(
    cli: &Cli,
    args: &LoginCmd,
    creds: &CredentialStore,
    cfg: &Config,
) -> Result<(), CliError> {
    check_login_flags(args)?;
    let login = &args.login;
    if creds.get(SESSION_ACCOUNT)?.is_some() && !login.overwrite {
        return Err(CliError::Usage(
            "a session is already stored; pass --overwrite to replace it (or `nlnt auth refresh` \
             to renew it)"
                .into(),
        ));
    }
    let browser = args.browser.browser;
    let fresh_profile = args.browser.fresh_profile;
    let retry = retry_command(browser, fresh_profile, login.overwrite);
    let raw = if browser {
        nlnt::browser::capture_session(cli.common.quiet, fresh_profile, &retry)?
    } else {
        let prompt = if login.non_interactive {
            None
        } else {
            Some("Paste the browser session (oidc.user JSON) or a Bearer token")
        };
        login.source.read(prompt)?
    };
    // From here both paths are one: the stdin parser, one verifying read,
    // the keychain.
    let session = Session::parse_captured(raw.expose()).map_err(|e| {
        if browser {
            unexpected_capture(e)
        } else {
            e
        }
    })?;
    let verify = !login.no_verify;
    client::establish_session(cfg, creds, session, verify, cli.common.verbose)
        .map_err(|e| rejected_at_login(e, &retry))?;
    if !cli.common.quiet {
        let how = if verify {
            "verified and stored"
        } else {
            "stored (unverified)"
        };
        let from = if browser { " from the browser" } else { "" };
        eprintln!(
            "session{from} {how} in the OS keychain ({})",
            creds.service()
        );
    }
    Ok(())
}

/// The command a failed login tells the owner to re-run: the same path in the
/// same kind of profile, and `--overwrite` again when it replaced a stored
/// session.
fn retry_command(browser: bool, fresh_profile: bool, overwrite: bool) -> String {
    format!(
        "{BIN} auth login{}{}{}",
        if browser { " --browser" } else { "" },
        if fresh_profile {
            " --fresh-profile"
        } else {
            ""
        },
        if overwrite { " --overwrite" } else { "" }
    )
}

/// The value the browser capture read is the portal's own, so one the parser
/// refuses means the portal changed what it stores (exit 5), not a usage
/// mistake.
fn unexpected_capture(err: CliError) -> CliError {
    CliError::Upstream(format!(
        "the session read from {} is not the token bundle this CLI expects ({err}); nothing \
         was stored — see docs/api.md § Auth",
        nlnt::browser::SPA_HOST
    ))
}

/// A verifying read the portal refused leaves nothing stored, so the read
/// guard's "run `auth refresh`" has nothing to refresh; point at a fresh
/// sign-in. Other errors (the bot wall, an outage) pass through.
fn rejected_at_login(err: CliError, retry: &str) -> CliError {
    match err {
        CliError::Auth(_) => CliError::Auth(format!(
            "the portal refused the session on the verifying read; nothing was stored — sign \
             in again and re-run `{retry}`"
        )),
        other => other,
    }
}

fn refresh(
    cli: &Cli,
    args: &RefreshArgs,
    store: &ConfigStore,
    creds: &CredentialStore,
    cfg: &Config,
) -> Result<(), CliError> {
    // Persist an explicit --command first, so a later plain `auth refresh` (and
    // automatic refresh) can use it.
    if args.save {
        let cmd = args
            .command
            .as_deref()
            .ok_or_else(|| CliError::Usage("--save requires --command <cmd> to persist".into()))?;
        let mut c: Config = store.load()?;
        c.set("refresh_command", cmd)?;
        store.save(&c)?;
        if !cli.common.quiet {
            eprintln!("saved refresh_command to config");
        }
    }

    // Resolve the capture command: --command flag, else env/config.
    let command = args
        .command
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| cfg.refresh_command());

    let refreshed = client::refresh_or_relogin(
        cfg,
        creds,
        command.as_deref(),
        cli.common.verbose,
        cli.common.quiet,
    )?;
    if !cli.common.quiet {
        match refreshed.expires_at {
            Some(exp) => eprintln!(
                "session refreshed — access token valid until {}",
                pk_cli_core::dates::fmt_rfc3339(exp)
            ),
            None => eprintln!("session refreshed"),
        }
    }
    Ok(())
}

fn config(cli: &Cli, cmd: &ConfigCmd, store: &ConfigStore) -> Result<(), CliError> {
    match cmd {
        ConfigCmd::Path => {
            println!("{}", store.path()?.display());
            Ok(())
        }
        ConfigCmd::Show => {
            let cfg: Config = store.load()?;
            let v = serde_json::to_value(&cfg).unwrap_or_default();
            if cli.common.json {
                output::json(&v);
            } else {
                output::render(&v);
            }
            Ok(())
        }
        ConfigCmd::Set { key, value } => {
            let mut cfg: Config = store.load()?;
            cfg.set(key, value)?;
            store.save(&cfg)
        }
        ConfigCmd::Unset { key } => {
            let mut cfg: Config = store.load()?;
            cfg.unset(key)?;
            store.save(&cfg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_retry_command_repeats_the_path_and_overwrite() {
        let cases = [
            (false, false, false, "nlnt auth login"),
            (false, false, true, "nlnt auth login --overwrite"),
            (true, false, false, "nlnt auth login --browser"),
            (true, false, true, "nlnt auth login --browser --overwrite"),
            (
                true,
                true,
                false,
                "nlnt auth login --browser --fresh-profile",
            ),
            (
                true,
                true,
                true,
                "nlnt auth login --browser --fresh-profile --overwrite",
            ),
        ];
        for (browser, fresh_profile, overwrite, want) in cases {
            assert_eq!(retry_command(browser, fresh_profile, overwrite), want);
        }
    }

    /// The logout's browser step on a temp dir through `test-util`'s
    /// `forget_profile_in`, so the test never reaches the owner's real profile.
    #[test]
    fn logout_removes_the_kept_browser_profile() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("piekstra.nlnt").join("browser-profile");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        let forget = || pk_cli_browser::forget_profile_in(root.path(), BIN);
        assert_eq!(
            logout_browser(forget).unwrap(),
            "logged out; browser profile removed"
        );
        assert!(!profile.exists());
        // No profile left: nothing to remove, and not an error.
        assert_eq!(logout_browser(forget).unwrap(), "logged out");
    }

    /// A profile in use or needing repair is refused with the crate's own
    /// message (what to close, or what to fix) and exit 1, never reported as
    /// logged out.
    #[test]
    fn a_refused_profile_removal_is_an_error_not_a_logout() {
        let refusals = [
            BrowserError::ProfileInUse("a Chrome (pid 7) is still running in x".into()),
            BrowserError::Profile("the browser profile dir x is a symlink".into()),
        ];
        for refusal in refusals {
            let shown = refusal.to_string();
            let err = logout_browser(|| Err(refusal)).unwrap_err();
            assert_eq!(err.exit_code(), 1, "{err}");
            assert!(err.to_string().contains(&shown), "{err}");
        }
    }

    /// A captured value the parser refuses is the portal's shape changing
    /// (exit 5), not the owner's usage mistake (the parser's exit 2).
    #[test]
    fn an_unparseable_capture_is_upstream() {
        let parsed = Session::parse_captured(r#"{"profile":{}}"#).unwrap_err();
        assert_eq!(parsed.exit_code(), 2);
        let e = unexpected_capture(parsed);
        assert_eq!(e.exit_code(), 5);
        let m = e.to_string();
        assert!(m.contains(nlnt::browser::SPA_HOST), "{m}");
        assert!(m.contains("nothing was stored"), "{m}");
    }

    #[test]
    fn a_refused_verifying_read_names_the_retry() {
        let e = rejected_at_login(
            CliError::Auth("portal returned 401 for /api/1/loan/overview".into()),
            "nlnt auth login --browser --overwrite",
        );
        assert_eq!(e.exit_code(), 3);
        let m = e.to_string();
        assert!(m.contains("nothing was stored"), "{m}");
        assert!(m.contains("`nlnt auth login --browser --overwrite`"), "{m}");
        // The read guard's advice does not apply: nothing is stored to refresh.
        assert!(!m.contains("auth refresh"), "{m}");
    }

    #[test]
    fn other_verify_failures_pass_through() {
        let e = rejected_at_login(CliError::Upstream("bot wall".into()), "nlnt auth login");
        assert!(matches!(e, CliError::Upstream(ref m) if m == "bot wall"));
    }
}
