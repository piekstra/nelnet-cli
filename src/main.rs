//! `nlnt` — the Nelnet federal student-loan servicing portal from the command
//! line. Conforms to `piekstra-cli/1`. Read-only. Unofficial.

use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserArgs, BrowserError};
use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{output, CliError, CommonArgs};
use pk_cli_http::ApiArgs;
use pk_cli_secrets::{CredentialStore, Secret};
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};

use nlnt::client::{self, Session};
use nlnt::commands::{autopay, documents, loans, repayment, summary, tax, transactions, Ctx};
use nlnt::config::{Config, SESSION_ACCOUNT};
use nlnt::mcp::{LiveSource, NelnetTools};
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
    /// Serve read-only Nelnet tools to Claude over MCP (stdio, or --http).
    ///
    /// For Claude Code (`claude mcp add nelnet -- nlnt mcp`), Claude Desktop and any
    /// MCP client. With --http, on 127.0.0.1 behind a bearer token, for your own
    /// Cloudflare Worker (see README). No tool can make a payment or change
    /// anything at Nelnet, and no tool signs in.
    Mcp(pk_cli_mcp::McpArgs),
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
    /// through this CLI. Once the portal has stored its session, `nlnt` reads it
    /// from the page and closes the window:
    ///
    ///   nlnt auth login --browser
    ///
    /// The window can't be read twice, so if the check can't tell (an outage, a
    /// dropped connection, an edge block) the session is stored with a warning
    /// that it is unverified. A session the portal refuses is not stored.
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
    /// Clear the session and remove the kept browser profile; --forget also clears saved settings.
    ///
    /// Every step is attempted, so one failing does not stop the rest. If a step
    /// fails, or a sign-in or a Chrome window is using the profile, this exits
    /// non-zero and says what was cleared, what remains and how to finish.
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
    // Before anything reads the config: listing the tools reads no file, and a
    // running server reads it on each call, so a later `config set` applies and a
    // malformed file is one tool's error rather than no server.
    if let Command::Mcp(args) = &cli.command {
        return pk_cli_mcp::run(args, NelnetTools::new(LiveSource::new(creds)));
    }
    dispatch(cli, &store, &creds, &|store, forget| {
        run_logout(
            &cli.common,
            store,
            forget,
            // Under the lock a renewal holds if it can be had, so one in flight
            // cannot store the session again after the logout. The delete runs
            // either way: the lock must not keep a credential on the machine.
            || RefreshLock::forget_for_binary(BIN, || creds.delete(SESSION_ACCOUNT)),
            || pk_cli_browser::forget_profile(BIN),
        )
    })
}

/// `auth logout`, passed in so a test can run the dispatch without the keychain
/// or the real browser profile.
type Logout<'a> = &'a dyn Fn(&ConfigStore, bool) -> Result<(), CliError>;

/// The config is read only by the arms that use it, so a file that can't be
/// parsed doesn't stop `auth logout`.
fn dispatch(
    cli: &Cli,
    store: &ConfigStore,
    creds: &CredentialStore,
    logout: Logout<'_>,
) -> Result<(), CliError> {
    let with_ctx = |command: &dyn Fn(&Ctx) -> Result<(), CliError>| -> Result<(), CliError> {
        let cfg: Config = store.load()?;
        command(&Ctx {
            common: &cli.common,
            cfg: &cfg,
            creds,
        })
    };

    match &cli.command {
        Command::Auth(cmd) => auth(cli, cmd, store, creds, logout),
        Command::Config(cmd) => config(cli, cmd, store),
        Command::Summary => with_ctx(&|ctx| summary::run(ctx)),
        Command::Loans(cmd) => with_ctx(&|ctx| loans::run(ctx, cmd)),
        Command::Transactions(cmd) => with_ctx(&|ctx| transactions::run(ctx, cmd)),
        Command::Repayment => with_ctx(&|ctx| repayment::run(ctx)),
        Command::Autopay => with_ctx(&|ctx| autopay::run(ctx)),
        Command::Tax => with_ctx(&|ctx| tax::run(ctx)),
        Command::Documents(cmd) => with_ctx(&|ctx| documents::run(ctx, cmd)),
        Command::Api(args) => with_ctx(&|ctx| api(ctx, args)),
        Command::Mcp(_) => unreachable!("served before dispatch"),
        Command::SelfUpdate(args) => Updater {
            repo: REPO.into(),
            binary: BIN.into(),
            target: env!("BUILD_TARGET").into(),
            current: env!("CARGO_PKG_VERSION").into(),
        }
        .run_noting(
            args,
            cli.common.json,
            cli.common.quiet,
            &pk_cli_mcp::restart_note(BIN),
        ),
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
                    "mcp",
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
    logout: Logout<'_>,
) -> Result<(), CliError> {
    match cmd {
        AuthCmd::Login(args) => login(cli, args, creds, &store.load()?),
        AuthCmd::Refresh(args) => refresh(cli, args, store, creds, &store.load()?),
        AuthCmd::Status => {
            let cfg: Config = store.load()?;
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
            let (kept, warning) = browser_profile_status(|| pk_cli_browser::profile_exists(BIN));
            status.browser_profile = kept;
            if let (Some(warning), false) = (warning, cli.common.quiet) {
                eprintln!("warning: {warning}");
            }
            status.emit(cli.common.json);
            Ok(())
        }
        AuthCmd::Logout(args) => logout(store, args.forget),
        AuthCmd::SetCredential(args) => {
            let cfg: Config = store.load()?;
            if creds.get(SESSION_ACCOUNT)?.is_some() && !args.overwrite {
                return Err(CliError::Usage(
                    "a session is already stored; pass --overwrite to replace it".into(),
                ));
            }
            // Before the read: a secret piped in once cannot be read again. It does
            // not wait on a busy lock, so bad input still fails at once.
            RefreshLock::for_binary(BIN)?.try_hold(|| Ok(()))?;
            let secret = args.source.read(None)?;
            let session = Session::parse_captured(secret.expose())?;
            // Verify with a live read before storing, same as `auth login`:
            // storing an unexercised token is how a keychain entry ends up
            // failing on the next unrelated command instead of here. The offline
            // path (headless, no network) is `auth login --stdin --no-verify`.
            client::establish_session(&cfg, creds, session, true, cli.common.verbose)?;
            if !cli.common.quiet {
                eprintln!(
                    "session verified and stored in the OS keychain ({})",
                    creds.service()
                );
            }
            emit_login_result(cli, true);
            Ok(())
        }
    }
}

/// `auth status`'s browser field: whether a `--browser` sign-in keeps a profile
/// here, not whether it is signed in. `auth status` works whatever state the CLI is
/// in, so a profile that needs repair leaves the field out and returns a warning for
/// stderr, unless `-q`. The crate's message names the path and the fix; `auth logout`
/// can't be the fix, since `forget_profile` refuses such a profile too. The check is
/// passed in: the binary binds it to `profile_exists(BIN)`, the
/// tests to `profile_exists_in` under a temp dir, so a test never reads the owner's
/// real data dir.
fn browser_profile_status(
    exists: impl FnOnce() -> Result<bool, BrowserError>,
) -> (Option<bool>, Option<String>) {
    match exists() {
        Ok(kept) => (Some(kept), None),
        Err(e) => (None, Some(e.to_string())),
    }
}

/// `auth logout`, with the keychain and the real profile passed in. Every step
/// runs whatever the one before it did: the steps come first and the profile last,
/// and `logout_browser` reports each. Clearing the file needs no parse, so
/// `--forget` also clears a config that can't be read.
fn run_logout(
    common: &CommonArgs,
    store: &ConfigStore,
    forget: bool,
    delete_session: impl FnOnce() -> Result<bool, CliError>,
    remove_profile: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<(), CliError> {
    let mut steps: Vec<LogoutStep> = vec![("the session", delete_session().map(drop))];
    if forget {
        steps.push(("the saved settings", store.clear().map(drop)));
    }
    let line = logout_browser(steps, remove_profile)?;
    if !common.quiet {
        eprintln!("{line}");
    }
    Ok(())
}

/// What a logout step clears, and how it went.
type LogoutStep = (&'static str, Result<(), CliError>);

/// `auth logout`'s last step, and its report. The profile `auth login --browser`
/// keeps holds the identity host's cookies (its remembered device and session) and
/// the rest of a Chrome profile, so a logout removes it too and the next sign-in
/// starts signed out, even when an earlier step failed. The removal is passed in:
/// the binary binds it to `forget_profile(BIN)`, the tests to `forget_profile_in`
/// under a temp dir, so a test never removes the owner's real profile. Returns the
/// status line.
fn logout_browser(
    steps: Vec<LogoutStep>,
    remove_profile: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<String, CliError> {
    match remove_profile() {
        Ok(removed) if steps.iter().all(|(_, result)| result.is_ok()) => Ok(format!(
            "logged out{}",
            if removed {
                "; browser profile removed"
            } else {
                ""
            }
        )),
        removal => Err(incomplete_logout(steps, removal)),
    }
}

/// A caller seeing a failed logout must be able to tell what is gone, what
/// remains and how to finish. The exit code is the first failure's.
///
/// `Upstream` from the session step is the lock's answer: the delete has run, and a
/// renewal in flight may store the session again. So that session is neither
/// cleared nor remaining, and the remedy is to wait, not to fix anything. A
/// `Keychain` error from the same step means the session is still stored.
fn incomplete_logout(steps: Vec<LogoutStep>, removal: Result<bool, BrowserError>) -> CliError {
    let (mut cleared, mut remains, mut reasons) = (Vec::new(), Vec::new(), Vec::new());
    let mut first = None;
    let mut forget_step_failed = false;
    let mut may_return = false;
    for (index, (name, result)) in steps.into_iter().enumerate() {
        match result {
            Ok(()) => cleared.push(name),
            Err(e) => {
                reasons.push(format!("{name}: {}", bare_message(&e)));
                if index == 0 && matches!(e, CliError::Upstream(_)) {
                    may_return = true;
                } else {
                    remains.push(name);
                    forget_step_failed |= index > 0;
                }
                first.get_or_insert(e);
            }
        }
    }
    let profile_finish = match removal {
        Ok(removed) => {
            if removed {
                cleared.push("the browser profile");
            }
            None
        }
        Err(e) => {
            let finish = match e {
                BrowserError::ProfileInUse(_) => "Once that window or sign-in is closed, run",
                _ => "Repair or delete that path, then run",
            };
            remains.push("the browser profile");
            reasons.push(format!("the browser profile: {e}"));
            first.get_or_insert(CliError::from(e));
            Some(finish)
        }
    };
    let finish = match (may_return, profile_finish) {
        (true, None) => "Wait a minute, then run".to_string(),
        (true, Some(finish)) => format!("Wait a minute. {finish}"),
        (false, Some(finish)) => finish.to_string(),
        (false, None) => "Fix that, then run".to_string(),
    };
    let mut clauses = Vec::new();
    match cleared.as_slice() {
        [] if may_return => {}
        [] => clauses.push("nothing is cleared".to_string()),
        [one] => clauses.push(format!("{one} is cleared")),
        many => clauses.push(format!("{} are cleared", and_list(many))),
    }
    if may_return {
        clauses.push("the session is deleted, but a renewal in flight may store it again".into());
    }
    match remains.as_slice() {
        [] => {}
        [one] => clauses.push(format!("only {one} remains")),
        many => clauses.push(format!("{} remain", and_list(many))),
    }
    let message = format!(
        "logout incomplete: {} ({}). {finish} `{BIN} auth logout{}` again.",
        clauses.join(" and "),
        reasons.join("; "),
        if forget_step_failed { " --forget" } else { "" }
    );
    match first {
        Some(first) => with_exit_code_of(first, message),
        None => CliError::Other(message),
    }
}

/// A `CliError`'s message without the prefix its `Display` adds, so a report
/// built from several doesn't repeat them.
fn bare_message(error: &CliError) -> &str {
    match error {
        CliError::Usage(m)
        | CliError::Auth(m)
        | CliError::NotFound(m)
        | CliError::Upstream(m)
        | CliError::ConfirmationRequired(m)
        | CliError::Keychain(m)
        | CliError::Other(m) => m,
    }
}

/// `message` with `first`'s exit code. `Keychain` and `Other` both exit 1 and only
/// `Other` adds no prefix. `NotFound`, `Upstream` and `ConfirmationRequired` alone
/// have their codes, so their `Display` prefix stays, once: the lock's delete can
/// return `Upstream` when a renewal outlasts its wait.
fn with_exit_code_of(first: CliError, message: String) -> CliError {
    match first {
        CliError::Keychain(_) | CliError::Other(_) => CliError::Other(message),
        other => nlnt::browser::map_message(other, |_| message),
    }
}

fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
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
    let verify = !login.no_verify;
    let lock = RefreshLock::for_binary(BIN)?;
    let mut unverified = None;
    // Both paths are one from the value on: the stdin parser, one verifying
    // read, the keychain. They differ on a read that can't tell: a sign-in from
    // the window can't be read again, and one piped in can be piped in again.
    let mut store_session = |raw: &Secret| -> Result<(), CliError> {
        let session = Session::parse_captured(raw.expose()).map_err(|e| {
            if browser {
                unexpected_capture(e)
            } else {
                e
            }
        })?;
        if browser {
            unverified = client::keep_signed_in_session(cfg, creds, session, cli.common.verbose)
                .map_err(|e| rejected_at_login(e, &retry))?;
            return Ok(());
        }
        client::establish_session(cfg, creds, session, verify, cli.common.verbose)
            .map_err(|e| rejected_at_login(e, &retry))
    };
    if browser {
        // Before anyone signs in: the write needs this lock.
        lock.before_signin()?;
        nlnt::browser::sign_in(cli.common.quiet, fresh_profile, &retry, store_session)?;
    } else {
        // Before the read: a session piped in once cannot be read again. It does
        // not wait on a busy lock, so bad input still fails at once.
        lock.try_hold(|| Ok(()))?;
        let prompt = if login.non_interactive {
            None
        } else {
            Some("Paste the browser session (oidc.user JSON) or a Bearer token")
        };
        store_session(&login.source.read(prompt)?)?;
    }
    // Under `-q` too: nothing has tested this session yet.
    if let Some(why) = &unverified {
        eprintln!("warning: {}", unverified_warning(why));
    }
    if !cli.common.quiet {
        let how = if verify && unverified.is_none() {
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
    emit_login_result(cli, verify && unverified.is_none());
    Ok(())
}

/// What `--json` prints once a session is stored. Nothing on stdout without it,
/// where the text is on stderr.
fn emit_login_result(cli: &Cli, verified: bool) {
    output::emit(
        cli.common.json,
        "auth-login",
        login_result(verified),
        |_| {},
    );
}

/// `verified` says whether a read accepted the session.
fn login_result(verified: bool) -> serde_json::Value {
    pk_cli_auth::AuthLogin::stored(verified).to_json()
}

/// `auth status` makes no request, so it isn't what tests the session. A later
/// read can repeat the answer. A new sign-in gets past that when the session is the
/// cause, and may not when the block is on this client.
fn unverified_warning(why: &client::Unverified) -> String {
    let way_out = if why.edge_block {
        client::EDGE_BLOCK_WAY_OUT
    } else {
        client::READS_KEEP_FAILING
    };
    format!(
        "the sign-in is kept, but its session is stored unverified: {}. A later read, such as \
         `{BIN} summary`, may settle it; {}.",
        client::without_way_out(&why.reason),
        way_out
    )
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
/// sign-in, keeping what the portal answered. Other errors (the bot wall, an
/// outage) pass through.
fn rejected_at_login(err: CliError, retry: &str) -> CliError {
    match err {
        CliError::Auth(m) => {
            let why = m.strip_suffix(client::RENEW_ADVICE).unwrap_or(&m);
            CliError::Auth(format!(
                "the portal refused the session on the verifying read ({why}); nothing was \
                 stored — sign in again and re-run `{retry}`"
            ))
        }
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

    let presented = client::stored_session(creds)?;
    let refreshed = client::refresh_or_relogin(
        cfg,
        creds,
        command.as_deref(),
        presented.as_ref(),
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

    /// The failures from after the bundle is read, likeliest of all to leave a
    /// live session in the kept profile, name it and keep their exit codes.
    #[test]
    fn a_failure_after_the_capture_names_the_kept_profile() {
        let parsed = Session::parse_captured(r#"{"profile":{}}"#).unwrap_err();
        let cases = [
            (unexpected_capture(parsed), 5),
            (
                rejected_at_login(
                    CliError::Auth("portal returned 401".into()),
                    "nlnt auth login --browser",
                ),
                3,
            ),
            (CliError::Upstream("portal HTTP 503".into()), 5),
            (CliError::Keychain("writing the session".into()), 1),
        ];
        for (failure, code) in cases {
            let e = nlnt::browser::finish_sign_in(false, || -> Result<(), _> {
                Err(BrowserError::Handler(failure.clone()))
            })
            .unwrap_err();
            assert_eq!(e.exit_code(), code, "{e}");
            let m = e.to_string();
            assert!(m.contains("browser profile stays on disk"), "{m}");
            assert!(m.contains("`nlnt auth logout` removes it"), "{m}");

            let fresh = nlnt::browser::finish_sign_in(true, || -> Result<(), _> {
                Err(BrowserError::Handler(failure))
            })
            .unwrap_err();
            assert_eq!(fresh.exit_code(), code, "{fresh}");
            assert!(!fresh.to_string().contains("stays on disk"), "{fresh}");
        }
    }

    /// `auth status` reports the kept profile through `profile_exists_in`, so the
    /// test never reads the owner's real data dir, and one needing repair is left
    /// off the wire.
    #[test]
    fn auth_status_reports_the_kept_browser_profile() {
        let root = tempfile::tempdir().unwrap();
        let exists = || pk_cli_browser::profile_exists_in(root.path(), BIN);
        assert_eq!(browser_profile_status(exists), (Some(false), None));
        let profile = root.path().join("piekstra.nlnt").join("browser-profile");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        assert_eq!(browser_profile_status(exists), (Some(true), None));

        let mut status = AuthStatus::new(true, true, AuthMethod::BrowserSession);
        status.browser_profile = browser_profile_status(exists).0;
        assert_eq!(status.to_json()["browser_profile"], true);

        let refused = || Err(BrowserError::Profile("needs repair".into()));
        let (kept, warning) = browser_profile_status(refused);
        status.browser_profile = kept;
        assert!(status.to_json().get("browser_profile").is_none());
        assert!(warning.unwrap().contains("needs repair"));
    }

    fn all_cleared() -> Vec<LogoutStep> {
        vec![("the session", Ok(()))]
    }

    /// The logout's profile step on a temp dir through `test-util`'s
    /// `forget_profile_in`, so the test never reaches the owner's real profile.
    #[test]
    fn logout_removes_the_kept_browser_profile() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("piekstra.nlnt").join("browser-profile");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        let remove = || pk_cli_browser::forget_profile_in(root.path(), BIN);
        assert_eq!(
            logout_browser(all_cleared(), remove).unwrap(),
            "logged out; browser profile removed"
        );
        assert!(!profile.exists());
        // No profile left: nothing to remove, and not an error.
        assert_eq!(logout_browser(all_cleared(), remove).unwrap(), "logged out");
    }

    /// A profile in use or needing repair is exit 1, and the message says what
    /// is already gone, what remains, the crate's reason and how to finish.
    #[test]
    fn a_refused_profile_removal_says_what_is_already_cleared() {
        let in_use = || BrowserError::ProfileInUse("a Chrome (pid 7) is in x".into());
        let repair = || BrowserError::Profile("the browser profile dir x is a symlink".into());
        let forgotten =
            || -> Vec<LogoutStep> { vec![("the session", Ok(())), ("the saved settings", Ok(()))] };
        let cases = [
            (
                in_use(),
                all_cleared(),
                "the session is cleared",
                "window or sign-in",
            ),
            (
                in_use(),
                forgotten(),
                "the session and the saved settings are cleared",
                "window or sign-in",
            ),
            (
                repair(),
                all_cleared(),
                "the session is cleared",
                "Repair or delete",
            ),
        ];
        for (refusal, steps, cleared, finish) in cases {
            let shown = refusal.to_string();
            let err = logout_browser(steps, || Err(refusal)).unwrap_err();
            assert_eq!(err.exit_code(), 1, "{err}");
            let m = err.to_string();
            assert!(m.contains(cleared), "{m}");
            assert!(m.contains("only the browser profile remains"), "{m}");
            assert!(m.contains(&shown), "{m}");
            assert!(m.contains(finish), "{m}");
            assert!(m.contains("`nlnt auth logout` again"), "{m}");
        }
    }

    /// A failed keychain step does not stop the rest: the profile is really
    /// removed, on a temp dir, and the report says what went and what stayed.
    #[test]
    fn a_failed_step_does_not_stop_the_profile_removal() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("piekstra.nlnt").join("browser-profile");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        let steps = vec![("the session", Err(CliError::Keychain("denied".into())))];
        let err = logout_browser(steps, || {
            pk_cli_browser::forget_profile_in(root.path(), BIN)
        })
        .unwrap_err();
        assert!(!profile.exists());
        assert_eq!(err.exit_code(), 1, "{err}");
        let m = err.to_string();
        assert!(m.starts_with("logout incomplete: "), "{m}");
        assert!(!m.contains("keychain error"), "{m}");
        assert!(m.contains("the browser profile is cleared"), "{m}");
        assert!(m.contains("only the session remains"), "{m}");
        assert!(m.contains("(the session: denied)"), "{m}");
        assert!(m.contains("`nlnt auth logout` again"), "{m}");
    }

    /// Every step is attempted, the exit code is the first failure's, and a
    /// failed `--forget` step is why the retry names `--forget`.
    #[test]
    fn every_failure_is_reported_with_the_first_exit_code() {
        let mut attempted = false;
        let steps = vec![
            ("the session", Ok(())),
            ("the saved settings", Err(CliError::Auth("first".into()))),
        ];
        let err = logout_browser(steps, || {
            attempted = true;
            Err(BrowserError::ProfileInUse("second".into()))
        })
        .unwrap_err();
        assert!(attempted);
        assert_eq!(err.exit_code(), 3, "{err}");
        let m = err.to_string();
        assert!(m.starts_with("logout incomplete: "), "{m}");
        assert!(m.contains("the session is cleared"), "{m}");
        assert!(
            m.contains("the saved settings and the browser profile remain"),
            "{m}"
        );
        for reason in ["first", "second"] {
            assert!(m.contains(reason), "{m}");
        }
        assert!(m.contains("`nlnt auth logout --forget` again"), "{m}");
    }

    /// The crate's own answer when a renewal outlasts the wait, from a lock this
    /// test holds on a temp path, with a delete that touches no keychain.
    fn a_renewal_outlasting_the_wait() -> CliError {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token-refresh.lock");
        RefreshLock::at(&path)
            .hold(|| {
                Ok(RefreshLock::at(&path)
                    .wait_at_most(std::time::Duration::from_millis(1))
                    .forget(|| Ok(true))
                    .unwrap_err())
            })
            .unwrap()
    }

    /// `Upstream` from the session step means deleted, but a renewal in flight may
    /// store it again: neither cleared nor remaining, exit 5 with its prefix once,
    /// the profile still removed, and the remedy is to wait and rerun.
    #[test]
    fn a_renewal_in_flight_is_neither_cleared_nor_remaining() {
        let upstream = a_renewal_outlasting_the_wait();
        assert!(matches!(upstream, CliError::Upstream(_)), "{upstream}");
        let mut attempted = false;
        let err = logout_browser(vec![("the session", Err(upstream.clone()))], || {
            attempted = true;
            Ok(true)
        })
        .unwrap_err();
        assert!(attempted);
        assert_eq!(err.exit_code(), 5, "{err}");
        let m = err.to_string();
        assert!(
            m.starts_with("network/upstream error: logout incomplete: "),
            "{m}"
        );
        assert_eq!(m.matches("network/upstream error").count(), 1, "{m}");
        assert!(m.contains(bare_message(&upstream)), "{m}");
        assert!(
            m.contains(
                "the browser profile is cleared and the session is deleted, but a renewal in \
                 flight may store it again"
            ),
            "{m}"
        );
        assert!(!m.contains("the session is cleared"), "{m}");
        assert!(!m.contains("session remains"), "{m}");
        assert!(!m.contains("Fix that"), "{m}");
        assert!(
            m.contains("Wait a minute, then run `nlnt auth logout` again"),
            "{m}"
        );

        // No profile to remove: the headline doesn't claim nothing is cleared.
        let err =
            logout_browser(vec![("the session", Err(upstream.clone()))], || Ok(false)).unwrap_err();
        let m = err.to_string();
        assert!(!m.contains("nothing is cleared"), "{m}");
        assert!(
            m.contains("logout incomplete: the session is deleted, but"),
            "{m}"
        );

        // A profile in use as well: both remedies, and the profile remains.
        let err = logout_browser(vec![("the session", Err(upstream))], || {
            Err(BrowserError::ProfileInUse("a Chrome is in x".into()))
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 5, "{err}");
        let m = err.to_string();
        assert!(m.contains("only the browser profile remains"), "{m}");
        assert!(
            m.contains("Wait a minute. Once that window or sign-in is closed, run"),
            "{m}"
        );
    }

    /// `Upstream` only means that from the session step. Elsewhere it is an ordinary
    /// failure, and `Keychain` from the session step means it is still stored.
    #[test]
    fn only_the_session_steps_upstream_is_a_renewal_in_flight() {
        let steps = vec![
            ("the session", Ok(())),
            ("the saved settings", Err(CliError::Upstream("x".into()))),
        ];
        let m = logout_browser(steps, || Ok(false)).unwrap_err().to_string();
        assert!(m.contains("only the saved settings remains"), "{m}");
        assert!(!m.contains("renewal"), "{m}");

        let steps = vec![("the session", Err(CliError::Keychain("denied".into())))];
        let m = logout_browser(steps, || Ok(false)).unwrap_err().to_string();
        assert!(m.contains("only the session remains"), "{m}");
        assert!(!m.contains("renewal"), "{m}");
        assert!(m.contains("Fix that, then run"), "{m}");
    }

    /// No prefix leads the report or repeats inside it, whichever variants the
    /// failures were.
    #[test]
    fn the_report_is_built_from_inner_messages() {
        let steps = vec![
            ("the session", Err(CliError::Keychain("denied".into()))),
            (
                "the saved settings",
                Err(CliError::Other("read-only".into())),
            ),
        ];
        let err = logout_browser(steps, || Ok(false)).unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        let m = err.to_string();
        assert!(
            m.starts_with("logout incomplete: nothing is cleared"),
            "{m}"
        );
        assert_eq!(m.matches("keychain error").count(), 0, "{m}");
        assert!(
            m.contains("(the session: denied; the saved settings: read-only)"),
            "{m}"
        );
    }

    /// A config that can't be parsed doesn't stop `auth logout`, which runs every
    /// step, and `--forget` clears the broken file. Nothing here reaches the
    /// keychain or the real profile: the seam stands in for both, and `auth status`
    /// stops at the config it can't load.
    #[test]
    fn logout_runs_on_a_config_that_cannot_be_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, "{not json").unwrap();
        let store = ConfigStore::new(BIN).with_override(Some(path.clone()));
        let creds = CredentialStore::for_binary(BIN);
        let parse = |args: &[&str]| {
            let mut argv = vec!["nlnt"];
            argv.extend_from_slice(args);
            Cli::try_parse_from(argv).unwrap()
        };
        let deleted = std::cell::Cell::new(0);
        let removed = std::cell::Cell::new(0);
        let common = parse(&["auth", "logout"]).common;
        let seam = |store: &ConfigStore, forget: bool| {
            run_logout(
                &common,
                store,
                forget,
                || {
                    deleted.set(deleted.get() + 1);
                    Ok(true)
                },
                || {
                    removed.set(removed.get() + 1);
                    Ok(false)
                },
            )
        };

        dispatch(&parse(&["auth", "logout"]), &store, &creds, &seam).unwrap();
        assert_eq!((deleted.get(), removed.get()), (1, 1));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not json");

        // The commands that read the config still say it's broken.
        let unused = |_: &ConfigStore, _: bool| -> Result<(), CliError> { panic!("not a logout") };
        assert!(dispatch(&parse(&["auth", "status"]), &store, &creds, &unused).is_err());

        dispatch(
            &parse(&["auth", "logout", "--forget"]),
            &store,
            &creds,
            &seam,
        )
        .unwrap();
        assert_eq!((deleted.get(), removed.get()), (2, 2));
        assert!(!path.exists());
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

    /// The refusal keeps the guard's own reason, not its renewal advice, and an
    /// edge block is not reworded as a dead session.
    #[test]
    fn a_refusal_keeps_its_reason_and_an_edge_block_stays_one() {
        let retry = "nlnt auth login --browser";
        let refused = client::guard("/dummy", 403, "application/json", "{}").unwrap_err();
        let e = rejected_at_login(refused, retry);
        assert_eq!(e.exit_code(), 3);
        let m = e.to_string();
        assert!(m.contains("(portal returned 403 for /dummy"), "{m}");
        assert!(!m.contains("auth refresh"), "{m}");
        assert!(m.contains("nothing was stored"), "{m}");

        let blocked = client::guard("/dummy", 403, "text/html", "<html></html>").unwrap_err();
        let e = rejected_at_login(blocked, retry);
        assert_eq!(e.exit_code(), 5);
        let m = e.to_string();
        assert!(m.contains("HTTP 403 with an HTML page"), "{m}");
        assert!(!m.contains("refused the session"), "{m}");
    }

    #[test]
    fn the_login_result_always_says_whether_a_read_accepted_the_session() {
        assert_eq!(
            output::tagged("auth-login", login_result(true)),
            serde_json::json!({ "schema": "auth-login/v1", "stored": true, "verified": true })
        );
        assert_eq!(
            output::tagged("auth-login", login_result(false)),
            serde_json::json!({ "schema": "auth-login/v1", "stored": true, "verified": false })
        );
    }

    fn outage(reason: &str) -> client::Unverified {
        client::Unverified {
            reason: reason.into(),
            edge_block: false,
        }
    }

    /// `auth status` makes no request, so the warning must not send anyone to it.
    #[test]
    fn the_unverified_warning_names_what_tests_the_session() {
        let w = unverified_warning(&outage("portal HTTP 503 for /dummy"));
        assert!(
            w.contains("stored unverified: portal HTTP 503 for /dummy"),
            "{w}"
        );
        assert!(w.contains("`nlnt summary`"), "{w}");
        assert!(!w.contains("auth status"), "{w}");
        assert!(
            w.ends_with("if reads keep failing, run `nlnt auth login --browser --overwrite`."),
            "{w}"
        );

        // An error that already names the way out does not name it twice.
        let blocked = client::guard("/dummy", 403, "text/html", "<html></html>").unwrap_err();
        let w = unverified_warning(&client::Unverified {
            reason: blocked.to_string(),
            edge_block: true,
        });
        assert!(w.contains("HTTP 403 with an HTML page"), "{w}");
        assert_eq!(w.matches("auth login --browser").count(), 1, "{w}");
    }

    /// A block on this client outlasts a new sign-in, so the warning doesn't offer
    /// one as the fix. An outage keeps the shorter wording.
    #[test]
    fn an_edge_block_warns_that_a_new_sign_in_may_not_clear_it() {
        let html = client::guard("/dummy", 403, "text/html", "<html></html>").unwrap_err();
        let bot = client::guard("/dummy", 403, "text/html", "HTTP 403 Access denied.").unwrap_err();
        let page = client::guard("/dummy", 200, "application/json", "<html></html>").unwrap_err();
        for blocked in [html, bot, page] {
            let w = unverified_warning(&client::Unverified {
                reason: blocked.to_string(),
                edge_block: true,
            });
            assert!(w.contains("may not clear this"), "{w}");
            assert!(w.contains("on this client rather than the session"), "{w}");
            assert!(w.contains("wait or try another network"), "{w}");
            let sign_in = w.find("auth login --browser").unwrap();
            assert!(w.find("try another network").unwrap() < sign_in, "{w}");
        }
        for reason in ["portal HTTP 503 for /dummy", "portal HTTP 429 for /dummy"] {
            let w = unverified_warning(&outage(reason));
            assert!(!w.contains("may not clear"), "{w}");
            assert!(w.contains("if reads keep failing"), "{w}");
        }
    }

    #[test]
    fn other_verify_failures_pass_through() {
        let e = rejected_at_login(CliError::Upstream("bot wall".into()), "nlnt auth login");
        assert!(matches!(e, CliError::Upstream(ref m) if m == "bot wall"));
    }
}
