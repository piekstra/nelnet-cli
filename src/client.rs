//! HTTP session against the Nelnet servicing API.
//!
//! # Auth model — CONFIRMED-LIVE 2026-08-12
//!
//! The portal is an Angular SPA (`nelnet.studentaid.gov`) over a .NET API on a
//! **separate host** (`mmaapi.nelnet.studentaid.gov`). Login is an OAuth2/OIDC
//! authorization-code + PKCE flow at Duende IdentityServer
//! (`auth.nelnet.studentaid.gov`), and the API authenticates with a
//! **Bearer access token**, not a cookie.
//!
//! Both hosts sit behind Akamai. The bot wall was found to key on **Chrome
//! client-hint headers** (`sec-ch-ua*` + `Sec-Fetch-*`), *not* on TLS
//! fingerprint or cookies: a plain HTTP client that sends those headers and a
//! Chrome `User-Agent` is admitted, and one that omits them gets a bare
//! `403 Access denied` *before the token is ever read*. That is why this module
//! sends the sentinel header set on every request, and why a 403 whose body is
//! the Akamai denial is reported as an upstream problem, not an auth failure.
//!
//! Because the token bundle carries a **refresh token** (`offline_access`
//! scope), the CLI renews the 15-minute access token on its own via the OAuth
//! refresh grant — no browser, no one-time code. Refresh tokens **rotate**, so
//! the new bundle is written back to the keychain after every refresh, exactly
//! as a rotating cookie jar would be.
//!
//! The initial bundle is captured once from a signed-in browser session:
//! `nlnt auth login --browser` reads it out of a Chrome window
//! (`crate::browser`), and `nlnt auth login --stdin` takes the same value
//! copied out of DevTools by hand.
//!
//! `docs/api.md` records the full endpoint map and the traps.

use std::time::Duration;

use pk_cli_auth::refresh_lock::RefreshLock;
use pk_cli_core::CliError;
use pk_cli_secrets::{CredentialStore, Secret};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::config::{Config, SESSION_ACCOUNT};

/// Major Chrome version impersonated. Akamai cross-checks the `User-Agent`
/// against `sec-ch-ua`, so both are derived from this single constant.
const CHROME_MAJOR: &str = "151";

/// The public SPA OAuth client id (Duende). CONFIRMED-LIVE from the authorize
/// request: `client_id=mma`, PKCE S256, `nds_client_id=1` (federal).
pub const OAUTH_CLIENT_ID: &str = "mma";

/// How a stored session that does not parse is reported.
pub const SESSION_UNREADABLE: &str = "stored session is unreadable";

/// How a dead refresh token words its way out, which a tool replaces with its own.
pub const SIGN_IN_AGAIN: &str = " — sign in again with";

/// A session stored without a refresh token.
pub const NO_REFRESH_TOKEN: &str = "the stored session has no refresh token";

/// The identity host's answer to a refresh token that has expired or was used.
pub const REFRESH_REJECTED: &str = "the refresh token was rejected (expired or already used)";

/// Portal API paths. CONFIRMED-LIVE 2026-08-12 by observing the SPA's own XHRs
/// and replaying each against `mmaapi.nelnet.studentaid.gov`.
pub mod paths {
    /// Account overview: `currentBalance`, `outstandingPrincipal`,
    /// `accruedInterest`, `lastBumpDate`. The paydown figures.
    pub const OVERVIEW: &str = "/api/1/loan/overview";
    /// Full account + per-loan-group detail. `federalAccounts[]` each carry a
    /// `borrowerGroupPayments[]` list — one entry per loan group.
    pub const LOAN_SUMMARY: &str = "/api/1/loan/summary";
    /// Payment/transaction history: `paymentHistoryList[]`.
    pub const PAYMENT_HISTORY: &str = "/api/1/payment/history";
    /// Upcoming scheduled payments: `scheduledPaymentsList[]` (same item shape
    /// as history, minus the applied principal/interest split).
    pub const PAYMENT_SCHEDULED: &str = "/api/1/payment/scheduled";
    /// Repayment status: plan status, school, separation date.
    pub const REPAYMENT_OVERVIEW: &str = "/api/1/borrower/repayment/overview";
    /// Income-driven-repayment application statuses (array).
    pub const IDR_STATUSES: &str = "/api/1/borrower/idr-application-statuses";
    /// Auto-debit (autopay) enrollment and next-cycle detail.
    pub const AUTO_DEBIT: &str = "/api/1/auto-debit/summary";
    /// Statement index: `statementList[]` (real PDFs).
    pub const STATEMENTS: &str = "/api/1/statements";
    /// 1098-E source data. **Not a file** — the SPA renders an HTML template
    /// from this and prints it. `edServicerAccount.taxInfoDictionary`.
    pub const TAX_INFO: &str = "/api/1/tax/account-tax-info";
    /// OAuth token endpoint (on the identity host, not the API host).
    pub const OIDC_TOKEN: &str = "/connect/token";

    /// Statement PDF: `/api/1/statements/pdf/{documentId}/{isDirect}` →
    /// `application/pdf`. The two path args are the document id (a GUID) and the
    /// account's `isDirect` boolean.
    pub fn statement_pdf(document_id: &str, is_direct: bool) -> String {
        format!("/api/1/statements/pdf/{document_id}/{is_direct}")
    }
}

fn user_agent() -> String {
    format!(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{CHROME_MAJOR}.0.0.0 Safari/537.36"
    )
}

fn sec_ch_ua() -> String {
    format!("\"Chromium\";v=\"{CHROME_MAJOR}\", \"Not.A/Brand\";v=\"24\"")
}

/// The sentinel header set that satisfies Akamai's bot wall. Empirically the
/// wall admits a request iff it carries `sec-ch-ua` **and** `Sec-Fetch-*`
/// alongside a Chrome UA; each alone is refused. Kept together so a future edit
/// cannot silently drop half of the pair.
fn sentinel_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "sec-ch-ua",
        HeaderValue::from_str(&sec_ch_ua())
            .expect("sec_ch_ua is pure ASCII from a compile-time constant"),
    );
    h.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    h.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
    h.insert("Sec-Fetch-Site", HeaderValue::from_static("same-site"));
    h.insert("Sec-Fetch-Mode", HeaderValue::from_static("cors"));
    h.insert("Sec-Fetch-Dest", HeaderValue::from_static("empty"));
    h
}

/// The OAuth token bundle. Stored as JSON in the keychain.
///
/// `expires_at` is unix seconds; it drives proactive refresh so a command does
/// not have to eat a 401 round trip first. It is optional because a bundle
/// captured as a bare bearer string carries no expiry — in that case expiry is
/// discovered from the first 401 instead.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Session {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Unix seconds when the access token expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Hand-written so a stray `{:?}` (a `dbg!`, an error context, a `--verbose`
/// line) can never spill the tokens — this is the most sensitive value the CLI
/// holds. The presence of each token is shown; its value never is.
impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |o: &Option<String>| o.as_ref().map(|_| "***");
        f.debug_struct("Session")
            .field("access_token", &"***")
            .field("refresh_token", &redact(&self.refresh_token))
            .field("id_token", &redact(&self.id_token))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Session {
    /// Parse a captured credential. Accepts the browser's `oidc.user` JSON
    /// object, a `{access_token, ...}` object, or a bare bearer string
    /// (optionally `Bearer <tok>`).
    pub fn parse_captured(raw: &str) -> Result<Session, CliError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(CliError::Auth("no token provided".into()));
        }
        if raw.starts_with('{') {
            let v: serde_json::Value = serde_json::from_str(raw)
                .map_err(|e| CliError::Usage(format!("the session is not valid JSON: {e}")))?;
            let access = v
                .get("access_token")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    CliError::Usage(
                        "the session JSON has no `access_token` — it should be the whole \
                         `oidc.user:…` value from localStorage (see `nlnt auth login --help`)"
                            .into(),
                    )
                })?;
            let expires_at = v.get("expires_at").and_then(|x| x.as_i64()).or_else(|| {
                v.get("expires_in")
                    .and_then(|x| x.as_i64())
                    .map(|s| now_secs() + s)
            });
            return Ok(Session {
                access_token: access.to_string(),
                refresh_token: v
                    .get("refresh_token")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from),
                id_token: v
                    .get("id_token")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(String::from),
                expires_at,
            });
        }
        // A bare token, possibly with a `Bearer ` prefix.
        let token = raw
            .strip_prefix("Bearer ")
            .or_else(|| raw.strip_prefix("bearer "))
            .unwrap_or(raw)
            .trim();
        Ok(Session {
            access_token: token.to_string(),
            ..Default::default()
        })
    }

    fn from_keychain(creds: &CredentialStore) -> Result<Session, CliError> {
        let raw = creds.get(SESSION_ACCOUNT)?.ok_or_else(|| {
            CliError::Auth("no stored session — run `nlnt auth login --browser`".into())
        })?;
        serde_json::from_str(raw.expose())
            .map_err(|e| CliError::Other(format!("{SESSION_UNREADABLE}: {e}")))
    }

    fn store(&self, creds: &CredentialStore) -> Result<(), CliError> {
        let json = serde_json::to_string(self)
            .map_err(|e| CliError::Other(format!("could not serialize session: {e}")))?;
        creds.set(SESSION_ACCOUNT, &Secret::new(json))
    }

    /// Whether the access token is at or past expiry (with a safety skew), so a
    /// refresh should happen before the call rather than after a 401.
    pub fn is_expired(&self, now: i64, skew_secs: i64) -> bool {
        match self.expires_at {
            Some(exp) => now + skew_secs >= exp,
            None => false,
        }
    }
}

pub fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The API session: a Bearer-authenticated HTTP client for the API host.
pub struct Portal {
    http: reqwest::blocking::Client,
    base: String,
    session: Session,
    verbose: bool,
}

impl Portal {
    fn build_client() -> Result<reqwest::blocking::Client, CliError> {
        reqwest::blocking::Client::builder()
            .user_agent(user_agent())
            .default_headers(sentinel_headers())
            .timeout(HTTP_TIMEOUT)
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| CliError::Other(format!("could not build HTTP client: {e}")))
    }

    /// A client authenticated with an explicit session (used at login, before
    /// anything is stored, to verify the token reads).
    pub fn with_session(
        base: impl Into<String>,
        session: Session,
        verbose: bool,
    ) -> Result<Self, CliError> {
        Ok(Portal {
            http: Self::build_client()?,
            base: base.into().trim_end_matches('/').to_string(),
            session,
            verbose,
        })
    }

    /// A client built from the cached session in the keychain.
    pub fn from_cached_session(
        cfg: &Config,
        creds: &CredentialStore,
        verbose: bool,
    ) -> Result<Self, CliError> {
        Self::with_session(cfg.base_url(), Session::from_keychain(creds)?, verbose)
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// The session behind this client's access token.
    pub fn session(&self) -> &Session {
        &self.session
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.session.access_token)
    }

    /// GET a JSON path and return the body, after the auth/bot guard.
    pub fn get_text(&self, path: &str) -> Result<String, CliError> {
        let answer = self.answer(path)?;
        guard(path, answer.status, &answer.content_type, &answer.body)?;
        Ok(answer.body)
    }

    /// GET a JSON path and return what came back, before anything judges it.
    fn answer(&self, path: &str) -> Result<Answer, CliError> {
        let url = self.url(path);
        if self.verbose {
            eprintln!("GET {url}");
        }
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.bearer())
            .header("Accept", "application/json, text/plain, */*")
            .send()
            .map_err(|e| CliError::Upstream(format!("GET {path} failed: {}", e.without_url())))?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp
            .text()
            .map_err(|e| CliError::Upstream(format!("reading response body for {path}: {e}")))?;
        Ok(Answer {
            status,
            content_type,
            body,
        })
    }

    /// Download bytes, requiring positive confirmation that it really is a PDF.
    pub fn get_pdf(&self, path: &str) -> Result<Vec<u8>, CliError> {
        let url = self.url(path);
        if self.verbose {
            eprintln!("GET {url} (expecting PDF)");
        }
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.bearer())
            .header("Accept", "application/pdf,*/*")
            .send()
            .map_err(|e| CliError::Upstream(format!("GET {path} failed: {}", e.without_url())))?;

        let status = resp.status().as_u16();
        // An auth/bot/not-found status never carries a PDF; classify it through
        // the shared helper (reading the small body only when the bot-wall check
        // needs it) so this path can't drift from `guard`.
        if matches!(status, 401 | 403 | 404) {
            let body = if status == 404 {
                String::new()
            } else {
                resp.text().unwrap_or_default()
            };
            return Err(classify_error(path, status, &body).unwrap_or_else(|| {
                CliError::Upstream(format!("portal HTTP {status} for {path}"))
            }));
        }

        let bytes = resp
            .bytes()
            .map_err(|e| CliError::Upstream(format!("reading {path}: {e}")))?
            .to_vec();

        if let Some(msg) = pdf_error(&bytes, path) {
            return Err(if status >= 400 {
                CliError::Upstream(format!("{path} returned HTTP {status}; {msg}"))
            } else {
                CliError::Upstream(msg)
            });
        }
        Ok(bytes)
    }

    /// Exchange the stored refresh token for a fresh bundle and write it back.
    ///
    /// Refresh tokens rotate, so the response's new refresh token replaces the
    /// old one in the keychain. Returns the refreshed session.
    pub fn refresh(&self, cfg: &Config, creds: &CredentialStore) -> Result<Session, CliError> {
        let refresh_token = self.session.refresh_token.as_deref().ok_or_else(|| {
            CliError::Auth(format!(
                "{NO_REFRESH_TOKEN}{SIGN_IN_AGAIN} `nlnt auth login --browser --overwrite`"
            ))
        })?;
        let url = format!(
            "{}{}",
            cfg.auth_url().trim_end_matches('/'),
            paths::OIDC_TOKEN
        );
        if self.verbose {
            eprintln!("POST {url} (refresh_token grant)");
        }
        let resp = self
            .http
            .post(&url)
            // The token endpoint is same-origin with the identity SPA.
            .header("Sec-Fetch-Site", "same-origin")
            .header("Accept", "application/json")
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", OAUTH_CLIENT_ID),
                ("refresh_token", refresh_token),
            ])
            .send()
            .map_err(|e| {
                CliError::Upstream(format!("token refresh failed: {}", e.without_url()))
            })?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .map_err(|e| CliError::Upstream(format!("reading refresh response: {e}")))?;
        if status == 403 && is_bot_wall(&body) {
            return Err(bot_wall_error(paths::OIDC_TOKEN));
        }
        if status == 400 || status == 401 {
            // invalid_grant: the refresh token expired or was already rotated.
            return Err(CliError::Auth(format!(
                "{REFRESH_REJECTED}{SIGN_IN_AGAIN} `nlnt auth login --browser --overwrite`"
            )));
        }
        if !(200..300).contains(&status) {
            return Err(CliError::Upstream(format!(
                "token endpoint returned HTTP {status}"
            )));
        }
        let v: serde_json::Value = serde_json::from_str(&body)
            .map_err(|e| CliError::Upstream(format!("token response was not JSON: {e}")))?;
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CliError::Upstream("token response carried no access_token".into()))?;
        let expires_at = v
            .get("expires_in")
            .and_then(|x| x.as_i64())
            .map(|s| now_secs() + s);
        let refreshed = Session {
            access_token: access.to_string(),
            // Keep the old refresh token if the server did not rotate one.
            refresh_token: v
                .get("refresh_token")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .or_else(|| self.session.refresh_token.clone()),
            id_token: v
                .get("id_token")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .or_else(|| self.session.id_token.clone()),
            expires_at,
        };
        refreshed.store(creds)?;
        Ok(refreshed)
    }
}

/// Run the capture command and parse its stdout into a [`Session`].
///
/// The command is a shell line (run via `sh -c`) whose **stdout** is a fresh
/// session bundle — the browser's `oidc.user` JSON, or a bare Bearer token. It
/// is how re-login becomes unattended: the reference script in `scripts/` drives
/// a real browser (silent OIDC renewal first, full login only when the identity
/// session has lapsed) and prints the bundle. Stderr is diagnostics.
pub fn run_capture_command(command: &str, verbose: bool) -> Result<Session, CliError> {
    if verbose {
        eprintln!("running capture command: {command}");
    }
    let mut sh = std::process::Command::new("sh");
    sh.arg("-c").arg(command);
    let output = output_within(sh, CAPTURE_DEADLINE, CAPTURE_STOP_GRACE)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let hint = stderr.trim().lines().next_back().unwrap_or("").trim();
        return Err(CliError::Auth(format!(
            "capture command failed ({}){}",
            output.status,
            if hint.is_empty() {
                String::new()
            } else {
                format!(": {hint}")
            }
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Err(CliError::Auth(
            "capture command produced no session on stdout".into(),
        ));
    }
    Session::parse_captured(&stdout)
}

/// `Command::output`, stopping the command once `deadline` passes: SIGTERM first so
/// it can clean up after itself, then SIGKILL after `grace`. The pipes are drained on
/// threads, so a chatty command cannot block on a full one, and a child that exits
/// while something it started still holds them counts as running.
///
/// The command stays in this process's group, so Ctrl-C reaches all of it. That
/// means the deadline can only stop the command itself.
fn output_within(
    mut command: std::process::Command,
    deadline: Duration,
    grace: Duration,
) -> Result<std::process::Output, CliError> {
    use std::io::Read;
    use std::process::Stdio;

    fn drain(
        mut pipe: impl Read + Send + 'static,
    ) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes).map(|_| bytes)
        })
    }

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let failed = |e| CliError::Other(format!("failed to run capture command: {e}"));
    let mut child = command.spawn().map_err(failed)?;
    let stdout = drain(child.stdout.take().expect("piped above"));
    let stderr = drain(child.stderr.take().expect("piped above"));
    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait().map_err(failed)? {
            Some(status) if stdout.is_finished() && stderr.is_finished() => break status,
            _ if started.elapsed() >= deadline => {
                stop(&mut child, grace);
                return Err(CliError::Upstream(format!(
                    "capture command was stopped after running for {deadline:?}; anything it \
                     started may still be running, so check that before trying again"
                )));
            }
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    let collected = |handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>>| {
        handle
            .join()
            .expect("the drain thread only reads")
            .map_err(failed)
    };
    Ok(std::process::Output {
        status,
        stdout: collected(stdout)?,
        stderr: collected(stderr)?,
    })
}

fn stop(child: &mut std::process::Child, grace: Duration) {
    stop_with(child, grace, ask_to_stop);
}

/// A child already reaped is left alone: its pid may belong to something else by
/// now, and anything it left behind is in the error's "may still be running".
fn stop_with(child: &mut std::process::Child, grace: Duration, ask: impl FnOnce(u32)) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    ask(child.id());
    let asked = std::time::Instant::now();
    while asked.elapsed() < grace {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn ask_to_stop(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-s", "TERM", &pid.to_string()])
        .status();
}

/// Nothing to ask with here, so the grace only delays the kill.
#[cfg(not(unix))]
fn ask_to_stop(_pid: u32) {}

/// Renew the session, preferring the cheap path.
///
/// 1. If a session is stored, exchange its refresh token (no browser).
/// 2. If that fails because the refresh token is dead — or nothing is stored —
///    and a capture command is available, run it for a whole fresh bundle and
///    store it. This is what makes re-login unattended.
///
/// An upstream error (bot wall, 5xx) is returned as-is rather than masked by the
/// fallback, so a transient outage does not needlessly drive a browser.
pub fn refresh_or_relogin(
    cfg: &Config,
    creds: &CredentialStore,
    command: Option<&str>,
    presented: Option<&Session>,
    verbose: bool,
    quiet: bool,
) -> Result<Session, CliError> {
    let lock = RefreshLock::for_binary(crate::BIN)?;
    let plan = renew_session(
        &lock,
        presented,
        || session_to_renew(|| Session::from_keychain(creds), command.is_some()),
        |stored| {
            let refresh = match stored {
                Some(session) => {
                    let portal = Portal::with_session(cfg.base_url(), session, verbose)?;
                    Some(portal.refresh(cfg, creds))
                }
                None => None,
            };
            Ok(plan_after_refresh(refresh, command.is_some()))
        },
    )?;
    match plan {
        RefreshPlan::Use(session) => Ok(session),
        RefreshPlan::Surface(err) => Err(err),
        RefreshPlan::RunCommand => {
            let command =
                command.expect("plan_after_refresh emits RunCommand only when has_command is true");
            let capture_lock = RefreshLock::at(lock.path().with_file_name(CAPTURE_LOCK))
                .wait_at_most(CAPTURE_LOCK_WAIT);
            capture_once(
                &capture_lock,
                presented,
                || session_to_renew(|| Session::from_keychain(creds), true),
                || {
                    if !quiet {
                        eprintln!("refresh token unavailable — running capture command");
                    }
                    relogin_via_command(cfg, creds, &lock, command, presented, verbose)
                },
                || {
                    if !quiet {
                        eprintln!("another nlnt process is running the capture command; waiting");
                    }
                },
            )
        }
    }
}

/// One request's limit, connecting included.
const HTTP_TIMEOUT: Duration = Duration::from_secs(45);
/// How long a capture command may run: past the reference script's own 4-minute
/// limit, so its teardown normally runs before this does.
const CAPTURE_DEADLINE: Duration = Duration::from_secs(300);
/// How long a stopped capture has to clean up: past the reference script's 15 s
/// limit on its one-time-code command, during which it cannot handle a signal.
const CAPTURE_STOP_GRACE: Duration = Duration::from_secs(20);
/// How long a process waits for another's capture: as long as that capture can hold
/// the lock, which is its deadline, its grace, and the read that proves its bundle,
/// with a little over. A store that has to wait on the refresh lock is rarer, and
/// costs this process only an error it can retry.
const CAPTURE_LOCK_WAIT: Duration = Duration::from_secs(
    CAPTURE_DEADLINE.as_secs() + CAPTURE_STOP_GRACE.as_secs() + HTTP_TIMEOUT.as_secs() + 15,
);
/// Beside the refresh lock, and as empty. It keeps two captures from running at
/// once. It is its own file because a capture can take minutes and needs a code,
/// and `RefreshLock`'s holders must not make a login or a logout wait on that.
const CAPTURE_LOCK: &str = "token-capture.lock";

/// What the stored session says about the one a caller `presented`.
enum Since {
    /// It is gone: a logout ran while this process waited or captured.
    LoggedOut,
    /// It changed: another process renewed or signed in.
    Replaced(Session),
    /// Still the same, or there was never one.
    Unchanged(Option<Session>),
}

/// The whole session is compared, because a bare bearer string has no refresh token
/// to tell one session from the next.
fn since_presented(stored: Option<Session>, presented: Option<&Session>) -> Since {
    match (stored, presented) {
        (None, Some(_)) => Since::LoggedOut,
        (Some(stored), Some(presented))
            if stored.access_token == presented.access_token
                && stored.refresh_token == presented.refresh_token =>
        {
            Since::Unchanged(Some(stored))
        }
        (Some(stored), _) => Since::Replaced(stored),
        (None, None) => Since::Unchanged(None),
    }
}

fn logged_out_meanwhile() -> CliError {
    CliError::Auth("logged out while this command ran — run `nlnt auth login --browser`".into())
}

/// The stored session, where nothing stored means a command can bootstrap one.
/// Without a command that surfaces the actionable "run `nlnt auth login`".
fn session_to_renew(
    read: impl FnOnce() -> Result<Session, CliError>,
    has_command: bool,
) -> Result<Option<Session>, CliError> {
    match read() {
        Ok(session) => Ok(Some(session)),
        Err(CliError::Auth(_)) if has_command => Ok(None),
        Err(e) => Err(e),
    }
}

/// One renewal, safe against every other `nlnt` process. They share one refresh
/// token, and Duende answers a second use of a retired one by revoking the whole
/// family (docs/api.md § Token lifetimes). So the session is read again under the
/// lock, and a stored session other than the one `presented` means another process
/// renewed while this one waited: it is used, with no grant.
fn renew_session(
    lock: &RefreshLock,
    presented: Option<&Session>,
    read: impl FnOnce() -> Result<Option<Session>, CliError>,
    renew: impl FnOnce(Option<Session>) -> Result<RefreshPlan, CliError>,
) -> Result<RefreshPlan, CliError> {
    lock.hold(|| match since_presented(read()?, presented) {
        Since::LoggedOut => Err(logged_out_meanwhile()),
        Since::Replaced(session) => Ok(RefreshPlan::Use(session)),
        Since::Unchanged(stored) => renew(stored),
    })
}

/// One capture at a time across every `nlnt` process, since a full login can spend
/// a one-time code. Whoever finds the lock free runs the command. Whoever finds it
/// held waits, and uses the session that capture stored; if nothing was stored, that
/// capture failed, and this process says so rather than spending another code.
fn capture_once(
    lock: &RefreshLock,
    presented: Option<&Session>,
    read: impl Fn() -> Result<Option<Session>, CliError>,
    capture: impl FnOnce() -> Result<Session, CliError>,
    waiting: impl FnOnce(),
) -> Result<Session, CliError> {
    let first = lock.try_hold(|| match since_presented(read()?, presented) {
        Since::LoggedOut => Err(logged_out_meanwhile()),
        Since::Replaced(session) => Ok(session),
        Since::Unchanged(_) => capture(),
    })?;
    if let Some(session) = first {
        return Ok(session);
    }
    waiting();
    after_another_capture(lock, presented, read)
}

/// The waiting half of [`capture_once`].
fn after_another_capture(
    lock: &RefreshLock,
    presented: Option<&Session>,
    read: impl Fn() -> Result<Option<Session>, CliError>,
) -> Result<Session, CliError> {
    lock.hold(|| match since_presented(read()?, presented) {
        Since::LoggedOut => Err(logged_out_meanwhile()),
        Since::Replaced(session) => Ok(session),
        Since::Unchanged(_) => Err(CliError::Auth(
            "another nlnt process just ran the capture command and it stored no session, so \
             this one did not spend another code — see its error, or run `nlnt auth refresh`"
                .into(),
        )),
    })
}

/// Store a captured bundle, unless what is stored changed during the capture: a
/// sign-in's newer session stays, and a logout stays a logout.
fn store_capture(
    lock: &RefreshLock,
    presented: Option<&Session>,
    captured: Session,
    read: impl FnOnce() -> Result<Option<Session>, CliError>,
    store: impl FnOnce(&Session) -> Result<(), CliError>,
) -> Result<Session, CliError> {
    lock.store_signin(|| match since_presented(read()?, presented) {
        Since::LoggedOut => Err(logged_out_meanwhile()),
        Since::Replaced(session) => Ok(session),
        Since::Unchanged(_) => {
            store(&captured)?;
            Ok(captured)
        }
    })
}

/// The session stored now, for an explicit `auth refresh`, which has no failed
/// read to compare against.
pub fn stored_session(creds: &CredentialStore) -> Result<Option<Session>, CliError> {
    session_to_renew(|| Session::from_keychain(creds), true)
}

/// What [`refresh_or_relogin`] should do, given the refresh-token outcome and
/// whether a capture command is available. **This is the fallback invariant**,
/// extracted pure so it is unit-testable without a keychain or the network:
/// only an *auth* failure may trigger the capture command; an upstream/transient
/// error is surfaced as-is so a blip never needlessly drives a browser.
#[derive(Debug)]
enum RefreshPlan {
    /// The refresh succeeded; use this session.
    Use(Session),
    /// Fall back to the capture command.
    RunCommand,
    /// Surface this error without falling back.
    Surface(CliError),
}

fn plan_after_refresh(
    refresh: Option<Result<Session, CliError>>,
    has_command: bool,
) -> RefreshPlan {
    match refresh {
        Some(Ok(session)) => RefreshPlan::Use(session),
        // Refresh token rejected (dead/rotated): fall back only if we can.
        Some(Err(e @ CliError::Auth(_))) => {
            if has_command {
                RefreshPlan::RunCommand
            } else {
                RefreshPlan::Surface(e)
            }
        }
        // Upstream/other error: surface it, never drive a browser over a blip.
        Some(Err(e)) => RefreshPlan::Surface(e),
        // No stored session (reached only when a command is present): bootstrap.
        None => RefreshPlan::RunCommand,
    }
}

/// Run the capture command, verify the bundle reads, and store it.
fn relogin_via_command(
    cfg: &Config,
    creds: &CredentialStore,
    lock: &RefreshLock,
    command: &str,
    presented: Option<&Session>,
    verbose: bool,
) -> Result<Session, CliError> {
    let session = run_capture_command(command, verbose)?;
    // A capture command should return a fresh token, but if it returns one the
    // portal rejects (a stale token, or an MFA-incomplete `acr`), the raw 401
    // from the verify read is baffling — the user just re-logged in. Translate
    // it into the real cause. Non-auth errors (bot wall, 5xx) pass through.
    prove_it_reads(cfg, &session, verbose)
        .map_err(nothing_stored)
        .map_err(rejected_capture)?;
    store_capture(
        lock,
        presented,
        session,
        || session_to_renew(|| Session::from_keychain(creds), true),
        |session| session.store(creds),
    )
}

fn rejected_capture(err: CliError) -> CliError {
    match err {
        CliError::Auth(_) => CliError::Auth(
            "the capture command returned a token the portal rejected — the identity session \
             has likely lapsed, so a full login (username/password and, unless this device is \
             trusted, an MFA code) is needed. Run `nlnt auth login --browser --overwrite`, or \
             check the capture command's setup."
                .into(),
        ),
        other => other,
    }
}

/// Log in from a captured bundle: **prove it reads**, then store it.
///
/// Storing a token that was never exercised is how a CLI ends up with a keychain
/// entry that fails on the next command instead of at login.
pub fn establish_session(
    cfg: &Config,
    creds: &CredentialStore,
    session: Session,
    verify: bool,
    verbose: bool,
) -> Result<(), CliError> {
    store_if_proven(
        || {
            if verify {
                prove_it_reads(cfg, &session, verbose)
            } else {
                Ok(())
            }
        },
        // Under the lock a renewal holds, so one in flight cannot overwrite this
        // session with the old one's tokens.
        || RefreshLock::for_binary(crate::BIN)?.store_signin(|| session.store(creds)),
    )
}

/// A value that can be supplied again stores nothing unless the read proves it.
fn store_if_proven(
    read: impl FnOnce() -> Result<(), CliError>,
    store: impl FnOnce() -> Result<(), CliError>,
) -> Result<(), CliError> {
    read().map_err(nothing_stored)?;
    store()
}

/// A session read out of the sign-in window: **keep it unless the portal refuses
/// it.** By the time this runs Chrome has stopped and the page's copy is gone, so
/// not storing it costs the owner another sign-in. Returns why the session is
/// unverified, if it is.
pub fn keep_signed_in_session(
    cfg: &Config,
    creds: &CredentialStore,
    session: Session,
    verbose: bool,
) -> Result<Option<Unverified>, CliError> {
    keep_finished_sign_in(
        || verifying_read(cfg, &session, verbose),
        || RefreshLock::for_binary(crate::BIN)?.store_signin(|| session.store(creds)),
    )
}

/// What the portal answered, before anything judges it.
struct Answer {
    status: u16,
    content_type: String,
    body: String,
}

/// Why a kept session is unverified.
#[derive(Debug, PartialEq, Eq)]
pub struct Unverified {
    pub reason: String,
    /// The answer was a block on this client rather than a word about the session,
    /// so a new sign-in may not clear it.
    pub edge_block: bool,
}

/// A verifying read that didn't accept the session.
#[derive(Debug)]
struct FailedRead {
    error: CliError,
    edge_block: bool,
}

impl From<CliError> for FailedRead {
    fn from(error: CliError) -> Self {
        FailedRead {
            error,
            edge_block: false,
        }
    }
}

/// The decision behind [`keep_signed_in_session`]. Only `Auth` is the portal
/// refusing the session ([`classify_error`]). Anything else, such as a 429, a 5xx, a
/// dropped connection, a body with no data or an edge block, says nothing about it.
/// Storing such a session is safe: site storage is cleared before Chrome starts, so
/// it can only be this sign-in's. A later read settles an outage, not an answer
/// that repeats, so the warning names a way out ([`READS_KEEP_FAILING`],
/// [`EDGE_BLOCK_WAY_OUT`]).
fn keep_finished_sign_in(
    read: impl FnOnce() -> Result<(), FailedRead>,
    store: impl FnOnce() -> Result<(), CliError>,
) -> Result<Option<Unverified>, CliError> {
    let unverified = match read() {
        Ok(()) => None,
        Err(FailedRead {
            error: refused @ CliError::Auth(_),
            ..
        }) => return Err(refused),
        Err(FailedRead { error, edge_block }) => Some(Unverified {
            reason: error.to_string(),
            edge_block,
        }),
    };
    store()?;
    Ok(unverified)
}

/// For a route that stores nothing when the read can't prove the session.
fn nothing_stored(err: CliError) -> CliError {
    match err {
        CliError::Upstream(m) => {
            CliError::Upstream(format!("{}; nothing was stored", without_way_out(&m)))
        }
        other => other,
    }
}

/// A cheap, read-only endpoint that proves the token is accepted.
fn prove_it_reads(cfg: &Config, session: &Session, verbose: bool) -> Result<(), CliError> {
    verifying_read(cfg, session, verbose).map_err(|failed| failed.error)
}

/// [`prove_it_reads`], saying whether a failure was an edge block. That comes from
/// the answer rather than the message, so rewording an error can't change it.
fn verifying_read(cfg: &Config, session: &Session, verbose: bool) -> Result<(), FailedRead> {
    let path = paths::OVERVIEW;
    let portal = Portal::with_session(cfg.base_url(), session.clone(), verbose)?;
    let answer = portal.answer(path)?;
    guard(path, answer.status, &answer.content_type, &answer.body)
        .and_then(|()| verifying_read_holds_data(path, &answer.body))
        .map_err(|error| FailedRead {
            error,
            edge_block: is_edge_answer(answer.status, &answer.content_type, &answer.body),
        })
}

/// An answer from something in front of the API, which never judged the session.
/// A `401` and a `404` are the portal's own.
fn is_edge_answer(status: u16, content_type: &str, body: &str) -> bool {
    let html = is_html_page(body);
    match status {
        401 | 404 => false,
        403 => html || is_bot_wall(body),
        200..=299 => html,
        _ => html && content_type.contains("application/json"),
    }
}

/// A 2xx with nothing in it doesn't show the token was accepted: a stale session
/// could get an empty body, `null` or `{}`. The overview is a JSON object, so anything but JSON with something in it is
/// inconclusive. The caller decides what that means for the session.
fn verifying_read_holds_data(path: &str, body: &str) -> Result<(), CliError> {
    if is_html_page(body) {
        return Err(CliError::Upstream(format!(
            "the verifying read of {path} answered with an HTML page rather than the API's \
             answer (edge error or challenge); {EDGE_BLOCK_WAY_OUT}"
        )));
    }
    let holds_data = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(fields)) => !fields.is_empty(),
        Ok(serde_json::Value::Array(items)) => !items.is_empty(),
        _ => false,
    };
    if holds_data {
        return Ok(());
    }
    Err(CliError::Upstream(format!(
        "the verifying read of {path} answered with no data, so it doesn't show the session \
         was accepted"
    )))
}

/// Whether a 403 body is Akamai's edge denial rather than the application
/// refusing an unauthenticated request. The wall answers a bare
/// `HTTP 403 Access denied.` (sometimes with a `Reference #`), never JSON.
pub fn is_bot_wall(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("access denied")
        || lower.contains("reference #")
        || lower.contains("edgesuite.net")
        || lower.contains("akamai")
}

/// Whether a body is an HTML page. The portal's API answers JSON, so an HTML 403
/// comes from in front of it, whichever vendor's wording it uses.
fn is_html_page(body: &str) -> bool {
    body.trim_start_matches('\u{feff}')
        .trim_start()
        .starts_with('<')
}

/// The advice on a refused read, kept apart so a login, with nothing stored to
/// refresh, can drop it and keep the reason.
pub const RENEW_ADVICE: &str =
    "; run `nlnt auth refresh` (or `nlnt auth login --browser --overwrite`)";

/// The way out of an answer a stored session can't get past. Nothing renews on an
/// edge block, and `auth login` refuses a stored session without `--overwrite`.
pub const READS_KEEP_FAILING: &str =
    "if reads keep failing, run `nlnt auth login --browser --overwrite`";

/// The way out of an edge block. A block on this client outlasts a new sign-in, so
/// the sign-in comes last.
pub const EDGE_BLOCK_WAY_OUT: &str = "a new sign-in may not clear this, because the block is on \
     this client rather than the session; wait or try another network, and if reads still \
     fail, run `nlnt auth login --browser --overwrite`";

/// The way out of the Akamai denial on an ordinary read, which names no sign-in: it
/// comes before any credential is considered.
const BOT_WALL_WAY_OUT: &str = "a new sign-in won't clear this, because the block is on this \
     client rather than the session; wait or try another network";

/// A message without its way out, for a caller that words its own, or that has no
/// stored session for reads to fail with.
pub fn without_way_out(message: &str) -> &str {
    [READS_KEEP_FAILING, EDGE_BLOCK_WAY_OUT, BOT_WALL_WAY_OUT]
        .iter()
        .find_map(|way_out| message.strip_suffix(way_out)?.strip_suffix("; "))
        .unwrap_or(message)
}

fn bot_wall_error(path: &str) -> CliError {
    CliError::Upstream(format!(
        "blocked by the portal's bot protection (Akamai) on {path}, not by your \
         credentials — the request was refused before the token was read. This usually \
         means the sentinel headers were stripped by a proxy. See the 'Akamai bot wall' \
         section of docs/api.md; {BOT_WALL_WAY_OUT}"
    ))
}

/// The shared bot-wall / auth / not-found classification, so the JSON path
/// ([`guard`]) and the PDF path ([`Portal::get_pdf`]) can never drift on how a
/// 403 is split between Akamai and a real auth failure. Returns the error for a
/// status that means "not your data", or `None` for a status the caller must
/// handle itself (2xx, or a body it needs to inspect further).
fn classify_error(path: &str, status: u16, body: &str) -> Option<CliError> {
    // A 403 from Akamai happens before any credential is considered; telling the
    // user to re-authenticate would have them re-capture a token for nothing.
    if status == 403 && is_bot_wall(body) {
        return Some(bot_wall_error(path));
    }
    // Any other edge block, in wording `is_bot_wall` doesn't know. Renewing would
    // spend a refresh token on a request the token never reached.
    if status == 403 && is_html_page(body) {
        return Some(CliError::Upstream(format!(
            "blocked in front of the portal on {path}: HTTP 403 with an HTML page rather than \
             the API's answer, which says nothing about the token; {EDGE_BLOCK_WAY_OUT}"
        )));
    }
    if matches!(status, 401 | 403) {
        return Some(CliError::Auth(format!(
            "portal returned {status} for {path} — the access token is missing or \
             expired{RENEW_ADVICE}"
        )));
    }
    if status == 404 {
        return Some(CliError::NotFound(format!("{path} (HTTP 404)")));
    }
    None
}

/// The auth/expiry/bot guard for a JSON GET.
pub fn guard(path: &str, status: u16, content_type: &str, body: &str) -> Result<(), CliError> {
    if let Some(err) = classify_error(path, status, body) {
        return Err(err);
    }
    // JSON was promised and HTML arrived: an Akamai interstitial or an error
    // page. Treat as upstream, not success.
    if content_type.contains("application/json") && is_html_page(body) {
        return Err(CliError::Upstream(format!(
            "portal returned HTML instead of JSON for {path} (edge error or challenge); \
             {EDGE_BLOCK_WAY_OUT}"
        )));
    }
    if !(200..300).contains(&status) {
        return Err(CliError::Upstream(format!(
            "portal HTTP {status} for {path}"
        )));
    }
    Ok(())
}

/// Confirm downloaded bytes really are a PDF, returning the human message when
/// they are not. The download path's only positive success signal: a `%PDF-`
/// header within the first kilobyte. Without it, an error page gets written to
/// disk under a `.pdf` name and the CLI prints "Saved".
pub fn pdf_error(bytes: &[u8], what: &str) -> Option<String> {
    const MAGIC: &[u8] = b"%PDF-";
    let window = &bytes[..bytes.len().min(1024)];
    if window.windows(MAGIC.len()).any(|w| w == MAGIC) {
        return None;
    }
    if bytes.is_empty() {
        return Some(format!(
            "portal returned an empty body for {what:?} instead of a PDF; nothing was written"
        ));
    }
    let first_visible = window
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|i| window[i]);
    if first_visible == Some(b'<') || first_visible == Some(b'{') {
        return Some(format!(
            "portal returned a non-PDF response for {what:?} (session likely lapsed) — run \
             `nlnt auth refresh` and retry. Nothing was written"
        ));
    }
    Some(format!(
        "portal returned {} bytes for {what:?} that are not a PDF (no %PDF- header) — \
         nothing was written",
        bytes.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verifying_read_with_no_data_is_inconclusive() {
        for body in [
            "",
            " \n",
            "null",
            "{}",
            "{ }",
            "[]",
            "true",
            "<html></html>",
        ] {
            let e = verifying_read_holds_data("/dummy", body).unwrap_err();
            let names_the_edge = e.to_string().ends_with(EDGE_BLOCK_WAY_OUT);
            assert_eq!(names_the_edge, body.starts_with('<'), "{body:?}");
            assert_eq!(e.exit_code(), 5, "{body:?}");
            let m = e.to_string();
            assert!(m.contains("/dummy"), "{m}");
            // The window route stores it, so only the piped route may say this.
            assert!(!m.contains("nothing was stored"), "{m}");
            assert!(nothing_stored(e).to_string().contains("nothing was stored"));
        }
        verifying_read_holds_data("/dummy", r#"{"dummy":1}"#).unwrap();
    }

    #[test]
    fn a_real_pdf_passes() {
        assert!(pdf_error(b"%PDF-1.7\n1 0 obj", "1098-E").is_none());
    }

    #[test]
    fn a_short_preamble_is_tolerated() {
        let mut bytes = vec![b'\n'; 8];
        bytes.extend_from_slice(b"%PDF-1.4");
        assert!(pdf_error(&bytes, "stmt").is_none());
    }

    #[test]
    fn html_masquerading_as_a_pdf_is_rejected() {
        let msg = pdf_error(b"<!DOCTYPE html><html><body>Sign in</body></html>", "stmt")
            .expect("must be rejected");
        assert!(msg.contains("Nothing was written") || msg.contains("nothing was written"));
    }

    #[test]
    fn json_error_masquerading_as_a_pdf_is_rejected() {
        assert!(pdf_error(br#"{"isDirect":["invalid"]}"#, "stmt").is_some());
    }

    #[test]
    fn magic_beyond_the_first_kilobyte_does_not_count() {
        let mut bytes = vec![b'x'; 2000];
        bytes.extend_from_slice(b"%PDF-1.4");
        assert!(pdf_error(&bytes, "doc").is_some());
    }

    #[test]
    fn empty_download_is_rejected() {
        assert!(pdf_error(b"", "doc").unwrap().contains("empty"));
    }

    #[test]
    fn a_bot_wall_403_is_upstream_not_auth() {
        let err = guard(
            "/api/1/loan/overview",
            403,
            "text/html",
            "\u{feff}HTTP 403 Access denied.",
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("bot protection"));
        assert!(!err.to_string().contains("auth login"));
        assert!(err.to_string().ends_with(BOT_WALL_WAY_OUT));
    }

    #[test]
    fn a_401_is_an_auth_error() {
        let err = guard("/api/1/loan/overview", 401, "application/json", "{}").unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("auth refresh"));
    }

    /// A portal on loopback that gives one raw answer to one request, then hangs up.
    fn portal_answering(raw: String) -> Config {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = conn.write_all(raw.as_bytes());
        });
        Config {
            base_url: Some(format!("http://127.0.0.1:{port}")),
            ..Config::default()
        }
    }

    /// The real verifying read of a dummy session against that portal.
    fn verifying_answer(status: u16, content_type: &str, body: &str) -> Result<(), CliError> {
        let raw = format!(
            "HTTP/1.1 {status} Dummy\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        );
        prove_it_reads(&portal_answering(raw), &session(), false)
    }

    /// The connection closes with no answer at all.
    fn dropped_connection() -> Result<(), CliError> {
        prove_it_reads(&portal_answering(String::new()), &session(), false)
    }

    /// Every answer that says nothing about the session, and a word of its reason.
    fn inconclusive_answers() -> Vec<(Result<(), CliError>, &'static str)> {
        let json = "application/json";
        vec![
            (verifying_answer(429, json, ""), "429"),
            (verifying_answer(500, json, ""), "500"),
            (verifying_answer(503, json, ""), "503"),
            (verifying_answer(200, json, ""), "no data"),
            (verifying_answer(200, json, "null"), "no data"),
            (verifying_answer(200, json, "{}"), "no data"),
            (verifying_answer(200, "text/plain", "not json"), "no data"),
            (verifying_answer(200, json, "<html></html>"), "HTML"),
            (verifying_answer(404, json, ""), "404"),
            (
                verifying_answer(403, "text/html", "<html>Forbidden</html>"),
                "HTML page",
            ),
            (
                verifying_answer(403, "text/html", "HTTP 403 Access denied."),
                "bot protection",
            ),
            (dropped_connection(), "failed"),
        ]
    }

    fn refusals() -> Vec<Result<(), CliError>> {
        vec![
            verifying_answer(401, "application/json", "{}"),
            verifying_answer(401, "text/plain", ""),
            verifying_answer(403, "application/json", r#"{"message":"dummy"}"#),
            verifying_answer(403, "text/plain", ""),
        ]
    }

    /// The warning's wording follows the answer itself, whatever the message says.
    #[test]
    fn the_verifying_read_names_an_edge_block_by_its_answer() {
        let json = "application/json";
        for (status, kind, body, edge) in [
            (403, "text/html", "<html>Forbidden</html>", true),
            (403, "text/html", "HTTP 403 Access denied.", true),
            (200, json, "<html></html>", true),
            (200, "text/html", "\u{feff}<html></html>", true),
            (503, json, "<html></html>", true),
            (429, json, "", false),
            (503, "text/html", "<html></html>", false),
            (200, json, "{}", false),
            (200, "text/plain", "not json", false),
            (404, "text/html", "<html></html>", false),
        ] {
            let raw = format!(
                "HTTP/1.1 {status} Dummy\r\ncontent-type: {kind}\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n{body}",
                body.len()
            );
            let failed = verifying_read(&portal_answering(raw), &session(), false).unwrap_err();
            assert_eq!(failed.edge_block, edge, "{status} {kind} {body:?}");
        }
        let dropped = verifying_read(&portal_answering(String::new()), &session(), false);
        assert!(!dropped.unwrap_err().edge_block);
    }

    #[test]
    fn a_kept_session_says_whether_the_read_was_an_edge_block() {
        let blocked = FailedRead {
            error: CliError::Upstream("dummy".into()),
            edge_block: true,
        };
        let kept = keep_finished_sign_in(|| Err(blocked), || Ok(()))
            .unwrap()
            .unwrap();
        assert!(kept.edge_block);
        assert_eq!(kept.reason, CliError::Upstream("dummy".into()).to_string());
    }

    /// Runs the decision with a store that only records it was called.
    fn keep(read: Result<(), CliError>) -> (Result<Option<Unverified>, CliError>, bool) {
        let stored = std::cell::Cell::new(false);
        let kept = keep_finished_sign_in(
            || read.map_err(FailedRead::from),
            || {
                stored.set(true);
                Ok(())
            },
        );
        (kept, stored.get())
    }

    /// Each answer that says nothing about the session stores it, and gives the
    /// reason for the warning.
    #[test]
    fn an_inconclusive_read_keeps_the_finished_sign_in() {
        for (read, reason) in inconclusive_answers() {
            let (kept, stored) = keep(read);
            let why = kept.unwrap().expect("marked unverified").reason;
            assert!(why.contains(reason), "{reason}: {why}");
            assert!(stored, "{reason}");
        }
    }

    #[test]
    fn a_definite_refusal_stores_nothing() {
        for read in refusals() {
            let (kept, stored) = keep(read);
            assert_eq!(kept.unwrap_err().exit_code(), 3);
            assert!(!stored);
        }
    }

    /// A value piped in can be piped in again, so only a proven read stores it.
    #[test]
    fn the_piped_route_stores_only_a_proven_session() {
        let piped = |read: Result<(), CliError>| {
            let stored = std::cell::Cell::new(false);
            let result = store_if_proven(
                || read,
                || {
                    stored.set(true);
                    Ok(())
                },
            );
            (result, stored.get())
        };
        for (read, reason) in inconclusive_answers() {
            let code = read.as_ref().unwrap_err().exit_code();
            let (result, stored) = piped(read);
            let e = result.unwrap_err();
            assert_eq!(e.exit_code(), code, "{reason}: {e}");
            assert!(e.to_string().contains(reason), "{reason}: {e}");
            if code == 5 {
                assert!(e.to_string().contains("nothing was stored"), "{e}");
            }
            assert!(!stored, "{reason}");
        }
        for read in refusals() {
            let (result, stored) = piped(read);
            assert_eq!(result.unwrap_err().exit_code(), 3);
            assert!(!stored);
        }
        let (result, stored) = piped(Ok(()));
        result.unwrap();
        assert!(stored);
    }

    #[test]
    fn a_proven_session_is_stored_with_nothing_to_warn_about() {
        let (kept, stored) = keep(verifying_answer(200, "application/json", r#"{"dummy":1}"#));
        assert_eq!(kept.unwrap(), None);
        assert!(stored);
    }

    /// The keychain write failing is not an unverified session: the owner must
    /// hear that nothing was kept.
    #[test]
    fn a_failed_store_is_an_error_even_after_an_inconclusive_read() {
        let e = keep_finished_sign_in(
            || Err(CliError::Upstream("HTTP 503".into()).into()),
            || Err(CliError::Keychain("denied".into())),
        )
        .unwrap_err();
        assert!(matches!(e, CliError::Keychain(_)), "{e}");
    }

    /// An HTML 403 is an edge block: not a refusal of the token, on any read, and
    /// its reason says so. The API's own 403 stays a refusal.
    #[test]
    fn an_html_403_keeps_its_reason_and_is_not_auth() {
        for body in [
            "<!DOCTYPE html><title>Blocked</title>",
            "\u{feff} <html></html>",
        ] {
            let err = guard("/dummy", 403, "text/html", body).unwrap_err();
            assert_eq!(err.exit_code(), 5, "{err}");
            let m = err.to_string();
            assert!(m.contains("/dummy"), "{m}");
            assert!(m.contains("HTTP 403 with an HTML page"), "{m}");
            assert!(m.contains("says nothing about the token"), "{m}");
            // Nothing renews on this answer, so the error names the way out.
            assert!(m.ends_with(&format!("; {EDGE_BLOCK_WAY_OUT}")), "{m}");
        }
    }

    /// A piped route has no stored session for reads to fail with.
    #[test]
    fn nothing_stored_drops_the_way_out_and_keeps_the_reason() {
        let blocked = guard("/dummy", 403, "text/html", "<html></html>").unwrap_err();
        let m = nothing_stored(blocked).to_string();
        assert!(m.contains("says nothing about the token"), "{m}");
        assert!(m.ends_with("; nothing was stored"), "{m}");
        assert!(!m.contains("may not clear"), "{m}");
        let bot = guard("/dummy", 403, "text/html", "HTTP 403 Access denied.").unwrap_err();
        let m = nothing_stored(bot).to_string();
        assert!(!m.contains("won't clear"), "{m}");
        assert_eq!(without_way_out("portal HTTP 503"), "portal HTTP 503");
        let outage =
            "portal HTTP 503; if reads keep failing, run `nlnt auth login --browser --overwrite`";
        assert_eq!(without_way_out(outage), "portal HTTP 503");
    }

    #[test]
    fn an_application_403_is_an_auth_error() {
        let err = guard(
            "/api/1/loan/overview",
            403,
            "application/json",
            r#"{"message":"forbidden"}"#,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3);
    }

    #[test]
    fn html_where_json_expected_is_upstream() {
        let err = guard(
            "/api/1/loan/overview",
            200,
            "application/json; charset=utf-8",
            "<!DOCTYPE html>",
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn missing_page_is_not_found() {
        let err = guard("/api/1/nope", 404, "application/json", "").unwrap_err();
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn server_error_is_upstream() {
        let err = guard("/api/1/loan/overview", 503, "text/html", "maintenance").unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn success_json_passes() {
        assert!(guard("/api/1/loan/overview", 200, "application/json", "{}").is_ok());
    }

    #[test]
    fn parse_captured_reads_the_oidc_user_object() {
        let raw = r#"{"access_token":"AAA","refresh_token":"RRR","id_token":"III","expires_at":1786551430}"#;
        let s = Session::parse_captured(raw).unwrap();
        assert_eq!(s.access_token, "AAA");
        assert_eq!(s.refresh_token.as_deref(), Some("RRR"));
        assert_eq!(s.expires_at, Some(1786551430));
    }

    #[test]
    fn parse_captured_accepts_a_bare_bearer_string() {
        let s = Session::parse_captured("Bearer XYZ").unwrap();
        assert_eq!(s.access_token, "XYZ");
        assert!(s.refresh_token.is_none());
        assert!(s.expires_at.is_none());
    }

    #[test]
    fn parse_captured_rejects_json_without_a_token() {
        let err = Session::parse_captured(r#"{"profile":{}}"#).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("access_token"));
    }

    #[test]
    fn expiry_uses_the_skew() {
        let s = Session {
            access_token: "a".into(),
            expires_at: Some(1000),
            ..Default::default()
        };
        assert!(!s.is_expired(900, 30));
        assert!(s.is_expired(980, 30)); // within skew
        assert!(s.is_expired(1001, 0));
        // No expiry known → never proactively refresh.
        let bare = Session {
            access_token: "a".into(),
            ..Default::default()
        };
        assert!(!bare.is_expired(i64::MAX, 0));
    }

    fn session() -> Session {
        Session {
            access_token: "a".into(),
            ..Default::default()
        }
    }

    fn holding(refresh: &str) -> Session {
        Session {
            refresh_token: Some(refresh.into()),
            ..session()
        }
    }

    /// Two contenders, each with its own open of the lock file, which is what
    /// contends, and both saw the same token refused. Offline, with the keychain
    /// and the token endpoint stood in for. The grant's sleep makes them overlap;
    /// `refresh_lock`'s own two-process test is the strict proof.
    #[test]
    fn two_contenders_post_one_grant_and_both_use_its_tokens() {
        use std::sync::{Arc, Barrier, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token-refresh.lock");
        let stored = Arc::new(Mutex::new(holding("dummy-refresh-1")));
        let grants = Arc::new(Mutex::new(Vec::new()));
        let start = Arc::new(Barrier::new(2));
        let contenders: Vec<_> = (0..2)
            .map(|_| {
                let (path, stored, grants, start) = (
                    path.clone(),
                    Arc::clone(&stored),
                    Arc::clone(&grants),
                    Arc::clone(&start),
                );
                std::thread::spawn(move || {
                    start.wait();
                    renew_session(
                        &RefreshLock::at(path),
                        Some(&holding("dummy-refresh-1")),
                        || Ok(Some(stored.lock().unwrap().clone())),
                        |session| {
                            let spent = session.unwrap().refresh_token.unwrap();
                            grants.lock().unwrap().push(spent);
                            std::thread::sleep(Duration::from_millis(100));
                            let fresh = holding("dummy-refresh-2");
                            *stored.lock().unwrap() = fresh.clone();
                            Ok(RefreshPlan::Use(fresh))
                        },
                    )
                })
            })
            .collect();
        for contender in contenders {
            let RefreshPlan::Use(session) = contender.join().unwrap().unwrap() else {
                panic!("a contender did not get a session");
            };
            assert_eq!(session.refresh_token.as_deref(), Some("dummy-refresh-2"));
        }
        assert_eq!(*grants.lock().unwrap(), ["dummy-refresh-1"]);
    }

    fn a_lock(dir: &tempfile::TempDir) -> RefreshLock {
        RefreshLock::at(dir.path().join("token.lock")).wait_at_most(Duration::from_millis(100))
    }

    #[test]
    fn a_stored_token_that_changed_skips_the_grant() {
        let dir = tempfile::tempdir().unwrap();
        let plan = renew_session(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            || Ok(Some(holding("dummy-refresh-2"))),
            |_| panic!("another process renewed: no grant"),
        )
        .unwrap();
        let RefreshPlan::Use(session) = plan else {
            panic!("expected the stored session");
        };
        assert_eq!(session.refresh_token.as_deref(), Some("dummy-refresh-2"));
    }

    #[test]
    fn a_logout_while_waiting_is_an_auth_error_and_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let err = renew_session(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            || Ok(None),
            |_| panic!("logged out: no grant and no capture"),
        )
        .err()
        .unwrap();
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn no_stored_session_still_reaches_the_renewal() {
        let dir = tempfile::tempdir().unwrap();
        let plan = renew_session(
            &a_lock(&dir),
            None,
            || Ok(None),
            |stored| {
                assert!(stored.is_none());
                Ok(RefreshPlan::RunCommand)
            },
        )
        .unwrap();
        assert!(matches!(plan, RefreshPlan::RunCommand));
    }

    #[test]
    fn a_held_lock_is_a_bounded_error_and_no_grant() {
        let dir = tempfile::tempdir().unwrap();
        let lock = a_lock(&dir);
        RefreshLock::at(lock.path())
            .hold(|| {
                let err = renew_session(
                    &lock,
                    Some(&holding("dummy-refresh-1")),
                    || panic!("no read without the lock"),
                    |_| panic!("no grant without the lock"),
                )
                .err()
                .unwrap();
                assert_eq!(err.exit_code(), 5, "{err}");
                assert!(err.to_string().contains("token.lock"), "{err}");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn nothing_stored_is_a_bootstrap_only_with_a_command() {
        let none = || Err(CliError::Auth("dummy: not logged in".into()));
        assert!(session_to_renew(none, true).unwrap().is_none());
        assert_eq!(session_to_renew(none, false).unwrap_err().exit_code(), 3);
        let down = || Err(CliError::Keychain("dummy: refused".into()));
        assert!(session_to_renew(down, true).is_err());
    }

    fn no_wait() {}

    #[test]
    fn first_in_line_runs_the_capture() {
        let dir = tempfile::tempdir().unwrap();
        let session = capture_once(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            || Ok(Some(holding("dummy-refresh-1"))),
            || Ok(holding("dummy-from-the-capture")),
            || panic!("the lock is free"),
        )
        .unwrap();
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("dummy-from-the-capture")
        );
    }

    #[test]
    fn first_in_line_uses_a_session_stored_since_it_was_refused() {
        let dir = tempfile::tempdir().unwrap();
        let session = capture_once(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            || Ok(Some(holding("dummy-refresh-2"))),
            || panic!("another process captured: no second capture"),
            no_wait,
        )
        .unwrap();
        assert_eq!(session.refresh_token.as_deref(), Some("dummy-refresh-2"));
    }

    #[test]
    fn a_logout_before_the_capture_starts_stays_a_logout() {
        let dir = tempfile::tempdir().unwrap();
        let err = capture_once(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            || Ok(None),
            || panic!("logged out: no capture"),
            no_wait,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn a_capture_already_running_is_never_joined_by_another() {
        let dir = tempfile::tempdir().unwrap();
        let lock = a_lock(&dir);
        RefreshLock::at(lock.path())
            .hold(|| {
                let waited = std::cell::Cell::new(false);
                let err = capture_once(
                    &lock,
                    Some(&holding("dummy-refresh-1")),
                    || Ok(Some(holding("dummy-refresh-1"))),
                    || panic!("another process is capturing: no second capture"),
                    || waited.set(true),
                )
                .unwrap_err();
                assert!(waited.get(), "the wait is announced");
                assert_eq!(err.exit_code(), 5, "bounded by the lock's wait: {err}");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn after_a_failed_capture_another_is_not_run() {
        let dir = tempfile::tempdir().unwrap();
        let err = after_another_capture(&a_lock(&dir), Some(&holding("dummy-refresh-1")), || {
            Ok(Some(holding("dummy-refresh-1")))
        })
        .unwrap_err();
        assert_eq!(err.exit_code(), 3, "{err}");
        assert!(
            err.to_string().contains("did not spend another code"),
            "{err}"
        );
    }

    #[test]
    fn after_a_good_capture_its_session_is_used() {
        let dir = tempfile::tempdir().unwrap();
        let session =
            after_another_capture(&a_lock(&dir), Some(&holding("dummy-refresh-1")), || {
                Ok(Some(holding("dummy-refresh-2")))
            })
            .unwrap();
        assert_eq!(session.refresh_token.as_deref(), Some("dummy-refresh-2"));
    }

    #[test]
    fn a_capture_is_stored_when_nothing_changed_meanwhile() {
        let dir = tempfile::tempdir().unwrap();
        let mut wrote = None;
        let session = store_capture(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            holding("dummy-from-the-capture"),
            || Ok(Some(holding("dummy-refresh-1"))),
            |session| {
                wrote = session.refresh_token.clone();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(wrote.as_deref(), Some("dummy-from-the-capture"));
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("dummy-from-the-capture")
        );
    }

    #[test]
    fn a_capture_does_not_overwrite_a_login_that_finished_first() {
        let dir = tempfile::tempdir().unwrap();
        let session = store_capture(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            holding("dummy-from-the-capture"),
            || Ok(Some(holding("dummy-from-the-login"))),
            |_| panic!("the login's session stays"),
        )
        .unwrap();
        assert_eq!(
            session.refresh_token.as_deref(),
            Some("dummy-from-the-login")
        );
    }

    #[test]
    fn a_capture_does_not_undo_a_logout_that_finished_first() {
        let dir = tempfile::tempdir().unwrap();
        let err = store_capture(
            &a_lock(&dir),
            Some(&holding("dummy-refresh-1")),
            holding("dummy-from-the-capture"),
            || Ok(None),
            |_| panic!("the logout stays"),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn a_capture_that_can_bootstrap_is_stored_with_nothing_there() {
        let dir = tempfile::tempdir().unwrap();
        let mut wrote = false;
        store_capture(
            &a_lock(&dir),
            None,
            holding("dummy-from-the-capture"),
            || Ok(None),
            |_| {
                wrote = true;
                Ok(())
            },
        )
        .unwrap();
        assert!(wrote);
    }

    fn bare(access: &str) -> Session {
        Session {
            access_token: access.into(),
            ..Default::default()
        }
    }

    /// A bare bearer string has no refresh token to tell one session from the next.
    #[test]
    fn a_capture_does_not_undo_the_logout_of_a_bare_token_session() {
        let dir = tempfile::tempdir().unwrap();
        let err = store_capture(
            &a_lock(&dir),
            Some(&bare("dummy-bearer-1")),
            holding("dummy-from-the-capture"),
            || Ok(None),
            |_| panic!("the logout stays"),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3, "{err}");
    }

    #[test]
    fn a_capture_does_not_overwrite_a_bare_token_login() {
        let dir = tempfile::tempdir().unwrap();
        let session = store_capture(
            &a_lock(&dir),
            Some(&bare("dummy-bearer-1")),
            holding("dummy-from-the-capture"),
            || Ok(Some(bare("dummy-bearer-2"))),
            |_| panic!("the login's session stays"),
        )
        .unwrap();
        assert_eq!(session.access_token, "dummy-bearer-2");
    }

    #[cfg(unix)]
    fn sh(script: &str) -> std::process::Command {
        let mut sh = std::process::Command::new("sh");
        sh.arg("-c").arg(script);
        sh
    }

    #[cfg(unix)]
    const NO_HURRY: Duration = Duration::from_secs(30);

    #[cfg(unix)]
    #[test]
    fn a_capture_within_its_deadline_returns_its_output() {
        let out =
            output_within(sh("echo dummy-out; echo dummy-err >&2"), NO_HURRY, NO_HURRY).unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "dummy-out");
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "dummy-err");
    }

    #[cfg(unix)]
    #[test]
    fn a_capture_past_its_deadline_is_asked_to_stop_so_it_can_clean_up() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("cleaned-up");
        let script = format!(
            "trap 'echo done > \"{}\"; exit 0' TERM; sleep 5 & wait",
            marker.display()
        );
        let err = output_within(sh(&script), Duration::from_secs(3), NO_HURRY).unwrap_err();
        assert_eq!(err.exit_code(), 5, "{err}");
        assert!(err.to_string().contains("stopped"), "{err}");
        assert!(err.to_string().contains("may still be running"), "{err}");
        assert!(marker.exists(), "the command never got to clean up");
    }

    #[cfg(unix)]
    #[test]
    fn a_capture_that_ignores_being_asked_is_killed_after_the_grace() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!(
            "trap '' TERM; echo $$ > '{}'; exec sleep 30",
            pidfile.display()
        );
        let err = output_within(
            sh(&script),
            Duration::from_secs(3),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 5, "{err}");
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        let alive = std::process::Command::new("kill")
            .args(["-0", pid.trim()])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        assert!(!alive, "the command was killed and reaped");
    }

    #[cfg(unix)]
    #[test]
    fn a_child_already_reaped_is_not_signalled() {
        let mut child = sh("exit 0").spawn().unwrap();
        child.wait().unwrap();
        stop_with(&mut child, NO_HURRY, |_| {
            panic!("its pid may belong to something else now")
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_background_child_holding_the_pipes_counts_as_running() {
        let err = output_within(sh("sleep 5 &"), Duration::from_millis(200), NO_HURRY).unwrap_err();
        assert!(err.to_string().contains("stopped"), "{err}");
    }

    #[test]
    fn a_successful_refresh_is_used() {
        assert!(matches!(
            plan_after_refresh(Some(Ok(session())), true),
            RefreshPlan::Use(_)
        ));
    }

    #[test]
    fn an_auth_failure_falls_back_only_when_a_command_exists() {
        // With a command → run it; without → surface the auth error (so the
        // user is told to `auth login`), never a silent success.
        assert!(matches!(
            plan_after_refresh(Some(Err(CliError::Auth("dead".into()))), true),
            RefreshPlan::RunCommand
        ));
        assert!(matches!(
            plan_after_refresh(Some(Err(CliError::Auth("dead".into()))), false),
            RefreshPlan::Surface(CliError::Auth(_))
        ));
    }

    /// The load-bearing invariant: a NON-auth error (bot wall, 5xx, network)
    /// must be surfaced as-is, never masked by driving the capture command,
    /// even when one is configured.
    #[test]
    fn a_non_auth_failure_is_surfaced_and_never_triggers_the_command() {
        assert!(matches!(
            plan_after_refresh(Some(Err(CliError::Upstream("bot wall".into()))), true),
            RefreshPlan::Surface(CliError::Upstream(_))
        ));
        assert!(matches!(
            plan_after_refresh(Some(Err(CliError::NotFound("x".into()))), true),
            RefreshPlan::Surface(CliError::NotFound(_))
        ));
    }

    #[test]
    fn no_stored_session_bootstraps_from_the_command() {
        assert!(matches!(
            plan_after_refresh(None, true),
            RefreshPlan::RunCommand
        ));
    }

    #[test]
    fn a_rejected_captured_token_gets_an_actionable_message() {
        // A 401 from verifying a just-captured token means the capture couldn't
        // truly renew — say so, don't parrot the raw 401.
        let e = rejected_capture(CliError::Auth("portal returned 401 for /x".into()));
        assert_eq!(e.exit_code(), 3);
        assert!(e.to_string().contains("full login"));
        assert!(e.to_string().contains("auth login"));
        // A non-auth error (bot wall, 5xx) passes through untouched.
        assert!(matches!(
            rejected_capture(CliError::Upstream("bot wall".into())),
            CliError::Upstream(_)
        ));
    }

    #[test]
    fn capture_command_parses_its_stdout_bundle() {
        let s = run_capture_command(
            r#"printf '{"access_token":"AAA","refresh_token":"RRR"}'"#,
            false,
        )
        .expect("parses");
        assert_eq!(s.access_token, "AAA");
        assert_eq!(s.refresh_token.as_deref(), Some("RRR"));
    }

    #[test]
    fn capture_command_failure_is_an_auth_error() {
        let err = run_capture_command("exit 7", false).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("capture command failed"));
    }

    #[test]
    fn capture_command_with_no_output_is_rejected() {
        let err = run_capture_command("true", false).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("no session"));
    }

    #[test]
    fn debug_redacts_every_token() {
        let s = Session {
            access_token: "SECRET_ACCESS".into(),
            refresh_token: Some("SECRET_REFRESH".into()),
            id_token: Some("SECRET_ID".into()),
            expires_at: Some(1786551430),
        };
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("SECRET_ACCESS"), "access token leaked: {dbg}");
        assert!(
            !dbg.contains("SECRET_REFRESH"),
            "refresh token leaked: {dbg}"
        );
        assert!(!dbg.contains("SECRET_ID"), "id token leaked: {dbg}");
        // Structure and non-secret fields still render.
        assert!(dbg.contains("Session"));
        assert!(dbg.contains("1786551430"));
    }

    #[test]
    fn statement_pdf_path_is_document_id_then_is_direct() {
        assert_eq!(
            paths::statement_pdf("abc-123", true),
            "/api/1/statements/pdf/abc-123/true"
        );
    }

    #[test]
    fn ua_and_sec_ch_ua_report_the_same_major() {
        assert!(user_agent().contains(&format!("Chrome/{CHROME_MAJOR}")));
        assert!(sec_ch_ua().contains(CHROME_MAJOR));
    }
}
