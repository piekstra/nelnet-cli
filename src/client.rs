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
            .map_err(|e| CliError::Other(format!("stored session is unreadable: {e}")))
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
            .timeout(Duration::from_secs(45))
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

    fn bearer(&self) -> String {
        format!("Bearer {}", self.session.access_token)
    }

    /// GET a JSON path and return the body, after the auth/bot guard.
    pub fn get_text(&self, path: &str) -> Result<String, CliError> {
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
            .map_err(|e| CliError::Upstream(format!("GET {path} failed: {e}")))?;
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
        guard(path, status, &content_type, &body)?;
        Ok(body)
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
            .map_err(|e| CliError::Upstream(format!("GET {path} failed: {e}")))?;

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
            CliError::Auth(
                "the stored session has no refresh token — sign in again with \
                 `nlnt auth login --browser --overwrite`"
                    .into(),
            )
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
            .map_err(|e| CliError::Upstream(format!("token refresh failed: {e}")))?;

        let status = resp.status().as_u16();
        let body = resp
            .text()
            .map_err(|e| CliError::Upstream(format!("reading refresh response: {e}")))?;
        if status == 403 && is_bot_wall(&body) {
            return Err(bot_wall_error(paths::OIDC_TOKEN));
        }
        if status == 400 || status == 401 {
            // invalid_grant: the refresh token expired or was already rotated.
            return Err(CliError::Auth(
                "the refresh token was rejected (expired or already used) — sign in again \
                 with `nlnt auth login --browser --overwrite`"
                    .into(),
            ));
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
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .map_err(|e| CliError::Other(format!("failed to run capture command: {e}")))?;
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
    verbose: bool,
    quiet: bool,
) -> Result<Session, CliError> {
    let refresh = match Portal::from_cached_session(cfg, creds, verbose) {
        Ok(portal) => Some(portal.refresh(cfg, creds)),
        // No stored session at all — only the command can bootstrap one, so
        // without a command surface the actionable "run `nlnt auth login`".
        Err(e @ CliError::Auth(_)) if command.is_none() => return Err(e),
        Err(CliError::Auth(_)) => None,
        Err(e) => return Err(e),
    };

    match plan_after_refresh(refresh, command.is_some()) {
        RefreshPlan::Use(session) => Ok(session),
        RefreshPlan::Surface(err) => Err(err),
        RefreshPlan::RunCommand => {
            if !quiet {
                eprintln!("refresh token unavailable — running capture command");
            }
            relogin_via_command(
                cfg,
                creds,
                command.expect("plan_after_refresh emits RunCommand only when has_command is true"),
                verbose,
            )
        }
    }
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
    command: &str,
    verbose: bool,
) -> Result<Session, CliError> {
    let session = run_capture_command(command, verbose)?;
    // A capture command should return a fresh token, but if it returns one the
    // portal rejects (a stale token, or an MFA-incomplete `acr`), the raw 401
    // from the verify read is baffling — the user just re-logged in. Translate
    // it into the real cause. Non-auth errors (bot wall, 5xx) pass through.
    establish_session(cfg, creds, session.clone(), true, verbose).map_err(rejected_capture)?;
    Ok(session)
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
    if verify {
        let portal = Portal::with_session(cfg.base_url(), session.clone(), verbose)?;
        // A cheap, read-only endpoint that proves the token is accepted.
        let body = portal.get_text(paths::OVERVIEW)?;
        verifying_read_holds_data(paths::OVERVIEW, &body)?;
    }
    session.store(creds)
}

/// A 2xx with nothing in it doesn't show the token was accepted: a stale session
/// from a kept browser profile could get an empty body, `null` or `{}`. The
/// overview is a JSON object, so anything but JSON with something in it is
/// inconclusive, and a session that can't be told from a stale one isn't stored.
fn verifying_read_holds_data(path: &str, body: &str) -> Result<(), CliError> {
    let holds_data = match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(fields)) => !fields.is_empty(),
        Ok(serde_json::Value::Array(items)) => !items.is_empty(),
        _ => false,
    };
    if holds_data {
        return Ok(());
    }
    Err(CliError::Upstream(format!(
        "the verifying read of {path} answered with no data, so this session can't be told from \
         a stale one; nothing was stored"
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

fn bot_wall_error(path: &str) -> CliError {
    CliError::Upstream(format!(
        "blocked by the portal's bot protection (Akamai) on {path}, not by your \
         credentials — the request was refused before the token was read. This usually \
         means the sentinel headers were stripped by a proxy. See the 'Akamai bot wall' \
         section of docs/api.md"
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
    if matches!(status, 401 | 403) {
        return Some(CliError::Auth(format!(
            "portal returned {status} for {path} — the access token is missing or expired; \
             run `nlnt auth refresh` (or `nlnt auth login --browser --overwrite`)"
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
    if content_type.contains("application/json") && body.trim_start().starts_with('<') {
        return Err(CliError::Upstream(format!(
            "portal returned HTML instead of JSON for {path} (edge error or challenge)"
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
            assert_eq!(e.exit_code(), 5, "{body:?}");
            let m = e.to_string();
            assert!(m.contains("/dummy"), "{m}");
            assert!(m.contains("nothing was stored"), "{m}");
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
    }

    #[test]
    fn a_401_is_an_auth_error() {
        let err = guard("/api/1/loan/overview", 401, "application/json", "{}").unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("auth refresh"));
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
