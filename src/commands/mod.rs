//! Command implementations, plus the shared context every read goes through.

pub mod autopay;
pub mod documents;
pub mod loans;
pub mod repayment;
pub mod summary;
pub mod tax;
pub mod transactions;

use std::cell::RefCell;

use pk_cli_auth::reauth::with_reauth;
use pk_cli_core::{CliError, CommonArgs};
use pk_cli_secrets::CredentialStore;
use serde_json::Value;

use crate::client::{Portal, Session};
use crate::config::Config;

pub use pk_cli_core::output::{rows_of as items, table_view};

/// What a lapsed access token says when `auto_refresh` is off.
pub const AUTO_REFRESH_OFF: &str =
    "access token expired — run `nlnt auth refresh` (auto_refresh is off)";

/// Everything a command needs: the global flags, resolved config, and the
/// keychain handle.
pub struct Ctx<'a> {
    pub common: &'a CommonArgs,
    pub cfg: &'a Config,
    pub creds: &'a CredentialStore,
}

impl Ctx<'_> {
    /// A portal session replayed from the keychain. Expiry surfaces as a
    /// `CliError::Auth` (exit 3) on the first read, pointing at `auth login`.
    pub fn client(&self) -> Result<Portal, CliError> {
        Portal::from_cached_session(self.cfg, self.creds, self.common.verbose)
    }

    /// Run a read against the portal, refreshing the access token once if it has
    /// lapsed.
    ///
    /// **Reads only** — `op` runs twice on the recovery path. The retry rails
    /// (at most one reauth, never a loop) live in `pk_cli_auth::reauth`, not
    /// here. The refresh spends no one-time code and needs no browser: it
    /// exchanges the stored refresh token.
    pub fn read<T>(&self, op: impl Fn(&Portal) -> Result<T, CliError>) -> Result<T, CliError> {
        self.read_renewing(op, self.cfg.refresh_command().as_deref())
    }

    /// [`Self::read`], for a caller that must not start a sign-in: it renews with
    /// the stored refresh token and never runs the capture command, so a dead
    /// refresh token is an auth error.
    pub fn read_without_capture<T>(
        &self,
        op: impl Fn(&Portal) -> Result<T, CliError>,
    ) -> Result<T, CliError> {
        self.read_renewing(op, None)
    }

    fn read_renewing<T>(
        &self,
        op: impl Fn(&Portal) -> Result<T, CliError>,
        capture: Option<&str>,
    ) -> Result<T, CliError> {
        let presented = RefCell::new(None);
        with_reauth(
            // Rebuilt per attempt so the retry picks up the freshly-refreshed
            // token that `refresh_session` just wrote to the keychain.
            || {
                let portal = self.client()?;
                presented.replace(Some(portal.session().clone()));
                op(&portal)
            },
            || self.refresh_session(presented.borrow().as_ref(), capture),
        )
    }

    /// `presented` is the session whose access token just failed, so a renewal can
    /// tell whether another process got there first.
    fn refresh_session(
        &self,
        presented: Option<&Session>,
        capture: Option<&str>,
    ) -> Result<(), CliError> {
        if !self.cfg.auto_refresh() {
            return Err(CliError::Auth(AUTO_REFRESH_OFF.into()));
        }
        if !self.common.quiet {
            eprintln!("access token expired — refreshing");
        }
        // Exchange the refresh token; if it is dead and a capture command is
        // configured, run it for a fresh bundle — so a read self-heals with no
        // browser in the common case and no human even when re-login is needed.
        crate::client::refresh_or_relogin(
            self.cfg,
            self.creds,
            capture,
            presented,
            self.common.verbose,
            self.common.quiet,
        )?;
        Ok(())
    }
}

pub fn emit(ctx: &Ctx, schema: &str, payload: Value, text: impl FnOnce(&Value)) {
    pk_cli_core::output::emit(ctx.common.json, schema, payload, text)
}

/// Apply `--since` / `--until` / `--limit` to a parsed list.
///
/// Comparison is lexicographic on ISO `YYYY-MM-DD`, which is exactly
/// chronological for that format — one of the reasons every date crossing this
/// CLI's boundary is normalized to ISO in `parse`.
///
/// Records with **no** date survive a date filter rather than being dropped: a
/// document the portal dated poorly should still be listable, and silently
/// hiding it would look like the portal published nothing.
pub fn filter_range<T>(
    items: Vec<T>,
    range: &pk_cli_core::RangeArgs,
    date_of: impl Fn(&T) -> Option<String>,
) -> Vec<T> {
    let mut out: Vec<T> = items
        .into_iter()
        .filter(|item| {
            let Some(date) = date_of(item) else {
                return true;
            };
            if let Some(since) = &range.since {
                if date.as_str() < since.as_str() {
                    return false;
                }
            }
            if let Some(until) = &range.until {
                if date.as_str() > until.as_str() {
                    return false;
                }
            }
            true
        })
        .collect();
    if let Some(limit) = range.limit {
        out.truncate(limit as usize);
    }
    out
}

pub fn note_empty(ctx: &Ctx, what: &str) {
    if !ctx.common.quiet {
        eprintln!("no {what} found");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undated_records_survive_a_date_filter() {
        // A record the servicer dated poorly must still list, not silently
        // vanish — hiding it would look like the portal published nothing.
        let range = pk_cli_core::RangeArgs {
            since: Some("2026-01-01".into()),
            until: None,
            limit: None,
        };
        let kept = filter_range(
            vec![("a", None), ("b", Some("2026-06-01"))],
            &range,
            |(_, d)| d.map(|s: &str| s.to_string()),
        );
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn date_filter_bounds_are_inclusive_and_limit_truncates() {
        let range = pk_cli_core::RangeArgs {
            since: Some("2026-02-01".into()),
            until: Some("2026-05-01".into()),
            limit: Some(1),
        };
        let items = vec![
            ("early", Some("2026-01-01")),
            ("mid", Some("2026-03-01")),
            ("late", Some("2026-06-01")),
        ];
        let kept = filter_range(items, &range, |(_, d)| d.map(|s: &str| s.to_string()));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, "mid");
    }
}
