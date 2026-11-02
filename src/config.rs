//! Non-secret settings (`~/.config/nlnt/config.json`).
//!
//! The OAuth token bundle (access token, refresh token) lives in the OS keychain
//! (service `piekstra.nlnt`), never here.

use pk_cli_core::CliError;
use serde::{Deserialize, Serialize};

/// The borrower **API** host. CONFIRMED-LIVE 2026-08-12 by replaying an
/// authenticated request captured from a logged-in session.
///
/// This is a **separate host** from the SPA (`nelnet.studentaid.gov`): the
/// Angular app is served from the SPA host but every `/api/N/...` call goes to
/// `mmaapi.nelnet.studentaid.gov`. `base_url` overrides this so a capture
/// session can be pointed at a recorded host without a rebuild.
pub const DEFAULT_BASE_URL: &str = "https://mmaapi.nelnet.studentaid.gov";

/// The OAuth2/OIDC identity host (Duende IdentityServer). Its `/connect/token`
/// endpoint is where the refresh grant is exchanged. CONFIRMED-LIVE 2026-08-12.
pub const DEFAULT_AUTH_URL: &str = "https://auth.nelnet.studentaid.gov";

/// Keychain account holding the OAuth token bundle (JSON: access/refresh token
/// and expiry). Portal reads authenticate with the access token; the refresh
/// token renews it without a fresh browser login.
pub const SESSION_ACCOUNT: &str = "session";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Portal username. Not needed for normal (token-replay) operation; used
    /// only by the unattended-relogin capture script's full-login path. Env
    /// fallback `$NLNT_USERNAME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_refresh: Option<bool>,
    /// Shell command whose stdout is a fresh session bundle (the `oidc.user`
    /// JSON, or a bare Bearer token). Run when the stored refresh token is dead,
    /// so re-login is unattended. Not a secret — it is a command line — so it
    /// lives in plain config; the reference capture script is in `scripts/`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_command: Option<String>,
}

impl Config {
    pub fn base_url(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
    }

    pub fn auth_url(&self) -> String {
        self.auth_url
            .clone()
            .unwrap_or_else(|| DEFAULT_AUTH_URL.to_string())
    }

    /// Servicer account number, where the household has more than one.
    pub fn account(&self) -> Option<String> {
        self.account
            .clone()
            .or_else(|| std::env::var("NLNT_ACCOUNT").ok().filter(|s| !s.is_empty()))
    }

    /// Portal username, from config then `$NLNT_USERNAME`.
    pub fn username(&self) -> Option<String> {
        self.username.clone().or_else(|| {
            std::env::var("NLNT_USERNAME")
                .ok()
                .filter(|s| !s.is_empty())
        })
    }

    /// Whether to refresh the access token automatically when it has expired.
    ///
    /// Defaults **on**. Unlike a password re-login, an automatic refresh spends
    /// no one-time code and needs no browser — it exchanges the stored refresh
    /// token. Turn it off if you would rather be told to refresh by hand.
    pub fn auto_refresh(&self) -> bool {
        self.auto_refresh.unwrap_or(true)
    }

    /// The capture command, resolved config-first then `$NLNT_REFRESH_COMMAND`
    /// — the same precedence as [`Self::account`] and [`Self::username`], so a
    /// stale env var can't silently shadow a value the user set with
    /// `nlnt config set`.
    pub fn refresh_command(&self) -> Option<String> {
        self.refresh_command
            .clone()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                std::env::var("NLNT_REFRESH_COMMAND")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
            })
    }

    pub fn set(&mut self, key: &str, value: &str) -> Result<(), CliError> {
        match key {
            "base_url" => self.base_url = Some(value.to_string()),
            "auth_url" => self.auth_url = Some(value.to_string()),
            "account" => self.account = Some(value.to_string()),
            "username" => self.username = Some(value.to_string()),
            "auto_refresh" => self.auto_refresh = Some(parse_bool(value)?),
            "refresh_command" => self.refresh_command = Some(value.to_string()),
            other => return Err(unknown_key(other)),
        }
        Ok(())
    }

    pub fn unset(&mut self, key: &str) -> Result<(), CliError> {
        match key {
            "base_url" => self.base_url = None,
            "auth_url" => self.auth_url = None,
            "account" => self.account = None,
            "username" => self.username = None,
            "auto_refresh" => self.auto_refresh = None,
            "refresh_command" => self.refresh_command = None,
            other => return Err(unknown_key(other)),
        }
        Ok(())
    }
}

/// Config keys settable via `nlnt config set <key> <value>`.
pub const KNOWN_KEYS: &[&str] = &[
    "base_url",
    "auth_url",
    "account",
    "username",
    "auto_refresh",
    "refresh_command",
];

fn parse_bool(raw: &str) -> Result<bool, CliError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => Err(CliError::Usage(format!(
            "`{other}` is not a boolean (use true/false, yes/no, on/off, 1/0)"
        ))),
    }
}

fn unknown_key(key: &str) -> CliError {
    CliError::Usage(format!(
        "unknown config key `{key}` (known: {})",
        KNOWN_KEYS.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_falls_back_to_the_api_host() {
        assert_eq!(Config::default().base_url(), DEFAULT_BASE_URL);
        let mut c = Config::default();
        c.set("base_url", "https://example.test").unwrap();
        assert_eq!(c.base_url(), "https://example.test");
    }

    #[test]
    fn auth_url_falls_back_to_the_identity_host() {
        assert_eq!(Config::default().auth_url(), DEFAULT_AUTH_URL);
    }

    /// Resolution is config-first, `$NLNT_REFRESH_COMMAND` as fallback — the same
    /// precedence as account/username, so a stale env var can't shadow a set
    /// value. Kept as ONE test because it is the only one that mutates this
    /// process-global env var, so it cannot race the rest of the suite.
    #[test]
    fn refresh_command_resolves_config_first_then_env() {
        std::env::remove_var("NLNT_REFRESH_COMMAND");
        let mut c = Config::default();
        assert!(c.refresh_command().is_none()); // neither set
        c.set("refresh_command", "config-cmd.sh").unwrap();
        assert_eq!(c.refresh_command().as_deref(), Some("config-cmd.sh"));
        // Env is only a fallback: config still wins when both are present.
        std::env::set_var("NLNT_REFRESH_COMMAND", "env-cmd.sh");
        assert_eq!(c.refresh_command().as_deref(), Some("config-cmd.sh"));
        // With no config value, the env var fills in.
        c.unset("refresh_command").unwrap();
        assert_eq!(c.refresh_command().as_deref(), Some("env-cmd.sh"));
        std::env::remove_var("NLNT_REFRESH_COMMAND");
    }

    #[test]
    fn auto_refresh_defaults_on_but_is_overridable() {
        assert!(Config::default().auto_refresh());
        let mut c = Config::default();
        c.set("auto_refresh", "off").unwrap();
        assert!(!c.auto_refresh());
    }

    #[test]
    fn unknown_key_is_a_usage_error_listing_the_known_ones() {
        let err = Config::default().set("passsword", "oops").unwrap_err();
        assert_eq!(err.exit_code(), 2);
        for key in KNOWN_KEYS {
            assert!(err.to_string().contains(key));
        }
    }

    #[test]
    fn non_boolean_auto_refresh_is_rejected() {
        let err = Config::default().set("auto_refresh", "maybe").unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    /// `KNOWN_KEYS` is kept in sync with `set`/`unset` by hand, so assert the
    /// sync rather than trusting it: every advertised key must actually work.
    #[test]
    fn every_known_key_round_trips_through_set_and_unset() {
        for key in KNOWN_KEYS {
            let mut c = Config::default();
            let value = if *key == "auto_refresh" {
                "true"
            } else {
                "value"
            };
            c.set(key, value)
                .unwrap_or_else(|e| panic!("`config set {key}` rejected: {e}"));
            c.unset(key)
                .unwrap_or_else(|e| panic!("`config unset {key}` rejected: {e}"));
        }
    }

    /// Guard against a secret field being added here later.
    #[test]
    fn config_only_serializes_non_secret_keys() {
        let mut c = Config::default();
        for key in KNOWN_KEYS {
            c.set(key, if *key == "auto_refresh" { "true" } else { "v" })
                .unwrap();
        }
        let v = serde_json::to_value(&c).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, KNOWN_KEYS);
    }
}
