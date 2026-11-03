//! `nlnt` — command-line access to the Nelnet federal student-loan servicing
//! portal. Read-only. Unofficial.
//!
//! The library exists so the parsers can be exercised directly by integration
//! tests, without going through the binary or the network. The whole test
//! suite is offline: see `CONTRIBUTING.md` for why that is a hard rule here.

pub mod browser;
pub mod client;
pub mod commands;
pub mod config;
pub mod mcp;
pub mod model;
pub mod parse;

/// Binary name. Drives the keychain service (`piekstra.nlnt`), the config
/// directory, and the env-var prefix (`NLNT_`) — never hardcode those.
pub const BIN: &str = "nlnt";

/// Repository, for `info` and self-update asset resolution.
pub const REPO: &str = "piekstra/nelnet-cli";
