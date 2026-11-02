//! `nlnt autopay` — auto-debit (autopay) enrollment and next-cycle detail.
//!
//! Surfaces whether auto-debit is on, the bank name and a masked account tail,
//! and the scheduled next-cycle amount and date. Bank routing, the full account
//! number, and the SSN are deliberately never read into the DTO.

use pk_cli_core::{output, CliError};

use crate::client::paths;
use crate::commands::Ctx;
use crate::parse;

pub fn run(ctx: &Ctx) -> Result<(), CliError> {
    let info = ctx.read(|portal| {
        let body = portal.get_text(paths::AUTO_DEBIT)?;
        parse::autopay(&body, paths::AUTO_DEBIT)
    })?;

    let v = serde_json::to_value(&info)
        .map_err(|e| CliError::Other(format!("could not serialize autopay info: {e}")))?;
    if ctx.common.json {
        output::json(&v);
    } else {
        output::render(&v);
    }
    Ok(())
}
