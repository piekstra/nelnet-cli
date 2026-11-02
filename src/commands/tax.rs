//! `nlnt tax` — the 1098-E student-loan-interest figure as data.
//!
//! Nelnet publishes no 1098-E PDF; the portal renders an HTML template from
//! `/api/1/tax/account-tax-info` and prints it. This command surfaces the same
//! deductible-interest figure (and the accrued interest this household is
//! paying down) as a proper DTO, so it can be scripted or filed without a
//! screenshot. See `docs/api.md` and `commands::documents::undownloadable`.

use pk_cli_core::{output, CliError};

use crate::client::paths;
use crate::commands::Ctx;
use crate::parse;

pub fn run(ctx: &Ctx) -> Result<(), CliError> {
    let info = ctx.read(|portal| {
        let body = portal.get_text(paths::TAX_INFO)?;
        parse::tax(&body, paths::TAX_INFO)
    })?;

    let v = serde_json::to_value(&info)
        .map_err(|e| CliError::Other(format!("could not serialize tax info: {e}")))?;

    if ctx.common.json {
        output::json(&v);
    } else {
        output::render(&v);
    }
    Ok(())
}
