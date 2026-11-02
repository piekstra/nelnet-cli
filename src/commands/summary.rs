//! `nlnt summary` — the paydown-tracking view.
//!
//! This is the command the CLI exists for. During a $0-payment IDR window the
//! "amount due" a servicer leads with is $0 and carries no information; what
//! moves is **accrued interest**, and whether extra payments are eating it
//! faster than it accrues. So the summary leads with principal, accrued
//! interest, and payoff rather than with a due amount.

use pk_cli_core::{output, CliError};

use crate::client::paths;
use crate::commands::Ctx;
use crate::parse;

pub fn run(ctx: &Ctx) -> Result<(), CliError> {
    let summary = ctx.read(|portal| {
        // Core figures from the overview; account/plan/next-payment enrichment
        // from loan/summary. Both go through the one closure so a lapsed token
        // refreshes and replays the whole thing.
        let overview = portal.get_text(paths::OVERVIEW)?;
        let detail = portal.get_text(paths::LOAN_SUMMARY).ok();
        parse::summary(&overview, detail.as_deref(), paths::OVERVIEW)
    })?;

    let v = serde_json::to_value(&summary)
        .map_err(|e| CliError::Other(format!("could not serialize summary: {e}")))?;

    if ctx.common.json {
        output::json(&v);
    } else {
        output::render(&v);
    }
    Ok(())
}
