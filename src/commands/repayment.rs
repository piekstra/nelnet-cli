//! `nlnt repayment` — repayment status and income-driven-repayment tracking.
//!
//! The plan *name* and recertification date are on `nlnt summary`
//! (`loan-summary/v1`); this view adds the repayment status, school context, and
//! the IDR application queue, which matter during an income-driven paydown.

use pk_cli_core::{output, CliError};

use crate::client::paths;
use crate::commands::Ctx;
use crate::parse;

pub fn run(ctx: &Ctx) -> Result<(), CliError> {
    let info = ctx.read(|portal| {
        let overview = portal.get_text(paths::REPAYMENT_OVERVIEW)?;
        // IDR statuses are supplementary — a lapse there must not fail the view.
        let idr = portal.get_text(paths::IDR_STATUSES).ok();
        Ok(parse::repayment(&overview, idr.as_deref()))
    })?;

    let v = serde_json::to_value(&info)
        .map_err(|e| CliError::Other(format!("could not serialize repayment info: {e}")))?;
    if ctx.common.json {
        output::json(&v);
    } else {
        output::render(&v);
    }
    Ok(())
}
