//! `nlnt transactions list` — payment and activity history.
//!
//! The principal/interest split is the column that matters here: during the
//! $0-IDR paydown, a payment landing entirely on interest is doing the intended
//! job, and one that reaches principal means accrued interest already hit zero.

use clap::{Args, Subcommand};
use pk_cli_core::{output, CliError, Paged, RangeArgs};

use crate::client::paths;
use crate::commands::{filter_range, items, note_empty, table_view, Ctx};
use crate::parse;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List posted transactions, newest first (transaction-list/v1).
    #[command(visible_alias = "ls")]
    List(ListArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[command(flatten)]
    pub range: RangeArgs,
    /// List upcoming scheduled payments instead of posted history.
    #[arg(long)]
    pub scheduled: bool,
}

pub fn run(ctx: &Ctx, cmd: &Cmd) -> Result<(), CliError> {
    let Cmd::List(args) = cmd;
    let range = &args.range;
    // Validate before any keychain or network access.
    range.validate()?;

    let scheduled = args.scheduled;
    let mut txns = ctx.read(|portal| {
        if scheduled {
            Ok(parse::scheduled_payments(
                &portal.get_text(paths::PAYMENT_SCHEDULED)?,
            ))
        } else {
            Ok(parse::transactions(
                &portal.get_text(paths::PAYMENT_HISTORY)?,
            ))
        }
    })?;

    // Newest first, per the profile convention for list commands. Undated
    // records sort last rather than jumbling the top of the table.
    parse::sort_newest_first(&mut txns, |t| t.date.clone());

    let txns = filter_range(txns, range, |t| t.date.clone());
    if txns.is_empty() {
        note_empty(
            ctx,
            if scheduled {
                "scheduled payments"
            } else {
                "transactions"
            },
        );
    }

    let page = Paged::new("transaction", txns);
    if ctx.common.json {
        page.emit(true);
    } else {
        let v = serde_json::to_value(&page)
            .map_err(|e| CliError::Other(format!("could not serialize transactions: {e}")))?;
        output::table(&table_view(
            &items(&v, "items"),
            &[
                "date",
                "kind",
                "description",
                "amount",
                "principal",
                "interest",
                "fees",
            ],
        ));
    }
    Ok(())
}
