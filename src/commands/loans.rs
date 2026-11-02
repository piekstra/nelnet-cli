//! `nlnt loans list|get` — per-loan balances and accrued interest.

use clap::{Args, Subcommand};
use pk_cli_core::{output, CliError, Paged, RangeArgs};

use crate::client::paths;
use crate::commands::{filter_range, items, note_empty, table_view, Ctx};
use crate::parse;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List every loan on the account (loan-list/v1).
    #[command(visible_alias = "ls")]
    List(RangeArgs),
    /// One loan by id, as shown in `loans list` (loan/v1).
    Get(GetArgs),
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Loan id from `loans list`.
    pub id: String,
}

pub fn run(ctx: &Ctx, cmd: &Cmd) -> Result<(), CliError> {
    match cmd {
        Cmd::List(range) => {
            // Validate before any keychain or network access, so bad input
            // never prompts, hangs, or hits the provider.
            range.validate()?;
            let loans = ctx.read(|portal| {
                let body = portal.get_text(paths::LOAN_SUMMARY)?;
                Ok(parse::loans(&body))
            })?;
            let loans = filter_range(loans, range, |l| l.disbursement_date.clone());
            if loans.is_empty() {
                note_empty(ctx, "loans");
            }
            let page = Paged::new("loan", loans);
            if ctx.common.json {
                page.emit(true);
            } else {
                let v = serde_json::to_value(&page)
                    .map_err(|e| CliError::Other(format!("could not serialize loans: {e}")))?;
                output::table(&table_view(
                    &items(&v, "items"),
                    &[
                        "id",
                        "loan_type",
                        "status",
                        "interest_rate",
                        "principal_balance",
                        "accrued_interest",
                    ],
                ));
            }
            Ok(())
        }
        Cmd::Get(args) => {
            let id = args.id.clone();
            let loan = ctx.read(move |portal| {
                let body = portal.get_text(paths::LOAN_SUMMARY)?;
                parse::loans(&body)
                    .into_iter()
                    .find(|l| l.id == id)
                    .ok_or_else(|| CliError::NotFound(format!("no loan with id `{id}`")))
            })?;
            let v = serde_json::to_value(&loan)
                .map_err(|e| CliError::Other(format!("could not serialize loan: {e}")))?;
            if ctx.common.json {
                output::json(&v);
            } else {
                output::render(&v);
            }
            Ok(())
        }
    }
}
