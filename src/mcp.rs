//! `nlnt mcp`: Nelnet balances, payments, repayment status and the 1098-E figure as
//! MCP tools (cli-common DESIGN.md §1.9, the MCP profile), for Claude Code, Claude
//! Desktop and any MCP client.
//!
//! Five read-only tools over the reads the commands use: `nelnet_loans`,
//! `nelnet_payments`, `nelnet_repayment`, `nelnet_tax` and `nelnet_documents`.
//!
//! # Nothing here can change anything at Nelnet
//!
//! A loan servicer's write endpoints move real money, so the guarantee is
//! structural. [`Reads`], the one way a tool reaches Nelnet, has `get_text` and
//! nothing else. A tool asks for a [`Want`], whose paths are `&'static str`, so
//! nothing a model passes can name another endpoint, even for a read. Filters run
//! over what comes back.
//!
//! # A long-running server and the session
//!
//! [`LiveSource::fetch`] reads the config and the keychain item afresh on each call,
//! so a sign-in or a renewal by any other `nlnt` process applies on the next call,
//! and no token is held between calls. Refresh tokens rotate; a renewal goes through
//! `client::refresh_or_relogin`'s `RefreshLock`, shared with every other process over
//! the keychain item, and reads back what another process renewed.
//!
//! A tool never signs in. It renews with the stored refresh token only and does not
//! run the `refresh_command` capture script, even where one is configured: that
//! drives a browser and may spend a one-time code, on a model's call, and can run
//! for minutes against a call limit of two. A dead session is an auth error naming
//! the command to run. Listing the tools touches no credential and no file.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use pk_cli_config::ConfigStore;
use pk_cli_core::dates;
use pk_cli_core::{CliError, CommonArgs, Money, RangeArgs};
use pk_cli_mcp::{
    parse_args, ListArgs, Page, PageRequest, ResponseFormat, Server, ToolDef, ToolError,
    ToolOutput, Toolset,
};
use pk_cli_secrets::CredentialStore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{paths, Portal, SESSION_UNREADABLE, SIGN_IN_AGAIN};
use crate::commands::{filter_range, Ctx, AUTO_REFRESH_OFF};
use crate::config::Config;
use crate::parse::{self, checked};
use crate::BIN;

pub const LOANS_TOOL: &str = "nelnet_loans";
pub const PAYMENTS_TOOL: &str = "nelnet_payments";
pub const REPAYMENT_TOOL: &str = "nelnet_repayment";
pub const TAX_TOOL: &str = "nelnet_tax";
pub const DOCUMENTS_TOOL: &str = "nelnet_documents";

/// What a person's next step is when the session is missing or dead. It takes
/// `--overwrite` because a dead session is still stored, and `auth login` refuses to
/// replace one without it.
const SIGN_IN: &str = "nlnt auth login --browser --overwrite";

/// How long one call may keep asking Nelnet, its wait for another call included:
/// just under the two minutes `--http` gives a call before it answers "try again" and
/// stops listening. The work is not cancelled then, so this is what ends it. A
/// request already sent still finishes, within the client's own timeout.
const CALL_BUDGET: Duration = Duration::from_secs(110);

/// How long a call waits for the one before it. Parallel calls from one model turn
/// are normal and short; past this, the model is better told than left to retry into
/// a queue.
const QUEUE_WAIT: Duration = Duration::from_secs(45);

/// One tool call's way to Nelnet: GET, and nothing else.
pub trait Reads {
    fn get_text(&self, path: &str) -> Result<String, CliError>;
}

impl Reads for Portal {
    fn get_text(&self, path: &str) -> Result<String, CliError> {
        Portal::get_text(self, path)
    }
}

/// What a tool asks for, from constants alone. A tool's answer needs every
/// `required` path. It can do without an `optional` one, and says so.
pub struct Want {
    pub required: &'static [&'static str],
    pub optional: &'static [&'static str],
}

/// The bodies a [`Want`] got back.
#[derive(Debug, Default)]
pub struct Answers(HashMap<&'static str, String>);

impl Answers {
    fn get(&self, path: &str) -> Option<&str> {
        self.0.get(path).map(String::as_str)
    }

    fn body(&self, path: &str) -> Result<&str, ToolError> {
        self.get(path)
            .ok_or_else(|| ToolError::other(format!("{path} was not requested")))
    }
}

/// Where the tools get Nelnet's data: the live portal, or fixtures. One `fetch` per
/// tool call, which is what a call's several requests share.
pub trait Source {
    fn fetch(&self, want: &Want) -> Result<Answers, CliError>;
}

/// The requests of one `fetch`. An auth failure on any of them ends it, optional or
/// not, because that is what starts a renewal; any other failure of an optional path
/// leaves that path out.
pub fn read_all(reads: &dyn Reads, want: &Want, deadline: Instant) -> Result<Answers, CliError> {
    let mut got = HashMap::new();
    let optional = want.optional.iter().map(|path| (path, false));
    for (path, required) in want
        .required
        .iter()
        .map(|path| (path, true))
        .chain(optional)
    {
        if Instant::now() >= deadline {
            return Err(CliError::Upstream(format!(
                "this call stopped after {} seconds without finishing; try again later",
                CALL_BUDGET.as_secs()
            )));
        }
        match reads.get_text(path) {
            Ok(body) => {
                got.insert(*path, body);
            }
            Err(e @ CliError::Auth(_)) => return Err(e),
            Err(e) if required => return Err(e),
            Err(_) => {}
        }
    }
    Ok(Answers(got))
}

/// The lock, or `None` once `wait` has passed.
fn hold(lock: &Mutex<()>, wait: Duration) -> Option<MutexGuard<'_, ()>> {
    let until = Instant::now() + wait;
    loop {
        match lock.try_lock() {
            Ok(held) => return Some(held),
            Err(TryLockError::Poisoned(e)) => return Some(e.into_inner()),
            Err(TryLockError::WouldBlock) if Instant::now() >= until => return None,
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// The live portal, through the session and renewal the commands use.
pub struct LiveSource {
    creds: CredentialStore,
    one_at_a_time: Mutex<()>,
}

impl LiveSource {
    pub fn new(creds: CredentialStore) -> Self {
        Self {
            creds,
            one_at_a_time: Mutex::new(()),
        }
    }
}

impl Source for LiveSource {
    /// One call at a time, so parallel tool calls do not race one rotating refresh
    /// token within a process. The config comes first: a malformed one reads no
    /// keychain item.
    fn fetch(&self, want: &Want) -> Result<Answers, CliError> {
        let deadline = Instant::now() + CALL_BUDGET;
        let _one = hold(&self.one_at_a_time, QUEUE_WAIT).ok_or_else(|| {
            CliError::Upstream(
                "another call to Nelnet is still running in this server, and may be waiting on \
                 a keychain prompt on this computer; ask the user to check for one, then try \
                 again"
                    .into(),
            )
        })?;
        let cfg: Config = ConfigStore::new(BIN).load()?;
        let common = CommonArgs {
            quiet: true,
            ..CommonArgs::default()
        };
        let ctx = Ctx {
            common: &common,
            cfg: &cfg,
            creds: &self.creds,
        };
        ctx.read_without_capture(|portal| read_all(portal, want, deadline))
    }
}

/// The toolset `nlnt mcp` serves.
pub struct NelnetTools<S: Source> {
    source: S,
}

impl<S: Source> NelnetTools<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }

    #[cfg(test)]
    pub fn source(&self) -> &S {
        &self.source
    }

    fn fetch(&self, want: &Want) -> Result<Answers, ToolError> {
        self.source.fetch(want).map_err(tool_err)
    }
}

/// A provider failure as a tool error, with the fix that one has. The family's
/// standard remedy for an auth failure is a new sign-in, which is the wrong step
/// when `auto_refresh` is simply off.
fn tool_err(e: CliError) -> ToolError {
    match e {
        CliError::Auth(m) if m == AUTO_REFRESH_OFF => {
            ToolError::auth("the access token has expired and auto_refresh is off").with_fix(
                "Ask the user to run `nlnt auth refresh` in a terminal, then call the tool again",
            )
        }
        CliError::Auth(m) => match m.split_once(SIGN_IN_AGAIN) {
            Some((reason, _)) => ToolError::auth(reason),
            None => CliError::Auth(m).into(),
        },
        CliError::Other(m) if m.starts_with(SESSION_UNREADABLE) => {
            ToolError::auth(SESSION_UNREADABLE)
        }
        other => other.into(),
    }
}

fn money(m: Option<Money>) -> Option<String> {
    m.map(|m| m.amount)
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// `since`/`until` as a checked range. Comparison downstream is on ISO text, so what
/// goes in has to be ISO.
fn range(since: Option<&str>, until: Option<&str>) -> Result<RangeArgs, ToolError> {
    let parse = |name: &str, v: Option<&str>| {
        v.map(|d| {
            dates::parse_iso(d).map(dates::fmt_iso).map_err(|_| {
                ToolError::usage(format!("{name} must be a date as YYYY-MM-DD, got `{d}`"))
            })
        })
        .transpose()
    };
    let (since, until) = (parse("since", since)?, parse("until", until)?);
    if let (Some(s), Some(u)) = (&since, &until) {
        if s > u {
            return Err(ToolError::usage(format!(
                "since ({s}) is after until ({u})"
            )));
        }
    }
    Ok(RangeArgs {
        limit: None,
        since,
        until,
    })
}

// ---- nelnet_loans ---------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LoansArgs {
    /// Only loans whose type contains this, such as SUB or UNSUB.
    #[serde(default)]
    pub loan_type: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct LoansFilter<'a> {
    loan_type: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct LoanItem {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interest_rate: Option<String>,
    /// Absent where Nelnet did not state it, which is not zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_balance: Option<String>,
    /// Absent where Nelnet did not state it, which is not zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accrued_interest: Option<String>,
    /// Absent where Nelnet did not state it, which is not zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payoff_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_payment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disbursement_date: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct LoansOut {
    /// The date Nelnet states these totals are current as of.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    /// Across every loan.
    pub principal_balance: String,
    /// Interest accrued and not yet capitalized, across every loan.
    pub accrued_interest: String,
    /// Principal plus accrued interest.
    pub payoff_amount: String,
    /// All loan groups on the account, however many this page shows.
    pub loan_count: usize,
    #[serde(flatten)]
    pub page: Page<LoanItem>,
}

fn loan_item(row: checked::LoanRow, detailed: bool) -> LoanItem {
    LoanItem {
        kind: row.loan_type,
        status: row.status,
        interest_rate: row.interest_rate,
        principal_balance: money(row.principal_balance),
        accrued_interest: money(row.accrued_interest),
        payoff_amount: money(row.payoff_amount),
        id: row.id.filter(|_| detailed),
        monthly_payment: money(row.monthly_payment.filter(|_| detailed)),
        disbursement_date: row.disbursement_date.filter(|_| detailed),
    }
}

// ---- nelnet_payments ------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PaymentsArgs {
    /// First day, YYYY-MM-DD. Default: the earliest Nelnet lists.
    #[serde(default)]
    pub since: Option<String>,
    /// Last day, YYYY-MM-DD. Default: the latest Nelnet lists.
    #[serde(default)]
    pub until: Option<String>,
    /// True for upcoming scheduled payments; false (default) for posted ones.
    #[serde(default)]
    pub scheduled: bool,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct PaymentsFilter<'a> {
    since: Option<&'a str>,
    until: Option<&'a str>,
    scheduled: bool,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct PaymentItem {
    /// Effective date, or the posting date where Nelnet states only that.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Absent where Nelnet did not state it, which is not zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// The part applied to principal. Absent on a payment not yet applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// The part applied to interest. Absent on a payment not yet applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub benefit_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PaymentsOut {
    #[serde(flatten)]
    pub page: Page<PaymentItem>,
}

fn payment_item(row: checked::PaymentRow, detailed: bool) -> PaymentItem {
    PaymentItem {
        date: row.date,
        description: row.description,
        amount: money(row.amount),
        principal: money(row.principal),
        interest: money(row.interest),
        fees: money(row.fees),
        kind: row.kind.filter(|_| detailed),
        post_date: row.post_date.filter(|_| detailed),
        benefit_status: row.benefit_status.filter(|_| detailed),
        confirmation: row.confirmation.filter(|_| detailed),
    }
}

// ---- nelnet_repayment -----------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct RepaymentArgs {
    /// `concise` (default): the fields a person reads. `detailed`: adds the school.
    #[serde(default)]
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct AutopayOut {
    pub enrolled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard_amount: Option<String>,
    /// Nelnet's own line on the next debit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct IdrApplicationOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct RepaymentOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// True when every loan is still in school. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_school: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repayment_plan: Option<String>,
    /// 0.00 is normal during an income-driven window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_payment_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_payment_due_date: Option<String>,
    /// When the income-driven plan must be recertified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idr_recertification_date: Option<String>,
    /// Absent when Nelnet did not answer for it; `note` then says so.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autopay: Option<AutopayOut>,
    /// Newest first. Empty when `note` says Nelnet did not answer for them.
    pub idr_applications: Vec<IdrApplicationOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_school: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub separation_date: Option<String>,
    /// What this answer could not cover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ---- nelnet_tax -----------------------------------------------------------------

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct TaxArgs {}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TaxOut {
    /// Student-loan interest paid, the 1098-E box 1 figure, as of `as_of`.
    pub deductible_interest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accrued_interest: Option<String>,
    /// The recipient TIN on a federal Direct Loan 1098-E.
    pub lender_tin: String,
    /// Whether Nelnet flags a 1098-E correction for the period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_correction: Option<String>,
    pub note: String,
}

/// What the figure is, since one number cannot say which year it closes.
const TAX_NOTE: &str = "A running total as of as_of, not a filed form. For a completed tax year, \
                        the 1098-E Nelnet finalizes at the end of January is authoritative. \
                        Nelnet publishes no 1098-E file; its January statement carries the same \
                        total.";

// ---- nelnet_documents -----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocumentsArgs {
    /// Only this category: statement, tax or notice.
    #[serde(default)]
    pub category: Option<String>,
    /// Only documents for this tax year. A 1098-E for a year comes out early the next
    /// one, so the year is the one the title names, and else the document's date's.
    #[serde(default)]
    pub tax_year: Option<u32>,
    /// First day, YYYY-MM-DD. Default: the earliest Nelnet lists.
    #[serde(default)]
    pub since: Option<String>,
    /// Last day, YYYY-MM-DD. Default: the latest Nelnet lists.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct DocumentsFilter<'a> {
    category: Option<&'a str>,
    tax_year: Option<u32>,
    since: Option<&'a str>,
    until: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct DocumentItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// statement, tax or notice. Absent where Nelnet's document fits none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// What `nlnt documents download` takes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocumentsOut {
    #[serde(flatten)]
    pub page: Page<DocumentItem>,
}

// ---- the toolset ----------------------------------------------------------------

impl<S: Source> Toolset for NelnetTools<S> {
    fn server(&self) -> Server {
        Server::new("nlnt", env!("CARGO_PKG_VERSION"), "Nelnet", "nelnet")
            .sign_in_command(SIGN_IN)
            .instructions(
                "Nelnet access here is read-only: no tool can make or schedule a payment, change \
                 autopay or a repayment plan, or change anything. During an income-driven \
                 repayment window an amount due of 0.00 is normal, and accrued interest is what \
                 moves. Amounts are USD decimal strings; keep every digit when adding them. A \
                 Nelnet session ends on Nelnet's schedule and then needs a person at a browser.",
            )
    }

    fn tools(&self) -> Vec<ToolDef> {
        vec![
            ToolDef::read(
                LOANS_TOOL,
                "Nelnet loan balances",
                "Shows what is owed on the user's federal student loans at Nelnet: total \
                 principal, accrued interest and payoff, and each loan group's type, status, \
                 rate and balances. Use it for how much is owed or which loan costs the most. \
                 Narrow with loan_type.",
            )
            .input::<LoansArgs>()
            .output::<LoansOut>(),
            ToolDef::read(
                PAYMENTS_TOOL,
                "Nelnet payments",
                "Lists payments on the user's Nelnet loans, newest first, each with its split \
                 between principal, interest and fees. Use it for what was paid over a period \
                 and how much of it reached principal. Pass scheduled for upcoming payments, and \
                 narrow with since and until.",
            )
            .input::<PaymentsArgs>()
            .output::<PaymentsOut>(),
            ToolDef::read(
                REPAYMENT_TOOL,
                "Nelnet repayment status",
                "Shows where the user's Nelnet repayment stands: status, plan, next payment, \
                 income-driven recertification date, autopay enrollment and income-driven \
                 applications. Use it for what is due next, whether autopay is on, or when to \
                 recertify. A note says what Nelnet did not answer for.",
            )
            .input::<RepaymentArgs>()
            .output::<RepaymentOut>(),
            ToolDef::read(
                TAX_TOOL,
                "Nelnet 1098-E interest",
                "Gives the student-loan interest Nelnet reports for the 1098-E, as a running \
                 total with its as-of date. Use it for the student-loan interest deduction. It \
                 covers the period Nelnet currently states, so check as_of against the tax year \
                 in question.",
            )
            .input::<TaxArgs>()
            .output::<TaxOut>(),
            ToolDef::read(
                DOCUMENTS_TOOL,
                "Nelnet documents",
                "Lists the documents Nelnet has published, newest first, with date, category and \
                 id. Use it to see whether a statement or notice has arrived. It returns no file \
                 contents; the user saves one with `nlnt documents download <id>` in a terminal. \
                 Narrow with category, tax_year, since and until.",
            )
            .input::<DocumentsArgs>()
            .output::<DocumentsOut>(),
        ]
    }

    async fn call(&self, name: &str, args: Value) -> Result<ToolOutput, ToolError> {
        match name {
            LOANS_TOOL => self.loans(parse_args(args)?),
            PAYMENTS_TOOL => self.payments(parse_args(args)?),
            REPAYMENT_TOOL => self.repayment(parse_args(args)?),
            TAX_TOOL => self.tax(parse_args(args)?),
            DOCUMENTS_TOOL => self.documents(parse_args(args)?),
            other => Err(ToolError::other(format!("no handler for {other}"))),
        }
    }
}

impl<S: Source> NelnetTools<S> {
    fn loans(&self, args: LoansArgs) -> Result<ToolOutput, ToolError> {
        let wanted = non_empty(args.loan_type.as_deref());
        let page = PageRequest::new(&args.list, &LoansFilter { loan_type: wanted })?;
        let detailed = args.list.format().is_detailed();

        let answers = self.fetch(&Want {
            required: &[paths::OVERVIEW, paths::LOAN_SUMMARY],
            optional: &[],
        })?;
        let totals = parse::summary(answers.body(paths::OVERVIEW)?, None, paths::OVERVIEW)
            .map_err(tool_err)?;
        let rows = checked::loans(answers.body(paths::LOAN_SUMMARY)?, paths::LOAN_SUMMARY)
            .map_err(tool_err)?;
        if rows.is_empty() && totals.principal_balance.amount != "0.00" {
            return Err(ToolError::upstream(
                "Nelnet states a principal balance and lists no loans; its answer has changed",
            ));
        }
        let loan_count = rows.len();
        let wanted = wanted.map(str::to_ascii_uppercase);
        let matched = rows
            .into_iter()
            .filter(|row| {
                wanted.as_deref().is_none_or(|w| {
                    row.loan_type
                        .as_deref()
                        .is_some_and(|t| t.to_ascii_uppercase().contains(w))
                })
            })
            .map(|row| loan_item(row, detailed))
            .collect();
        ToolOutput::new(&LoansOut {
            as_of: totals.as_of,
            principal_balance: totals.principal_balance.amount,
            accrued_interest: totals.accrued_interest.amount,
            payoff_amount: totals.payoff_amount.amount,
            loan_count,
            page: page.page(matched, "loan_type")?,
        })
    }

    fn payments(&self, args: PaymentsArgs) -> Result<ToolOutput, ToolError> {
        let window = range(
            non_empty(args.since.as_deref()),
            non_empty(args.until.as_deref()),
        )?;
        let page = PageRequest::new(
            &args.list,
            &PaymentsFilter {
                since: window.since.as_deref(),
                until: window.until.as_deref(),
                scheduled: args.scheduled,
            },
        )?;
        let detailed = args.list.format().is_detailed();

        let (path, list_key): (&'static str, &str) = if args.scheduled {
            (paths::PAYMENT_SCHEDULED, "scheduledPaymentsList")
        } else {
            (paths::PAYMENT_HISTORY, "paymentHistoryList")
        };
        let answers = if args.scheduled {
            self.fetch(&Want {
                required: &[paths::PAYMENT_SCHEDULED],
                optional: &[],
            })?
        } else {
            self.fetch(&Want {
                required: &[paths::PAYMENT_HISTORY],
                optional: &[],
            })?
        };
        let rows = checked::payments(answers.body(path)?, list_key, path).map_err(tool_err)?;
        let matched = filter_range(rows, &window, |r| r.date.clone())
            .into_iter()
            .map(|row| payment_item(row, detailed))
            .collect();
        ToolOutput::new(&PaymentsOut {
            page: page.page(matched, "since/until")?,
        })
    }

    fn repayment(&self, args: RepaymentArgs) -> Result<ToolOutput, ToolError> {
        let detailed = args.response_format.unwrap_or_default().is_detailed();
        let answers = self.fetch(&Want {
            required: &[paths::REPAYMENT_OVERVIEW, paths::LOAN_SUMMARY],
            optional: &[paths::IDR_STATUSES, paths::AUTO_DEBIT],
        })?;
        let idr = answers.get(paths::IDR_STATUSES);
        let info = checked::repayment_info(
            answers.body(paths::REPAYMENT_OVERVIEW)?,
            paths::REPAYMENT_OVERVIEW,
            idr,
            paths::IDR_STATUSES,
        )
        .map_err(tool_err)?;
        let terms = checked::terms(answers.body(paths::LOAN_SUMMARY)?, paths::LOAN_SUMMARY)
            .map_err(tool_err)?;
        let autopay = answers
            .get(paths::AUTO_DEBIT)
            .map(|body| parse::autopay(body, paths::AUTO_DEBIT))
            .transpose()
            .map_err(tool_err)?;

        let mut note = Vec::new();
        if terms.accounts > 1 {
            note.push(format!(
                "Nelnet lists {} federal accounts; the plan and next payment here are the first \
                 one's.",
                terms.accounts
            ));
        }
        if idr.is_none() {
            note.push(
                "Nelnet did not answer for income-driven applications, so an empty list here \
                 does not mean there are none."
                    .to_string(),
            );
        }
        if autopay.is_none() {
            note.push(
                "Nelnet did not answer for autopay, so this says nothing about whether it is on."
                    .to_string(),
            );
        }

        ToolOutput::new(&RepaymentOut {
            status: info.status,
            in_school: info.in_school.then_some(true),
            repayment_plan: terms.repayment_plan,
            next_payment_amount: money(terms.next_payment_amount),
            next_payment_due_date: terms.next_payment_due_date,
            idr_recertification_date: terms.idr_recertification_date,
            // The bank account's tail stays out: the bank's name answers what a
            // person asks, and a tool result leaves this computer.
            autopay: autopay.map(|a| AutopayOut {
                enrolled: a.enrolled,
                bank_name: a.bank_name,
                next_amount: money(a.next_payment_amount),
                next_date: a.next_payment_date,
                standard_amount: money(a.standard_amount),
                status: a.status,
            }),
            idr_applications: info
                .idr_applications
                .into_iter()
                .map(|a| IdrApplicationOut {
                    requested: a.requested,
                    status: a.status,
                    kind: a.kind,
                })
                .collect(),
            current_school: info.current_school.filter(|_| detailed),
            separation_date: info.separation_date.filter(|_| detailed),
            note: (!note.is_empty()).then(|| note.join(" ")),
        })
    }

    fn tax(&self, _args: TaxArgs) -> Result<ToolOutput, ToolError> {
        let answers = self.fetch(&Want {
            required: &[paths::TAX_INFO],
            optional: &[],
        })?;
        let tax = parse::tax(answers.body(paths::TAX_INFO)?, paths::TAX_INFO).map_err(tool_err)?;
        ToolOutput::new(&TaxOut {
            deductible_interest: tax.deductible_interest.amount,
            as_of: tax.as_of,
            accrued_interest: money(tax.accrued_interest),
            lender_tin: tax.lender_tin,
            form_correction: tax.form_correction,
            note: TAX_NOTE.to_string(),
        })
    }

    fn documents(&self, args: DocumentsArgs) -> Result<ToolOutput, ToolError> {
        let window = range(
            non_empty(args.since.as_deref()),
            non_empty(args.until.as_deref()),
        )?;
        let category = non_empty(args.category.as_deref()).map(str::to_ascii_lowercase);
        if let Some(year) = args.tax_year.filter(|y| !(1998..=2100).contains(y)) {
            return Err(ToolError::usage(format!(
                "tax_year must be a year such as 2025, got {year}"
            )));
        }
        let page = PageRequest::new(
            &args.list,
            &DocumentsFilter {
                category: category.as_deref(),
                tax_year: args.tax_year,
                since: window.since.as_deref(),
                until: window.until.as_deref(),
            },
        )?;

        let answers = self.fetch(&Want {
            required: &[paths::STATEMENTS],
            optional: &[],
        })?;
        let rows = checked::documents(answers.body(paths::STATEMENTS)?, paths::STATEMENTS)
            .map_err(tool_err)?;
        let matched = filter_range(rows, &window, |r| r.date.clone())
            .into_iter()
            .filter(|r| category.is_none() || r.category == category)
            .filter(|r| args.tax_year.is_none() || r.tax_year == args.tax_year)
            .map(|r| DocumentItem {
                date: r.date,
                category: r.category,
                id: r.id,
            })
            .collect();
        ToolOutput::new(&DocumentsOut {
            page: page.page(matched, "category, tax_year or since/until")?,
        })
    }
}

#[cfg(test)]
mod tests;
