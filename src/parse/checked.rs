//! The readers `nlnt mcp` uses, over the same field names as the parsers above.
//!
//! The list parsers there are total for a reason: a redesign thins out a table a
//! person is looking at, and a person notices. They drop a row they cannot read,
//! turn an unrecognized answer into an empty list, and read an absent accrued
//! interest as `0.00`. A model given those results would say "you have no loans" or
//! "nothing has accrued". So here an answer of the wrong shape is an error naming
//! the field, a row with an unreadable figure stays in the list with that figure
//! absent, and a list none of whose rows can be read is an error. `null` is
//! allowed where a list is expected, because that is how this API writes an empty
//! one (`groupLevelPaymentHistories`, for one).

use pk_cli_core::{CliError, Money};
use serde_json::Value;

use super::{
    as_date, as_money, as_nonzero_id, as_text, classify, letter_type_category, missing, plan_of,
    repayment, sort_newest_first,
};
use crate::model::RepaymentInfo;

fn json_of(body: &str, what: &str, path: &str) -> Result<Value, CliError> {
    serde_json::from_str(body).map_err(|_| missing(&format!("{what} (non-JSON response)"), path))
}

fn list_at<'a>(obj: &'a Value, key: &str, path: &str) -> Result<&'a [Value], CliError> {
    match obj.get(key) {
        Some(Value::Array(rows)) => Ok(rows),
        Some(Value::Null) => Ok(&[]),
        _ => Err(missing(key, path)),
    }
}

/// One loan group. A figure Nelnet did not state is absent, which is not zero.
#[derive(Debug, Clone, Default)]
pub struct LoanRow {
    pub id: Option<String>,
    pub loan_type: Option<String>,
    pub status: Option<String>,
    pub interest_rate: Option<String>,
    pub principal_balance: Option<Money>,
    pub accrued_interest: Option<Money>,
    pub payoff_amount: Option<Money>,
    pub monthly_payment: Option<Money>,
    pub disbursement_date: Option<String>,
}

/// Every loan group on every federal account. See `parse`'s first trap: at this
/// level `currentBalance` is principal and `outstandingBalance` is the payoff.
pub fn loans(body: &str, path: &str) -> Result<Vec<LoanRow>, CliError> {
    let root = json_of(body, "loan summary", path)?;
    let mut rows = Vec::new();
    for acct in list_at(&root, "federalAccounts", path)? {
        for g in list_at(acct, "borrowerGroupPayments", path)? {
            rows.push(LoanRow {
                id: as_text(g, "groupId"),
                loan_type: as_text(g, "loanType").or_else(|| as_text(g, "groupLoanType")),
                status: as_text(g, "statusDesc").or_else(|| as_text(g, "status")),
                interest_rate: as_text(g, "interestRate").map(|r| format!("{r}%")),
                principal_balance: as_money(g, "currentBalance"),
                accrued_interest: as_money(g, "accruedInterest"),
                payoff_amount: as_money(g, "outstandingBalance"),
                monthly_payment: as_money(g, "monthlyPaymentAmount"),
                disbursement_date: as_date(g, "firstDisbursementDate"),
            });
        }
    }
    if !rows.is_empty() && rows.iter().all(|r| r.principal_balance.is_none()) {
        return Err(missing("currentBalance", path));
    }
    Ok(rows)
}

/// What the account's first federal account says of its plan and next payment.
#[derive(Debug, Clone, Default)]
pub struct Terms {
    pub accounts: usize,
    pub repayment_plan: Option<String>,
    pub next_payment_amount: Option<Money>,
    pub next_payment_due_date: Option<String>,
    pub idr_recertification_date: Option<String>,
}

pub fn terms(body: &str, path: &str) -> Result<Terms, CliError> {
    let root = json_of(body, "loan summary", path)?;
    let accounts = list_at(&root, "federalAccounts", path)?;
    let Some(first) = accounts.first() else {
        return Ok(Terms::default());
    };
    let (repayment_plan, idr_recertification_date) =
        plan_of(list_at(first, "borrowerGroupPayments", path)?);
    Ok(Terms {
        accounts: accounts.len(),
        repayment_plan,
        next_payment_amount: as_money(first, "nextPaymentAmountDue"),
        next_payment_due_date: as_date(first, "paymentDueDate"),
        idr_recertification_date,
    })
}

/// One payment, posted or scheduled.
#[derive(Debug, Clone, Default)]
pub struct PaymentRow {
    pub date: Option<String>,
    pub post_date: Option<String>,
    pub kind: Option<String>,
    pub description: Option<String>,
    pub amount: Option<Money>,
    pub principal: Option<Money>,
    pub interest: Option<Money>,
    pub fees: Option<Money>,
    pub benefit_status: Option<String>,
    pub confirmation: Option<String>,
}

/// Payments under `list_key`, newest first, with an undated row last.
pub fn payments(body: &str, list_key: &str, path: &str) -> Result<Vec<PaymentRow>, CliError> {
    let root = json_of(body, "payments", path)?;
    let mut rows: Vec<PaymentRow> = list_at(&root, list_key, path)?
        .iter()
        .map(|item| PaymentRow {
            date: as_date(item, "effectiveDate").or_else(|| as_date(item, "postDate")),
            post_date: as_date(item, "postDate"),
            kind: as_text(item, "paymentType"),
            description: as_text(item, "description"),
            amount: as_money(item, "sumOfPaymentAmount"),
            principal: as_money(item, "sumOfPrincipal"),
            interest: as_money(item, "sumOfInterest"),
            fees: as_money(item, "sumOfFees"),
            benefit_status: as_text(item, "repaymentBenefitStatus"),
            confirmation: as_nonzero_id(item, "confirmationNumber"),
        })
        .collect();
    if !rows.is_empty() && rows.iter().all(|r| r.amount.is_none()) {
        return Err(missing("sumOfPaymentAmount", path));
    }
    sort_newest_first(&mut rows, |r| r.date.clone());
    Ok(rows)
}

/// One published document. Its title is read only to classify it and never kept:
/// Nelnet's titles embed an identifier (`STMT-<digits>-<date>-…pdf`).
#[derive(Debug, Clone, Default)]
pub struct DocumentRow {
    pub id: Option<String>,
    pub date: Option<String>,
    pub category: Option<String>,
}

/// The statement index, newest first, with an undated row last.
pub fn documents(body: &str, path: &str) -> Result<Vec<DocumentRow>, CliError> {
    let root = json_of(body, "statements", path)?;
    let mut rows: Vec<DocumentRow> = list_at(&root, "statementList", path)?
        .iter()
        .map(|item| DocumentRow {
            id: as_text(item, "documentId"),
            date: as_date(item, "docReceivedDate").or_else(|| as_date(item, "createdDate")),
            category: letter_type_category(as_text(item, "letterType").as_deref())
                .or_else(|| as_text(item, "documentTitle").and_then(|t| classify(&t)))
                .map(str::to_string),
        })
        .collect();
    if !rows.is_empty() && rows.iter().all(|r| r.id.is_none()) {
        return Err(missing("documentId", path));
    }
    sort_newest_first(&mut rows, |r| r.date.clone());
    Ok(rows)
}

/// Repayment status and the IDR queue. `idr` is `None` when that request got no
/// answer, which the caller says; an answer of the wrong shape is an error here.
pub fn repayment_info(
    overview: &str,
    overview_path: &str,
    idr: Option<&str>,
    idr_path: &str,
) -> Result<RepaymentInfo, CliError> {
    let root = json_of(overview, "repayment overview", overview_path)?;
    if root.get("statusDesc").is_none() && root.get("hasOnlyInSchoolLoans").is_none() {
        return Err(missing("statusDesc", overview_path));
    }
    if let Some(body) = idr {
        let list = json_of(body, "IDR applications", idr_path)?;
        if !matches!(list, Value::Array(_) | Value::Null) {
            return Err(missing("IDR application list", idr_path));
        }
    }
    Ok(repayment(overview, idr))
}
