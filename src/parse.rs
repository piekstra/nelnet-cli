//! Turning portal responses into DTOs.
//!
//! # These field names are CONFIRMED-LIVE 2026-08-12
//!
//! Every response the API returns is JSON, and the field names below were read
//! from real authenticated responses (scrubbed into `tests/fixtures/`). Two
//! traps are baked into the mappings and worth stating up front:
//!
//! 1. **`currentBalance` means different things on different endpoints.** On
//!    `/api/1/loan/overview` it is the *total* (principal + accrued interest),
//!    with principal in `outstandingPrincipal`. On a per-loan *group*
//!    (`borrowerGroupPayments[]`) it is the *principal*, and the total lives in
//!    `outstandingBalance`. The two parsers therefore read different keys for
//!    the same DTO field; the invariant `principal + accrued == payoff` is
//!    pinned by a fixture test.
//! 2. **Money arrives as JSON numbers** (e.g. `1234.56`), except the tax
//!    dictionary, which uses comma-grouped strings (`"1,812.34"`). [`money`]
//!    accepts both.
//!
//! A missing headline figure is an **error naming the field**, never a
//! defaulted `$0.00`: a fabricated zero accrued interest reads as good news in
//! this household's paydown workflow. Absent *optional* fields are simply
//! omitted. Parsers over list endpoints are total with respect to junk input:
//! unrecognized JSON yields an empty list, never a panic.

use pk_cli_core::{CliError, Money};
use pk_cli_documents::Document;
use serde_json::Value;

use crate::client::paths;
use crate::model::{AutopayInfo, Loan, LoanSummary, RepaymentInfo, TaxInfo, Transaction};

// ---------------------------------------------------------------------------
// Coercion helpers
// ---------------------------------------------------------------------------

/// Coerce a JSON value to [`Money`]. Accepts a JSON number (`1234.56`), a
/// decimal string (`"1,812.34"`, `"$1,234.56"`), or a `{amount}` object.
///
/// A JSON *number* cannot represent every cent exactly; the servicer emits two
/// decimals, so rounding to cents is exact for the values seen. Where a string
/// form of the same figure exists (the tax dictionary), it is preferred.
pub fn money(v: &Value) -> Option<Money> {
    match v {
        Value::String(s) if !s.trim().is_empty() => Money::parse_usd(s),
        Value::Number(n) => n
            .as_f64()
            .map(|f| Money::from_cents((f * 100.0).round() as i64)),
        Value::Object(_) => v.get("amount").and_then(money),
        _ => None,
    }
}

fn as_money(obj: &Value, key: &str) -> Option<Money> {
    obj.get(key).and_then(money)
}

fn as_text(obj: &Value, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

fn as_date(obj: &Value, key: &str) -> Option<String> {
    as_text(obj, key).and_then(|raw| iso_date(&raw))
}

/// A non-zero integer field as a string id, or `None` when it is absent or `0`
/// (the servicer uses `0` as "no id" for some records).
fn as_nonzero_id(obj: &Value, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(Value::Number(n)) => {
            let i = n.as_i64().unwrap_or(0);
            (i != 0).then(|| i.to_string())
        }
        Some(Value::String(s)) if !s.trim().is_empty() && s.trim() != "0" => {
            Some(s.trim().to_string())
        }
        _ => None,
    }
}

/// Normalize a provider date string to ISO `YYYY-MM-DD`, or drop it.
///
/// The API dates are ISO with a time (`2026-08-11T00:00:00`); the tax
/// dictionary and some fields use `MM/DD/YYYY`. Both normalize; anything else is
/// dropped rather than passed through, because SPEC §1.4 promises ISO.
pub fn iso_date(raw: &str) -> Option<String> {
    let s = raw.trim();
    // `get(..10)` is None when the string is under 10 bytes OR byte 10 is not a
    // UTF-8 char boundary — so a multi-byte character in a date-shaped field can
    // never panic here, keeping the module's "junk in → None, never a panic"
    // invariant even for garbled/localized responses.
    if let Some(head) = s.get(..10) {
        let b = head.as_bytes();
        if b[4] == b'-' && b[7] == b'-' && head.chars().filter(|c| c.is_ascii_digit()).count() == 8
        {
            return Some(head.to_string());
        }
    }
    pk_cli_core::dates::parse_mm_slash_dd_yyyy(s).map(pk_cli_core::dates::fmt_iso)
}

/// Mask an account identifier so `--verbose`, logs and JSON never carry the full
/// number (SPEC §1.7).
pub fn mask(account: &str) -> String {
    let digits: Vec<char> = account.chars().filter(|c| c.is_alphanumeric()).collect();
    if digits.len() <= 4 {
        return "*".repeat(digits.len());
    }
    let tail: String = digits[digits.len() - 4..].iter().collect();
    format!("****{tail}")
}

/// Sort a list newest-first by an optional ISO date; undated records sort last.
/// ISO `YYYY-MM-DD` compares lexicographically as chronological, so a plain
/// string compare is exact. Shared so the list commands can't drift on ordering.
pub fn sort_newest_first<T>(items: &mut [T], date_of: impl Fn(&T) -> Option<String>) {
    items.sort_by(|a, b| match (date_of(a), date_of(b)) {
        (Some(x), Some(y)) => y.cmp(&x),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
}

fn missing(field: &str, path: &str) -> CliError {
    CliError::Upstream(format!(
        "could not find `{field}` in the response from {path} — the portal's response shape \
         may have changed. Re-capture it (see docs/api.md) and correct src/parse.rs"
    ))
}

/// Money addition in integer cents, for deriving a total the portal omits.
fn add(a: &Money, b: &Money) -> Money {
    match (cents(a), cents(b)) {
        (Some(x), Some(y)) => Money::from_cents(x + y),
        _ => a.clone(),
    }
}

fn cents(m: &Money) -> Option<i64> {
    let s = m.amount.trim();
    let negative = s.starts_with('-');
    let digits: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let (whole, frac) = match digits.split_once('.') {
        Some((w, f)) => (w, f),
        None => (digits.as_str(), ""),
    };
    let whole: i64 = whole.parse().ok()?;
    let frac = format!("{frac:0<2}");
    let frac: i64 = frac.get(..2)?.parse().ok()?;
    let total = whole * 100 + frac;
    Some(if negative { -total } else { total })
}

// ---------------------------------------------------------------------------
// Summary — /api/1/loan/overview (+ optional /api/1/loan/summary enrichment)
// ---------------------------------------------------------------------------

/// The paydown-tracking summary.
///
/// Core figures come from `/api/1/loan/overview`; the optional enrichment
/// (account, loan count, repayment plan, next payment, recertification) comes
/// from `/api/1/loan/summary` when provided. Fails with a named field rather
/// than defaulting a headline figure to zero.
pub fn summary(
    overview: &str,
    loan_summary: Option<&str>,
    path: &str,
) -> Result<LoanSummary, CliError> {
    let root: Value = serde_json::from_str(overview)
        .map_err(|_| missing("loan overview (non-JSON response)", path))?;

    let principal = as_money(&root, "outstandingPrincipal")
        .ok_or_else(|| missing("outstandingPrincipal", path))?;
    let accrued =
        as_money(&root, "accruedInterest").ok_or_else(|| missing("accruedInterest", path))?;
    // On this endpoint currentBalance is the total; derive it if absent.
    let payoff = as_money(&root, "currentBalance").unwrap_or_else(|| add(&principal, &accrued));

    let mut s = LoanSummary::new(0, principal, accrued, payoff);
    s.as_of = as_date(&root, "lastBumpDate");

    if let Some(body) = loan_summary {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            enrich_summary(&mut s, &v);
        }
    }
    Ok(s)
}

/// Best-effort enrichment from `/api/1/loan/summary`. Never fails the command:
/// the headline figures are already in hand.
fn enrich_summary(s: &mut LoanSummary, v: &Value) {
    let Some(acct) = v
        .get("federalAccounts")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
    else {
        return;
    };
    s.account = as_text(acct, "accountNumber").map(|a| mask(&a));
    s.next_payment_amount = as_money(acct, "nextPaymentAmountDue");
    s.next_payment_due_date = as_date(acct, "paymentDueDate");

    if let Some(groups) = acct.get("borrowerGroupPayments").and_then(|g| g.as_array()) {
        s.loan_count = groups.len() as u32;
        // Repayment plan and recertification are the same across active groups;
        // take them from the first group that states them.
        for g in groups {
            if s.repayment_plan.is_none() {
                s.repayment_plan = as_text(g, "repaymentPlan");
            }
            if s.idr_recertification_date.is_none() {
                s.idr_recertification_date = as_date(g, "recertificationDate");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Loans — /api/1/loan/summary → federalAccounts[].borrowerGroupPayments[]
// ---------------------------------------------------------------------------

/// Per-loan-group detail. Returns an empty list for unrecognized JSON.
///
/// Each `borrowerGroupPayments[]` entry is one loan group with its own type,
/// rate and balance — this is what the portal's "My Loans" view shows. At this
/// level `currentBalance` is principal and `outstandingBalance` is the payoff
/// (see the module trap note).
pub fn loans(body: &str) -> Vec<Loan> {
    let Ok(root) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(accounts) = root.get("federalAccounts").and_then(|a| a.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for acct in accounts {
        let Some(groups) = acct.get("borrowerGroupPayments").and_then(|g| g.as_array()) else {
            continue;
        };
        for g in groups {
            let Some(principal) = as_money(g, "currentBalance") else {
                continue;
            };
            let accrued = as_money(g, "accruedInterest").unwrap_or_else(|| Money::usd("0.00"));
            let payoff =
                as_money(g, "outstandingBalance").unwrap_or_else(|| add(&principal, &accrued));
            let id = as_text(g, "groupId").unwrap_or_else(|| "unknown".into());
            let mut loan = Loan::new(id, principal, accrued);
            loan.loan_type = as_text(g, "loanType").or_else(|| as_text(g, "groupLoanType"));
            loan.status = as_text(g, "statusDesc").or_else(|| as_text(g, "status"));
            loan.interest_rate = as_text(g, "interestRate").map(|r| format!("{r}%"));
            loan.payoff_amount = Some(payoff);
            loan.disbursement_date = as_date(g, "firstDisbursementDate");
            out.push(loan);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Transactions — /api/1/payment/history → paymentHistoryList[]
// ---------------------------------------------------------------------------

/// Posted payment / activity history. Returns an empty list for unrecognized JSON.
pub fn transactions(body: &str) -> Vec<Transaction> {
    payment_list(body, "paymentHistoryList")
}

/// Upcoming scheduled payments — same item shape as history (the applied
/// principal/interest split is naturally absent for a payment not yet made).
pub fn scheduled_payments(body: &str) -> Vec<Transaction> {
    payment_list(body, "scheduledPaymentsList")
}

/// Shared payment-record parser for both the posted-history and scheduled lists.
fn payment_list(body: &str, list_key: &str) -> Vec<Transaction> {
    let Ok(root) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(items) = root.get(list_key).and_then(|a| a.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            let amount = as_money(item, "sumOfPaymentAmount")?;
            let id = as_nonzero_id(item, "confirmationNumber")
                .or_else(|| as_nonzero_id(item, "paymentId"))
                .unwrap_or_else(|| format!("tx-{i}"));
            let mut t = Transaction::new(id, amount);
            t.date = as_date(item, "effectiveDate").or_else(|| as_date(item, "postDate"));
            t.effective_date = as_date(item, "effectiveDate");
            t.kind =
                as_text(item, "paymentType").or_else(|| as_text(item, "repaymentBenefitStatus"));
            t.description = as_text(item, "description");
            t.principal = as_money(item, "sumOfPrincipal");
            t.interest = as_money(item, "sumOfInterest");
            t.fees = as_money(item, "sumOfFees");
            Some(t)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Repayment — /api/1/borrower/repayment/overview (+ idr-application-statuses)
// ---------------------------------------------------------------------------

/// Repayment status and IDR application tracking. Never errors — a thin/empty
/// response is a valid "nothing to report" status, not a failure.
pub fn repayment(overview: &str, idr: Option<&str>) -> RepaymentInfo {
    let mut r = RepaymentInfo::new();
    if let Ok(v) = serde_json::from_str::<Value>(overview) {
        r.status = as_text(&v, "statusDesc");
        r.in_school = v
            .get("hasOnlyInSchoolLoans")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        r.current_school = as_text(&v, "currentSchool");
        r.separation_date = as_date(&v, "separationDate");
    }
    if let Some(idr_body) = idr {
        if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(idr_body) {
            r.idr_applications = items
                .iter()
                .map(|it| crate::model::IdrApplication {
                    requested: as_date(it, "requestDateTime"),
                    status: as_text(it, "status").or_else(|| as_text(it, "statusDesc")),
                    kind: as_text(it, "type").or_else(|| as_text(it, "functionTypeDesc")),
                })
                .collect();
            sort_newest_first(&mut r.idr_applications, |a| a.requested.clone());
        }
    }
    r
}

// ---------------------------------------------------------------------------
// Autopay — /api/1/auto-debit/summary
// ---------------------------------------------------------------------------

/// Auto-debit enrollment and next-cycle detail. Bank routing, full account and
/// SSN are deliberately not read into the DTO.
pub fn autopay(body: &str, path: &str) -> Result<AutopayInfo, CliError> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| missing("auto-debit summary (non-JSON)", path))?;
    // Require the enrollment flag: a response without it is an unrecognized
    // shape, not a genuine "not enrolled" (which would be misleading here).
    let enrolled = v
        .get("achFlag")
        .and_then(|b| b.as_bool())
        .ok_or_else(|| missing("achFlag", path))?;
    let mut a = AutopayInfo::new(enrolled);
    a.bank_name = as_text(&v, "bankName");
    a.bank_account = as_text(&v, "bankAccountNumber").map(|n| mask_tail(&n));
    a.next_payment_amount = as_money(&v, "nextCycleAmount");
    a.next_payment_date = as_date(&v, "nextCycleDate");
    a.standard_amount = as_money(&v, "standardAmount");
    a.status = as_text(&v, "processingStatus");
    Ok(a)
}

/// Present a bank-account tail as `****NNNN`.
///
/// Distinct from [`mask`] on purpose: the auto-debit endpoint returns only the
/// **last four** of the account, so those four are already safe to show — this
/// prefixes them with `****` (revealing them). [`mask`], by contrast, hides a
/// short value entirely (`"*".repeat(n)`), because there it is masking a value
/// that might be complete. A value longer than four here is unexpected, so it is
/// routed through [`mask`] as a belt-and-suspenders guard against a full number
/// ever leaking.
fn mask_tail(raw: &str) -> String {
    let digits: String = raw.chars().filter(|c| c.is_alphanumeric()).collect();
    if digits.len() <= 4 {
        format!("****{digits}")
    } else {
        mask(&digits)
    }
}

// ---------------------------------------------------------------------------
// Documents — /api/1/statements → statementList[]
// ---------------------------------------------------------------------------

/// A listed document plus where to fetch it. The href is kept out of the DTO —
/// the download path embeds the document id, and DTOs stay free of routing.
#[derive(Debug, Clone)]
pub struct DocumentRef {
    pub doc: Document,
    pub href: String,
}

/// The statement index. Returns an empty list for unrecognized JSON.
pub fn documents(body: &str) -> Vec<DocumentRef> {
    let Ok(root) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(items) = root.get("statementList").and_then(|a| a.as_array()) else {
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            let name = as_text(item, "documentTitle")?;
            let id = as_text(item, "documentId").unwrap_or_else(|| format!("doc-{i}"));
            let is_direct = item
                .get("isDirect")
                .and_then(|b| b.as_bool())
                .unwrap_or(true);
            let mut doc = Document::new(id.clone(), name.clone());
            doc.date = as_date(item, "docReceivedDate").or_else(|| as_date(item, "createdDate"));
            doc.category = letter_type_category(as_text(item, "letterType").as_deref())
                .or_else(|| classify(&name))
                .map(str::to_string);
            doc.file = Some(name);
            let href = paths::statement_pdf(&id, is_direct);
            Some(DocumentRef { doc, href })
        })
        .collect()
}

/// Map the servicer's `letterType` code to an archiver category.
fn letter_type_category(letter_type: Option<&str>) -> Option<&'static str> {
    match letter_type.map(|s| s.to_ascii_uppercase()) {
        Some(ref t) if t == "STMT" => Some("statement"),
        Some(ref t) if t.contains("1098") || t.contains("TAX") => Some("tax"),
        _ => None,
    }
}

/// Classify a document from its title when the servicer states no usable type.
pub fn classify(name: &str) -> Option<&'static str> {
    let l = name.to_ascii_lowercase();
    if l.contains("1098") || l.contains("tax") {
        Some("tax")
    } else if l.contains("stmt") || l.contains("statement") {
        Some("statement")
    } else if l.contains("notice") || l.contains("letter") {
        Some("notice")
    } else {
        None
    }
}

/// Whether a document is a 1098-E, for `documents list --tax-year`.
pub fn is_1098e(doc: &Document) -> bool {
    doc.name.to_ascii_lowercase().contains("1098") || doc.category.as_deref() == Some("tax")
}

// ---------------------------------------------------------------------------
// Tax — /api/1/tax/account-tax-info → edServicerAccount
// ---------------------------------------------------------------------------

/// The 1098-E deductible-interest figure, as data.
///
/// Reads the federal (`edServicerAccount`) block, falling back to a commercial
/// `servicerAccount` block. Prefers the string dictionary figure
/// (`TaxDeductibleInterest`) for exactness, then the numeric `taxDeductibleInterest`.
pub fn tax(body: &str, path: &str) -> Result<TaxInfo, CliError> {
    let root: Value =
        serde_json::from_str(body).map_err(|_| missing("tax info (non-JSON response)", path))?;
    let acct = root
        .get("edServicerAccount")
        .filter(|v| v.is_object())
        .or_else(|| root.get("servicerAccount").filter(|v| v.is_object()))
        .ok_or_else(|| missing("edServicerAccount", path))?;

    let dict = acct.get("taxInfoDictionary");
    let deductible = dict
        .and_then(|d| as_money(d, "TaxDeductibleInterest"))
        .or_else(|| as_money(acct, "taxDeductibleInterest"))
        .ok_or_else(|| missing("TaxDeductibleInterest", path))?;

    let mut t = TaxInfo::new(deductible);
    t.as_of = as_date(acct, "refreshDate");
    t.account = as_text(acct, "accountNumber")
        .or_else(|| dict.and_then(|d| as_text(d, "AccountNumber")))
        .map(|a| mask(&a));
    t.accrued_interest = as_money(acct, "totalInterestAccruedAmount");
    t.form_correction = dict.and_then(|d| as_text(d, "TaxFormCorrection"));
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_reads_overview_figures() {
        let overview = r#"{"currentBalance":10250.00,"outstandingPrincipal":10000.00,"accruedInterest":250.00,"lastBumpDate":"2026-08-01T00:00:00"}"#;
        let s = summary(overview, None, "/x").unwrap();
        assert_eq!(s.principal_balance.amount, "10000.00");
        assert_eq!(s.accrued_interest.amount, "250.00");
        assert_eq!(s.payoff_amount.amount, "10250.00");
        assert_eq!(s.as_of.as_deref(), Some("2026-08-01"));
    }

    #[test]
    fn summary_derives_payoff_when_absent() {
        let overview = r#"{"outstandingPrincipal":100.00,"accruedInterest":1.50}"#;
        let s = summary(overview, None, "/x").unwrap();
        assert_eq!(s.payoff_amount.amount, "101.50");
    }

    #[test]
    fn summary_enriches_from_loan_summary() {
        let overview =
            r#"{"outstandingPrincipal":100.00,"accruedInterest":1.50,"currentBalance":101.50}"#;
        let ls = r#"{"federalAccounts":[{"accountNumber":"E000004321","nextPaymentAmountDue":0,"paymentDueDate":"2027-01-28T00:00:00","borrowerGroupPayments":[{"repaymentPlan":"Standard Repayment","recertificationDate":"2027-01-15T00:00:00"},{}]}]}"#;
        let s = summary(overview, Some(ls), "/x").unwrap();
        assert_eq!(s.account.as_deref(), Some("****4321"));
        assert_eq!(s.loan_count, 2);
        assert_eq!(s.repayment_plan.as_deref(), Some("Standard Repayment"));
        assert_eq!(s.idr_recertification_date.as_deref(), Some("2027-01-15"));
        assert_eq!(
            s.next_payment_amount.map(|m| m.amount).as_deref(),
            Some("0.00")
        );
    }

    #[test]
    fn missing_accrued_interest_is_an_error_not_a_zero() {
        let err = summary(r#"{"outstandingPrincipal":100.00}"#, None, "/x").unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("accruedInterest"));
    }

    #[test]
    fn zero_accrued_interest_is_preserved() {
        let s = summary(
            r#"{"outstandingPrincipal":100.00,"accruedInterest":0}"#,
            None,
            "/x",
        )
        .unwrap();
        assert_eq!(s.accrued_interest.amount, "0.00");
        assert_eq!(s.payoff_amount.amount, "100.00");
    }

    #[test]
    fn loans_read_group_fields_with_inverted_balance_semantics() {
        let body = r#"{"federalAccounts":[{"borrowerGroupPayments":[
            {"groupId":"G1","loanType":"DIRECT SUB     ","statusDesc":"REPAYMENT","interestRate":"4.500","currentBalance":1000.00,"accruedInterest":20.00,"outstandingBalance":1020.00,"firstDisbursementDate":"2015-09-01T00:00:00"}
        ]}]}"#;
        let loans = loans(body);
        assert_eq!(loans.len(), 1);
        let l = &loans[0];
        assert_eq!(l.id, "G1");
        assert_eq!(l.loan_type.as_deref(), Some("DIRECT SUB")); // trimmed
        assert_eq!(l.status.as_deref(), Some("REPAYMENT"));
        assert_eq!(l.interest_rate.as_deref(), Some("4.500%"));
        assert_eq!(l.principal_balance.amount, "1000.00");
        assert_eq!(l.accrued_interest.amount, "20.00");
        assert_eq!(l.payoff_amount.as_ref().unwrap().amount, "1020.00");
        // The invariant the inverted semantics must preserve.
        assert_eq!(l.disbursement_date.as_deref(), Some("2015-09-01"));
    }

    #[test]
    fn transactions_expose_the_principal_interest_split() {
        let body = r#"{"paymentHistoryList":[
            {"effectiveDate":"2026-06-15T00:00:00","description":"Electronic","sumOfPaymentAmount":500.00,"sumOfPrincipal":450.00,"sumOfInterest":50.00,"sumOfFees":0.00,"paymentId":0,"confirmationNumber":0}
        ]}"#;
        let txns = transactions(body);
        assert_eq!(txns.len(), 1);
        let t = &txns[0];
        assert_eq!(t.amount.amount, "500.00");
        assert_eq!(t.principal.as_ref().unwrap().amount, "450.00");
        assert_eq!(t.interest.as_ref().unwrap().amount, "50.00");
        assert_eq!(t.date.as_deref(), Some("2026-06-15"));
        // Both ids are 0 → synthetic id, not "0".
        assert_eq!(t.id, "tx-0");
    }

    #[test]
    fn documents_map_statements_and_build_the_pdf_href() {
        let body = r#"{"statementList":[
            {"documentId":"00000000-0000-0000-0000-00000000abcd","documentTitle":"STMT-000-20260801.pdf","docReceivedDate":"2026-08-01T17:00:00","createdDate":"2026-08-02T10:37:08","letterType":"STMT","isDirect":true}
        ]}"#;
        let docs = documents(body);
        assert_eq!(docs.len(), 1);
        let d = &docs[0];
        assert_eq!(d.doc.category.as_deref(), Some("statement"));
        assert_eq!(d.doc.date.as_deref(), Some("2026-08-01"));
        assert_eq!(d.doc.file.as_deref(), Some("STMT-000-20260801.pdf"));
        assert_eq!(
            d.href,
            "/api/1/statements/pdf/00000000-0000-0000-0000-00000000abcd/true"
        );
    }

    #[test]
    fn tax_reads_the_deductible_interest_figure() {
        let body = r#"{"edServicerAccount":{"accountNumber":"E000004321","refreshDate":"2026-08-01T00:00:00","totalInterestAccruedAmount":250.00,"taxDeductibleInterest":1812.34,"taxInfoDictionary":{"TaxDeductibleInterest":"1,812.34","TaxFormCorrection":null}}}"#;
        let t = tax(body, "/x").unwrap();
        assert_eq!(t.deductible_interest.amount, "1812.34");
        assert_eq!(t.as_of.as_deref(), Some("2026-08-01"));
        assert_eq!(t.account.as_deref(), Some("****4321"));
        assert_eq!(t.accrued_interest.as_ref().unwrap().amount, "250.00");
        assert_eq!(t.lender_tin, "52-1198289");
        assert!(t.form_correction.is_none());
    }

    #[test]
    fn tax_errors_when_the_figure_is_missing() {
        let err = tax(
            r#"{"edServicerAccount":{"refreshDate":"2026-08-12T00:00:00"}}"#,
            "/x",
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("TaxDeductibleInterest"));
    }

    #[test]
    fn money_accepts_numbers_and_comma_strings() {
        assert_eq!(money(&serde_json::json!(250.5)).unwrap().amount, "250.50");
        assert_eq!(
            money(&serde_json::json!("1,812.34")).unwrap().amount,
            "1812.34"
        );
        assert_eq!(
            money(&serde_json::json!("$1,234.56")).unwrap().amount,
            "1234.56"
        );
        assert!(money(&serde_json::json!(null)).is_none());
    }

    #[test]
    fn dates_are_normalized_to_iso() {
        assert_eq!(
            iso_date("2026-08-11T00:00:00").as_deref(),
            Some("2026-08-11")
        );
        assert_eq!(iso_date("06/15/2026").as_deref(), Some("2026-06-15"));
        assert_eq!(iso_date("sometime"), None);
    }

    /// A multi-byte character crossing byte index 10 must yield `None`, not a
    /// slice-on-non-char-boundary panic.
    #[test]
    fn iso_date_does_not_panic_on_multibyte_input() {
        assert_eq!(iso_date("2026-08-1\u{00e9}xtra"), None); // é (2 bytes) straddles index 10
        assert_eq!(iso_date("\u{1f4b0}\u{1f4b0}\u{1f4b0}"), None); // 4-byte chars, >10 bytes
        assert_eq!(iso_date("çççççççççç"), None);
    }

    #[test]
    fn account_numbers_are_masked() {
        assert_eq!(mask("E000004321"), "****4321");
        assert_eq!(mask("12"), "**");
    }

    #[test]
    fn mask_tail_shows_a_provided_tail_but_never_a_full_number() {
        // The servicer already returns only the last four — show them prefixed.
        assert_eq!(mask_tail("9962"), "****9962");
        assert_eq!(mask_tail("0000"), "****0000");
        // A longer value (unexpected) is masked, not exposed — contrast `mask`.
        assert_eq!(mask_tail("123456789"), "****6789");
        assert_eq!(mask_tail(""), "****");
    }

    #[test]
    fn parsers_tolerate_unrecognized_json() {
        for junk in ["", "{}", "not json", r#"{"unexpected":true}"#] {
            assert!(loans(junk).is_empty());
            assert!(transactions(junk).is_empty());
            assert!(documents(junk).is_empty());
            assert!(summary(junk, None, "/x").is_err());
            assert!(tax(junk, "/x").is_err());
        }
    }

    #[test]
    fn documents_are_classified_for_the_archiver() {
        assert_eq!(classify("2025 Form 1098-E"), Some("tax"));
        assert_eq!(classify("STMT-000-20260801.pdf"), Some("statement"));
        assert_eq!(letter_type_category(Some("STMT")), Some("statement"));
        assert_eq!(classify("Something else"), None);
    }
}
