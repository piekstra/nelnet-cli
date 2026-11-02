//! Provider-shaped DTOs for the student-loan domain (SPEC v1 §1.4).
//!
//! These are deliberately **not** `utility/v1` shapes. A utility summary is
//! "amount due + due date"; the thing this household actually needs to watch is
//! principal vs. **accrued interest** during a $0-payment IDR window, where the
//! due amount is $0 and therefore carries no information. `utility/v1` has no
//! place to put accrued interest, and PROFILES.md is explicit that a profile is
//! designed from the consumer's needs rather than stretched to fit — so the
//! lending shapes stay provider-shaped here.
//!
//! `documents/v1` *is* adopted, via `pk-cli-documents`, because listing and
//! downloading the 1098-E is exactly the shape that profile owns.
//!
//! Money is always [`Money`] (string decimal, never a float). Dates are ISO
//! `YYYY-MM-DD`. Optional fields are omitted rather than emitted as null.

use pk_cli_core::Money;
use serde::{Deserialize, Serialize};

/// The paydown-tracking view (`loan-summary/v1`).
///
/// Field order is deliberate and load-bearing for the rendered output (§1.4:
/// insertion order): identity first, then the three numbers that matter —
/// principal, accrued interest, payoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoanSummary {
    pub schema: String,
    /// Masked servicer account identifier — never the full number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Date the servicer states these figures are current as of.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    pub loan_count: u32,
    /// Outstanding principal across all loans.
    pub principal_balance: Money,
    /// Interest accrued and not yet capitalized. The number this CLI exists to
    /// surface: during a $0-payment IDR window it is the only balance moving,
    /// and paying it down is what prevents capitalization later.
    pub accrued_interest: Money,
    /// Principal + accrued interest — what it would take to close today.
    pub payoff_amount: Money,
    /// Weighted or stated interest rate, as the servicer expresses it
    /// (e.g. `"5.375%"`). A string because providers publish a range as often
    /// as a single figure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interest_rate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repayment_plan: Option<String>,
    /// Scheduled amount due. Expected to be `0.00` in the IDR window — that is
    /// the normal case here, not an error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_payment_amount: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_payment_due_date: Option<String>,
    /// When the income-driven plan must be recertified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idr_recertification_date: Option<String>,
}

impl LoanSummary {
    /// Build a summary from the three figures that always exist; set the
    /// optional provider extras afterwards.
    pub fn new(loan_count: u32, principal: Money, accrued: Money, payoff: Money) -> Self {
        LoanSummary {
            schema: "loan-summary/v1".into(),
            account: None,
            as_of: None,
            loan_count,
            principal_balance: principal,
            accrued_interest: accrued,
            payoff_amount: payoff,
            interest_rate: None,
            repayment_plan: None,
            next_payment_amount: None,
            next_payment_due_date: None,
            idr_recertification_date: None,
        }
    }
}

/// One loan within the servicer's account (`loan/v1`), carried in
/// `loan-list/v1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Loan {
    /// Servicer's loan sequence/identifier, as a string so numeric and
    /// alphanumeric providers share one shape.
    pub id: String,
    /// e.g. `"Direct Unsubsidized"`, `"Direct Subsidized"`, `"Direct PLUS"` —
    /// verbatim from the servicer, not a closed set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loan_type: Option<String>,
    /// e.g. `"Repayment"`, `"In Grace"`, `"Deferment"` — verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interest_rate: Option<String>,
    pub principal_balance: Money,
    pub accrued_interest: Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payoff_amount: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disbursement_date: Option<String>,
    /// Total interest paid on this loan in the current tax year, where the
    /// servicer publishes it per-loan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interest_paid_ytd: Option<Money>,
}

impl Loan {
    pub fn new(id: impl Into<String>, principal: Money, accrued: Money) -> Self {
        Loan {
            id: id.into(),
            loan_type: None,
            status: None,
            interest_rate: None,
            principal_balance: principal,
            accrued_interest: accrued,
            payoff_amount: None,
            disbursement_date: None,
            interest_paid_ytd: None,
        }
    }
}

/// A posted transaction — a payment, a disbursement, an interest accrual, or a
/// capitalization event (`transaction/v1`), carried in `transaction-list/v1`.
///
/// The `principal` / `interest` / `fees` split is the whole point for this
/// household: during the $0-IDR paydown a payment that lands entirely on
/// interest is doing the intended job, and one that touches principal means
/// accrued interest already hit zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    /// Posting date, ISO `YYYY-MM-DD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Effective date, when the servicer distinguishes it from posting date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_date: Option<String>,
    /// e.g. `"Payment"`, `"Interest Accrual"`, `"Capitalization"` — verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub amount: Money,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interest: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<Money>,
    /// Which loan it applied to, where the servicer breaks a payment out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub loan_id: Option<String>,
}

impl Transaction {
    pub fn new(id: impl Into<String>, amount: Money) -> Self {
        Transaction {
            id: id.into(),
            date: None,
            effective_date: None,
            kind: None,
            description: None,
            amount,
            principal: None,
            interest: None,
            fees: None,
            loan_id: None,
        }
    }
}

/// The student-loan-interest figure that feeds the 1098-E (`tax-info/v1`).
///
/// Nelnet publishes **no 1098-E PDF**: the portal renders an HTML template from
/// `/api/1/tax/account-tax-info` and prints it. This DTO surfaces the same
/// figure as data. `deductible_interest` is the servicer's running total of
/// tax-deductible interest **as of** `as_of`; for a completed tax year the
/// finalized 1098-E (available end of January) is authoritative, and the
/// January billing statement carries the same total as a real PDF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxInfo {
    pub schema: String,
    /// Masked servicer account identifier — never the full number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The date the servicer states this figure is current as of (ISO).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    /// Student-loan interest paid, i.e. the 1098-E box-1 figure.
    pub deductible_interest: Money,
    /// Interest accrued and not yet capitalized, for paydown context — the
    /// balance this household is actively working down.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accrued_interest: Option<Money>,
    /// Recipient/lender TIN for federal Direct Loans (U.S. Department of
    /// Education), as printed on the 1098-E. Constant, surfaced for filing.
    pub lender_tin: String,
    /// Whether the servicer flags a 1098-E correction for the period.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub form_correction: Option<String>,
}

impl TaxInfo {
    /// The U.S. Department of Education recipient TIN on federal Direct Loan
    /// 1098-E forms.
    pub const ED_LENDER_TIN: &'static str = "52-1198289";

    pub fn new(deductible_interest: Money) -> Self {
        TaxInfo {
            schema: "tax-info/v1".into(),
            account: None,
            as_of: None,
            deductible_interest,
            accrued_interest: None,
            lender_tin: Self::ED_LENDER_TIN.to_string(),
            form_correction: None,
        }
    }
}

/// Repayment status and income-driven-repayment application tracking
/// (`repayment/v1`). The plan *name* and recertification date live on
/// `loan-summary/v1` (`nlnt summary`); this view adds status, school context,
/// and the IDR application queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepaymentInfo {
    pub schema: String,
    /// Servicer's repayment status, verbatim (e.g. `"REPAYMENT"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Whether every loan is still in-school (no repayment due yet).
    pub in_school: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_school: Option<String>,
    /// When the borrower separated from school (ISO), where stated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub separation_date: Option<String>,
    /// Income-driven-repayment applications and their statuses, newest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub idr_applications: Vec<IdrApplication>,
}

/// One income-driven-repayment application (`idr-application/v1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdrApplication {
    /// When the application was requested (ISO).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// e.g. an application vs. recertification, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

impl RepaymentInfo {
    pub fn new() -> Self {
        RepaymentInfo {
            schema: "repayment/v1".into(),
            status: None,
            in_school: false,
            current_school: None,
            separation_date: None,
            idr_applications: Vec::new(),
        }
    }
}

impl Default for RepaymentInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Auto-debit (autopay) enrollment and next-cycle detail (`autopay/v1`).
///
/// Bank routing, full account, and SSN are **never** surfaced — only the bank
/// name and a masked account tail, so `--json` output carries no raw banking
/// PII.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutopayInfo {
    pub schema: String,
    /// Whether auto-debit is enrolled.
    pub enrolled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_name: Option<String>,
    /// Masked bank-account tail (e.g. `****1234`) — never the full number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_account: Option<String>,
    /// The scheduled next-cycle debit amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_payment_amount: Option<Money>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_payment_date: Option<String>,
    /// The standard (non-alternate) auto-debit amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standard_amount: Option<Money>,
    /// The servicer's human-readable status line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl AutopayInfo {
    pub fn new(enrolled: bool) -> Self {
        AutopayInfo {
            schema: "autopay/v1".into(),
            enrolled,
            bank_name: None,
            bank_account: None,
            next_payment_amount: None,
            next_payment_date: None,
            standard_amount: None,
            status: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_is_schema_tagged_and_leads_with_identity() {
        let s = LoanSummary::new(
            2,
            Money::usd("31000.00"),
            Money::usd("412.55"),
            Money::usd("31412.55"),
        );
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["schema"], "loan-summary/v1");
        assert_eq!(v["principal_balance"]["amount"], "31000.00");
        assert_eq!(v["accrued_interest"]["amount"], "412.55");
        // `preserve_order` is on, so JSON key order mirrors build order.
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(keys[0], "schema");
        assert_eq!(
            keys.iter().position(|k| *k == "principal_balance"),
            Some(keys.iter().position(|k| *k == "loan_count").unwrap() + 1)
        );
    }

    #[test]
    fn unset_optionals_are_omitted_not_null() {
        let v =
            serde_json::to_value(Loan::new("1", Money::usd("100.00"), Money::usd("1.00"))).unwrap();
        assert!(v.get("loan_type").is_none());
        assert!(v.get("payoff_amount").is_none());
        assert!(v.get("interest_paid_ytd").is_none());
        // Required fields stay present.
        assert_eq!(v["principal_balance"]["currency"], "USD");
    }

    #[test]
    fn money_never_serializes_as_a_float() {
        let t = Transaction::new("t1", Money::usd("50.00"));
        let v = serde_json::to_value(&t).unwrap();
        assert!(v["amount"]["amount"].is_string());
    }
}
