//! The tools over the scrubbed fixtures, offline: no network, no keychain. Every
//! request a tool makes goes through [`Fixtures`], which records it, so the read-only
//! guarantee is tested against the requests themselves.

use std::collections::HashMap;
use std::sync::Mutex;

use pk_cli_mcp::conformance::{assert_conforms, assert_fits, call, definitions_size};
use pk_cli_mcp::{tools_list_json, CallToolResult};
use serde_json::{json, Value};

use super::*;

const OVERVIEW: &str = include_str!("../../tests/fixtures/overview.json");
const LOAN_SUMMARY: &str = include_str!("../../tests/fixtures/loan_summary.json");
const HISTORY: &str = include_str!("../../tests/fixtures/payment_history.json");
const SCHEDULED: &str = include_str!("../../tests/fixtures/payment_scheduled.json");
const REPAYMENT: &str = include_str!("../../tests/fixtures/repayment_overview.json");
const IDR: &str = include_str!("../../tests/fixtures/idr_statuses.json");
const AUTO_DEBIT: &str = include_str!("../../tests/fixtures/auto_debit.json");
const TAX: &str = include_str!("../../tests/fixtures/tax_info.json");
const STATEMENTS: &str = include_str!("../../tests/fixtures/statements.json");

const ALL_TOOLS: [&str; 5] = [
    LOANS_TOOL,
    PAYMENTS_TOOL,
    REPAYMENT_TOOL,
    TAX_TOOL,
    DOCUMENTS_TOOL,
];

/// Nelnet, as the fixtures have it. An entry in `answers` replaces what a path
/// answers, and one in `failures` fails it.
#[derive(Default)]
struct Fixtures {
    calls: Mutex<Vec<String>>,
    answers: HashMap<&'static str, String>,
    failures: HashMap<&'static str, fn() -> CliError>,
}

impl Fixtures {
    fn answering(mut self, path: &'static str, body: &str) -> Self {
        self.answers.insert(path, body.to_string());
        self
    }

    fn failing(mut self, path: &'static str, e: fn() -> CliError) -> Self {
        self.failures.insert(path, e);
        self
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Reads for Fixtures {
    fn get_text(&self, path: &str) -> Result<String, CliError> {
        self.calls.lock().unwrap().push(path.to_string());
        if let Some(fail) = self.failures.get(path) {
            return Err(fail());
        }
        if let Some(body) = self.answers.get(path) {
            return Ok(body.clone());
        }
        let body = match path {
            paths::OVERVIEW => OVERVIEW,
            paths::LOAN_SUMMARY => LOAN_SUMMARY,
            paths::PAYMENT_HISTORY => HISTORY,
            paths::PAYMENT_SCHEDULED => SCHEDULED,
            paths::REPAYMENT_OVERVIEW => REPAYMENT,
            paths::IDR_STATUSES => IDR,
            paths::AUTO_DEBIT => AUTO_DEBIT,
            paths::TAX_INFO => TAX,
            paths::STATEMENTS => STATEMENTS,
            other => return Err(CliError::NotFound(format!("no fixture for {other}"))),
        };
        Ok(body.to_string())
    }
}

impl Source for Fixtures {
    fn fetch(&self, want: &Want) -> Result<Answers, CliError> {
        read_all(self, want, Instant::now() + Duration::from_secs(60))
    }
}

fn tools() -> NelnetTools<Fixtures> {
    NelnetTools::new(Fixtures::default())
}

fn with(source: Fixtures) -> NelnetTools<Fixtures> {
    NelnetTools::new(source)
}

fn text(result: &CallToolResult) -> String {
    result.text().to_string()
}

/// A call's error text, asserting it is an error.
fn error(tools: &NelnetTools<Fixtures>, tool: &str, args: Value) -> String {
    let result = call(tools, tool, args);
    assert!(result.is_error(), "{}", text(&result));
    text(&result)
}

fn ok(tools: &NelnetTools<Fixtures>, tool: &str, args: Value) -> Value {
    let result = call(tools, tool, args);
    assert_fits(tools, tool, &result).clone()
}

/// The error text when one path fails this way.
fn failing_with(path: &'static str, tool: &str, e: fn() -> CliError) -> String {
    error(&with(Fixtures::default().failing(path, e)), tool, json!({}))
}

// ---- the profile -------------------------------------------------------------

#[test]
fn the_tools_conform_to_the_profile() {
    assert_conforms(&tools());
    assert!(definitions_size(&tools()) < 8_000);
}

#[test]
fn listing_the_tools_opens_no_session() {
    struct Refuses;
    impl Source for Refuses {
        fn fetch(&self, _: &Want) -> Result<Answers, CliError> {
            panic!("listing the tools must not read a credential");
        }
    }
    let tools = NelnetTools::new(Refuses);
    let names: Vec<String> = tools.tools().into_iter().map(|t| t.name).collect();
    assert_eq!(names, ALL_TOOLS);
    let _ = tools_list_json(&tools);
}

// ---- read-only ---------------------------------------------------------------

/// Every path a tool can ask for, over every filter it takes.
#[test]
fn every_request_any_tool_makes_is_a_listed_read() {
    let allowed = [
        paths::OVERVIEW,
        paths::LOAN_SUMMARY,
        paths::PAYMENT_HISTORY,
        paths::PAYMENT_SCHEDULED,
        paths::REPAYMENT_OVERVIEW,
        paths::IDR_STATUSES,
        paths::AUTO_DEBIT,
        paths::TAX_INFO,
        paths::STATEMENTS,
    ];
    let tools = tools();
    for (tool, args) in [
        (LOANS_TOOL, json!({})),
        (
            LOANS_TOOL,
            json!({"loan_type": "SUB", "response_format": "detailed"}),
        ),
        (PAYMENTS_TOOL, json!({})),
        (PAYMENTS_TOOL, json!({"scheduled": true})),
        (
            PAYMENTS_TOOL,
            json!({"since": "2026-01-01", "until": "2026-12-31"}),
        ),
        (REPAYMENT_TOOL, json!({})),
        (REPAYMENT_TOOL, json!({"response_format": "detailed"})),
        (TAX_TOOL, json!({})),
        (DOCUMENTS_TOOL, json!({})),
        (
            DOCUMENTS_TOOL,
            json!({"category": "tax", "since": "2026-01-01"}),
        ),
    ] {
        ok(&tools, tool, args);
    }
    let calls = tools.source().calls();
    assert!(!calls.is_empty());
    for path in calls {
        assert!(allowed.contains(&path.as_str()), "{path}");
    }
}

/// Filters run over what comes back: nothing a model passes reaches a path.
#[test]
fn a_call_cannot_steer_a_request_to_another_path() {
    let hostile = "/api/1/auto-debit/../payment/make";
    let tools = tools();
    ok(&tools, LOANS_TOOL, json!({"loan_type": hostile}));
    ok(&tools, DOCUMENTS_TOOL, json!({"category": hostile}));
    for path in tools.source().calls() {
        assert_ne!(path, hostile);
        assert!(!path.contains(".."), "{path}");
        assert!(
            path == paths::OVERVIEW || path == paths::LOAN_SUMMARY || path == paths::STATEMENTS
        );
    }
}

#[test]
fn every_definition_is_a_read() {
    let list = tools_list_json(&tools());
    for tool in list["tools"].as_array().unwrap() {
        let hints = &tool["annotations"];
        assert_eq!(hints["readOnlyHint"], true, "{tool}");
        assert_eq!(hints["destructiveHint"], false, "{tool}");
    }
}

/// `Portal::refresh` holds the binary's one POST, to the token endpoint. The tools'
/// way out has `get_text` and nothing else.
#[test]
fn neither_the_tools_nor_the_client_have_a_write_verb() {
    for verb in [".put(", ".patch(", ".delete(", ".request("] {
        assert!(!include_str!("../client.rs").contains(verb), "`{verb}`");
        assert!(!include_str!("../mcp.rs").contains(verb), "`{verb}`");
    }
    assert_eq!(include_str!("../client.rs").matches(".post(").count(), 1);
    let trait_body = include_str!("../mcp.rs")
        .split("pub trait Reads {")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    assert_eq!(trait_body.matches("fn ").count(), 1, "{trait_body}");
    assert!(trait_body.contains("fn get_text("), "{trait_body}");
}

/// The fixtures hold a dummy in every place the real answers hold something
/// identifying, so a result carrying one shows here. Every tool, in both formats.
#[test]
fn no_result_carries_an_account_number_a_name_or_a_document_title() {
    let tools = tools();
    for tool in ALL_TOOLS {
        let mut args = vec![json!({})];
        if tool != TAX_TOOL {
            args.push(json!({"response_format": "detailed"}));
        }
        for args in args {
            let out = ok(&tools, tool, args).to_string();
            for dummy in [
                "000000000000",
                "STMT-",
                ".pdf",
                "JANE",
                "DOE",
                "EXAMPLE ST",
                "ANYTOWN",
                "user@example.com",
                "XXX-XX",
                "routing",
                "\"account",
                "bank_account",
                "****",
            ] {
                assert!(!out.contains(dummy), "{tool}: `{dummy}` in {out}");
            }
        }
    }
}

// ---- nelnet_loans ----------------------------------------------------------------

#[test]
fn the_loans_give_the_totals_and_each_group() {
    let out = ok(&tools(), LOANS_TOOL, json!({}));
    assert_eq!(out["principal_balance"], "11111.11");
    assert_eq!(out["accrued_interest"], "222.22");
    assert_eq!(out["payoff_amount"], "11333.33");
    assert_eq!(out["as_of"], "2026-08-11");
    assert_eq!(out["loan_count"], 2);
    let first = &out["items"][0];
    assert_eq!(first["type"], "DIRECT SUB");
    assert_eq!(first["status"], "REPAYMENT");
    assert_eq!(first["interest_rate"], "3.760%");
    assert_eq!(first["principal_balance"], "5000.00");
    assert_eq!(first["accrued_interest"], "111.11");
    assert_eq!(first["payoff_amount"], "5111.11");
    assert!(first.get("id").is_none(), "concise");
    assert!(first.get("monthly_payment").is_none(), "concise");
}

#[test]
fn detailed_loans_add_the_id_payment_and_disbursement() {
    let out = ok(&tools(), LOANS_TOOL, json!({"response_format": "detailed"}));
    let first = &out["items"][0];
    assert_eq!(first["id"], "0000000001");
    assert_eq!(first["monthly_payment"], "200.00");
    assert_eq!(first["disbursement_date"], "2015-09-01");
}

#[test]
fn loan_type_narrows_the_list_and_not_the_count() {
    let out = ok(&tools(), LOANS_TOOL, json!({"loan_type": "unsub"}));
    let items = out["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{out}");
    assert!(items[0]["type"].as_str().unwrap().contains("UNSUB"));
    assert_eq!(out["loan_count"], 2);
}

#[test]
fn a_cursor_continues_only_its_own_query() {
    let tools = tools();
    let first = ok(&tools, LOANS_TOOL, json!({"limit": 1}));
    let cursor = first["next_cursor"].as_str().unwrap();
    let rest = ok(&tools, LOANS_TOOL, json!({"limit": 1, "cursor": cursor}));
    assert_ne!(first["items"][0], rest["items"][0]);
    let says = error(
        &tools,
        LOANS_TOOL,
        json!({"limit": 1, "cursor": cursor, "loan_type": "UNSUB"}),
    );
    assert!(says.starts_with("usage:"), "{says}");
}

/// A figure Nelnet did not state stays absent, in a row that stays in the list.
#[test]
fn an_absent_accrued_interest_is_not_zero_and_its_row_stays() {
    let body = json!({"federalAccounts": [{"borrowerGroupPayments": [
        {"loanType": "DIRECT SUB", "currentBalance": 5000.0},
        {"loanType": "DIRECT UNSUB"},
    ]}]})
    .to_string();
    let out = ok(
        &with(Fixtures::default().answering(paths::LOAN_SUMMARY, &body)),
        LOANS_TOOL,
        json!({}),
    );
    let items = out["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert!(items[0].get("accrued_interest").is_none(), "{out}");
    assert!(items[1].get("principal_balance").is_none(), "{out}");
}

#[test]
fn an_answer_nelnet_did_not_give_is_an_error_not_no_loans() {
    for body in [
        "not json",
        "[]",
        "{}",
        r#"{"federalAccounts": "x"}"#,
        r#"{"federalAccounts": [{}]}"#,
        r#"{"federalAccounts": [{"borrowerGroupPayments": 1}]}"#,
        r#"{"federalAccounts": [{"borrowerGroupPayments": [{"currentBalance": "x"}]}]}"#,
    ] {
        let says = error(
            &with(Fixtures::default().answering(paths::LOAN_SUMMARY, body)),
            LOANS_TOOL,
            json!({}),
        );
        assert!(says.starts_with("upstream:"), "{body}: {says}");
    }
}

#[test]
fn a_balance_with_no_loans_is_an_error_and_no_balance_with_none_is_not() {
    let empty = r#"{"federalAccounts": []}"#;
    let says = error(
        &with(Fixtures::default().answering(paths::LOAN_SUMMARY, empty)),
        LOANS_TOOL,
        json!({}),
    );
    assert!(says.contains("lists no loans"), "{says}");

    let paid_off = r#"{"outstandingPrincipal": 0, "accruedInterest": 0, "currentBalance": 0}"#;
    let out = ok(
        &with(
            Fixtures::default()
                .answering(paths::LOAN_SUMMARY, empty)
                .answering(paths::OVERVIEW, paid_off),
        ),
        LOANS_TOOL,
        json!({}),
    );
    assert_eq!(out["loan_count"], 0);
    assert_eq!(out["principal_balance"], "0.00");
}

/// A fabricated zero would read as good news.
#[test]
fn totals_nelnet_did_not_state_are_an_error_not_a_zero() {
    for (body, field) in [
        (r#"{"outstandingPrincipal": 1.0}"#, "accruedInterest"),
        (r#"{"accruedInterest": 1.0}"#, "outstandingPrincipal"),
        (
            r#"{"outstandingPrincipal": "x", "accruedInterest": 1.0}"#,
            "outstandingPrincipal",
        ),
        ("not json", "loan overview"),
    ] {
        let says = error(
            &with(Fixtures::default().answering(paths::OVERVIEW, body)),
            LOANS_TOOL,
            json!({}),
        );
        assert!(says.starts_with("upstream:"), "{body}: {says}");
        assert!(says.contains(field), "{body}: {says}");
    }
}

// ---- nelnet_payments -------------------------------------------------------------

#[test]
fn payments_come_newest_first_with_their_split() {
    let out = ok(&tools(), PAYMENTS_TOOL, json!({}));
    let items = out["items"].as_array().unwrap();
    assert_eq!(items[0]["date"], "2026-06-12");
    assert_eq!(items[0]["description"], "Electronic");
    assert_eq!(items[0]["amount"], "100.00");
    assert_eq!(items[0]["principal"], "95.11");
    assert_eq!(items[0]["interest"], "4.89");
    assert_eq!(items[0]["fees"], "0.00");
    assert!(items[0]["date"].as_str() > items[1]["date"].as_str());
    assert!(items[0].get("benefit_status").is_none(), "concise");
    assert!(
        items[0].get("type").is_none(),
        "no payment type in this row"
    );
}

/// The CLI falls back to `repaymentBenefitStatus` for a row's kind; as a `type`, a
/// model would read "Not Qualified" as what the payment was.
#[test]
fn a_benefit_status_is_not_reported_as_the_type() {
    let out = ok(
        &tools(),
        PAYMENTS_TOOL,
        json!({"response_format": "detailed"}),
    );
    let first = &out["items"][0];
    assert!(first.get("type").is_none(), "{first}");
    assert_eq!(first["benefit_status"], "Not Qualified");
}

#[test]
fn since_and_until_bound_payments_and_both_ends_count() {
    let out = ok(
        &tools(),
        PAYMENTS_TOOL,
        json!({"since": "2026-06-12", "until": "2026-06-12"}),
    );
    let items = out["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{out}");
    assert_eq!(items[0]["date"], "2026-06-12");
}

#[test]
fn a_bad_range_is_a_usage_error_before_any_request() {
    for args in [
        json!({"since": "2026-13-01"}),
        json!({"until": "yesterday"}),
        json!({"since": "2026-02-01", "until": "2026-01-01"}),
    ] {
        for tool in [PAYMENTS_TOOL, DOCUMENTS_TOOL] {
            let tools = tools();
            let says = error(&tools, tool, args.clone());
            assert!(says.starts_with("usage:"), "{says}");
            assert!(tools.source().calls().is_empty(), "{args}");
        }
    }
}

#[test]
fn scheduled_reads_the_scheduled_list() {
    let tools = tools();
    let out = ok(&tools, PAYMENTS_TOOL, json!({"scheduled": true}));
    assert_eq!(tools.source().calls(), [paths::PAYMENT_SCHEDULED]);
    let first = &out["items"][0];
    assert_eq!(first["date"], "2027-01-28");
    assert_eq!(first["amount"], "333.33");
    assert_eq!(first["description"], "Auto Debit");
    assert!(first.get("principal").is_none(), "not applied yet: {first}");
}

#[test]
fn an_unreadable_payment_list_is_an_error_and_an_empty_one_is_not() {
    for body in [
        "not json",
        "{}",
        r#"{"paymentHistoryList": "x"}"#,
        r#"{"paymentHistoryList": [{"sumOfPaymentAmount": null}]}"#,
    ] {
        let says = error(
            &with(Fixtures::default().answering(paths::PAYMENT_HISTORY, body)),
            PAYMENTS_TOOL,
            json!({}),
        );
        assert!(says.starts_with("upstream:"), "{body}: {says}");
    }
    for body in [
        r#"{"paymentHistoryList": []}"#,
        r#"{"paymentHistoryList": null}"#,
    ] {
        let out = ok(
            &with(Fixtures::default().answering(paths::PAYMENT_HISTORY, body)),
            PAYMENTS_TOOL,
            json!({}),
        );
        assert_eq!(out["returned"], 0, "{body}");
    }
}

#[test]
fn a_payment_with_no_date_is_kept_and_sorts_last() {
    let body = json!({"paymentHistoryList": [
        {"sumOfPaymentAmount": 1.0},
        {"sumOfPaymentAmount": 2.0, "effectiveDate": "2026-01-01T00:00:00"},
    ]})
    .to_string();
    let out = ok(
        &with(Fixtures::default().answering(paths::PAYMENT_HISTORY, &body)),
        PAYMENTS_TOOL,
        json!({"since": "2025-01-01"}),
    );
    let items = out["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["amount"], "2.00");
    assert_eq!(items[1]["amount"], "1.00");
}

/// With no confirmation number, what a row says is what holds its place. A row saying nothing has
/// nothing to hold it.
#[test]
fn a_payment_saying_nothing_is_an_upstream_error() {
    let body = json!({"paymentHistoryList": [
        {"sumOfPaymentAmount": 1.0, "effectiveDate": "2026-02-01T00:00:00"},
        {"effectiveDate": "2026-01-01T00:00:00"},
    ]})
    .to_string();
    let says = error(
        &with(Fixtures::default().answering(paths::PAYMENT_HISTORY, &body)),
        PAYMENTS_TOOL,
        json!({"since": "2025-01-01"}),
    );
    assert!(says.starts_with("upstream:"), "{says}");
    assert!(says.contains("no id"), "{says}");
}

// ---- nelnet_repayment ------------------------------------------------------------

#[test]
fn repayment_gives_the_plan_next_payment_autopay_and_applications() {
    let out = ok(&tools(), REPAYMENT_TOOL, json!({}));
    assert_eq!(out["status"], "Standard Repayment");
    assert_eq!(out["repayment_plan"], "Standard Repayment");
    assert_eq!(out["next_payment_amount"], "0.00");
    assert_eq!(out["next_payment_due_date"], "2027-01-28");
    assert_eq!(out["idr_recertification_date"], "2027-01-15");
    assert_eq!(out["autopay"]["enrolled"], true);
    assert_eq!(out["autopay"]["bank_name"], "SAMPLE BANK");
    assert_eq!(out["autopay"]["next_amount"], "333.33");
    assert_eq!(out["idr_applications"][0]["status"], "PROCESSED");
    assert!(out.get("note").is_none(), "{out}");
    assert!(out.get("in_school").is_none(), "{out}");
    assert!(out.get("current_school").is_none(), "concise");
}

#[test]
fn detailed_repayment_adds_the_school() {
    let out = ok(
        &tools(),
        REPAYMENT_TOOL,
        json!({"response_format": "detailed"}),
    );
    assert_eq!(out["current_school"], "SAMPLE UNIVERSITY");
    assert_eq!(out["separation_date"], "2018-08-19");
}

/// Applications and autopay are supplementary: without them the view still answers,
/// and says what it cannot.
#[test]
fn a_supplementary_read_that_fails_is_noted_rather_than_read_as_none() {
    let upstream: fn() -> CliError = || CliError::Upstream("portal HTTP 500".into());
    let out = ok(
        &with(
            Fixtures::default()
                .failing(paths::IDR_STATUSES, upstream)
                .failing(paths::AUTO_DEBIT, upstream),
        ),
        REPAYMENT_TOOL,
        json!({}),
    );
    assert_eq!(out["status"], "Standard Repayment");
    assert!(out.get("autopay").is_none(), "{out}");
    assert_eq!(out["idr_applications"].as_array().unwrap().len(), 0);
    let note = out["note"].as_str().unwrap();
    assert!(note.contains("income-driven"), "{note}");
    assert!(note.contains("autopay"), "{note}");
}

/// A lapsed token on a supplementary read still has to start a renewal.
#[test]
fn an_auth_failure_on_a_supplementary_read_fails_the_fetch() {
    let says = failing_with(paths::AUTO_DEBIT, REPAYMENT_TOOL, || {
        CliError::Auth("portal returned 401 for /x — the access token is missing or expired; run `nlnt auth refresh`".into())
    });
    assert!(says.starts_with("auth:"), "{says}");
}

#[test]
fn an_answer_of_the_wrong_shape_is_an_error_for_repayment() {
    for (path, body) in [
        (paths::REPAYMENT_OVERVIEW, "not json"),
        (paths::REPAYMENT_OVERVIEW, "{}"),
        (paths::LOAN_SUMMARY, "{}"),
        (paths::IDR_STATUSES, r#"{"unexpected": true}"#),
        (paths::AUTO_DEBIT, r#"{"bankName": "x"}"#),
    ] {
        let says = error(
            &with(Fixtures::default().answering(path, body)),
            REPAYMENT_TOOL,
            json!({}),
        );
        assert!(says.starts_with("upstream:"), "{path} {body}: {says}");
    }
}

#[test]
fn more_than_one_federal_account_is_noted() {
    let body = json!({"federalAccounts": [
        {"borrowerGroupPayments": [{"repaymentPlan": "Standard Repayment"}]},
        {"borrowerGroupPayments": []},
    ]})
    .to_string();
    let out = ok(
        &with(Fixtures::default().answering(paths::LOAN_SUMMARY, &body)),
        REPAYMENT_TOOL,
        json!({}),
    );
    assert!(
        out["note"].as_str().unwrap().contains("2 federal accounts"),
        "{out}"
    );
}

// ---- nelnet_tax ------------------------------------------------------------------

#[test]
fn tax_gives_the_figure_with_what_it_is() {
    let out = ok(&tools(), TAX_TOOL, json!({}));
    assert_eq!(out["deductible_interest"], "222.22");
    assert_eq!(out["lender_tin"], crate::model::TaxInfo::ED_LENDER_TIN);
    assert!(out["note"].as_str().unwrap().contains("as_of"), "{out}");
}

#[test]
fn a_tax_answer_with_no_figure_is_an_error_not_a_zero() {
    for body in ["not json", "{}", r#"{"edServicerAccount": {}}"#] {
        let says = error(
            &with(Fixtures::default().answering(paths::TAX_INFO, body)),
            TAX_TOOL,
            json!({}),
        );
        assert!(says.starts_with("upstream:"), "{body}: {says}");
    }
}

// ---- nelnet_documents ------------------------------------------------------------

#[test]
fn documents_list_date_category_and_id_and_never_the_title() {
    let out = ok(&tools(), DOCUMENTS_TOOL, json!({}));
    let items = out["items"].as_array().unwrap();
    assert_eq!(items[0]["date"], "2026-08-01");
    assert_eq!(items[0]["category"], "statement");
    assert_eq!(items[0]["id"], "00000000-0000-0000-0000-000000000001");
    assert!(items[0]["date"].as_str() > items[1]["date"].as_str());
}

#[test]
fn category_narrows_documents_whatever_its_case() {
    let out = ok(&tools(), DOCUMENTS_TOOL, json!({"category": "STATEMENT"}));
    assert!(out["returned"].as_u64().unwrap() > 0);
    let out = ok(&tools(), DOCUMENTS_TOOL, json!({"category": "notice"}));
    assert_eq!(out["returned"], 0);
}

/// The rule `documents list --tax-year` has: a 1098-E for year N is published in N+1.
#[test]
fn tax_year_uses_the_year_a_title_names_and_else_the_date() {
    let body = json!({"statementList": [
        {"documentId": "named", "documentTitle": "2025 Form 1098-E", "letterType": "TAX",
         "docReceivedDate": "2026-01-31T00:00:00"},
        {"documentId": "dated", "documentTitle": "Tax Statement",
         "docReceivedDate": "2025-02-01T00:00:00"},
        {"documentId": "other", "documentTitle": "June Statement",
         "docReceivedDate": "2026-06-01T00:00:00"},
        {"documentId": "identifier", "documentTitle": "STMT-1202512-June.pdf",
         "docReceivedDate": "2026-07-01T00:00:00"},
    ]})
    .to_string();
    let tools = with(Fixtures::default().answering(paths::STATEMENTS, &body));
    let ids = |year: u32| {
        let out = ok(&tools, DOCUMENTS_TOOL, json!({"tax_year": year}));
        let items = out["items"].as_array().unwrap().clone();
        let ids: Vec<String> = items
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_string())
            .collect();
        ids
    };
    assert_eq!(ids(2025), ["named", "dated"]);
    assert_eq!(ids(2026), ["identifier", "other"]);

    let says = error(&tools, DOCUMENTS_TOOL, json!({"tax_year": 25}));
    assert!(says.starts_with("usage:"), "{says}");
}

/// A row with no id could not hold its place in a position cursor, so it fails the call.
#[test]
fn a_document_with_no_id_is_an_upstream_error() {
    let body = json!({"statementList": [
        {"documentId": "kept", "documentTitle": "July Statement",
         "docReceivedDate": "2026-07-01T00:00:00"},
        {"documentTitle": "June Statement", "docReceivedDate": "2026-06-01T00:00:00"},
    ]})
    .to_string();
    let says = error(
        &with(Fixtures::default().answering(paths::STATEMENTS, &body)),
        DOCUMENTS_TOOL,
        json!({}),
    );
    assert!(says.starts_with("upstream:"), "{says}");
    assert!(says.contains("no id"), "{says}");
}

#[test]
fn a_document_list_nelnet_did_not_give_is_an_error_not_no_documents() {
    for body in [
        "not json",
        "{}",
        r#"{"statementList": 1}"#,
        r#"{"statementList": [{}]}"#,
    ] {
        let says = error(
            &with(Fixtures::default().answering(paths::STATEMENTS, body)),
            DOCUMENTS_TOOL,
            json!({}),
        );
        assert!(says.starts_with("upstream:"), "{body}: {says}");
    }
}

// ---- errors ----------------------------------------------------------------------

const REMEDY: &str = "`nlnt auth login --browser --overwrite`";

/// Each of these is what the client itself returns, so a reworded one fails here.
#[test]
fn a_missing_or_dead_session_names_the_one_command_that_fixes_it() {
    let lapsed: fn() -> CliError =
        || crate::client::guard("/api/1/loan/summary", 401, "application/json", "{}").unwrap_err();
    let unreadable: fn() -> CliError =
        || crate::client::session_unreadable("expected value at line 1");
    for e in [
        crate::client::no_stored_session,
        lapsed,
        crate::client::refresh_rejected,
        crate::client::no_refresh_token,
        unreadable,
    ] {
        let says = failing_with(paths::TAX_INFO, TAX_TOOL, e);
        assert!(says.starts_with("auth:"), "{says}");
        assert!(says.contains(REMEDY), "{says}");
        assert_eq!(says.matches("nlnt auth login").count(), 1, "{says}");
        assert!(!says.contains("nlnt auth refresh"), "{says}");
    }
}

/// A renewal writes the session back before it spends the token, so this is what a
/// person refusing that prompt sees. A new sign-in would not help.
#[test]
fn a_refused_keychain_asks_for_access_and_not_a_sign_in() {
    let says = failing_with(paths::TAX_INFO, TAX_TOOL, || {
        CliError::Keychain("storing credential: denied".into())
    });
    assert!(says.contains("storing credential"), "{says}");
    let fix = if cfg!(target_os = "macos") {
        "Keychain Access"
    } else if cfg!(windows) {
        "Credential Manager"
    } else {
        "desktop keyring"
    };
    assert!(says.contains(fix), "{says}");
    assert!(!says.contains("auth login"), "{says}");
    assert!(!says.contains("could not be read"), "{says}");
}

/// A page boundary falls inside a day, and a payment posts before the next page is read.
/// A cursor holds no server state, so a second set of answers stands for the later read.
#[test]
fn a_payment_that_posts_between_pages_repeats_nothing_and_skips_nothing() {
    let body = |rows: &[(&str, &str)]| {
        let list: Vec<Value> = rows
            .iter()
            .map(|(date, confirmation)| {
                json!({"effectiveDate": date, "sumOfPaymentAmount": 10.0,
                       "confirmationNumber": confirmation})
            })
            .collect();
        json!({"paymentHistoryList": list}).to_string()
    };
    let before = [
        ("2026-05-02", "4"),
        ("2026-05-01", "3"),
        ("2026-05-01", "2"),
        ("2026-04-01", "1"),
    ];
    let mut after = vec![("2026-06-01", "5"), ("2026-05-01", "6")];
    after.extend(before);
    let args = json!({"limit": 2, "response_format": "detailed"});
    let confirmations = |page: &Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["confirmation"].as_str().unwrap().to_string())
            .collect()
    };

    let first = ok(
        &with(Fixtures::default().answering(paths::PAYMENT_HISTORY, &body(&before))),
        PAYMENTS_TOOL,
        args.clone(),
    );
    let mut seen = confirmations(&first);
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], "4");

    let later = with(Fixtures::default().answering(paths::PAYMENT_HISTORY, &body(&after)));
    let mut cursor = first["next_cursor"].clone();
    while cursor.is_string() {
        let mut next = args.clone();
        next["cursor"] = cursor;
        let page = ok(&later, PAYMENTS_TOOL, next);
        seen.extend(confirmations(&page));
        cursor = page["next_cursor"].clone();
    }
    // Each row that was there is seen once, and the newer day is behind the cursor. Which side
    // the new row of the 1st falls on is up to its fingerprint.
    for id in ["4", "3", "2", "1"] {
        assert_eq!(
            seen.iter().filter(|s| *s == id).count(),
            1,
            "{id}: {seen:?}"
        );
    }
    assert!(!seen.contains(&"5".to_string()), "{seen:?}");
}

#[test]
fn auto_refresh_off_asks_for_a_refresh_and_not_a_sign_in() {
    let says = failing_with(paths::TAX_INFO, TAX_TOOL, crate::commands::auto_refresh_off);
    assert!(says.starts_with("auth:"), "{says}");
    assert!(says.contains("`nlnt auth refresh`"), "{says}");
    assert!(!says.contains("nlnt auth login"), "{says}");
}

/// Akamai blocks this client, not the session, so a new sign-in is not the first fix.
#[test]
fn an_edge_block_is_upstream_and_says_a_sign_in_may_not_help() {
    let says = failing_with(paths::TAX_INFO, TAX_TOOL, || {
        crate::client::guard(
            "/api/1/tax/account-tax-info",
            403,
            "text/html",
            "<html>Access denied</html>",
        )
        .unwrap_err()
    });
    assert!(says.starts_with("upstream:"), "{says}");
    assert!(says.contains("rather than the session"), "{says}");
}

// ---- a call nobody is waiting for ------------------------------------------------

#[test]
fn a_call_past_its_time_stops_asking_nelnet() {
    let fixtures = Fixtures::default();
    let want = Want {
        required: &[paths::TAX_INFO],
        optional: &[],
    };
    let err = read_all(&fixtures, &want, Instant::now()).unwrap_err();
    assert!(matches!(err, CliError::Upstream(_)), "{err:?}");
    assert!(
        fixtures.calls().is_empty(),
        "nothing is sent past the deadline"
    );
}
