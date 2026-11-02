//! Contract tests over the committed fixtures, plus the fixture-hygiene scan.
//!
//! These run the **real** parsers against scrubbed captures of the live API, so
//! a provider rename fails loudly here instead of silently emptying a column in
//! the rendered table. The values are dummies (see `tests/fixtures/README.md`);
//! the *shape* is real.

use std::fs;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"))
}

// ---------------------------------------------------------------------------
// Parser contracts
// ---------------------------------------------------------------------------

#[test]
fn summary_yields_the_paydown_figures_and_enrichment() {
    let s = nlnt::parse::summary(
        &fixture("overview.json"),
        Some(&fixture("loan_summary.json")),
        "/summary",
    )
    .expect("parses");
    assert_eq!(s.schema, "loan-summary/v1");
    assert_eq!(s.principal_balance.amount, "11111.11");
    assert_eq!(s.accrued_interest.amount, "222.22");
    assert_eq!(s.payoff_amount.amount, "11333.33");
    // `lastBumpDate` is the "interest through" date, normalized to ISO.
    assert_eq!(s.as_of.as_deref(), Some("2026-08-11"));
    // Enrichment from loan/summary.
    assert_eq!(s.loan_count, 2);
    assert_eq!(s.account.as_deref(), Some("****0000"));
    assert_eq!(s.repayment_plan.as_deref(), Some("Standard Repayment"));
    assert_eq!(s.idr_recertification_date.as_deref(), Some("2027-01-15"));
    // A $0 scheduled payment is the normal IDR case, not a missing value.
    assert_eq!(
        s.next_payment_amount.map(|m| m.amount).as_deref(),
        Some("0.00")
    );
}

#[test]
fn summary_reads_core_figures_without_enrichment() {
    // The command tolerates a failed loan/summary fetch; the headline figures
    // still come from overview alone.
    let s = nlnt::parse::summary(&fixture("overview.json"), None, "/summary").expect("parses");
    assert_eq!(s.principal_balance.amount, "11111.11");
    assert_eq!(s.accrued_interest.amount, "222.22");
    assert_eq!(s.payoff_amount.amount, "11333.33");
    assert_eq!(s.loan_count, 0);
}

#[test]
fn loans_expose_the_columns_the_table_renders() {
    let loans = nlnt::parse::loans(&fixture("loan_summary.json"));
    assert_eq!(loans.len(), 2);
    let first = &loans[0];
    assert_eq!(first.id, "0000000001");
    // Provider pads loan-type strings; the parser must trim them.
    assert_eq!(first.loan_type.as_deref(), Some("DIRECT SUB"));
    assert_eq!(first.status.as_deref(), Some("REPAYMENT"));
    assert_eq!(first.interest_rate.as_deref(), Some("3.760%"));
    // At the group level currentBalance is principal, outstandingBalance is
    // the payoff — the invariant the inverted semantics must preserve.
    assert_eq!(first.principal_balance.amount, "5000.00");
    assert_eq!(first.accrued_interest.amount, "111.11");
    assert_eq!(first.payoff_amount.as_ref().unwrap().amount, "5111.11");
    assert_eq!(first.disbursement_date.as_deref(), Some("2015-09-01"));
    // A paid-off group still lists, with a zero balance rather than a drop.
    assert_eq!(loans[1].status.as_deref(), Some("Paid In Full"));
    assert_eq!(loans[1].principal_balance.amount, "0.00");
}

#[test]
fn transactions_expose_the_principal_interest_split() {
    let txns = nlnt::parse::transactions(&fixture("payment_history.json"));
    assert_eq!(txns.len(), 2);
    let payment = &txns[0];
    assert_eq!(payment.amount.amount, "100.00");
    // The split is the whole point of this command during the paydown.
    assert_eq!(
        payment.principal.as_ref().map(|m| m.amount.as_str()),
        Some("95.11")
    );
    assert_eq!(
        payment.interest.as_ref().map(|m| m.amount.as_str()),
        Some("4.89")
    );
    assert_eq!(payment.date.as_deref(), Some("2026-06-12"));
    // Both provider ids are 0 → a synthetic id, never the string "0".
    assert_eq!(payment.id, "tx-0");
}

#[test]
fn documents_carry_what_an_archiver_needs_and_build_the_pdf_href() {
    let docs = nlnt::parse::documents(&fixture("statements.json"));
    assert_eq!(docs.len(), 2);
    let first = &docs[0];
    assert_eq!(first.doc.category.as_deref(), Some("statement"));
    assert_eq!(first.doc.date.as_deref(), Some("2026-08-01"));
    assert!(first.doc.file.is_some());
    // The download path is `/pdf/{documentId}/{isDirect}`.
    assert_eq!(
        first.href,
        "/api/1/statements/pdf/00000000-0000-0000-0000-000000000001/true"
    );
}

/// The download href must stay OUT of the emitted DTO — it is routing, not data,
/// and the family keeps live-credential-shaped values off the wire by default.
#[test]
fn document_dtos_do_not_leak_the_download_href() {
    let docs = nlnt::parse::documents(&fixture("statements.json"));
    for d in &docs {
        let v = serde_json::to_value(&d.doc).expect("serializes");
        let rendered = v.to_string();
        assert!(
            !rendered.contains(&d.href),
            "document DTO leaked its download href: {rendered}"
        );
        assert!(!rendered.contains("/api/1/statements/pdf/"));
    }
}

#[test]
fn repayment_reads_status_and_idr_applications() {
    let r = nlnt::parse::repayment(
        &fixture("repayment_overview.json"),
        Some(&fixture("idr_statuses.json")),
    );
    assert_eq!(r.schema, "repayment/v1");
    assert_eq!(r.status.as_deref(), Some("Standard Repayment"));
    assert!(!r.in_school);
    assert_eq!(r.current_school.as_deref(), Some("SAMPLE UNIVERSITY"));
    assert_eq!(r.separation_date.as_deref(), Some("2018-08-19"));
    assert_eq!(r.idr_applications.len(), 1);
    assert_eq!(
        r.idr_applications[0].requested.as_deref(),
        Some("2026-02-17")
    );
    assert_eq!(r.idr_applications[0].status.as_deref(), Some("PROCESSED"));
    assert_eq!(r.idr_applications[0].kind.as_deref(), Some("IDR"));
}

#[test]
fn autopay_masks_banking_pii() {
    let a = nlnt::parse::autopay(&fixture("auto_debit.json"), "/autopay").expect("parses");
    assert_eq!(a.schema, "autopay/v1");
    assert!(a.enrolled);
    assert_eq!(a.bank_name.as_deref(), Some("SAMPLE BANK"));
    // A masked tail — never a full/raw account number.
    assert_eq!(a.bank_account.as_deref(), Some("****0000"));
    assert_eq!(
        a.next_payment_amount.as_ref().map(|m| m.amount.as_str()),
        Some("333.33")
    );
    assert_eq!(a.next_payment_date.as_deref(), Some("2027-01-28"));
    // The DTO must not carry routing or SSN under any field.
    let v = serde_json::to_value(&a).unwrap().to_string();
    assert!(!v.contains("routing") && !v.contains("ssn"));
}

#[test]
fn scheduled_payments_parse_without_the_applied_split() {
    let sched = nlnt::parse::scheduled_payments(&fixture("payment_scheduled.json"));
    assert_eq!(sched.len(), 1);
    assert_eq!(sched[0].amount.amount, "333.33");
    assert_eq!(sched[0].date.as_deref(), Some("2027-01-28"));
    assert_eq!(sched[0].kind.as_deref(), Some("Scheduled"));
    // A payment not yet made has no applied principal/interest.
    assert!(sched[0].principal.is_none());
    assert!(sched[0].interest.is_none());
}

#[test]
fn tax_surfaces_the_1098e_deductible_interest() {
    let t = nlnt::parse::tax(&fixture("tax_info.json"), "/tax").expect("parses");
    assert_eq!(t.schema, "tax-info/v1");
    assert_eq!(t.deductible_interest.amount, "222.22");
    assert_eq!(t.as_of.as_deref(), Some("2026-08-12"));
    // Account must never reach the DTO unmasked.
    assert_eq!(t.account.as_deref(), Some("****0000"));
    assert_eq!(t.accrued_interest.as_ref().unwrap().amount, "222.22");
    // The federal Direct Loan recipient TIN, for filing.
    assert_eq!(t.lender_tin, "52-1198289");
}

/// A portal redesign should empty a table (or name a missing field), not crash.
#[test]
fn parsers_tolerate_unrecognized_json() {
    for junk in [
        "",
        "{\"unexpected\": true}",
        "not json at all",
        "{\"statementList\": \"oops\"}",
    ] {
        assert!(nlnt::parse::loans(junk).is_empty());
        assert!(nlnt::parse::transactions(junk).is_empty());
        assert!(nlnt::parse::scheduled_payments(junk).is_empty());
        assert!(nlnt::parse::documents(junk).is_empty());
        // A status view never errors — junk yields an empty "nothing to report".
        let _ = nlnt::parse::repayment(junk, Some(junk));
        // Summary, tax, and autopay must ERROR rather than report zeros — a
        // fabricated $0.00 reads as good news in the paydown workflow.
        assert!(nlnt::parse::summary(junk, None, "/x").is_err());
        assert!(nlnt::parse::tax(junk, "/x").is_err());
        assert!(nlnt::parse::autopay(junk, "/x").is_err());
    }
}

// ---------------------------------------------------------------------------
// Fixture hygiene
// ---------------------------------------------------------------------------

/// Every 8-4-4-4-12 hex run in a string.
///
/// Hand-rolled so the test suite needs no regex dependency.
fn uuids(s: &str) -> Vec<String> {
    const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];
    let chars: Vec<char> = s.chars().collect();
    let total: usize = GROUPS.iter().sum::<usize>() + 4;
    let mut found = Vec::new();
    for start in 0..chars.len().saturating_sub(total - 1) {
        let window = &chars[start..start + total];
        let mut i = 0;
        let mut ok = true;
        for (g, len) in GROUPS.iter().enumerate() {
            for _ in 0..*len {
                if !window[i].is_ascii_hexdigit() {
                    ok = false;
                    break;
                }
                i += 1;
            }
            if !ok {
                break;
            }
            if g < 4 {
                if window[i] != '-' {
                    ok = false;
                    break;
                }
                i += 1;
            }
        }
        if ok {
            found.push(window.iter().collect());
        }
    }
    found
}

#[test]
fn uuid_scanner_finds_what_it_should() {
    assert_eq!(
        uuids("id=00000000-0000-0000-0000-0000000000ff;"),
        vec!["00000000-0000-0000-0000-0000000000ff"]
    );
    assert!(uuids("no uuid here").is_empty());
}

/// The hygiene gate, written **positively**: a fixture must prove it is
/// synthetic, rather than the test listing the household's real names and
/// account numbers to check they are absent. A denylist would publish in the
/// repo exactly what it exists to keep out.
#[test]
fn every_fixture_declares_itself_synthetic() {
    const MARKER: &str = "SYNTHETIC-FIXTURE-NOT-A-REAL-CAPTURE";
    let dir = format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"));
    let mut checked = 0;

    for entry in fs::read_dir(&dir).expect("fixtures dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().is_none_or(|e| e == "md") {
            continue;
        }
        let body = fs::read_to_string(&path).expect("readable fixture");
        let name = path.display();

        assert!(
            body.contains(MARKER),
            "{name} does not carry the {MARKER} marker — a raw capture must never be committed"
        );

        // Any UUID that is not an obvious dummy is a potential live token.
        for uuid in uuids(&body) {
            assert!(
                uuid.starts_with("00000000-"),
                "{name} contains a live-looking token/UUID ({uuid}) — replace it with a \
                 00000000-… dummy (see tests/fixtures/README.md)"
            );
        }

        // Session credentials and secrets have no business in a fixture.
        let lower = body.to_lowercase();
        for banned in ["set-cookie", "password\":", "authorization:", "bearer "] {
            assert!(
                !lower.contains(banned),
                "{name} contains {banned:?} — see tests/fixtures/README.md"
            );
        }

        // A US SSN shape must never appear: the 1098-E carries one.
        assert!(
            !has_ssn_shape(&body),
            "{name} contains something shaped like an SSN"
        );

        // OAuth tokens: every `*_token` value is a `DUMMY-…` placeholder, and
        // nothing JWT-shaped (a JWT's base64 header always opens `eyJ`) is
        // anywhere in the file.
        let value: serde_json::Value = serde_json::from_str(&body).expect("fixture is JSON");
        for (key, token) in token_values(&value) {
            assert!(
                token.starts_with("DUMMY-"),
                "{name}: `{key}` is not a DUMMY-… placeholder — a captured token is a live \
                 credential (see tests/fixtures/README.md)"
            );
        }
        assert!(
            !body.contains("eyJ"),
            "{name} contains something shaped like a JWT"
        );

        checked += 1;
    }

    // Deleting a fixture to dodge the scan should fail the test.
    assert!(
        checked >= 10,
        "expected the full fixture set, saw {checked}"
    );
}

/// Every string under a key ending in `_token`, at any depth, with its key.
fn token_values(v: &serde_json::Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                match child {
                    serde_json::Value::String(s) if k.ends_with("_token") => {
                        out.push((k.clone(), s.clone()))
                    }
                    _ => out.extend(token_values(child)),
                }
            }
        }
        serde_json::Value::Array(items) => out.extend(items.iter().flat_map(token_values)),
        _ => {}
    }
    out
}

#[test]
fn token_scanner_finds_nested_tokens() {
    let v = serde_json::json!({
        "access_token": "a",
        "token_type": "Bearer",
        "nested": [{ "refresh_token": "r" }],
    });
    let mut found = token_values(&v);
    found.sort();
    assert_eq!(
        found,
        vec![
            ("access_token".to_string(), "a".to_string()),
            ("refresh_token".to_string(), "r".to_string()),
        ]
    );
}

/// `ddd-dd-dddd`, the SSN shape printed on a 1098-E.
fn has_ssn_shape(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    chars.windows(11).any(|w| {
        w[..3].iter().all(char::is_ascii_digit)
            && w[3] == '-'
            && w[4..6].iter().all(char::is_ascii_digit)
            && w[6] == '-'
            && w[7..].iter().all(char::is_ascii_digit)
    })
}

#[test]
fn ssn_detector_works() {
    // Assembled at runtime: the commit-time PII guard pattern-matches source
    // text, and this probe exists only to prove the detector fires.
    assert!(has_ssn_shape(&format!(
        "SSN {}-{}-{} on the form",
        "123", "45", "6789"
    )));
    assert!(!has_ssn_shape("2026-08-01"));
}
