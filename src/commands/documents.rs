//! `nlnt documents list|download` — the `documents/v1` profile
//! (`pk-cli-documents`), which is what makes the yearly 1098-E a one-liner.
//!
//! Adopting the shared profile rather than inventing a fifth spelling is
//! deliberate: the `organize-scans` archiver carries a per-CLI adapter table
//! precisely because every CLI grew its own `bills download` / `statements` /
//! `bill --save`. One `documents list --json` plus one
//! `documents download <id> -o <path>` collapses that.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use pk_cli_core::{output, CliError, Paged, RangeArgs};
use pk_cli_documents::{Document, DownloadBatch, SavedDocument};

use crate::client::{paths, Portal};
use crate::commands::{filter_range, items, note_empty, table_view, Ctx};
use crate::parse::{self, DocumentRef};

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List published documents, newest first (document-list/v1).
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Download a document — one by id, or every one with --all
    /// (document-download/v1, document-download-batch/v1).
    #[command(visible_alias = "get")]
    Download(DownloadArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[command(flatten)]
    pub range: RangeArgs,
    /// Only tax documents (the 1098-E and friends).
    #[arg(long)]
    pub tax: bool,
    /// Only documents for this tax year, e.g. `--tax-year 2025`.
    #[arg(long, value_name = "YYYY")]
    pub tax_year: Option<u32>,
}

#[derive(Args, Debug)]
pub struct DownloadArgs {
    /// A document id from `documents list`. Omit and pass --all for every one.
    pub id: Option<String>,
    /// Download every listed document (filter with --since/--until/--limit).
    #[arg(long, conflicts_with = "id")]
    pub all: bool,
    /// Output target: a file path or `-` for stdout (single id), or a directory
    /// (with --all). Defaults to the portal's filename in the current dir.
    #[arg(short, long)]
    pub output: Option<String>,
    #[command(flatten)]
    pub range: RangeArgs,
}

pub fn run(ctx: &Ctx, cmd: &Cmd) -> Result<(), CliError> {
    match cmd {
        Cmd::List(args) => list(ctx, args),
        Cmd::Download(args) => download(ctx, args),
    }
}

fn list(ctx: &Ctx, args: &ListArgs) -> Result<(), CliError> {
    // Validate before any keychain or network access.
    args.range.validate()?;
    if let Some(year) = args.tax_year {
        if !(1998..=2100).contains(&year) {
            return Err(CliError::Usage(format!(
                "--tax-year {year} is not a plausible year"
            )));
        }
    }

    let refs = ctx.read(fetch_index)?;
    let docs = select(refs, args);

    if docs.is_empty() {
        note_empty(ctx, "documents");
    }
    let page = Paged::new(
        "document",
        docs.into_iter().map(|r| r.doc).collect::<Vec<_>>(),
    );
    if ctx.common.json {
        page.emit(true);
    } else {
        let v = serde_json::to_value(&page)
            .map_err(|e| CliError::Other(format!("could not serialize documents: {e}")))?;
        output::table(&table_view(
            &items(&v, "items"),
            &["id", "date", "category", "name", "file"],
        ));
    }
    Ok(())
}

fn fetch_index(portal: &Portal) -> Result<Vec<DocumentRef>, CliError> {
    let body = portal.get_text(paths::STATEMENTS)?;
    Ok(parse::documents(&body))
}

/// Apply the list filters. Pure, so the tax-year logic is unit-testable.
fn select(refs: Vec<DocumentRef>, args: &ListArgs) -> Vec<DocumentRef> {
    let mut refs: Vec<DocumentRef> = refs
        .into_iter()
        .filter(|r| !args.tax || parse::is_1098e(&r.doc))
        .filter(|r| match args.tax_year {
            // A 1098-E for tax year N is published in early N+1, so its
            // publication date is the WRONG year to filter on. When the title
            // names a year, that year is authoritative and the date is not
            // consulted at all — otherwise "2024 Form 1098-E" dated 2025-01-31
            // would answer a request for tax year 2025.
            Some(year) => match title_year(&r.doc.name) {
                Some(named) => named == year,
                None => r
                    .doc
                    .date
                    .as_deref()
                    .is_some_and(|d| d.starts_with(&year.to_string())),
            },
            None => true,
        })
        .collect();

    // Newest first; undated records sort last.
    parse::sort_newest_first(&mut refs, |r| r.doc.date.clone());
    filter_range(refs, &args.range, |r| r.doc.date.clone())
}

/// Why a document cannot be downloaded as a file, if it cannot.
///
/// The 1098-E is the case that matters. CONFIRMED from the platform's JS: the
/// portal publishes **no 1098-E PDF**. Its SPA fills an HTML template
/// client-side from `/api/1/tax/account-tax-info` and calls `window.print()` —
/// so there is no file to fetch, and never was.
///
/// Without this check the user would get "downloaded file is not a PDF", which
/// is true but sounds like a bug and sends them looking for one. Saying what is
/// actually going on, and where the data really lives, is the honest answer.
pub fn undownloadable(doc: &Document) -> Option<String> {
    if parse::is_1098e(doc) {
        return Some(format!(
            "`{}` has no PDF to download. Nelnet does not publish the 1098-E as a file — \
             the portal renders it in the browser from {} and prints it. Run `nlnt tax` to \
             get the deductible-interest figure as data. The January statement carries the \
             same interest total and IS a real PDF.",
            doc.name,
            crate::client::paths::TAX_INFO
        ));
    }
    None
}

/// The four-digit year named in a document title, if any.
///
/// Scans for a plausible year rather than any four digits, so an account number
/// or a form number ("1098") in the title is not mistaken for one.
fn title_year(name: &str) -> Option<u32> {
    let chars: Vec<char> = name.chars().collect();
    for window in chars.windows(4) {
        if window.iter().all(|c| c.is_ascii_digit()) {
            let year: u32 = window.iter().collect::<String>().parse().ok()?;
            if (1998..=2100).contains(&year) {
                return Some(year);
            }
        }
    }
    None
}

/// Why a download cannot proceed, if it cannot.
///
/// Pure and checked **before** any keychain or network access, so a malformed
/// invocation never prompts for a credential or spends a request.
pub fn download_blocked(
    json: bool,
    all: bool,
    id: Option<&str>,
    output: Option<&str>,
) -> Option<String> {
    if id.is_none() && !all {
        return Some("give a document id (from `nlnt documents list`) or pass --all".into());
    }
    if all && output.map(|o| o == "-").unwrap_or(false) {
        return Some("--all writes multiple files, so -o - (stdout) is not possible".into());
    }
    if json && output.map(|o| o == "-").unwrap_or(false) {
        return Some(
            "--json and -o - both write to stdout; choose one (write the file to a path, \
             or drop --json)"
                .into(),
        );
    }
    None
}

fn download(ctx: &Ctx, args: &DownloadArgs) -> Result<(), CliError> {
    args.range.validate()?;
    if let Some(reason) = download_blocked(
        ctx.common.json,
        args.all,
        args.id.as_deref(),
        args.output.as_deref(),
    ) {
        return Err(CliError::Usage(reason));
    }

    if args.all {
        // List and fetch inside ONE `read` closure, so a session that lapses
        // mid-batch replays from the top rather than leaving a half-written
        // directory behind.
        let dir = args.output.clone().unwrap_or_else(|| ".".to_string());
        let range = args.range.clone();
        let batch = ctx.read(move |portal| {
            let refs = fetch_index(portal)?;
            let refs = filter_range(refs, &range, |r| r.doc.date.clone());
            std::fs::create_dir_all(&dir)
                .map_err(|e| CliError::Other(format!("could not create {dir}: {e}")))?;
            let mut used: Vec<String> = Vec::new();
            let mut saved: Vec<SavedDocument> = Vec::new();
            for r in &refs {
                // Skip rather than abort: one printable-only 1098-E must not
                // fail a batch that is otherwise fetching real statement PDFs.
                if undownloadable(&r.doc).is_some() {
                    continue;
                }
                let bytes = portal.get_pdf(&r.href)?;
                let name = disambiguate(&preferred_name(&r.doc), &r.doc.id, &mut used);
                let path = Path::new(&dir).join(&name);
                write_bytes(&path, &bytes)?;
                saved.push(SavedDocument::from_document(
                    &r.doc,
                    path.to_string_lossy().to_string(),
                    bytes.len() as u64,
                ));
            }
            Ok(DownloadBatch::new(dir.clone(), saved))
        })?;

        if batch.count == 0 {
            note_empty(ctx, "documents");
        }
        let v = serde_json::to_value(&batch)
            .map_err(|e| CliError::Other(format!("could not serialize batch: {e}")))?;
        if ctx.common.json {
            output::json(&v);
        } else {
            for item in &batch.items {
                println!("{}", item.path);
            }
        }
        return Ok(());
    }

    let id = args.id.clone().expect("checked by download_blocked");
    let want_stdout = args.output.as_deref() == Some("-");
    let out = args.output.clone();

    let (doc, bytes) = ctx.read(move |portal| {
        let refs = fetch_index(portal)?;
        let r = refs
            .into_iter()
            .find(|r| r.doc.id == id)
            .ok_or_else(|| CliError::NotFound(format!("no document with id `{id}`")))?;
        if let Some(reason) = undownloadable(&r.doc) {
            return Err(CliError::NotFound(reason));
        }
        let bytes = portal.get_pdf(&r.href)?;
        Ok((r.doc, bytes))
    })?;

    if want_stdout {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| CliError::Other(format!("could not write to stdout: {e}")))?;
        return Ok(());
    }

    let path = resolve_path(out.as_deref(), &doc);
    write_bytes(&path, &bytes)?;

    let saved =
        SavedDocument::from_document(&doc, path.to_string_lossy().to_string(), bytes.len() as u64);
    let v = serde_json::to_value(&saved)
        .map_err(|e| CliError::Other(format!("could not serialize result: {e}")))?;
    if ctx.common.json {
        output::json(&v);
    } else {
        output::render(&v);
    }
    Ok(())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::Other(format!("could not create {}: {e}", parent.display()))
            })?;
        }
    }
    std::fs::write(path, bytes)
        .map_err(|e| CliError::Other(format!("could not write {}: {e}", path.display())))
}

/// Where a single download lands: an explicit path, an explicit directory, or
/// the portal's own filename in the current directory.
fn resolve_path(output: Option<&str>, doc: &Document) -> PathBuf {
    match output {
        Some(o) if Path::new(o).is_dir() => Path::new(o).join(preferred_name(doc)),
        Some(o) => PathBuf::from(o),
        None => PathBuf::from(preferred_name(doc)),
    }
}

/// The filename to save under: the portal's own, else a slug of the title.
fn preferred_name(doc: &Document) -> String {
    if let Some(file) = &doc.file {
        if !file.trim().is_empty() {
            return sanitize(file);
        }
    }
    let stem = sanitize(&doc.name);
    let stem = stem.trim_matches('-').to_string();
    let stem = if stem.is_empty() {
        format!("document-{}", sanitize(&doc.id))
    } else {
        stem
    };
    if stem.to_ascii_lowercase().ends_with(".pdf") {
        stem
    } else {
        format!("{stem}.pdf")
    }
}

/// Keep filenames to characters that are safe on every filesystem, and refuse
/// to let a provider-supplied name escape the output directory.
fn sanitize(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // `..` in a provider-supplied filename is a path-traversal attempt.
    cleaned.replace("..", "-")
}

/// Avoid clobbering a file already written in this batch.
fn disambiguate(preferred: &str, id: &str, used: &mut Vec<String>) -> String {
    let candidate = preferred.to_string();
    if !used.contains(&candidate) {
        used.push(candidate.clone());
        return candidate;
    }
    let (stem, ext) = match candidate.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{e}")),
        None => (candidate.clone(), String::new()),
    };
    for n in 2..=1024 {
        let next = format!("{stem}_{n}{ext}");
        if !used.contains(&next) {
            used.push(next.clone());
            return next;
        }
    }
    let fallback = format!("{stem}_{}{ext}", sanitize(id));
    used.push(fallback.clone());
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(tax: bool, tax_year: Option<u32>) -> ListArgs {
        ListArgs {
            range: RangeArgs::default(),
            tax,
            tax_year,
        }
    }

    fn doc_ref(id: &str, name: &str, date: Option<&str>) -> DocumentRef {
        let mut d = Document::new(id, name);
        d.date = date.map(|s| s.to_string());
        d.category = parse::classify(name).map(str::to_string);
        DocumentRef {
            doc: d,
            href: format!("/doc/{id}"),
        }
    }

    #[test]
    fn download_needs_an_id_or_all() {
        assert!(download_blocked(false, false, None, None)
            .unwrap()
            .contains("--all"));
        assert!(download_blocked(false, true, None, None).is_none());
        assert!(download_blocked(false, false, Some("1"), None).is_none());
    }

    #[test]
    fn all_cannot_write_to_stdout() {
        assert!(download_blocked(false, true, None, Some("-"))
            .unwrap()
            .contains("stdout"));
    }

    #[test]
    fn json_and_stdout_both_claim_stdout() {
        assert!(download_blocked(true, false, Some("1"), Some("-"))
            .unwrap()
            .contains("both write to stdout"));
    }

    /// A 1098-E for tax year N is published in early N+1, so a naive date
    /// filter returns the wrong form. The title must win.
    #[test]
    fn tax_year_matches_the_title_not_the_publication_date() {
        let refs = vec![
            doc_ref("a", "2025 Form 1098-E", Some("2026-01-31")),
            doc_ref("b", "2024 Form 1098-E", Some("2025-01-31")),
        ];
        let picked = select(refs, &args(true, Some(2025)));
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].doc.id, "a");
    }

    /// The portal publishes no 1098-E file, so asking for one must explain
    /// that rather than reporting a broken download.
    #[test]
    fn the_1098e_reports_that_no_pdf_exists() {
        let mut d = Document::new("t1", "2025 Form 1098-E");
        d.category = Some("tax".into());
        let msg = undownloadable(&d).expect("must be refused");
        assert!(msg.contains("no PDF"));
        assert!(msg.contains("account-tax-info"));
        // It must point somewhere useful, not just say no.
        assert!(msg.contains("statement"));
    }

    #[test]
    fn ordinary_statements_are_still_downloadable() {
        let mut d = Document::new("s1", "June 2026 Statement");
        d.category = Some("statement".into());
        assert!(undownloadable(&d).is_none());
    }

    #[test]
    fn title_year_ignores_the_form_number() {
        // "1098" is not a year; "2025" is.
        assert_eq!(title_year("2025 Form 1098-E"), Some(2025));
        assert_eq!(title_year("Form 1098-E"), None);
        assert_eq!(title_year("June Statement"), None);
    }

    /// When the title names no year, fall back to the publication date.
    #[test]
    fn undated_titles_fall_back_to_the_document_date() {
        let refs = vec![doc_ref("a", "Tax Statement", Some("2025-01-31"))];
        assert_eq!(select(refs.clone(), &args(false, Some(2025))).len(), 1);
        assert_eq!(select(refs, &args(false, Some(2024))).len(), 0);
    }

    #[test]
    fn tax_filter_keeps_only_tax_documents() {
        let refs = vec![
            doc_ref("a", "2025 Form 1098-E", Some("2026-01-31")),
            doc_ref("b", "June 2026 Statement", Some("2026-06-15")),
        ];
        assert_eq!(select(refs.clone(), &args(true, None)).len(), 1);
        assert_eq!(select(refs, &args(false, None)).len(), 2);
    }

    #[test]
    fn listing_is_newest_first() {
        let refs = vec![
            doc_ref("old", "A", Some("2024-01-01")),
            doc_ref("new", "B", Some("2026-01-01")),
        ];
        let sorted = select(refs, &args(false, None));
        assert_eq!(sorted[0].doc.id, "new");
    }

    #[test]
    fn filenames_are_sanitized_and_cannot_traverse() {
        let mut d = Document::new("1", "x");
        d.file = Some("../../etc/passwd".into());
        let name = preferred_name(&d);
        assert!(!name.contains(".."));
        assert!(!name.contains('/'));
    }

    #[test]
    fn a_titled_document_gets_a_pdf_extension() {
        let d = Document::new("1", "2025 Form 1098-E");
        assert_eq!(preferred_name(&d), "2025-Form-1098-E.pdf");
    }

    #[test]
    fn colliding_names_are_disambiguated() {
        let mut used = Vec::new();
        assert_eq!(disambiguate("a.pdf", "1", &mut used), "a.pdf");
        assert_eq!(disambiguate("a.pdf", "2", &mut used), "a_2.pdf");
        assert_eq!(disambiguate("a.pdf", "3", &mut used), "a_3.pdf");
    }

    #[test]
    fn explicit_output_path_is_honored() {
        let d = Document::new("1", "2025 Form 1098-E");
        assert_eq!(
            resolve_path(Some("/tmp/mine.pdf"), &d),
            PathBuf::from("/tmp/mine.pdf")
        );
    }
}
