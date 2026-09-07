// Fixture for feature 0087 (CWE-778 as a multi-language observability check).
// VALUE-ERROR family, Rust arm. Work-order step 12.
//
// MARKER CONTRACT
//
// Every candidate site carries a trailing marker:
//
//     // EXPECT: finding   the Rust arm MUST emit a CWE-778 row anchored on this line
//     // EXPECT: clean     the Rust arm MUST NOT emit a row on this line
//     // EXPECT: deferred  outcome deliberately UNSPECIFIED by the 0087 plan;
//                          tests must exclude these lines from BOTH populations
//
// A marker only counts when it TRAILS code on the same line. The three lines
// above are prose inside a doc block and are ignored by the collector, which
// requires non-comment text before the `//`. Unmarked code lines are
// implicitly clean, so the strict assertion is
//
//     reported == {finding}  (plus, optionally, any subset of {deferred})
//
// which catches a spurious row on scaffolding as well as a missed one.
//
// MARKERS CARRY NO PROSE, ON PURPOSE. The detector is line-based and reads the
// site line verbatim. A marker that explained itself inline would put the
// words `log`, `err`, `return` and `panic` inside the very text the excusal
// patterns are matched against, and the fixture would then be testing its own
// comments. The reason for every line is in EXPECTATIONS_VALUE.md, keyed by
// line number.
//
// This file is read as TEXT by the detector; it is never compiled. There is no
// Cargo.toml here and the third-party crates are not vendored. It is kept
// rustfmt-shaped so that line positions do not drift under an editor.
//
// Two properties are deliberate and load-bearing:
//
//   1. No authentication or authorization decision keyword appears anywhere in
//      this file, in code or in prose. Any row reported on this file is
//      therefore attributable to the Rust value-error arm and never to the
//      `auth_decision` arm, and a count on this file is unambiguous.
//   2. No exception-family keyword appears anywhere either -- no token that the
//      brace/`catch` shape could match -- so that family cannot claim a row
//      here either. `.rs` IS inside the widened extension gate
//      (plan B7 / step 9), so the file IS scanned; everything it yields comes
//      from the Rust arm.
//
// WHY THE PANIC AND PROPAGATION CASES CARRY THE MOST WEIGHT
//
// Plan D-drop-2 is the whole risk of this arm. `?` is Rust's propagation
// operator, and enumerating it as a handler site makes almost every line of a
// fallible function an "error-handling site that does not log", which drives
// any Rust repository's D1a score to zero and buries the three real shapes in
// noise. `.unwrap()` and `.expect()` both panic, which is CWE-248, and they
// are additionally undecidable line-locally between `Result` and `Option` --
// `iter.next().unwrap()` is an `Option`, and no line-local rule can tell it
// apart from `parse().unwrap()`. Acceptance criterion 7 gates all three.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_TIMEOUT_SECONDS: u64 = 30;
const MAX_SWEEP_BATCH: usize = 512;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("record {0} not found")]
    NotFound(String),
    #[error("io failure: {0}")]
    Io(#[from] io::Error),
    #[error("decode failure: {0}")]
    Decode(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub payload: Vec<u8>,
    pub updated_at: u64,
}

pub struct Store {
    root: PathBuf,
    cache: HashMap<String, Record>,
    stale: usize,
    last_failure: Option<String>,
}

// ---------------------------------------------------------------------------
// PROPAGATION -- the `?` operator. Plan D-drop-2: `?` IS the propagation
// operator, the direct analogue of Go's `return err`, and the single largest
// false-positive risk in this arm. The caller still receives the error, so no
// evidence is destroyed here and CWE-778 does not apply. Acceptance criterion
// 7 names `?` explicitly.
// ---------------------------------------------------------------------------

impl Store {
    /// Reads one record off disk by id.
    pub fn load(&self, id: &str) -> Result<Record> {
        let path = self.root.join(format!("{id}.json"));
        let raw = fs::read(&path)?; // EXPECT: clean
        let rec: Record = serde_json::from_slice(&raw)?; // EXPECT: clean
        Ok(rec)
    }

    /// Writes one record through, creating the parent directory if needed.
    pub fn save(&self, rec: &Record) -> Result<()> {
        fs::create_dir_all(&self.root)?; // EXPECT: clean
        let encoded = serde_json::to_vec(rec)?; // EXPECT: clean
        let path = self.root.join(format!("{}.json", rec.id));
        let mut file = File::create(&path)?; // EXPECT: clean
        file.write_all(&encoded)?; // EXPECT: clean
        Ok(())
    }

    /// Renames a record, converting the io error into the crate error first.
    pub fn rename(&self, from: &str, to: &str) -> Result<()> {
        let src = self.root.join(format!("{from}.json"));
        let dst = self.root.join(format!("{to}.json"));
        fs::rename(&src, &dst).map_err(StoreError::Io)?; // EXPECT: clean
        Ok(())
    }

    /// Returns the record or an explicit error value.
    pub fn require(&self, id: &str) -> Result<&Record> {
        match self.cache.get(id) {
            Some(rec) => Ok(rec),
            None => Err(StoreError::NotFound(id.to_string())), // EXPECT: clean
        }
    }
}

// ---------------------------------------------------------------------------
// RECORDED -- the handler emits a diagnostic record. Not a defect. One case
// per facility the Rust D3 set must cover.
//
// NOTE FOR THE IMPLEMENTER. The shipped `_LOG_CALL` alternation carries
// `\btracing::` but its Rust-relevant `log` branch is `\blog\.` -- a DOT.
// Rust spells it `log::error!` with a PATH separator and a bang, so
// `log::error!` does NOT match the shipped alternation. Per plan §3.3 the
// Rust D3 set is added by UNION; the `log::` and `tracing::` cases below are
// the gated statement of that requirement, not decoration.
// ---------------------------------------------------------------------------

impl Store {
    /// Warms the cache and records every failure through the `log` facade.
    pub fn warm(&mut self, ids: &[String]) {
        for id in ids {
            if let Err(e) = self.load(id) { // EXPECT: clean
                log::error!("warm: load {id} failed: {e}");
            }
        }
    }

    /// Compacts the store, reporting a partial failure through `tracing`.
    pub fn compact(&mut self) {
        match fs::read_dir(&self.root) {
            Ok(entries) => self.stale = entries.count(),
            Err(e) => { // EXPECT: clean
                tracing::error!(error = %e, "compact: directory unreadable");
            }
        }
    }

    /// Single-line handler: the whole body sits on the header line.
    ///
    /// Defect B1 (`_handler_is_excused` hands the body-only slice to the
    /// body-record test) makes exactly this shape a false positive, and
    /// one-line handlers are the Rust norm. Gated regression guard.
    pub fn touch(&self, id: &str) {
        let path = self.root.join(format!("{id}.json"));
        if let Err(e) = fs::write(&path, b"") { log::warn!("touch {id}: {e}"); } // EXPECT: clean
    }

    /// Reports a failure through a delegate rather than logging inline.
    pub fn refresh_all(&mut self, ids: &[String]) {
        for id in ids {
            if let Err(e) = self.load(id) { // EXPECT: clean
                self.report_error(&e);
            }
        }
    }

    fn report_error(&self, e: &StoreError) {
        log::error!("store failure: {e}");
    }
}

// ---------------------------------------------------------------------------
// SWALLOW -- `if let Err(..)` whose body neither records nor forwards. This is
// the Rust analogue of Go's three swallow classes and is the arm's core.
// ---------------------------------------------------------------------------

impl Store {
    /// Deletes a record and ignores whether the delete worked.
    pub fn delete(&self, id: &str) {
        let path = self.root.join(format!("{id}.json"));
        if let Err(e) = fs::remove_file(&path) { // EXPECT: finding
        }
    }

    /// Drops every cached entry, ignoring a failed on-disk eviction.
    pub fn evict(&mut self, ids: &[String]) {
        for id in ids {
            if let Err(_e) = fs::remove_file(self.root.join(format!("{id}.json"))) { // EXPECT: finding
                self.stale += 1;
            }
            self.cache.remove(id);
        }
    }

    /// Stores the failure text on a struct field.
    ///
    /// COLLISION GUARD. `e.to_string()` is Rust's `Display` conversion, the
    /// direct analogue of Go's `err.Error()`. A D3 set that matched a bare
    /// `to_string` or a bare `.error` substring would excuse this line, and it
    /// must not: a string on a struct field is not a diagnostic record, and
    /// nothing is forwarded either.
    pub fn probe(&mut self, id: &str) {
        if let Err(e) = self.load(id) { // EXPECT: finding
            self.last_failure = Some(e.to_string());
        }
    }
}

/// Resolves the configured timeout, falling back to the default.
///
/// The Rust analogue of Go swallow class 3: a malformed setting becomes
/// indistinguishable from an absent one.
pub fn request_timeout(raw: &str) -> Duration {
    let seconds = match raw.parse::<u64>() {
        Ok(v) => v,
        Err(e) => DEFAULT_TIMEOUT_SECONDS, // EXPECT: finding
    };
    Duration::from_secs(seconds)
}

// ---------------------------------------------------------------------------
// MATCH ARMS -- `match .. { Err(e) => .. }`. The plan lists this as its own
// site shape alongside `if let Err`, because a match arm carries a body the
// `if let` shape does not reach.
// ---------------------------------------------------------------------------

/// Reads the sweep manifest, returning an empty batch when it cannot be read.
pub fn read_manifest(path: &Path) -> Vec<String> {
    match fs::read_to_string(path) {
        Ok(text) => text.lines().take(MAX_SWEEP_BATCH).map(str::to_owned).collect(),
        Err(e) => Vec::new(), // EXPECT: finding
    }
}

/// Counts the lines in one file.
pub fn count_lines(path: &Path) -> usize {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return 0, // EXPECT: finding
    };
    BufReader::new(file).lines().count()
}

/// Applies the unit-arm form the plan calls out by name.
pub fn note_stale(path: &Path) {
    match fs::metadata(path) {
        Ok(_) => {}
        Err(e) => (), // EXPECT: finding
    }
}

/// Emits every record and keeps going past a bad one.
pub fn emit_all(recs: &[Record], out: &mut impl Write) -> usize {
    let mut written = 0usize;
    for rec in recs {
        match serde_json::to_vec(rec) {
            Ok(bytes) => {
                match out.write_all(&bytes) {
                    Ok(()) => written += 1,
                    Err(e) => continue, // EXPECT: finding
                }
            }
            Err(e) => { // EXPECT: clean
                log::warn!("emit: encode {} failed: {e}", rec.id);
                continue;
            }
        }
    }
    written
}

// ---------------------------------------------------------------------------
// STATEMENT-POSITION `.ok()` -- the third shape in the plan's Rust site set.
//
// `Result::ok()` converts `Result<T, E>` into `Option<T>` and DISCARDS `E`. In
// statement position -- terminated by `;`, result unbound -- the whole
// expression exists only to throw the error away, which is exactly the
// weakness. In EXPRESSION position (`let x = f().ok();`, `f().ok()?`,
// `if f().ok().is_some()`) the `Option` is used, so the value is not
// discarded and it is not a site. The distinction is the `;` with no binding.
// ---------------------------------------------------------------------------

/// Flushes the writer and moves on regardless.
pub fn flush_quietly(out: &mut impl Write) {
    out.flush().ok(); // EXPECT: finding
}

/// Best-effort removal of a scratch directory.
pub fn cleanup_scratch(root: &Path) {
    fs::remove_dir_all(root.join("scratch")).ok(); // EXPECT: finding
}

/// Reads an optional sidecar, using the `Option` the conversion produces.
pub fn sidecar(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path.with_extension("meta")).ok(); // EXPECT: clean
    text
}

/// Reports whether the sidecar is present.
pub fn has_sidecar(path: &Path) -> bool {
    fs::metadata(path.with_extension("meta")).ok().is_some() // EXPECT: clean
}

// ---------------------------------------------------------------------------
// PANIC -- `.unwrap()` and `.expect()`. Plan D-drop-2 and acceptance criterion
// 7: both panic, which is CWE-248, a different weakness, and the process stops
// so the failure cannot go unnoticed. Criterion 7 requires a fixture case for
// each. The LLD guarded only `.unwrap()`; `.expect()` is the identical class
// and is gated here too.
// ---------------------------------------------------------------------------

/// Loads the embedded schema at start-up.
pub fn load_schema(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap() // EXPECT: clean
}

/// Resolves the data root, refusing to start without it.
pub fn data_root() -> PathBuf {
    let raw = std::env::var("STORE_ROOT").expect("STORE_ROOT must be set"); // EXPECT: clean
    PathBuf::from(raw)
}

/// Timestamps a record.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch") // EXPECT: clean
        .as_secs()
}

// ---------------------------------------------------------------------------
// OPTION, NOT RESULT -- the stronger half of the D-drop-2 argument. These
// `.unwrap()`/`.expect()` calls are on `Option`, where there is no error value
// in existence to record. No line-local rule can tell them from the `Result`
// spellings above, which is why the arm excludes the shape outright rather
// than trying to classify it.
// ---------------------------------------------------------------------------

/// Returns the first id in the batch.
pub fn first_id(ids: &[String]) -> String {
    let mut iter = ids.iter();
    iter.next().unwrap().clone() // EXPECT: clean
}

/// Returns the stem of a record path.
pub fn record_stem(path: &Path) -> String {
    path.file_stem().expect("record path has a stem").to_string_lossy().into_owned() // EXPECT: clean
}

/// Looks up a cached record by id.
pub fn cached<'a>(cache: &'a HashMap<String, Record>, id: &str) -> Option<&'a Record> {
    cache.get(id) // EXPECT: clean
}

// ---------------------------------------------------------------------------
// OUT OF SCOPE -- undecidable line-locally between `Result` and `Option`, and
// named in plan §9 as things this skill will NOT detect. They must not be
// reported: a row here is a regression against the stated scope.
// ---------------------------------------------------------------------------

/// Best-effort telemetry flush during shutdown.
pub fn shutdown(out: &mut impl Write) {
    let _ = out.flush(); // EXPECT: clean
}

/// Reads the retry budget, defaulting when absent or malformed.
pub fn retry_budget(raw: &str) -> u32 {
    raw.parse::<u32>().unwrap_or_default() // EXPECT: clean
}

/// Reads the batch size with an explicit default.
pub fn batch_size(raw: &str) -> usize {
    raw.parse::<usize>().unwrap_or(MAX_SWEEP_BATCH) // EXPECT: clean
}

// ---------------------------------------------------------------------------
// SCOPE TEST -- plan §3.5. `collect_handler_body` returns the next five
// non-blank lines within ten raw lines and tracks neither brace depth nor
// indentation, so the facility call in the SUCCESSOR function lands inside
// `quarantine`'s collected "body" and silently excuses it. Counting from the
// header: the `self.stale` line, `}`, `}`, the `pub fn` line, then the
// `log::info!` call -- the fifth non-blank line. `collect_scoped_body` must
// stop at the closing brace of the `if let`, which is why `quarantine` is a
// finding.
//
// Do not insert a comment or a blank-separated declaration between these two
// functions: it changes which line is fifth and neuters the test.
// ---------------------------------------------------------------------------

impl Store {
    pub fn quarantine(&mut self, id: &str) {
        if let Err(e) = fs::rename(self.root.join(id), self.root.join("quarantine").join(id)) { // EXPECT: finding
            self.stale += 1;
        }
    }

    pub fn sweep_report(&self) {
        log::info!("sweep complete: stale={} last={:?}", self.stale, self.last_failure);
    }
}
