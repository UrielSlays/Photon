//! The store-open contract: raw-header preflight, atomic bootstrap, and the per-connection
//! durability and foreign-key checks.

use std::path::{Path, PathBuf};

/// Photon's registered SQLite `application_id`: ASCII `PHTN`, big-endian at header offset 68.
/// Every build recognizes this one value; changing it is a schema-version-class decision,
/// never a build choice.
pub const APPLICATION_ID: u32 = 0x5048_544E;

/// The u32 view of the crate's `SCHEMA_VERSION` (`lib.rs`); the raw header and the PRAGMA reads
/// compare in u32. No literal version number appears in this module's logic, so a version bump
/// changes exactly one constant.
const CURRENT_VERSION: u32 = crate::SCHEMA_VERSION as u32;

/// The oldest on-disk schema version this binary will admit and upgrade in place. Below it the
/// pre-v8 refusal stands (`refuse_pre_v8`): those stores were minted before the pre-state
/// substrate existed, carry no ownership id and no admission binding, and have no honest
/// backfill. From v8 forward the store is migratable: the open chokepoint brings its schema up
/// to this build's shape inside the same write transaction that stamps the new version, and a
/// legacy population the new constraints cannot accept refuses explicitly instead of being
/// reshaped behind the operator's back (see `refuse_duplicate_placement_identity`).
const MIN_UPGRADABLE_VERSION: u32 = 8;

const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
const OFF_USER_VERSION: usize = 60;
const OFF_APPLICATION_ID: usize = 68;

/// The preflight decision, computed from the raw file family with no connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Preflight {
    /// Absent or zero-length main, no sidecars: atomic bootstrap.
    FreshBootstrap,
    /// Sidecar-free, owned, header reads a version in the supported band
    /// (`MIN_UPGRADABLE_VERSION..=CURRENT_VERSION`): open and verify, upgrading in place if it
    /// is below current.
    OpenVerifiedSupported,
    /// Owned or legacy-candidate main with a -wal/-journal sidecar: the header may be stale in
    /// either direction, and only SQLite's own crash protocol can answer.
    RecoveryProbe,
}

fn refusal(msg: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(msg),
    )
}

pub(crate) fn refuse_pre_v8(version: u32) -> rusqlite::Error {
    refusal(format!(
        "this database is a pre-v8 store (schema version {version}); a v8 binary refuses to \
         open or migrate it (design #24 §7a Option A). reset: delete the store file family \
         (<db>, <db>-wal, <db>-shm, <db>-journal) or export/re-drill from the provider"
    ))
}

fn sidecar_paths(main: &Path) -> [PathBuf; 3] {
    let s = main.as_os_str().to_os_string();
    let mk = |ext: &str| {
        let mut o = s.clone();
        o.push(ext);
        PathBuf::from(o)
    };
    [mk("-wal"), mk("-shm"), mk("-journal")]
}

/// A sidecar name is occupied or it is not, decided by lstat and failing closed.
/// `Path::exists()` follows symlinks (a dangling `-wal` symlink read as "absent" and a fresh
/// store was installed beside it) and maps every lookup error to `false`. Only NotFound means
/// absent; a dangling symlink still occupies the name; anything unclassifiable refuses.
fn sidecar_present(p: &Path) -> Result<bool, rusqlite::Error> {
    match std::fs::symlink_metadata(p) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(refusal(format!(
            "cannot classify sidecar {}: {e} — failing closed; an unreadable family \
             member must never be treated as absent",
            p.display()
        ))),
    }
}

/// The sidecars that carry persistent journal state: -wal and -journal. They supersede the main
/// header (the raw-header read applies only with no -wal and no -journal) and they damage a
/// fresh install (their frames would be replayed over it). `-shm` is deliberately not in this
/// set: per sqlite.org/tempfiles.html §2.3 the shared-memory file "contains no persistent
/// content" and is "recreated from scratch" during WAL recovery, so a lone orphan -shm cannot
/// resurrect refused state, and treating it as damaging would brick first run.
fn persistent_sidecar(main: &Path) -> Result<bool, rusqlite::Error> {
    let [wal, _shm, journal] = sidecar_paths(main);
    Ok(sidecar_present(&wal)? || sidecar_present(&journal)?)
}

/// At fresh bootstrap the `-shm` name must be unoccupied, whatever its type. A lone -shm
/// carries no persistent content, but treating the name as disposable would let bootstrap
/// install a main whose WAL open then overwrites whatever sits at `<db>-shm` (an unrelated
/// user file from a mistaken store path), or fail on a non-regular node. An installed store
/// owns its family namespace; an absent store owns nothing, and this module's standing rule
/// (no file we did not mint is ever adopted, overwritten, or unlinked) wins over the
/// convenience. Ownership of stray -shm bytes cannot be established from content (the
/// WAL-index has no durable magic), so occupancy is the whole test.
fn refuse_occupied_shm_name(main: &Path) -> Result<(), rusqlite::Error> {
    let [_wal, shm, _journal] = sidecar_paths(main);
    if sidecar_present(&shm)? {
        return Err(refusal(format!(
            "{} is occupied beside an absent or empty store — refusing to bootstrap \
             into an occupied family namespace (the WAL open would overwrite it); \
             remove it, or reset the whole file family (<db>, -wal, -shm, -journal)",
            shm.display()
        )));
    }
    Ok(())
}

/// What occupies the store path, as a classification that fails closed. Treating
/// PermissionDenied and every other I/O error as "absent, so fresh bootstrap", and testing
/// length but never type, would classify a directory (length 0 on Windows), FIFO, socket or
/// device node at the store path as a bootstrappable destination, and bootstrap would
/// `remove_file` it (unlink succeeds on unix specials). Only NotFound may mean absent; only a
/// regular file may be zero-length-fresh; a symlink is seen as itself (lstat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorePathState {
    /// The name is unoccupied (confirmed NotFound, nothing else).
    Absent,
    /// A zero-length regular file: SQLite never committed a page.
    EmptyRegular,
    /// A non-empty regular file: a candidate store — the header decides.
    Populated,
}

fn classify_store_path(main: &Path) -> Result<StorePathState, rusqlite::Error> {
    match std::fs::symlink_metadata(main) {
        Ok(m) if m.file_type().is_symlink() => Err(refusal(format!(
            "{} is a symbolic link — refused: multiple names for one database file \
             split its -wal/-journal family (sqlite.org howtocorrupt §multiple-links); \
             open the real path",
            main.display()
        ))),
        Ok(m) if !m.is_file() => Err(refusal(format!(
            "{} exists but is not a regular file — refused; a Photon store is a regular \
             file, and a non-regular node (directory, FIFO, socket, device) at the store \
             path is never unlinked or replaced",
            main.display()
        ))),
        Ok(m) if m.len() == 0 => Ok(StorePathState::EmptyRegular),
        Ok(_) => Ok(StorePathState::Populated),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StorePathState::Absent),
        Err(e) => Err(refusal(format!(
            "cannot classify store path {}: {e} — refusing; only a confirmed-absent \
             path may bootstrap, an unreadable one must never be treated as absent",
            main.display()
        ))),
    }
}

struct RawHeader {
    user_version: u32,
    application_id: u32,
}

/// Read only the 100-byte SQLite file header, bounded: reading the whole database would buffer
/// a multi-GB store (or any file an operator points the path at) just to look at four bytes at
/// offset 60 and four at offset 68. A file shorter than the header cannot be a Photon store;
/// a short read maps to the same foreign-store refusal as bad magic. The bytes come from the
/// writer-gate registry's retained descriptor via a positioned read (see the body).
fn read_raw_header(main: &Path) -> Result<RawHeader, rusqlite::Error> {
    let not_a_store = || {
        refusal(format!(
            "{} is not a Photon store (bad SQLite magic) — refusing foreign store",
            main.display()
        ))
    };
    // This function owns no descriptor, deliberately. On unix, closing any descriptor to a file
    // cancels the whole process's POSIX advisory locks on it (sqlite.org howtocorrupt §2.2), so
    // opening the store, reading 100 bytes and dropping the file would silently destroy the WAL
    // locking of any connection the first `SqliteIntentLog::open` held on the same store when a
    // second open ran. The close was the hazard, not the open, so the decision tree is
    // unchanged and simply reads through the one registry-owned descriptor per identity, opened
    // once for the process and never closed. `SqliteIntentLog::open`'s `for pass in 1..=2`
    // lost-race loop can therefore read the header twice with no second descriptor to drop.
    let mut header = [0u8; 100];
    let read = crate::writer_gate::read_retained_header_at(main, 0, &mut header)
        .map_err(|e| refusal(format!("cannot read store header of {}: {e}", main.display())))?;
    // A file shorter than the header cannot be a Photon store: the same refusal the earlier
    // `read_exact` short-read produced.
    if read < header.len() {
        return Err(not_a_store());
    }
    if &header[..16] != SQLITE_MAGIC {
        return Err(not_a_store());
    }
    let be = |off: usize| u32::from_be_bytes(header[off..off + 4].try_into().unwrap());
    Ok(RawHeader {
        user_version: be(OFF_USER_VERSION),
        application_id: be(OFF_APPLICATION_ID),
    })
}

/// The name-domain contract: a Photon store name is a plain filesystem path whose final
/// component is a real file name. Refused by complement:
/// - names whose file name begins with ':' (SQLite special names: ":memory:" opens an
///   in-memory database regardless of the URI flag, and sqlite.org/uri.html directs
///   "./"-prefixing to escape them);
/// - symlinked mains: multiple names for one database split its journal family
///   (sqlite.org/howtocorrupt.html §multiple-links), enforced by our lstat classification at
///   every entry point (`classify_store_path` and `refuse_aliased_family`, final component
///   only). `SQLITE_OPEN_NOFOLLOW` was tried and removed: SQLite defines it as whole-path "may
///   not CONTAIN a symlink", which refused every legitimate macOS store under
///   `/var` -> `/private/var` (see `existing_store_flags`);
/// - URI interpretation is disabled everywhere (rusqlite's default flags include
///   `SQLITE_OPEN_URI`, so `file:` names would silently open a different database than the
///   literal path we preflight, fsync, and install);
/// - Windows names outside the ordinary filesystem namespace (ADS colon forms, reserved DOS
///   device names including with an extension, trailing dot/space), refused at this same
///   chokepoint on Windows only (see `windows_name_domain_defect`).
fn reject_special_name(main: &Path) -> Result<(), rusqlite::Error> {
    if let Some(name) = main.file_name() {
        let name = name.to_string_lossy();
        if name.starts_with(':') {
            return Err(refusal(format!(
                "'{}' is an SQLite special name (leading ':'), not a durable store file — \
                 refused; a Photon store is a plain filesystem path",
                main.display()
            )));
        }
        #[cfg(windows)]
        if let Some(defect) = windows_name_domain_defect(&name) {
            return Err(refusal(format!(
                "{defect} — refused; a Photon store is a plain file in the ordinary \
                 filesystem namespace (#57; learn.microsoft.com \"Naming Files, Paths, \
                 and Namespaces\")"
            )));
        }
    }
    Ok(())
}

/// The Windows name-domain complement: the three name classes Win32 silently maps out of the
/// ordinary filesystem namespace instead of failing (see
/// learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
/// - Interior ':' is the NTFS alternate-data-stream address form. `carrier.db:photon` passes
///   the leading-colon check, every derived sibling (`....photon-init.lock`) then becomes a
///   stream on the carrier file, and SQLite writes a whole database into an ADS with the
///   carrier's visible size unchanged.
/// - Reserved DOS device names (CON PRN AUX NUL, COM/LPT followed by 1-9 or the superscripts),
///   including with an extension ("NUL.txt and NUL.tar.gz are both equivalent to NUL"), with
///   the base matched after trimming trailing spaces so "COM1 .txt" cannot slip past.
///   Bootstrap would otherwise mint real stores at CON/COM1 that Explorer/cmd cannot delete.
/// - A trailing dot or space is stripped by Win32 at creation, so the installed file would be
///   a different name than the one preflighted, locked, and fsynced.
///
/// Reserved characters that already fail at the filesystem layer (< > " | ? *) need no check;
/// only the silent mappings are closed here. Enforcement is Windows-only: on unix these are
/// ordinary legal names, and a broader guard would refuse legitimate stores (the
/// `SQLITE_OPEN_NOFOLLOW` lesson above). Residuals: a unix-minted out-of-domain name refuses
/// if its family is ever copied to Windows; directory components are outside the contract
/// (final component only, like the symlink rule); a `\\?\` verbatim path could create such
/// NTFS names but lands on this same refusal; case-insensitive name collisions are unclosed.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_name_domain_defect(name: &str) -> Option<String> {
    if name.contains(':') {
        return Some(format!(
            "'{name}' addresses an NTFS alternate data stream (':' inside the file name); \
             a store there is invisible to directory listings, and the lock/temp siblings \
             derived from it become streams on the carrier file"
        ));
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Some(format!(
            "'{name}' ends with a dot or space, which Win32 strips at creation — the file \
             installed would not be the name that was preflighted and locked"
        ));
    }
    let base = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper: String = base.chars().map(|c| c.to_ascii_uppercase()).collect();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((upper.starts_with("COM") || upper.starts_with("LPT"))
            && matches!(upper.chars().nth(3), Some('1'..='9' | '¹' | '²' | '³'))
            && upper.chars().count() == 4);
    if reserved {
        return Some(format!(
            "'{name}' is a reserved DOS device name — Windows maps it to a device or an \
             undeletable file, never an ordinary store"
        ));
    }
    None
}

/// Per-store open flags: existing-store entry points never create and never interpret URIs.
///
/// `SQLITE_OPEN_NOFOLLOW` is deliberately absent. sqlite.org/c3ref/open.html defines it as "the
/// database filename is not allowed to CONTAIN a symbolic link", whole-path semantics on unix,
/// while the name-domain contract restricts only the final component. On macOS the default
/// temp and store roots cross system symlinks (`/var` -> `/private/var`), so the flag refused
/// every legitimate store under them. The enforcement is ours: final-component symlinks,
/// hard-link aliases and non-regular nodes refuse via `classify_store_path` and
/// `refuse_aliased_family` at every entry point, before any connection exists. The lstat-to-open
/// window remains check-then-act for an on-box actor; that is out of scope (code already
/// running on the user's machine with the user's privileges), and the flag never closed it
/// either.
fn existing_store_flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
}

/// The normative preflight decision tree. Reads bytes and directory entries only: no
/// connection is opened before ownership is established, and a refused store is never mutated.
pub(crate) fn preflight(main: &Path) -> Result<Preflight, rusqlite::Error> {
    reject_special_name(main)?;
    // The classification refuses a symlinked main from lstat, before any read; this is the
    // enforcement (see `existing_store_flags`). The lstat-to-open window and intermediate
    // directory links are the accepted on-box TOCTOU residual (LWN 899543).
    match classify_store_path(main)? {
        // Case (a): absent or zero-length regular. Fresh only with no persistent sidecar
        // (orphaned -wal/-journal frames would be replayed over a fresh store); a lone -shm is
        // harmless (see `persistent_sidecar`).
        StorePathState::Absent | StorePathState::EmptyRegular => {
            if persistent_sidecar(main)? {
                Err(refusal(format!(
                    "damaged store family: orphaned -wal/-journal beside an absent or \
                     empty {} — refusing; reset removes the whole file family",
                    main.display()
                )))
            } else {
                refuse_occupied_shm_name(main)?;
                Ok(Preflight::FreshBootstrap)
            }
        }
        StorePathState::Populated => {
            // No SQLite entry point opens an aliased family (see `refuse_aliased_family`);
            // checked before the header read routes anywhere.
            refuse_aliased_family(main)?;
            let hdr = read_raw_header(main)?;
            // Ownership decides first, from the raw header, before any connection: registered id
            // means owned; 0 means legacy candidate (refusal-only, but admitted to the recovery
            // probe); anything else is foreign.
            let owned_or_legacy = match hdr.application_id {
                id if id == APPLICATION_ID => true,
                0 => true,
                other => {
                    return Err(refusal(format!(
                        "{} carries application_id {other:#010x}, not Photon's {:#010x} — \
                         refusing foreign store without opening it",
                        main.display(),
                        APPLICATION_ID
                    )))
                }
            };
            debug_assert!(owned_or_legacy);
            if persistent_sidecar(main)? {
                // Case (c): the truth may live in the sidecar.
                return Ok(Preflight::RecoveryProbe);
            }
            // Case (b): the header is authoritative.
            if hdr.application_id == 0 {
                // Legacy candidate: never accepted as supported regardless of `user_version`;
                // routed to the pre-v8 refusal path.
                return Err(refuse_pre_v8(hdr.user_version));
            }
            match hdr.user_version {
                v if (MIN_UPGRADABLE_VERSION..=CURRENT_VERSION).contains(&v) => {
                    Ok(Preflight::OpenVerifiedSupported)
                }
                v if v < MIN_UPGRADABLE_VERSION => Err(refuse_pre_v8(v)),
                v => Err(refusal(format!(
                    "database schema version {v} is newer than this binary supports \
                     (max {CURRENT_VERSION}); refusing to open"
                ))),
            }
        }
    }
}

/// Re-apply the ownership/version rule through the connection that is about to be mutated. The
/// raw preflight reads bytes and then closes, so the file it inspected and the file the
/// following `Connection::open` holds are the same store only by assumption: a concurrent
/// bootstrap, a replacement, or a hot sidecar recovering to a different header in that window
/// would break it, and the next steps are the persistent `journal_mode=WAL` flip and the DDL.
/// `PRAGMA application_id` / `PRAGMA user_version` are non-mutating reads, so running this
/// first keeps refusal-before-mutation intact while making the connection self-verified.
///
/// The rule is the preflight's: Photon's registered id plus a version in the supported band
/// (`MIN_UPGRADABLE_VERSION..=CURRENT_VERSION`) is Ok; id `0` (legacy candidate) or a version
/// below the band gives the pre-v8 refusal; any other id is foreign; a version above the band
/// gives the newer-binary refusal.
pub(crate) fn verify_owned_supported_version(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let app: i64 = conn.query_row("PRAGMA application_id;", [], |r| r.get(0))?;
    let version = conn.query_row("PRAGMA user_version;", [], |r| r.get::<_, i64>(0))? as u32;
    match app as u32 {
        id if id == APPLICATION_ID => {}
        // Legacy candidate: refusal-only, never accepted whatever the version reads.
        0 => return Err(refuse_pre_v8(version)),
        other => {
            return Err(refusal(format!(
                "the opened store carries application_id {other:#010x}, not Photon's \
                 {APPLICATION_ID:#010x} — refusing foreign store"
            )))
        }
    }
    match version {
        v if (MIN_UPGRADABLE_VERSION..=CURRENT_VERSION).contains(&v) => Ok(()),
        v if v < MIN_UPGRADABLE_VERSION => Err(refuse_pre_v8(v)),
        v => Err(refusal(format!(
            "database schema version {v} is newer than this binary supports \
             (max {CURRENT_VERSION}); refusing to open"
        ))),
    }
}

/// The native-resource-key expression: the one text used by the expression index and by every
/// consumer predicate that must use it. SQLite matches an expression index textually, so a
/// consumer whose expression differs by so much as a guard silently falls back to a full table
/// scan; sharing the literal makes the index serve the query and keeps the two from drifting.
///
/// **Malformed-safe.** A bare `json_extract(frozen_basis, ...)` aborts on malformed JSON, and
/// SQLite evaluates the index expression over every existing row while building the index, so
/// the first open that created it over a store already holding a malformed non-NULL
/// `frozen_basis` would die inside `CREATE INDEX`, before [`integrity_scan`] could report
/// anything. That would invert the contract that integrity evidence never refuses an open. The
/// `json_valid` guard makes the expression total: a malformed basis indexes as NULL, and the
/// scan reports it as [`IntegrityEvidence::FrozenBasisMissing`]. NULL is also right for the
/// lookup, since `NULL = ?` is never true, so a malformed row is never mistaken for a
/// native-key predecessor.
pub(crate) const NATIVE_KEY_EXPR_SQL: &str =
    "CASE WHEN frozen_basis IS NOT NULL AND json_valid(frozen_basis) \
     THEN json_extract(frozen_basis, '$.native_resource_key') END";

/// The activation trigger's scan stop: how many `intents` rows either occupancy probe in
/// `intents_status_activation`'s `WHEN` clause may visit before it has enough to answer.
/// Interpolated into both probes' `LIMIT`.
///
/// A probe can stop early because each conjunct asks `occupancy <= bound`, never "how many". A
/// scan that stops after `stop` rows returns `min(occupancy, stop)`, and provided
/// `stop > bound` that answers the inequality identically: at or under the bound it is the
/// occupancy, and above it the truncated count is at least `bound + 1`, which fails
/// `<= bound` exactly as the true count does.
///
/// The expression is act-derived with a constant fallback:
/// `COALESCE(<domain-guarded bound derivation> + 1, <the constant>)`. A constant stop
/// (`MAX_ACTIVE_OPS_MAX + 1`) is json-free but costs O(min(active, 8193)) per probe per
/// firing, which failed the 250 ms gate (353.8 ms mixed/pending) in the honest worst case, a
/// domain-floor reduction pending through most of a 1024-member sever, because roughly twice
/// the active count of index visits across about 992 expensive firings dwarfs the few json
/// operations the act-derived stop costs. The prefilter still zeroes the no-pending case, and
/// the fallback is the constant (never `-1` or unbounded), so a malformed or out-of-domain act
/// still gets a bounded scan and the overflow class stays closed: the `+ 1` arithmetic runs
/// only inside the domain-guarded `THEN`, where both operands are at most 8192, and an
/// untrusted value never reaches it. `the_limit_bounded_activation_probes_agree_with_the_unbounded_form`
/// pins the behaviour.
pub(crate) fn activation_probe_limit_sql() -> String {
    format!(
        "COALESCE(
                                 (SELECT CASE WHEN json_valid(payload) THEN CASE WHEN {domain_guard} THEN
                                             CAST(json_extract(payload, '$.capacity.max_active_ops') AS INTEGER) + 1
                                             END END
                                    FROM engine_config
                                   WHERE kind = 'capacity'
                                     AND generation = (SELECT MAX(generation) FROM engine_config
                                                        WHERE kind = 'capacity')), {ceiling})",
        domain_guard = capacity_domain_guard_sql("payload"),
        ceiling = crate::capacity::MAX_ACTIVE_OPS_MAX as i64 + 1
    )
}

/// The constant arm of [`activation_probe_limit_sql`]'s `COALESCE`: the domain ceiling + 1,
/// still exposed on its own so tests can pin the fallback's value. `#[cfg(test)]` because the
/// tests are its only callers (the lib target would carry it dead, which fails CI's
/// `clippy -D warnings`; the production DDL uses the `_sql` twin above).
#[cfg(test)]
pub(crate) fn activation_probe_limit() -> i64 {
    crate::capacity::MAX_ACTIVE_OPS_MAX as i64 + 1
}

/// The capacity domain check as SQL. Mirrors `capacity::CapacityConfig::validate`'s full
/// domain: `MAX_ACTIVE_OPS_MIN..=MAX_ACTIVE_OPS_MAX` for `max_active_ops`, `1..max_active_ops`
/// for `undo_reserve`, and `1..=u32::MAX` for each of `writer_chunk_budget_ms`,
/// `sever_watchdog_ms` and `sever_joiner_cap` (`validate()` refuses a zero in any of the
/// three, and the fields are `u32`, so the serde parse refuses anything above `u32::MAX`
/// before `validate()` runs; the SQL upper bound mirrors that), over the json-extracted values
/// read straight off a raw `engine_config` payload. Mirroring only the first two bounds would
/// let a payload carrying `sever_joiner_cap: 0` activate through the trigger while every Rust
/// reader refused it by name, defeating "out-of-domain is inert end to end" one entry point
/// over. The payload column expression is a parameter (`c.payload` inside the trigger's `WHEN`
/// clause via [`activation_fit_predicate_sql`]) so one domain text serves every consumer, like
/// [`NATIVE_KEY_EXPR_SQL`]. The two range bounds are read from `capacity::MAX_ACTIVE_OPS_MIN`
/// and `MAX`, not re-spelled, so the SQL and Rust domains cannot drift.
///
/// It composes with the caller's own `json_valid` guard rather than repeating it: every call
/// site wraps it as `CASE WHEN json_valid(<payload>) THEN CASE WHEN {this} THEN ... END END`.
/// The nested `CASE` is deliberate and not a flat `AND`. `json_valid(X) AND {this}` does not
/// guarantee `{this}`, which mixes plain `json_type`/`json_extract` scalar reads with
/// `NOT EXISTS (... json_each ...)` subqueries in one `AND` chain, is reached only once `X`
/// parses. Under the bundled SQLite 3.45.0 the term order held, but at 3.53.2 the optimizer
/// reorders the conjuncts and evaluates a later scalar term before the earlier subquery term,
/// so an unreadable payload's `json_type`/`json_extract` call still raises behind a leading
/// `json_valid(X) AND`. A `CASE`'s `WHEN`/`THEN` selection has no such freedom: only the
/// matched branch is evaluated. This rests on SQLite's documented posture ("The CASE
/// expression", sqlite.org/lang_expr.html documents both `CASE` forms as lazy and documents no
/// evaluation order for an `AND` chain), not on observed behaviour. The same composition is
/// used at every call site sharing it (`activation_probe_limit_sql`,
/// `activation_fit_predicate_sql` twice, and the trigger's `capacity_activated` pointer read in
/// [`schema_ddl`]); inside the domain check a missing or out-of-range number still makes a
/// `BETWEEN` here false.
///
/// **The numeric fields are also `json_type`-guarded.** `CAST(... AS INTEGER)` on a TEXT value
/// takes the value's leading numeric prefix rather than refusing a non-numeric string:
/// `CAST('garbage' AS INTEGER)` is `0` (always out of domain), but `CAST('100abc' AS INTEGER)`
/// is `100`, in domain for `max_active_ops`. A wrong-typed string field with a numeric prefix
/// would therefore read as a legitimate number, even though
/// `capacity::CapacityConfig::from_engine_payload` refuses a JSON string for these fields
/// unconditionally. `json_type({expr}, path) = 'integer'` requires the JSON value itself to be
/// a number with no fractional part before the `CAST` is trusted. See the numeric-prefixed
/// capacity field test in `lib.rs`.
/// **No duplicate known members, as SQL: the exact serde mirror, not a stricter one.**
/// SQLite's json reader keeps every duplicate member and `json_extract` answers from the
/// first, while the Rust authorities parse through serde named-field visitors that refuse a
/// duplicate of a field they know. A raw act carrying
/// `"sever_joiner_cap":16,"sever_joiner_cap":0` would read as in-domain in SQL while every Rust
/// reader refused it; the same shape on the newest `capacity_activated` row would let the
/// trigger append a fresh clean row over a pointer Rust refuses.
///
/// It is per known key and not `COUNT(*) = COUNT(DISTINCT key)`, because serde skips unknown
/// members, duplicates included. A payload with duplicated unknown extension members is
/// Rust-readable, so a guard refusing any duplicate would leave a legitimately activatable act
/// trigger-inert (the inverse divergence: SQL refuses what Rust accepts), parking it as pending
/// and leaving undo admission on stale larger bounds. The mirror cuts where serde cuts: a
/// duplicate of a known key refuses on both sides, a duplicate of an unknown key is ignored on
/// both. `keys` is the caller's own known set, the same field roster its Rust twin parses.
///
/// A non-object at `path` yields `json_each` rows with NULL keys (matching no known key, so
/// these conjuncts stay vacuously true, and the caller's `json_type` conjuncts refuse the
/// non-object as the Rust side does); a missing `path` yields zero rows (same). It composes
/// behind `json_valid` like every other json read in this family, since `json_each` raises on
/// malformed input.
fn no_duplicate_known_members_sql(payload_expr: &str, path: Option<&str>, keys: &[&str]) -> String {
    let each = match path {
        Some(p) => format!("json_each({payload_expr}, '{p}')"),
        None => format!("json_each({payload_expr})"),
    };
    // One `json_each` scan per call: a per-key `(SELECT COUNT(*) ...) <= 1` conjunct list re-ran
    // the table function once per key, measured at the 250 ms gate as the difference between
    // about 1 ms and about 30 ms of headroom on the pending arms, where this text runs per firing.
    let key_list = keys.iter().map(|k| format!("'{k}'")).collect::<Vec<_>>().join(", ");
    format!(
        "NOT EXISTS (SELECT 1 FROM {each} WHERE key IN ({key_list}) \
         GROUP BY key HAVING COUNT(*) > 1)"
    )
}

fn capacity_domain_guard_sql(payload_expr: &str) -> String {
    format!(
        "{no_dup_top} \
         AND {no_dup_capacity} \
         AND json_type({payload_expr}, '$.capacity.max_active_ops') = 'integer' \
         AND CAST(json_extract({payload_expr}, '$.capacity.max_active_ops') AS INTEGER) \
         BETWEEN {min} AND {max} \
         AND json_type({payload_expr}, '$.capacity.undo_reserve') = 'integer' \
         AND CAST(json_extract({payload_expr}, '$.capacity.undo_reserve') AS INTEGER) \
         BETWEEN 1 AND CAST(json_extract({payload_expr}, '$.capacity.max_active_ops') AS INTEGER) - 1 \
         AND json_type({payload_expr}, '$.capacity.writer_chunk_budget_ms') = 'integer' \
         AND CAST(json_extract({payload_expr}, '$.capacity.writer_chunk_budget_ms') AS INTEGER) \
         BETWEEN 1 AND {u32max} \
         AND json_type({payload_expr}, '$.capacity.sever_watchdog_ms') = 'integer' \
         AND CAST(json_extract({payload_expr}, '$.capacity.sever_watchdog_ms') AS INTEGER) \
         BETWEEN 1 AND {u32max} \
         AND json_type({payload_expr}, '$.capacity.sever_joiner_cap') = 'integer' \
         AND CAST(json_extract({payload_expr}, '$.capacity.sever_joiner_cap') AS INTEGER) \
         BETWEEN 1 AND {u32max}",
        min = crate::capacity::MAX_ACTIVE_OPS_MIN,
        max = crate::capacity::MAX_ACTIVE_OPS_MAX,
        u32max = u32::MAX,
        no_dup_top = no_duplicate_known_members_sql(payload_expr, None, &["capacity"]),
        no_dup_capacity = no_duplicate_known_members_sql(
            payload_expr,
            Some("$.capacity"),
            &[
                "max_active_ops",
                "undo_reserve",
                "writer_chunk_budget_ms",
                "sever_watchdog_ms",
                "sever_joiner_cap",
            ],
        ),
    )
}

/// The schema source, used by both the fresh bootstrap and the verified reopen (every
/// statement is `IF NOT EXISTS`, so a verified store no-ops). It is a function, not a const,
/// only so the native-key index can interpolate [`NATIVE_KEY_EXPR_SQL`]; the schema still has
/// exactly one home, so open and bootstrap cannot drift apart.
pub(crate) fn schema_ddl() -> String {
    format!(
        "{SCHEMA_DDL_STATIC_HEAD}{MESSAGE_HEADER_TABLE_DDL}{SCHEMA_DDL_STATIC_MID}{PLAN_MEMBER_TABLE_DDL}{SCHEMA_DDL_STATIC_TAIL}
            -- §7a: the native-keyed tail reads the frozen basis — expression index over the
            -- JSON native key (SQLite JSON is core ≥3.38; bundled is 3.53, #56 bump). Applies to
            -- stage-1-created v8 stores at their next open (IF NOT EXISTS, pre-release
            -- accretion — not a migration). The expression is `NATIVE_KEY_EXPR_SQL`, the SAME
            -- text every consumer predicate uses (SQLite matches expression indexes textually).
            --
            -- codex-r3 F3: the ORIGINAL, UNGUARDED `idx_intents_native_key` is dropped first.
            -- Its bare `json_extract` aborted the whole open while building over a malformed
            -- non-NULL frozen_basis, and an `IF NOT EXISTS` on the same name would leave a dev
            -- store carrying the unguarded definition forever — the guard has to arrive under a
            -- NEW name for the DROP/CREATE pair to be unambiguous. Pre-release accretion, not a
            -- migration: there is no released population, and the index holds no data of its own.
            DROP INDEX IF EXISTS idx_intents_native_key;
            CREATE INDEX IF NOT EXISTS idx_intents_native_key_guarded
                ON intents ({NATIVE_KEY_EXPR_SQL});
            -- codex-r3 F4 / codex-r4 F1: the head-predecessor predicate's OTHER lane — a message
            -- identified by its Photon-local `message_ref`. That lane had no index at all, so
            -- SQLite could not take the OR-by-union path and planned a full `SCAN intents` on
            -- every admission and every recovery pass.
            --
            -- r3 landed it PARTIAL (`WHERE frozen_basis IS NULL`), matching a lane that then
            -- restricted the CANDIDATE's basis. r4 F1 removed that restriction (mixed-generation
            -- rows on one message escaped BOTH lanes), and a partial index can only serve a query
            -- whose WHERE provably implies the index's own — so the partial index became
            -- unusable-by-anyone the moment the predicate widened: pure write cost, zero reads.
            -- It is DROPPED rather than left documented-superseded, for the same reason the
            -- unguarded native-key index above was: dev stores would otherwise carry a dead index
            -- forever, and a `CREATE ... IF NOT EXISTS` under the old name could never correct it.
            -- Pre-release accretion, not a migration — no released population, and an index holds
            -- no data of its own.
            --
            -- The plain replacement also serves `latest_intent_for_message_ref`, whose
            -- `WHERE account = ? AND message_ref = ?` had the same shape and the same non-index.
            DROP INDEX IF EXISTS idx_intents_null_basis_msgref;
            CREATE INDEX IF NOT EXISTS idx_intents_account_msgref
                ON intents (account, message_ref);
            -- #24-1b T12 (the failing 250ms witness's own demand — evidence file, runs 1-4:
            -- the mixed/pending arm crossed the gate at 262.6ms and 281.3ms because the
            -- activation trigger below fires PER ROW during a sever's ~960-member
            -- terminalization, and each firing's occupancy COUNT full-scanned every
            -- accumulated intents row, ~9.6k by cycle 10 — O(members x total-history) per
            -- sever). A PARTIAL INDEX over exactly the non-terminal domain turns both
            -- occupancy COUNTs (the trigger's and `record`'s admission door) into
            -- O(active) index scans. The predicate text MUST stay byte-identical to the
            -- interpolated `NON_TERMINAL_STATUS_SQL` in both consumers — SQLite uses a
            -- partial index only when the query's WHERE implies the index's WHERE, and
            -- textual identity is what guarantees the implication here. An index is build
            -- placement under the design's STOP LINE, not machinery.
            CREATE INDEX IF NOT EXISTS idx_intents_active_occupancy
                ON intents (compensates)
                WHERE status IN {NON_TERMINAL_STATUS_SQL};
            -- #24-1b Task 4 (design §5.3 CONFIGURATION-DOMAIN-PINNING pending reductions,
            -- :851-858) — THE ACTIVATION TRIGGER, the SOLE status-side authority that closes
            -- a pending capacity reduction (r3 council: ONE authority per event — the settle
            -- path performs NO Rust-side activation call; a second authority spelling would
            -- be exactly the dual-authority drift r3 killed). It fires on EVERY
            -- `intents.status` write, whatever its source spelling, because it rides the
            -- column itself rather than a call site — beside `engine_config`'s append-only
            -- triggers above, which is where it and the config ledger they both write to
            -- belong.
            --
            -- The WHEN clause carries BOTH conjuncts of the contract as ONE mechanical unit:
            -- `EXISTS(a pending, not-yet-activated capacity act)` — this doubles as the
            -- IDEMPOTENCE conjunct (r3 Opus's probe: one activation row from three status
            -- writes) — once activated, the newest `capacity` act's generation is no longer
            -- greater than the last-activated one, so a later status write finds nothing
            -- pending and stays silent (the `engine_config_no_replace` append-only guard
            -- above would also refuse a second activation row naming the same generation,
            -- and r3 verified that guard still fires from INSIDE this trigger — but the WHEN
            -- clause means a settled reduction never even attempts the INSERT) — AND the
            -- CURRENT occupancy, read AFTER this UPDATE (i.e. the releasing effect this very
            -- write just had), fits BOTH the pending act's bounds — the SQL twin of
            -- `capacity.rs::activation_fits`, over the SAME `NON_TERMINAL_STATUS_SQL`/
            -- `compensates` split `record`'s admission door counts against.
            --
            -- The WHEN EXISTS(pending) conjunct above is the idempotence conjunct (stated
            -- again, plainly, per the plan): once a pending capacity act activates, no
            -- later status write ever finds a pending act again, so this trigger fires its
            -- INSERT at most once per crossing — idempotent by construction, not by a guard
            -- elsewhere.
            --
            -- ⚠ THE FIRST CONJUNCT IS A JSON-FREE PREFILTER (#24-1b codex-r8 F1, the 250ms
            -- regression). Everything after it — the pointer read, the domain guard, the fit
            -- probes — evaluates json PER FIRING, and this trigger fires on EVERY status
            -- write. The prefilter compares two indexed integer MAXes and nothing else:
            -- does any capacity act OUTDATE the newest activation ROW? Under first-party
            -- append discipline that is implied by the real pending question (every writer —
            -- this trigger's own INSERT and `record_capacity_config`'s no-traffic activation
            -- alike — appends the activation row at global MAX(generation)+1, in the same
            -- transaction as / immediately after the act it activates, and always activates
            -- the NEWEST act; so a readable pointer P implies its row outdates P, and any act
            -- past P outdates that row too — prefilter false ⇒ the full clause below is false).
            -- A store with NO capacity acts at all — every store running on the compiled
            -- DEFAULT — now exits at the prefilter with zero json work, and so does every
            -- firing after a pending act activates.
            --
            -- The ONE shape that can diverge, named: a RAW out-of-order `capacity_activated`
            -- row (generation planted AHEAD of the act counter — no first-party writer can
            -- produce one; raw SQL or corruption only). The old clause could ACTIVATE behind
            -- it; the prefilter reads it as newest and stays INERT — fail-CLOSED, the same
            -- direction the r7 corrupt-pointer semantics already committed to (no activation
            -- while a suspect row is the newest; every Rust reader keeps refusing it by
            -- name). Witness: `codex_r8_f1_an_out_of_order_activation_row_prefilters_inert`.
            --
            -- ⚠ BOTH OCCUPANCY PROBES ARE LIMIT-BOUNDED (#24-1b codex-r3 F2) — AT A CONSTANT
            -- STOP (#24-1b codex-r8 F1). They used to be plain `COUNT(*)`s over the whole
            -- non-terminal domain: under a pending reduction that does NOT yet fit, every
            -- terminalized row of a sever re-fires this trigger and each firing counted the
            -- FULL active pool — O(active) per row, O(active^2) per sever, ~67M index-row
            -- visits at the 8192 ceiling. Neither count needs a number, though: each one only
            -- has to decide `<= bound`, so a scan that stops ABOVE the largest trustable
            -- bound gives the SAME verdict as one that scans everything.
            -- `activation_probe_limit()` is that stop — `MAX_ACTIVE_OPS_MAX + 1`, a
            -- compile-time constant (see its doc for why the r3-era per-firing json
            -- derivation of the stop was the r8 regression's largest term, and why the
            -- constant closes the r6-F1 overflow class by construction). The comparisons are
            -- UNCHANGED — the LIMIT can shorten the scan, never move the answer
            -- (`the_limit_bounded_activation_probes_agree_with_the_unbounded_form` is the
            -- guard, over the same edge table `both_authorities_agree_at_the_edges` uses,
            -- PLUS a saturating case where the limit provably binds).
            --
            -- Per-row cost in the still-pending window is O(min(active, 8193)) on the partial
            -- index — the honest ledger row is unchanged: worst case O(active x members) for
            -- a full sever at the 8192 ceiling, bounded, named, benchmark covers the DEFAULT
            -- profile (1024). The moment the reduction fits, activation fires and the
            -- PREFILTER kills every later firing's cost outright.
            --
            -- The first probe is spelled `WHERE ... AND compensates IS NULL` rather than
            -- `COUNT(*) FILTER (WHERE compensates IS NULL)`: a FILTER cannot stop the scan
            -- early (it must visit every row to decide which ones to count), and the WHERE
            -- form still implies `idx_intents_active_occupancy`'s own predicate textually, so
            -- it rides the same partial index — as an equality seek on `compensates` rather
            -- than a full index scan.
            --
            -- ⚠ EVERY JSON READ IN THIS `WHEN` CLAUSE IS `json_valid`-GUARDED (#24-1b
            -- codex-r4 F1, P1). A bare `json_extract` over malformed JSON RAISES rather than
            -- returning NULL, and a RAISE from inside a `WHEN` clause aborts the UPDATE that
            -- fired the trigger — so ONE unreadable `kind='capacity'` row used to fail EVERY
            -- `intents.status` write in the store (adjudication, sever drainage,
            -- terminalization): the store wedged on a config row. Guarded, each read is NULL
            -- on an unreadable payload, the comparison it feeds is NULL, and the `WHEN` clause
            -- is FALSE.
            --
            -- #56 EVIDENCE: the guard is a NESTED `CASE` (`json_valid` in the outer `WHEN`,
            -- every dependent read inside the inner `CASE`'s `THEN`), never a flat `AND` — see
            -- [`capacity_domain_guard_sql`]'s doc for why the bundled-SQLite bump made that
            -- distinction load-bearing.
            --
            -- THE SEMANTICS THAT CHOICE COMMITS TO, STATED: **a malformed pending act can
            -- never ACTIVATE** — it does not FIT, because a bound nobody can read is not a
            -- bound that was met — so it sits in the ledger INERT. That is fail-SAFE and not
            -- fail-SILENT, because the act is loud on the READ side, which is the side where a
            -- wrong capacity answer would matter: `record`'s admission read
            -- (`read_effective_bounds` → `capacity::effective_bounds` →
            -- `CapacityConfig::from_engine_payload`) REFUSES an unreadable payload by name, and
            -- so does `capacity_config_at_open` (codex-r4 F2 — it used to swallow the same
            -- refusal into `capacity::DEFAULT`). `record_capacity_config` writes through that
            -- same parse, so the API door never admits one: raw SQL or corruption is the only
            -- way such a row enters. Witness:
            -- `codex_r4_f1_a_malformed_capacity_act_is_inert_not_a_wedge`.
            --
            -- The `capacity_activated` read is guarded the OTHER way round, deliberately: an
            -- unreadable NEWEST activation act falls back to `c.generation` itself, so
            -- `c.generation > c.generation` is FALSE and no activation fires. Falling back to
            -- the `0` that means NEVER-ACTIVATED would have been fail-OPEN — it would let a
            -- reduction re-activate behind an activation record nobody can read. The outer
            -- `COALESCE(..., 0)` still carries the genuinely-absent case (no activation row at
            -- all), which is a different fact from an unreadable one.
            --
            -- ⚠ THE `activates_generation` READ IS ALSO TYPE- AND RANGE-GUARDED (#24-1b
            -- codex-r7 F2, P2). `json_valid` proves the PAYLOAD parses; it says nothing about
            -- whether `$.activates_generation` is the INTEGER the `CAST` assumes.
            -- `CAST('garbage' AS INTEGER)` does not raise and does not return NULL — SQLite
            -- coerces a non-numeric-prefixed string to `0`, silently, and `0` is NOT the
            -- `c.generation` fallback above; it is the ledger's OWN never-activated sentinel.
            -- A wrong-typed pointer therefore used to make `COALESCE(..., c.generation)`
            -- resolve to `0` instead — `c.generation > 0` is true for every real generation
            -- (`generation INTEGER PRIMARY KEY CHECK (generation >= 1)`), so the trigger fired
            -- and appended a FRESH, well-typed `capacity_activated` row over the corrupt one.
            -- Every Rust reader (`capacity::parse_activation_pointer`) reads only the NEWEST
            -- such row, so that fresh row silently buried the corruption exactly where a
            -- reader would otherwise have refused it.
            --
            -- `json_type(a.payload, '$.activates_generation') = 'integer'` (present AND
            -- typed) plus `CAST(...) >= 1` (in-domain — `>= 1` matching the column's own
            -- `CHECK`, so a type-correct but sub-1 value, including a genuine `0`, cannot
            -- collide with the sentinel either) route a wrong-typed or out-of-range pointer
            -- through the SAME `CASE`-with-no-`ELSE` `NULL` an unreadable payload already
            -- takes, so `COALESCE(NULL, c.generation)` lands on the intended fallback and
            -- `c.generation > c.generation` is FALSE — inert, not fail-open. See
            -- `codex_r7_f2_a_wrong_typed_activation_pointer_must_not_hide_behind_a_fresh_
            -- activation_row` (`lib.rs`) for the RED this closes and the both-directions
            -- semantics: a pending act is never wrongly read as already-activated, AND no new
            -- activation may append while the corrupt row is the newest — the corrupt row
            -- stays VISIBLE, and every Rust reader keeps refusing it by name.
            --
            -- codex-r14 F2 — WHY THE INTEGER PREFILTER IN `WHEN` IS EXACT: on an honest
            -- ledger, a-pending-act-exists and MAX(capacity) > MAX(capacity_activated) are
            -- the same fact, because both first-party activation writers point at the
            -- newest act they can see and append their row at global MAX+1 — no honest
            -- ledger holds an act BETWEEN the pointer and its own activation row. The one
            -- ledger shape where the two diverge (a raw/restored act STRANDED in that gap,
            -- which this prefilter can never see and so could never activate) is REFUSED BY
            -- NAME by every Rust reader (capacity::effective_bounds, the stranded-behind
            -- refusal) — the prefilter's silence there is the CONSISTENT half of a refusal,
            -- not a missed activation. Witnesses: lib.rs
            -- codex_r14_f2_an_act_stranded_behind_the_activation_row_refuses_the_read,
            -- store_open codex_r14_f1_a_forward_activation_pointer_refuses_the_open_
            -- capacity_read.
            --
            -- ⚠ the sqlite.org CREATE-TRIGGER footgun, VERBATIM (r3, seat-3's own control):
            -- \"UPDATE OF column names are NOT validated; a typo or future rename silently
            -- never fires (an AFTER UPDATE OF statu5 trigger was accepted and never fired)
            -- — which is why the positive-control witness is NOT optional.\" (The witness
            -- is `any_status_write_fires_activation`: a deliberately alternate-spelled raw
            -- `UPDATE\\n  intents\\nSET\\n  status = …`.)
            --
            -- The DROP is how the r4 F1 guard REACHES a store an earlier build of this branch
            -- already created: `CREATE TRIGGER IF NOT EXISTS` under the same name would leave
            -- that store carrying the UNGUARDED text forever, and unlike this branch's other
            -- carried-over shapes the old trigger does not fail loud — it silently keeps the
            -- exact wedge this fix closes. A trigger holds no data of its own, so DROP/CREATE
            -- inside the same DDL batch is a total replacement with nothing to migrate (the
            -- same reasoning `idx_intents_native_key`'s guarded replacement above uses; a
            -- trigger can take the SAME name back because the DROP provably precedes the
            -- CREATE in this one batch, which is what an index's `IF NOT EXISTS` could not).
            DROP TRIGGER IF EXISTS intents_status_activation;
            CREATE TRIGGER IF NOT EXISTS intents_status_activation
                AFTER UPDATE OF status ON intents
                WHEN (SELECT COALESCE(MAX(generation), 0) FROM engine_config WHERE kind = 'capacity')
                     > (SELECT COALESCE(MAX(generation), 0) FROM engine_config WHERE kind = 'capacity_activated')
                 AND EXISTS (
                    SELECT 1 FROM engine_config c
                     WHERE c.kind = 'capacity'
                       AND c.generation = (SELECT MAX(generation) FROM engine_config WHERE kind = 'capacity')
                       AND c.generation > COALESCE(
                           (SELECT COALESCE(
                                       CASE WHEN json_valid(a.payload) THEN CASE
                                            WHEN {no_dup_pointer}
                                             AND json_type(a.payload, '$.activates_generation') = 'integer'
                                             AND CAST(json_extract(a.payload, '$.activates_generation') AS INTEGER) >= 1
                                            THEN
                                            CAST(json_extract(a.payload, '$.activates_generation') AS INTEGER)
                                       END END,
                                       c.generation)
                              FROM engine_config a
                             WHERE a.kind = 'capacity_activated'
                             ORDER BY a.generation DESC LIMIT 1),
                           0)
                       AND {activation_fit}
                )
                BEGIN
                    INSERT INTO engine_config (generation, recorded_at, kind, payload)
                    VALUES (
                        (SELECT MAX(generation) + 1 FROM engine_config),
                        strftime('%s','now'),
                        'capacity_activated',
                        json_object('activates_generation',
                            (SELECT MAX(generation) FROM engine_config WHERE kind = 'capacity'))
                    );
                END;
            -- #24-1b Task 7 (design §5.3 coalescing, :799-820) — THE SEVER ATTRIBUTION CHILD.
            -- Overlapping sever requests COALESCE into ONE service and therefore into ONE
            -- epoch bump; every requester that was not the leader still has to be recorded,
            -- durably, against that one epoch.
            --
            -- WHY A CHILD TABLE AND NOT A COLUMN ON THE WITNESS (r2 council, EXECUTED):
            -- `sever_witness.epoch` is **UNIQUE** and the reader treats EVERY row as a
            -- canonical full witness (`verify_sever_witness`) — so a second row for the same
            -- epoch is refused by the append-only trigger, and a joiner column would have to
            -- be rewritten in place on an append-only table AFTER the leader committed.
            -- Attribution therefore CANNOT ride that table's rows. `sever_witness` is
            -- UNTOUCHED, FULL STOP: schema, digest input, reader and golden bytes are
            -- byte-identical to what stage 4 froze, and the freeze suite is this task's
            -- regression fence.
            --
            -- `epoch` is a FK to the witness and is deliberately NOT unique — many rows per
            -- epoch is the entire point. `kind` is CLOSED over the design's three windows:
            --   'in-snapshot'     — arrived before the leader's witness snapshot closed and
            --                       inside `sever_joiner_cap`; INSERTED IN THE LEADER'S OWN
            --                       TRANSACTION, atomically with the witness row;
            --   'overflow-joiner' — arrived before the close but past the cap;
            --   'post-snapshot'   — arrived after the close, before completion.
            -- The last two append THEMSELVES against the already-bumped epoch after the
            -- leader commits, and their requester does not return Ok until that row is
            -- durable (r43: a crash in that window leaves the request truthfully
            -- UNACKNOWLEDGED, never confirmed-then-lost).
            --
            -- `created_at` is INTEGER unix seconds — the `engine_config.recorded_at` house
            -- convention for ledger rows, deliberately NOT the fact clock: nothing orders
            -- attribution against the attempt-fact chain, and borrowing the clamped fact clock
            -- would imply an ordering guarantee this row does not have.
            --
            -- Append-only triggers mirror `engine_config`'s three-trigger pattern. The
            -- no-replace guard keys on `rowid`: this table declares no UNIQUE constraint (by
            -- design), but every rowid table can still be REPLACE-conflicted by an INSERT that
            -- names an existing `rowid` explicitly — and that implicit DELETE fires no delete
            -- trigger under `recursive_triggers=off`.
            CREATE TABLE IF NOT EXISTS sever_attribution (
                epoch         INTEGER NOT NULL REFERENCES sever_witness(epoch),
                requester_ref TEXT NOT NULL,
                kind          TEXT NOT NULL CHECK (kind IN ('in-snapshot','overflow-joiner',
                                                            'post-snapshot')),
                created_at    INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sever_attribution_epoch
                ON sever_attribution (epoch);
            CREATE TRIGGER IF NOT EXISTS sever_attribution_no_update
                BEFORE UPDATE ON sever_attribution
                BEGIN SELECT RAISE(ABORT, 'sever_attribution is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS sever_attribution_no_delete
                BEFORE DELETE ON sever_attribution
                BEGIN SELECT RAISE(ABORT, 'sever_attribution is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS sever_attribution_no_replace
                BEFORE INSERT ON sever_attribution
                WHEN NEW.rowid IS NOT NULL
                 AND EXISTS (SELECT 1 FROM sever_attribution WHERE rowid = NEW.rowid)
                BEGIN SELECT RAISE(ABORT, 'sever_attribution is append-only'); END;
",
        NON_TERMINAL_STATUS_SQL = crate::NON_TERMINAL_STATUS_SQL,
        activation_fit = activation_fit_predicate_sql(),
        no_dup_pointer = no_duplicate_known_members_sql("a.payload", None, &["activates_generation"])
    )
}

/// The activation fit predicate as one text: the two occupancy conjuncts of [`schema_ddl`]'s
/// `intents_status_activation` `WHEN` clause, the SQL twin of `capacity::activation_fits`. It
/// is lifted out so the trigger and the test that checks the `LIMIT`-bounded rewrite against
/// the unbounded one evaluate the same bytes; a copy in the test would only prove the copy.
///
/// It reads `c.payload`, so it is only meaningful inside a query that binds `c` to the newest
/// `capacity` act (the trigger does, and so does
/// `the_limit_bounded_activation_probes_agree_with_the_unbounded_form`).
///
/// Both bound expressions are `json_valid`-guarded, one guard per conjunct wrapping that
/// conjunct's whole right-hand side: inside the `THEN` branch the payload is proved parseable,
/// so no read under it can raise. An unreadable act makes each bound NULL, each comparison
/// NULL, and the `WHEN` clause false, so the act is inert instead of aborting the status write
/// that fired the trigger (see the trigger's comment in [`schema_ddl`] and the
/// malformed-capacity-act inertness test).
///
/// Both are also domain-guarded: `json_valid` proves the payload parses, not that the number
/// is one `validate()` would have accepted. Without a domain check, a syntactically valid but
/// out-of-domain act (planted only by raw SQL or corruption) would be compared and could
/// activate a config `record_capacity_config` would have refused. Both `CASE`s therefore gain
/// the same [`capacity_domain_guard_sql`] guard, so an out-of-domain act's bound is NULL, its
/// comparison NULL, and the `WHEN` clause false: inert, identical to an unreadable one.
pub(crate) fn activation_fit_predicate_sql() -> String {
    let domain_guard = capacity_domain_guard_sql("c.payload");
    format!(
        "(SELECT COUNT(*) FROM (
                              SELECT 1 FROM intents
                               WHERE status IN {NON_TERMINAL_STATUS_SQL}
                                 AND compensates IS NULL
                               LIMIT {activation_probe_limit}))
                           <= CASE WHEN json_valid(c.payload) THEN CASE WHEN {domain_guard} THEN
                                CAST(json_extract(c.payload, '$.capacity.max_active_ops') AS INTEGER)
                              - CAST(json_extract(c.payload, '$.capacity.undo_reserve') AS INTEGER)
                              END END
                       AND (SELECT COUNT(*) FROM (
                              SELECT 1 FROM intents
                               WHERE status IN {NON_TERMINAL_STATUS_SQL}
                               LIMIT {activation_probe_limit}))
                           <= CASE WHEN json_valid(c.payload) THEN CASE WHEN {domain_guard} THEN
                                CAST(json_extract(c.payload, '$.capacity.max_active_ops') AS INTEGER)
                              END END",
        NON_TERMINAL_STATUS_SQL = crate::NON_TERMINAL_STATUS_SQL,
        activation_probe_limit = activation_probe_limit_sql(),
        domain_guard = domain_guard
    )
}

/// Columns this build adds to a table an earlier build of the same schema version already
/// created: `(table, column, the ALTER that adds it)`.
///
/// `CREATE TABLE IF NOT EXISTS` does not ALTER an existing table, so [`schema_ddl`] is a no-op
/// on every table a store already carries. A store minted by an earlier build of the same
/// version is a legitimate store (the preflight admits it, the ownership id and version stamp
/// match, the chokepoint verifies it), yet it lacks the newer columns. Without an upgrade it
/// would open clean and fail deep, at the first statement naming the column ("no such column:
/// capture_generation"). Failing at the entry point is the point of having one.
///
/// The same mechanism serves both in-version accretion and a real cross-version upgrade (8 to
/// 9). The property a column add needs is identical: idempotent by its own `PRAGMA table_info`
/// guard (SQLite offers no `ADD COLUMN IF NOT EXISTS`), a constant DEFAULT so nothing needs
/// backfilling, and applied inside the one write transaction that also runs [`schema_ddl`] and
/// stamps the version, so a store is never left half-upgraded. What it cannot express is a
/// change that can fail on existing data (a new UNIQUE index, a narrowed CHECK); those need a
/// pre-scan that refuses by name (see [`refuse_duplicate_placement_identity`]).
///
/// `pre_state` is the only table extended in place; `attempt_fact`, `attempt_head`,
/// `adjudication_record`, `adjudication_annotation`, `exposure_obligation` and `sever_witness`
/// are new, so `CREATE TABLE IF NOT EXISTS` creates them whole and they carry no hazard of this
/// class.
///
/// The CHECK rides the ALTER. SQLite forbids UNIQUE / PRIMARY KEY and non-constant defaults on
/// `ADD COLUMN`; a CHECK is allowed, lands in `sqlite_master`, and is enforced on every later
/// write (verified on the bundled 3.45.0 and on 3.53.2; see the added-column CHECK test). An
/// upgraded store is therefore not weaker than a fresh one.
const IN_VERSION_COLUMN_UPGRADES: &[(&str, &str, &str)] = &[
    (
        "pre_state",
        "capture_generation",
        "ALTER TABLE pre_state ADD COLUMN capture_generation INTEGER NOT NULL DEFAULT 1 \
         CHECK (capture_generation >= 1);",
    ),
    // The 8 to 9 half. A v8 store's `message_header` predates both columns; `CREATE TABLE IF
    // NOT EXISTS` will not add them, and the page SELECTs name them, so without these ALTERs a
    // legitimate v8 store opens clean and then fails on the first listing query. DEFAULT 0 is
    // the honest value: a row recorded before this build could observe provider state has no
    // seen/flagged fact behind it.
    (
        "message_header",
        "seen",
        "ALTER TABLE message_header ADD COLUMN seen INTEGER NOT NULL DEFAULT 0;",
    ),
    (
        "message_header",
        "flagged",
        "ALTER TABLE message_header ADD COLUMN flagged INTEGER NOT NULL DEFAULT 0;",
    ),
    // The reconcile CAS's version marker (see the column's comment in `schema_ddl`).
    // In-version accretion: a store this build did not create carries a `message_header`
    // without it, and the reconcile's DELETE names the column. DEFAULT 0 needs no backfill and
    // means only "no ingest write has been counted on this row yet"; the CAS compares the value
    // it read to the value at apply time, so any starting point is equally correct.
    (
        "message_header",
        "ingest_revision",
        "ALTER TABLE message_header ADD COLUMN ingest_revision INTEGER NOT NULL DEFAULT 0;",
    ),
    // The effect evidence (see the columns' comments in `schema_ddl`). In-version accretion: a
    // store an earlier build of this version created carries an `intents` and a `pre_state`
    // without them, and the evidence reads and writes name them. NULL is the honest value for
    // every existing row (nothing was recorded or captured), so nothing is backfilled. The
    // CHECKs ride the ALTERs as `capture_generation`'s does; `ripple_unexpected`'s CHECK names
    // `ripple_verdict`, so its row comes after that column's. The four columns and two CHECKs
    // are pinned on a fresh and an upgraded store by
    // `s1_the_witness_columns_are_added_in_version_and_carry_their_checks_on_a_fresh_and_an_upgraded_store`.
    (
        "intents",
        "effect_label_vector",
        "ALTER TABLE intents ADD COLUMN effect_label_vector TEXT;",
    ),
    (
        "intents",
        "ripple_verdict",
        "ALTER TABLE intents ADD COLUMN ripple_verdict TEXT CHECK (ripple_verdict IS NULL \
         OR ripple_verdict IN ('within_closure','outside_closure'));",
    ),
    (
        "intents",
        "ripple_unexpected",
        "ALTER TABLE intents ADD COLUMN ripple_unexpected TEXT CHECK ((ripple_unexpected IS NULL) \
         = (ripple_verdict IS NULL OR ripple_verdict = 'within_closure'));",
    ),
    (
        "pre_state",
        "observed_label_vector",
        "ALTER TABLE pre_state ADD COLUMN observed_label_vector TEXT;",
    ),
    // The plan-child link (see the columns' comment in `schema_ddl`). In-version accretion: an
    // earlier build's `intents` lacks them, and every intents read names them
    // (`INTENT_COLUMNS`). NULL is the honest value for every existing row (no existing
    // operation is a plan child). `plan_member`'s CHECK names `plan_id`, so its row comes after
    // that column's. Pinned on a fresh and an upgraded store by
    // `s1_the_plan_link_columns_and_their_belt_arrive_in_version_on_an_upgraded_store`.
    ("intents", "plan_id", "ALTER TABLE intents ADD COLUMN plan_id TEXT;"),
    (
        "intents",
        "plan_member",
        "ALTER TABLE intents ADD COLUMN plan_member TEXT CHECK ((plan_member IS NULL) = (plan_id IS NULL));",
    ),
    // The frozen bypass-lane notice (see the column's comment in `schema_ddl`). In-version
    // accretion: an earlier build's `triage_plan` lacks it, and every plan read and insert names
    // it (`TRIAGE_PLAN_COLUMNS`). NULL is the honest value for every existing row (no earlier
    // build froze a notice), and a NULL on a bypass-lane plan minted under `backups: off` is
    // what the send guard's `BypassNoticeAbsent` row refuses. The CHECK rides the ALTER (existing
    // rows are NULL, so it holds). Pinned on a fresh and an upgraded store by
    // `s1_review_f1_the_bypass_notice_column_arrives_in_version_on_an_upgraded_store`.
    (
        "triage_plan",
        "bypass_notice",
        "ALTER TABLE triage_plan ADD COLUMN bypass_notice TEXT CHECK (bypass_notice IS NULL \
         OR (admission_lane = 'bypassed' AND backups_on = 0 AND length(bypass_notice) > 0));",
    ),
    // The structured sender (see the columns' comments in `schema_ddl`). In-version accretion: an
    // earlier build's `message_header` and `plan_member` lack them, and the header write and the
    // plan's insert and read name them. `unavailable` / NULL is the honest value for every
    // existing row (a header split by the old last-`<...>` rule is never re-parsed into a
    // domain; its next ingest rewrites it, and a member an earlier build froze has no parse on
    // record), so nothing is backfilled. Each status column precedes the columns whose CHECK
    // names it; the CHECKs hold on the existing rows. Pinned on a fresh and an upgraded store by
    // the sender-columns-on-an-upgraded-store test.
    //
    // The vocabulary CHECK these two ALTERs used to carry (`... IN ('ok','unavailable',
    // 'malformed')`, later widened to four values) is gone: the closed token table in code is
    // the one vocabulary authority, and the database polices shape, not vocabulary (see
    // `MESSAGE_HEADER_TABLE_DDL`'s doc). A store this ALTER already ran against under an earlier
    // build (so the ALTER is skipped) still carries the stale CHECK on disk;
    // `rebuild_status_check_tables`, called right after this function at the one open site,
    // detects that and rebuilds those two tables via SQLite's documented ALTER-TABLE procedure.
    (
        "message_header",
        "from_status",
        "ALTER TABLE message_header ADD COLUMN from_status TEXT NOT NULL DEFAULT 'unavailable';",
    ),
    (
        "message_header",
        "from_domain",
        "ALTER TABLE message_header ADD COLUMN from_domain TEXT CHECK ((from_domain IS NOT NULL) = (from_status = 'ok'));",
    ),
    (
        "plan_member",
        "sender_status",
        "ALTER TABLE plan_member ADD COLUMN sender_status TEXT NOT NULL DEFAULT 'unavailable';",
    ),
    (
        "plan_member",
        "sender_addr",
        "ALTER TABLE plan_member ADD COLUMN sender_addr TEXT CHECK ((sender_addr IS NOT NULL) = (sender_status = 'ok'));",
    ),
    (
        "plan_member",
        "sender_domain",
        "ALTER TABLE plan_member ADD COLUMN sender_domain TEXT CHECK ((sender_domain IS NOT NULL) = (sender_status = 'ok'));",
    ),
    // The address half's own frozen display copy (see the column's comment in `schema_ddl`).
    // In-version accretion: `''` is the honest value for every existing row (a member an
    // earlier build froze composed `sender` as one string and kept no separate address copy), so
    // nothing is backfilled; the next mint of that message re-freezes both fields split.
    (
        "plan_member",
        "sender_address",
        "ALTER TABLE plan_member ADD COLUMN sender_address TEXT NOT NULL DEFAULT '';",
    ),
    // The durable per-member fact "this intent's Applied effect has been written to the local
    // projection". The upgrade backfills `projected = 1` for every row already `applied`. That
    // can only be wrong in the direction of skipping a row earlier code already failed to
    // project, the same silent gap this column closes going forward, not a new one. Backfilling
    // 0 and re-projecting every already-applied row on the next sweep would replay a potentially
    // ancient delta over whatever newer observation a refresh has since written, which
    // `plan_projection_writes`'s own rule forbids. New `Applied` writes after this ALTER start
    // at the column's default, `0`: unprojected until the writer that settles them marks it.
    (
        "intents",
        "projected",
        "ALTER TABLE intents ADD COLUMN projected INTEGER NOT NULL DEFAULT 0 CHECK (projected IN (0,1));
         UPDATE intents SET projected = 1 WHERE status = 'applied';",
    ),
    // The structured-sender local part (see the column's comment in
    // `schema_ddl`/`PLAN_MEMBER_TABLE_DDL`). In-version accretion, as for
    // `sender_addr`/`sender_domain` above: an earlier build's `plan_member` lacks this column,
    // and every plan insert and read-back names it. NULL is the honest value for every existing
    // row (an earlier build split only `sender_addr`/`sender_domain`), so nothing is backfilled;
    // the next mint of that message re-freezes all three fields split.
    (
        "plan_member",
        "sender_local",
        "ALTER TABLE plan_member ADD COLUMN sender_local TEXT CHECK ((sender_local IS NOT NULL) = (sender_status = 'ok'));",
    ),
    // The freshness stamp an intent's effect was committed against, frozen at record time and
    // never re-derived: the last `message_header.ingest_revision` for (account, message_ref)
    // before the provider call, or NULL when no header row existed yet. Like `projected`
    // immediately above, it is never declared in the fresh `intents` DDL; this ALTER is the only
    // writer of the column's shape on a fresh and an upgraded store alike, so there is no
    // column-order question. NULL is the honest value for every existing row (no earlier build
    // recorded a basis), so nothing is backfilled; the projection path treats a NULL basis as "no
    // freshness claim" (skip the placement/header writes, mark projected; see
    // `ReadCoordinator::project_applied_intent`).
    (
        "intents",
        "basis_ingest_revision",
        "ALTER TABLE intents ADD COLUMN basis_ingest_revision INTEGER;",
    ),
];

/// The indexes over an in-version column. They cannot live in [`schema_ddl`]: it runs before
/// [`upgrade_in_version_columns`] at both schema sites, and on an upgraded store the column
/// does not exist yet at that point, so the `CREATE INDEX` would fail the open.
/// [`upgrade_in_version_columns`] runs these after its ALTERs. Each is `IF NOT EXISTS`, a
/// no-op on every open after the first.
///
/// `idx_intents_plan_child` is the plan child's `UNIQUE(plan_id, member)`. It is partial
/// (`WHERE plan_id IS NOT NULL`) because SQLite's `ADD COLUMN` cannot carry a UNIQUE
/// constraint and an index can; rows with no link are outside it. A second row for one (plan,
/// member) under any key is refused by it, whatever wrote the first.
const IN_VERSION_INDEXES: &[&str] = &[
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_plan_child
         ON intents (plan_id, plan_member) WHERE plan_id IS NOT NULL;",
];

/// Apply [`IN_VERSION_COLUMN_UPGRADES`] to a store this build is about to use. Runs at both
/// schema sites (fresh bootstrap and verified reopen), for the same reason [`schema_ddl`] has
/// one home: a no-op on a store this build just created, and the whole point on one it did not.
/// Guarded, so it is idempotent and costs one `pragma_table_info` per listed column.
pub(crate) fn upgrade_in_version_columns(
    conn: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    for (table, column, alter) in IN_VERSION_COLUMN_UPGRADES {
        let present: i64 = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2;",
            rusqlite::params![table, column],
            |r| r.get(0),
        )?;
        if present == 0 {
            conn.execute_batch(alter)?;
        }
    }
    // The indexes over those columns, after the ALTERs that create them (see
    // [`IN_VERSION_INDEXES`]).
    for index in IN_VERSION_INDEXES {
        conn.execute_batch(index)?;
    }
    Ok(())
}

/// Does `table`'s own on-disk DDL still carry the vocabulary CHECK (`_status IN (`), added by
/// any earlier build? `upgrade_in_version_columns`'s "column present, skip" guard cannot see
/// this: the column exists either way, so the ALTER that would carry the fixed shape never runs
/// again.
fn table_carries_vocabulary_check(
    conn: &rusqlite::Connection,
    table: &str,
) -> rusqlite::Result<bool> {
    use rusqlite::OptionalExtension;
    let sql: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1;",
            [table],
            |r| r.get(0),
        )
        .optional()?;
    Ok(sql.is_some_and(|s| s.contains("_status IN (")))
}

/// Rebuild `message_header` and/or `plan_member` when [`table_carries_vocabulary_check`] finds
/// either still carrying the vocabulary CHECK. SQLite cannot ALTER a column's CHECK in place,
/// so this follows SQLite's documented 12-step ALTER-TABLE procedure (sqlite.org
/// lang_altertable.html §7):
///
/// - `PRAGMA foreign_keys` is toggled OFF and back ON around the whole operation, outside the
///   rebuild's own transaction, because it is a no-op inside an open transaction (the FK check
///   was already turned ON at the open site before this function runs).
/// - One transaction per table, with explicit `BEGIN`/`COMMIT` rather than `execute_batch`'s own
///   encompassing one, so a mid-rebuild failure can be rolled back before the pragma flips back
///   ON over a half-rebuilt store.
/// - The new table is created under a temp name from [`MESSAGE_HEADER_TABLE_DDL`] /
///   [`PLAN_MEMBER_TABLE_DDL`], the same text [`schema_ddl`] uses for the real name
///   (`.replacen(name, temp, 1)`: the table's own name is always the first occurrence, before
///   any comment can repeat the word), never a second hand-typed spelling of the shape.
/// - `INSERT INTO new (columns...) SELECT columns... FROM old` is by column name, never
///   `SELECT *`, so a column-order difference between builds cannot misalign a copy.
///   `message_header`'s copy carries `rowid` explicitly: its FTS5 index (`message_header_fts`)
///   is external-content keyed on `rowid`, and fresh rowids would desync every existing row
///   from its search tokens.
/// - `DROP TABLE` the old name, then `RENAME` the temp table into it. Dropping the old table
///   auto-drops every index and trigger defined on it (`message_header`'s FTS5 sync and
///   ingest-revision triggers, `plan_member`'s append-only guards). The FTS5 virtual table is a
///   separate object, is not dropped, and needs no rebuild (the rowid-preserving copy keeps it
///   in sync).
/// - [`schema_ddl`] is called again once, after both renames commit: every `CREATE ... IF NOT
///   EXISTS` for an object that still exists is a no-op, and every one the DROP removed is
///   created fresh from the same one-source text.
/// - `PRAGMA foreign_key_check` runs before the commit (`plan_member.plan_id REFERENCES
///   triage_plan(plan_id)` is a real FK); any violation refuses before commit, never leaving a
///   silent orphan.
pub(crate) fn rebuild_status_check_tables(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let needs_message_header = table_carries_vocabulary_check(conn, "message_header")?;
    let needs_plan_member = table_carries_vocabulary_check(conn, "plan_member")?;
    if !needs_message_header && !needs_plan_member {
        return Ok(());
    }
    conn.execute_batch("PRAGMA foreign_keys=OFF;")?;
    let result = rebuild_status_check_tables_txn(conn, needs_message_header, needs_plan_member);
    if result.is_err() {
        // Best-effort: the transaction may never have opened, or may already be gone on some
        // failure paths. Never let a rollback error mask the original one.
        let _ = conn.execute_batch("ROLLBACK;");
    }
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    result
}

fn rebuild_status_check_tables_txn(
    conn: &rusqlite::Connection,
    needs_message_header: bool,
    needs_plan_member: bool,
) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN;")?;
    if needs_message_header {
        let temp_ddl = MESSAGE_HEADER_TABLE_DDL.replacen("message_header", "message_header_r3fold_a2", 1);
        conn.execute_batch(&temp_ddl)?;
        conn.execute_batch(
            "INSERT INTO message_header_r3fold_a2
                (rowid, account, message_ref, mailbox, received_at, from_addr, from_name, subject,
                 seen, flagged, ingest_revision, from_status, from_domain)
             SELECT rowid, account, message_ref, mailbox, received_at, from_addr, from_name, subject,
                    seen, flagged, ingest_revision, from_status, from_domain
               FROM message_header;
             DROP TABLE message_header;
             ALTER TABLE message_header_r3fold_a2 RENAME TO message_header;",
        )?;
    }
    if needs_plan_member {
        // `plan_member`'s own CREATE TABLE also names `triage_plan` (its FK target) but never
        // `plan_member` a second time before this, so `.replacen(..., 1)`'s first hit is always
        // the table's own name.
        let temp_ddl = PLAN_MEMBER_TABLE_DDL.replacen("plan_member", "plan_member_r3fold_a2", 1);
        conn.execute_batch(&temp_ddl)?;
        conn.execute_batch(
            "INSERT INTO plan_member_r3fold_a2
                (plan_id, message_ref, sender, subject, date, size, observed_state, forward_target,
                 sender_status, sender_addr, sender_domain, sender_address)
             SELECT plan_id, message_ref, sender, subject, date, size, observed_state, forward_target,
                    sender_status, sender_addr, sender_domain, sender_address
               FROM plan_member;
             DROP TABLE plan_member;
             ALTER TABLE plan_member_r3fold_a2 RENAME TO plan_member;",
        )?;
    }
    let violations: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check;", [], |r| r.get(0))?;
    if violations != 0 {
        return Err(refusal(format!(
            "class A2 rebuild refused: foreign_key_check found {violations} violation row(s)"
        )));
    }
    conn.execute_batch("COMMIT;")?;
    conn.execute_batch(&schema_ddl())?;
    Ok(())
}

/// Seed `ingest_revision_seq`'s single row, the third thing a schema site owes beside
/// [`schema_ddl`] and [`upgrade_in_version_columns`]. Called at both sites for the same reason:
/// a no-op on a store this build just created, and the whole point on one it did not.
///
/// The seed is `MAX(ingest_revision)` over whatever `message_header` already holds, not zero.
/// A store carrying earlier per-row counters has live rows numbered above 0, and a high water
/// starting below them would re-issue a number one of those rows still wears, the collision the
/// monotone marker exists to prevent. Seeding at the observed maximum makes the first value this
/// build issues strictly greater than every value the previous build wrote.
///
/// It is `INSERT ... ON CONFLICT DO UPDATE ... MAX(...)` rather than a bare INSERT: the row is
/// created once and only ever raised, so a re-run (every open runs this) cannot lower a high
/// water the running store has advanced past. `message_header` is created by [`schema_ddl`]
/// immediately above every call site, so the subquery is well-formed.
///
/// **The `WHERE true` is required** (sqlite.org lang_upsert.html §2.2, "Parsing Ambiguity"):
/// when an upsert's source is a SELECT rather than a VALUES list, SQLite cannot tell an
/// `ON CONFLICT` clause from a join constraint and rejects the statement with `near "DO": syntax
/// error`. The documented remedy is a trailing WHERE on the SELECT.
pub(crate) fn seed_ingest_revision_seq(
    conn: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "INSERT INTO ingest_revision_seq (id, high_water)
              SELECT 0, COALESCE(MAX(ingest_revision), 0) FROM message_header WHERE true
         ON CONFLICT(id) DO UPDATE SET
              high_water = MAX(ingest_revision_seq.high_water, excluded.high_water);",
    )
}

/// The v9 data migration for legacy display headers, the third thing an 8 to 9 upgrade owes
/// beside the added columns and the identity pre-scan.
///
/// [`crate::header_normalize::normalize_display`] is the ingest chokepoint every `from_name` /
/// `subject` passes through on its way into `message_header`, and it landed with the read side.
/// Every row a v8 binary wrote predates it: a persisted `U+202E` right-to-left override, a
/// CR/LF-injected fake chrome line, a Cf codepoint. Adding the flag columns and stamping v9
/// leaves those bytes as the provider sent them, so the first thing an upgraded store renders
/// is the payload the chokepoint exists to strip.
///
/// **The same function, never a second normalizer.** The migration calls `normalize_display`
/// itself, so an upgraded row and a freshly ingested one are normalized by one authority; if
/// the table gains a codepoint, both populations move together at the next upgrade.
///
/// **`from_addr` is not touched.** It is identity bytes and must round-trip exactly as the
/// provider sent them (see `header_normalize`'s module doc). Only the two display columns are
/// read and written.
///
/// **Upgrade-only**, like [`refuse_duplicate_placement_identity`]: on a store already stamped
/// `SCHEMA_VERSION` every row went in through the chokepoint, so a full `message_header` scan
/// per open would re-prove a property ingest already enforces. The call site guards it on
/// `current < SCHEMA_VERSION`; the table-existence guard keeps the function total anyway.
///
/// The FTS index follows for free: `message_header_fts` is external-content and the
/// `message_header_au` trigger re-writes the row's tokens on UPDATE, so search sees the
/// normalized text. Rows are written only when normalization changes them, so a clean store
/// pays a read and no writes.
///
/// The read is materialized whole, deliberately. It is a one-time pass over two display columns
/// at a version boundary, inside the transaction that stamps v9, so it either lands completely
/// or the store stays v8 and the next open retries. Chunking it would shrink the peak
/// allocation at the price of making a partially normalized store representable.
///
/// The migrated population is empty in any production v8 store: at v8 every caller of
/// `record_header` and `record_optimistic_placement` in `src/` was test-module code, so the rows
/// this pass normalizes, and the `seen = 0` / `flagged = 0` defaults the column-add stamps onto
/// them, exist only in test and perf stores, which are rebuilt, never migrated. A default of `0`
/// on that empty population misrepresents nothing, and the first refresh re-ingests real state.
pub(crate) fn normalize_legacy_display_headers(
    conn: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    let table_present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'message_header';",
        [],
        |r| r.get(0),
    )?;
    if table_present == 0 {
        return Ok(());
    }
    // Read the whole set first, then write: the UPDATE below fires the FTS sync trigger, and
    // mutating a table while its own SELECT cursor is open is the shape SQLite leaves
    // implementation-defined.
    let legacy: Vec<(String, String, String, String)> = {
        let mut stmt = conn
            .prepare("SELECT account, message_ref, from_name, subject FROM message_header;")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut update = conn.prepare(
        "UPDATE message_header SET from_name = ?3, subject = ?4
          WHERE account = ?1 AND message_ref = ?2;",
    )?;
    for (account, message_ref, from_name, subject) in legacy {
        let normalized_name = crate::header_normalize::normalize_display(&from_name);
        let normalized_subject = crate::header_normalize::normalize_display(&subject);
        if normalized_name == from_name && normalized_subject == subject {
            continue;
        }
        update.execute(rusqlite::params![
            account,
            message_ref,
            normalized_name,
            normalized_subject
        ])?;
    }
    Ok(())
}

/// The v9 upgrade guard for the `message_placement` identity inverse.
///
/// v8 constrained `message_placement` on `(account, message_ref)` only, so a v8 store may hold
/// two refs pointing at one provider message. v9's `UNIQUE (account, email_id)` forbids it, and
/// there are three ways to meet that population:
///
/// 1. let `CREATE UNIQUE INDEX` hit it: SQLite aborts the whole open with a bare "UNIQUE
///    constraint failed" from inside a batch, naming nothing an operator can act on;
/// 2. dedupe: the engine silently picks which of the operator's rows is real, and the ref it
///    deletes may be the one some intent row still points at;
/// 3. refuse by name, naming the colliding identity, touching nothing.
///
/// This is (3). It runs before [`schema_ddl`] (the index build is inside that batch) and inside
/// the same write transaction, so a refused store is left exactly as found. The
/// table-existence guard lets the fresh-bootstrap site call it too: degenerate on a store with
/// no rows.
pub(crate) fn refuse_duplicate_placement_identity(
    conn: &rusqlite::Connection,
) -> Result<(), rusqlite::Error> {
    use rusqlite::OptionalExtension;
    let table_present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'message_placement';",
        [],
        |r| r.get(0),
    )?;
    if table_present == 0 {
        return Ok(());
    }
    // ORDER BY makes the reported collision deterministic: an operator who runs the tool twice
    // must be told about the same row twice, not a different one each time.
    let collision: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT account, email_id, COUNT(*) FROM message_placement
              GROUP BY account, email_id HAVING COUNT(*) > 1
              ORDER BY account, email_id LIMIT 1;",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let total: i64 = conn.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM message_placement
                                GROUP BY account, email_id HAVING COUNT(*) > 1);",
        [],
        |r| r.get(0),
    )?;
    match collision {
        None => Ok(()),
        Some((account, email_id, n)) => Err(refusal(format!(
            "DUPLICATE-PLACEMENT-IDENTITY: this store cannot be upgraded to schema version \
             {CURRENT_VERSION}. Its `message_placement` holds {n} rows for account {account:?} \
             all naming provider message {email_id:?} ({total} colliding identit\
             {} in total), and v{CURRENT_VERSION} requires (account, email_id) to be UNIQUE so a \
             message can never be minted a second local ref. The upgrade REFUSES rather than \
             deciding which of those rows to delete — an intent row may still name either one. \
             Resolve it deliberately (inspect: SELECT account, email_id, message_ref FROM \
             message_placement GROUP BY account, email_id HAVING COUNT(*) > 1), or reset the \
             store file family and re-drill from the provider.",
            if total == 1 { "y" } else { "ies" }
        ))),
    }
}

const SCHEMA_DDL_STATIC_HEAD: &str = "
            CREATE TABLE IF NOT EXISTS intents (
                idempotency_key TEXT PRIMARY KEY,
                account         TEXT NOT NULL,
                facet           TEXT NOT NULL,
                action_kind     TEXT NOT NULL,
                message_ref     TEXT NOT NULL,
                status          TEXT NOT NULL,
                -- Reserved ActionEnvelope (D6.1) + pre-state snapshot pointer (D6.2): nullable,
                -- all NULL until the moat pass.
                principal       TEXT,
                epoch           INTEGER,
                evidence_ref    TEXT,
                snapshot_ref    TEXT,
                tier            TEXT,
                -- Explicit deferred-undo compensation link: the original key this row undoes
                -- (NULL for normal commands). recover() heals that original (codex P2).
                compensates     TEXT,
                -- Durable monotonic record order (separate from the key PK); recover ORDER BY this.
                seq             INTEGER NOT NULL,
                -- Durable transient-retry counter (ADR-P013 (b)): at RETRY_CAP the intent
                -- dead-letters to `Failed`. DEFAULT 0 so the column needs no backfill (decision B:
                -- M0 is pre-release with no persisted DBs, so a fresh DB is created at the current
                -- SCHEMA_VERSION and there is no data-migration path).
                -- #24-1b Task 10: this counter and the `attempt_fact` claim chain are TWO
                -- accountings of overlapping information, NOT ONE, and are NOT equivalent and
                -- cannot be reconciled from facts alone — `FailureKind` lives outside the fact
                -- grammar entirely, so no query over `attempt_fact` can recover which charges were
                -- transient without this column. This counter REMAINS the retry-budget authority
                -- (see `charge_and_dead_letter_if_quiescent`'s doc for the full relation). A future
                -- consolidation (fact-level retry-charge recording) is design-gate work, not
                -- smuggled in here.
                attempts        INTEGER NOT NULL DEFAULT 0,
                -- v8 (#24 stage 1, design §1c/§7a): admission binding. intent_id is the opaque
                -- operation identity (NOT NULL UNIQUE — the §2.2b FK parent when pre_state lands).
                intent_id               TEXT NOT NULL UNIQUE,
                kind                    TEXT NOT NULL CHECK (kind IN ('forward','undo')),
                parent_intent_id        TEXT,
                journal_required        INTEGER NOT NULL CHECK (journal_required IN (0,1)),
                capture_mode_generation INTEGER NOT NULL,
                admitted_control_epoch  INTEGER NOT NULL,
                batch_id                TEXT,
                -- frozen_basis: admission-frozen native identities (design BASIS-5). Nullable in
                -- stage 1 — populated when stage 2 lands the resolver seam; the open-time
                -- integrity rule ships there with W-CAPTURE-HEAD.
                frozen_basis            TEXT,
                -- #75 S1 (Task B8, design v7 §1-§2): THE EFFECT WITNESS, beside the operation.
                -- IN-VERSION accretion (v9 stays v9): a store an earlier v9 build created gets
                -- these three through `IN_VERSION_COLUMN_UPGRADES`, CHECKs included.
                -- `effect_label_vector`: the provider label vector the dispatch route answered
                -- at effect, as the canonical JSON array `prestate::label_vector_json` spells;
                -- NULL = no vector persisted (no successful dispatch yet, or its route observed
                -- none — a connector on the trait default, JMAP), or — the third meaning — the
                -- witness is written in its own transaction AFTER the settlement, so a crash or a
                -- store failure between them leaves an Applied operation with a NULL witness that
                -- nothing re-records. Reader rule: a NULL witness on an Applied operation reads
                -- as UNDETERMINED, never as within-closure. Never overwritten —
                -- `IntentLog::record_effect_witness` refuses every record once one is persisted.
                -- `ripple_verdict`: did any label OUTSIDE the frozen closure differ between the
                -- capture's observe read and the route's answer — the route's own ripple and any
                -- other writer in that interval both land here (`prestate::RippleVerdict`'s doc)
                -- — judged over the pre-to-post DELTA (`prestate::ripple_verdict`); NULL = no
                -- pre-effect vector to judge against. `ripple_unexpected`: those labels, present
                -- exactly when the verdict is 'outside_closure', so the verdict reads back whole.
                effect_label_vector     TEXT,
                ripple_verdict          TEXT CHECK (ripple_verdict IS NULL
                                            OR ripple_verdict IN ('within_closure','outside_closure')),
                ripple_unexpected       TEXT CHECK ((ripple_unexpected IS NULL)
                                            = (ripple_verdict IS NULL OR ripple_verdict = 'within_closure')),
                -- #75 S1 Part D (v3 §3): THE PLAN-CHILD LINK — the plan this operation is a child
                -- of, and the member it acts on. Both or neither (the CHECK; `intent_from_raw`
                -- refuses half a link on read too). One row per (plan, member): the partial UNIQUE
                -- index `idx_intents_plan_child`, created after `IN_VERSION_COLUMN_UPGRADES` (see
                -- `IN_VERSION_INDEXES`). IN-VERSION accretion (v10 stays v10), appended LAST so a
                -- fresh and an upgraded store carry the same column order.
                plan_id                 TEXT,
                plan_member             TEXT CHECK ((plan_member IS NULL) = (plan_id IS NULL))
            );
            -- Read-side optimistic projection (M0 DoD §2): the believed mailbox placement of a
            -- message. Lives in the SAME DB FILE as `intents`. NOTE (council ChatGPT, 2026-06-25):
            -- today `SqliteMessageStore` uses a SEPARATE connection, so the optimistic write and the
            -- intent record are SEPARATE autocommit transactions — NOT one atomic write-ahead boundary.
            -- That window is inert in M0 (no production path pairs the two writes — the optimistic-apply
            -- pipeline is unwired; the projection is a rebuildable CQRS read-model). The atomic
            -- co-commit is OWED when the pipeline is wired into execute() — tracked as a follow-up
            -- issue. `placement` is the durable Placement token. `email_id` holds the
            -- provider-opaque message id (`read_model::ProviderMessageId`); the column name is
            -- NOT renamed — a rename is a migration with zero behavioral gain (design §2.2, #23).
            CREATE TABLE IF NOT EXISTS message_placement (
                account     TEXT NOT NULL,
                message_ref TEXT NOT NULL,
                email_id    TEXT NOT NULL,
                placement   TEXT NOT NULL,
                PRIMARY KEY (account, message_ref)
            );
            -- v9 (#66 §2 S1, the IDENTITY clause): the INVERSE of the table's own key —
            -- `(account, email_id) -> message_ref`. Ingest looks the provider id up here BEFORE
            -- minting a ref, so the same message arriving on a later page or a later refresh
            -- reuses its ref instead of minting a second one. UNIQUE is the load-bearing half:
            -- 'we look it up first' is a convention a future writer can forget, while the
            -- constraint makes a duplicate mint impossible for anyone. On an UPGRADE this index
            -- meets data that predates the rule — see `refuse_duplicate_placement_identity`,
            -- which refuses by name rather than letting SQLite abort mid-build or letting the
            -- engine pick a winner.
            CREATE UNIQUE INDEX IF NOT EXISTS idx_message_placement_identity
                ON message_placement(account, email_id);
            -- Canonical header read-side (M0 DoD §5): minimal headers for the folder-list + search
            -- floors. Photon-local refs only (provider ids stay below the seam). Separate from
            -- message_placement (placement = divergence concern; headers = read/list/search concern).
            ";

/// `message_header`'s CREATE TABLE, factored out of [`SCHEMA_DDL_STATIC_HEAD`] /
/// [`SCHEMA_DDL_STATIC_MID`] so [`rebuild_status_check_tables`] can build a temp-named copy from
/// the same text (`.replacen("message_header", <temp name>, 1)`; the table's own name is the
/// first occurrence, before any comment can repeat the word). The vocabulary CHECK is gone: the
/// closed token table in code (`mailbox::SenderStatus`'s `closed_tokens!`) is the one
/// vocabulary authority, and the database polices shape only. The cross-column shape CHECK on
/// `from_domain` is unchanged.
const MESSAGE_HEADER_TABLE_DDL: &str = "
            CREATE TABLE IF NOT EXISTS message_header (
                account     TEXT NOT NULL,
                message_ref TEXT NOT NULL,
                mailbox     TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                from_addr   TEXT NOT NULL,
                from_name   TEXT NOT NULL,
                subject     TEXT NOT NULL,
                -- v9 (#66 §2 S1, the FLAGS clause): provider-neutral message state, modelled on
                -- JMAP's keyword shape ($seen/$flagged) because it is the neutral one — Gmail's
                -- UNREAD/STARRED labels map onto it, not the other way round. 0/1 INTEGER with
                -- DEFAULT 0, so the upgrade needs no backfill: 'unseen, unflagged' is the honest
                -- answer for a row recorded before this build could know either.
                seen        INTEGER NOT NULL DEFAULT 0,
                flagged     INTEGER NOT NULL DEFAULT 0,
                -- #24-1b codex-r4 F3: THE VERSION MARKER the reconcile's apply-phase
                -- compare-and-set rides. `refresh_reconcile` decides its removals against an
                -- UNGATED read snapshot and applies them in later, separately-enrolled chunks;
                -- between the two, a NEWER `ingest_page` can re-confirm one of those messages
                -- into the Inbox. `mailbox='Inbox'` — the only thing the CAS used to compare —
                -- still matches the re-upserted row, so the older reconcile deleted CURRENT
                -- provider evidence. Nothing else on the row discriminates: `received_at` is a
                -- property of the message and a re-confirm writes it back unchanged, and an
                -- upsert preserves the rowid. So the row carries a counter of its own, bumped
                -- by `message_header::upsert_header_row` on EVERY ingest write, and the DELETE
                -- proves the row is still the one that was decided.
                --
                -- INGEST writes, specifically, and that is the honest scope: the verdict a
                -- reconcile makes is THE-PROVIDER-DID-NOT-RETURN-THIS-MESSAGE, and only a
                -- write carrying fresh provider evidence can invalidate it. A star flip
                -- (`apply_verb_delta`'s `StarSet`) changes the row without touching that
                -- question, and a mailbox move is already covered by the `mailbox` half of the
                -- same CAS.
                --
                -- #24-1b codex-r5: THE MARKER IS STORE-MONOTONIC, NEVER PER-ROW. r4 wrote a
                -- literal 0 on the INSERT arm and `+ 1` on the UPDATE arm, which made the
                -- counter a property of the ROW — and a row can be DELETED. A reconcile that
                -- decided a row at revision 0 (every fresh row) still matched that same row
                -- after a delete-and-reinsert, so the r4 CAS deleted post-verdict provider
                -- evidence exactly as the pre-r4 one did. The value now comes from
                -- `ingest_revision_seq` below: one number per STORE, never lowered by a
                -- delete, so a row written after a decision is UNNAMEABLE by it. The DEFAULT
                -- stays 0 for the ALTER-added upgrade population (see
                -- `IN_VERSION_COLUMN_UPGRADES`) and for raw fixtures; no production write
                -- takes it.
                ingest_revision INTEGER NOT NULL DEFAULT 0,
                -- #75 S1 council r2 (seat 3, S3-1): the SENDER `from_addr` names, derived at the
                -- row's one write door (`message_header::upsert_header_row`) by RFC 5322 §3.4
                -- (`mailbox::sender_facts`) — `from_status` the closed set, `from_domain` the parsed
                -- mailbox's domain, present exactly when the status is `ok`. DEFAULT 'unavailable'
                -- is the honest value for the ALTER-added upgrade population: an earlier build split
                -- that row's From header by the LAST-`<…>` rule (the defect these columns close), so
                -- its `from_addr` is never re-parsed into a domain; the next ingest of the message
                -- rewrites both columns. #75 S1 r3 fold class A2 (TAR-PIT Q4): the vocabulary CHECK
                -- is gone — `mailbox::SenderStatus`'s closed token table is the one vocabulary
                -- authority; this column keeps only its SHAPE (NOT NULL, a default for the
                -- ALTER-added upgrade population).
                from_status TEXT NOT NULL DEFAULT 'unavailable',
                from_domain TEXT CHECK ((from_domain IS NOT NULL) = (from_status = 'ok')),
                PRIMARY KEY (account, message_ref)
            );
            ";

const SCHEMA_DDL_STATIC_MID: &str = "
            -- #24-1b codex-r5 — THE STORE'S INGEST-REVISION HIGH WATER. One row, forever
            -- (`CHECK (id = 0)` makes a second one unrepresentable), holding the greatest
            -- `message_header.ingest_revision` this store has EVER issued.
            --
            -- WHY A COUNTER TABLE AND NOT `MAX(ingest_revision) + 1` OVER THE HEADERS: a MAX
            -- over a table rows can leave is not monotonic — deleting the highest-numbered row
            -- LOWERS it, and the next insert re-issues a value some live reconcile may already
            -- be holding. That is the r5 bug in another costume, so it is not the fix. This
            -- table is never deleted from, so its number never goes down.
            --
            -- The pattern is the house's own: `engine_config.generation` is likewise a
            -- monotone number over an append-only surface, minted inside the transaction that
            -- uses it.
            CREATE TABLE IF NOT EXISTS ingest_revision_seq (
                id         INTEGER PRIMARY KEY CHECK (id = 0),
                high_water INTEGER NOT NULL CHECK (high_water >= 0)
            );
            -- THE BUMP, AND WHY IT IS A TRIGGER. `upsert_header_row` ISSUES `high_water + 1`
            -- inside its single INSERT…ON CONFLICT statement; these triggers raise the high
            -- water to the value that statement just issued, in the SAME statement and
            -- therefore the same atomic unit. That is what makes the issue-then-record pair
            -- indivisible without asking `upsert_header_row` to open a transaction it cannot
            -- open (it takes `&Connection` and is called both standalone AND from inside a
            -- caller's transaction — a nested BEGIN there is an error, and a two-statement
            -- autocommit form would leave a window in which two writers issue one number).
            --
            -- The `WHEN` guard keeps them inert for every write that does NOT itself draw a
            -- fresh revision: the v9 display-normalization migration UPDATEs `message_header`
            -- without moving `ingest_revision` (a bulk backward-compat backfill, not a live
            -- projection mutation, so the predicate is false and no write happens), and a raw
            -- fixture INSERT that omits the column lands at DEFAULT 0 and is likewise inert.
            --
            -- ⚠ A STAR FLIP IS NOT ONE OF THOSE (#24-1b codex-r6 F2, closing a stale scope note
            -- this same comment used to carry). `read_coordinator::write_verb_delta`'s `StarSet`
            -- arm now draws the SAME `high_water + 1` expression `upsert_header_row` does, so
            -- these triggers DO fire for it — see that function's own doc (Uniform, not
            -- per-arm-clever) for why a flag-only write is not exempt: the marker's contract is
            -- 'this row changed since revision N', and a flag flip is a change a later
            -- reconcile's CAS must be able to see.
            --
            -- ⚠ the sqlite.org CREATE-TRIGGER footgun applies here as it does to
            -- `intents_status_activation`: these are deliberately NOT `UPDATE OF
            -- ingest_revision` triggers, because `UPDATE OF` column names are NOT validated and
            -- a future rename would silently stop firing. They fire on ANY update and let the
            -- `WHEN` clause — which names the column in an EXPRESSION, where a rename IS a
            -- compile-time-visible error — decide.
            CREATE TRIGGER IF NOT EXISTS message_header_ingest_revision_ai
                AFTER INSERT ON message_header
                WHEN NEW.ingest_revision >
                     (SELECT high_water FROM ingest_revision_seq WHERE id = 0)
                BEGIN
                    UPDATE ingest_revision_seq SET high_water = NEW.ingest_revision WHERE id = 0;
                END;
            CREATE TRIGGER IF NOT EXISTS message_header_ingest_revision_au
                AFTER UPDATE ON message_header
                WHEN NEW.ingest_revision >
                     (SELECT high_water FROM ingest_revision_seq WHERE id = 0)
                BEGIN
                    UPDATE ingest_revision_seq SET high_water = NEW.ingest_revision WHERE id = 0;
                END;
            CREATE INDEX IF NOT EXISTS idx_folder
                ON message_header(account, mailbox, received_at, message_ref);
            -- FTS5 (token + prefix) over the searchable header columns; external-content so text is
            -- not duplicated. Created BEFORE any insert; the AFTER INSERT trigger keeps it in sync
            -- (external-content FTS does NOT backfill rows that predate the trigger — design §3.1).
            CREATE VIRTUAL TABLE IF NOT EXISTS message_header_fts USING fts5(
                subject, from_addr, from_name,
                content='message_header', content_rowid='rowid',
                prefix='2 3'
            );
            CREATE TRIGGER IF NOT EXISTS message_header_ai AFTER INSERT ON message_header BEGIN
                INSERT INTO message_header_fts(rowid, subject, from_addr, from_name)
                    VALUES (new.rowid, new.subject, new.from_addr, new.from_name);
            END;
            -- External-content FTS5 sync for UPDATE/DELETE (the canonical pattern: a special
            -- 'delete' row removes the OLD tokens, then the new tokens are inserted). Required
            -- because record_header UPSERTs (ON CONFLICT DO UPDATE) — without these the FTS index
            -- desyncs on a re-record (council code-review C3 / codex CLI, 2026-06-26).
            CREATE TRIGGER IF NOT EXISTS message_header_ad AFTER DELETE ON message_header BEGIN
                INSERT INTO message_header_fts(message_header_fts, rowid, subject, from_addr, from_name)
                    VALUES ('delete', old.rowid, old.subject, old.from_addr, old.from_name);
            END;
            CREATE TRIGGER IF NOT EXISTS message_header_au AFTER UPDATE ON message_header BEGIN
                INSERT INTO message_header_fts(message_header_fts, rowid, subject, from_addr, from_name)
                    VALUES ('delete', old.rowid, old.subject, old.from_addr, old.from_name);
                INSERT INTO message_header_fts(rowid, subject, from_addr, from_name)
                    VALUES (new.rowid, new.subject, new.from_addr, new.from_name);
            END;
            -- v8: the always-on append-only generation-numbered config ledger (design §1).
            CREATE TABLE IF NOT EXISTS engine_config (
                generation  INTEGER PRIMARY KEY CHECK (generation >= 1),
                recorded_at INTEGER NOT NULL,
                kind        TEXT NOT NULL,
                payload     TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS engine_config_no_update
                BEFORE UPDATE ON engine_config
                BEGIN SELECT RAISE(ABORT, 'engine_config is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS engine_config_no_delete
                BEFORE DELETE ON engine_config
                BEGIN SELECT RAISE(ABORT, 'engine_config is append-only'); END;
            -- codex-r1 P2: the update/delete pair does NOT cover `INSERT OR REPLACE`. Under
            -- SQLite's default `recursive_triggers=off` the implicit DELETE that REPLACE
            -- performs on the conflicting row fires NO delete trigger, so a recorded act —
            -- including the generation-1 first-run act that admission provenance points at —
            -- could be rewritten in place through an append-only ledger. A BEFORE INSERT
            -- guard on an already-recorded generation closes it (and does not depend on the
            -- recursive_triggers setting, which is per-connection and not ours to assume).
            CREATE TRIGGER IF NOT EXISTS engine_config_no_replace
                BEFORE INSERT ON engine_config
                WHEN EXISTS (SELECT 1 FROM engine_config WHERE generation = NEW.generation)
                BEGIN SELECT RAISE(ABORT, 'engine_config is append-only'); END;
            -- #75 S1 Part A: the root commitment key's NON-SECRET fingerprint (key_custody.rs
            -- `KeyRegistry`). ONE row, written once: a key read back from the OS custodian is
            -- verified against it (restore ≠ import). The key material itself is NEVER in this
            -- store (ADR-P010). Append-once: the CHECK pins the single id, the triggers refuse
            -- UPDATE, DELETE and a REPLACE — re-registration is a refusal, never a rotation
            -- (rotation is a design act). The REPLACE guard is `engine_config_no_replace`'s
            -- (codex-r1 P2, above): a REPLACE's implicit DELETE of the conflicting row fires no
            -- delete trigger under SQLite's default `recursive_triggers=off`, so without it the
            -- update/delete pair would not stop a replace rewriting the row in place.
            CREATE TABLE IF NOT EXISTS commitment_key_registry (
                id           INTEGER PRIMARY KEY CHECK (id = 1),
                fingerprint  TEXT NOT NULL CHECK (length(fingerprint) > 0),
                registered_at TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS commitment_key_registry_no_update
                BEFORE UPDATE ON commitment_key_registry
                BEGIN SELECT RAISE(ABORT, 'commitment_key_registry is write-once'); END;
            CREATE TRIGGER IF NOT EXISTS commitment_key_registry_no_delete
                BEFORE DELETE ON commitment_key_registry
                BEGIN SELECT RAISE(ABORT, 'commitment_key_registry is write-once'); END;
            CREATE TRIGGER IF NOT EXISTS commitment_key_registry_no_replace
                BEFORE INSERT ON commitment_key_registry
                WHEN EXISTS (SELECT 1 FROM commitment_key_registry)
                BEGIN SELECT RAISE(ABORT, 'commitment_key_registry is write-once'); END;
            -- #75 S1 Part C (design v7 §3): THE IMMUTABLE TRIAGE PLAN. Append-only: a plan is
            -- minted once and never edited; a change is a NEW plan (re-plan is one action).
            -- Every digest is an `mw.commitment.v1` tag stored beside its randomizer; the profile
            -- around it is re-derived from the domain (plan.rs), the key_ref columns and the
            -- randomizer. The aggregate view's randomizer is minted at plan freeze and stored
            -- here; its TAG is committed at APPROVAL (Aggregate evidence's `view_digest`), so the
            -- plan row carries no aggregate-view digest. The closed CHECK vocabularies are guarded
            -- against their enums by plan.rs's `the_plan_vocabularies_match_their_ddl_check_constraints`.
            -- The three `_no_replace` guards are `commitment_key_registry_no_replace`'s: a REPLACE's
            -- implicit DELETE fires no delete trigger under the default recursive_triggers=off.
            CREATE TABLE IF NOT EXISTS triage_plan (
                plan_id                  TEXT PRIMARY KEY,
                account                  TEXT NOT NULL,
                provider_principal       TEXT NOT NULL,
                grant_generation         INTEGER NOT NULL CHECK (grant_generation >= 0),
                control_epoch            INTEGER NOT NULL,
                verb                     TEXT NOT NULL CHECK (verb IN ('trash','mark_spam')),
                tier                     TEXT NOT NULL CHECK (tier = 'red'),
                rationale                TEXT,
                minted_at                TEXT NOT NULL,
                expires_at               TEXT NOT NULL,
                member_count             INTEGER NOT NULL CHECK (member_count >= 1),
                admission_lane           TEXT NOT NULL CHECK (admission_lane IN ('per_member','aggregate','bypassed')),
                bypass_config_generation INTEGER,
                approval_mode            TEXT NOT NULL CHECK (approval_mode IN ('full_list','summary_sample')),
                configured_k             INTEGER CHECK (configured_k IS NULL OR configured_k >= 1),
                effective_k              INTEGER CHECK (effective_k IS NULL OR effective_k >= 1),
                coverage_generation      INTEGER NOT NULL CHECK (coverage_generation >= 0),
                backups_on               INTEGER NOT NULL CHECK (backups_on IN (0,1)),
                -- The header's §4.7 verb-specific warning, FROZEN as minted (the presentation
                -- digest covers it): present exactly when backups are OFF, never empty.
                warning                  TEXT,
                set_digest               TEXT NOT NULL, set_randomizer          TEXT NOT NULL,
                state_digest             TEXT NOT NULL, state_randomizer        TEXT NOT NULL,
                presentation_digest      TEXT NOT NULL, presentation_randomizer TEXT NOT NULL,
                shape_digest             TEXT NOT NULL, shape_randomizer        TEXT NOT NULL,
                sample_seed              TEXT NOT NULL, sample_seed_randomizer  TEXT NOT NULL,
                aggregate_view_randomizer TEXT NOT NULL,
                key_ref_namespace        TEXT NOT NULL,
                key_ref_epoch            INTEGER NOT NULL CHECK (key_ref_epoch >= 1),
                -- #75 S1 Part-D review r1 F1: THE BYPASS-LANE NOTICE (design v7 §3: the bypass
                -- waives the screen, never the notice) — the verb's §4.7 warning, FROZEN at mint
                -- exactly when the lane is 'bypassed' and backups are OFF; NULL otherwise. A NULL on
                -- such a plan (a row minted before this column existed) is refused at the send fence
                -- (`PlanSendRefusal::BypassNoticeAbsent`). IN-VERSION accretion (v10 stays v10), last
                -- column, so a fresh and an upgraded store carry the same column order; the CHECK
                -- rides the ALTER in `IN_VERSION_COLUMN_UPGRADES`.
                bypass_notice            TEXT CHECK (bypass_notice IS NULL
                                             OR (admission_lane = 'bypassed' AND backups_on = 0 AND length(bypass_notice) > 0)),
                CHECK ((backups_on = 1 AND warning IS NULL)
                    OR (backups_on = 0 AND warning IS NOT NULL AND length(warning) > 0))
            );
            CREATE TRIGGER IF NOT EXISTS triage_plan_no_update BEFORE UPDATE ON triage_plan
                BEGIN SELECT RAISE(ABORT, 'triage_plan is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS triage_plan_no_delete BEFORE DELETE ON triage_plan
                BEGIN SELECT RAISE(ABORT, 'triage_plan is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS triage_plan_no_replace BEFORE INSERT ON triage_plan
                WHEN EXISTS (SELECT 1 FROM triage_plan WHERE plan_id = NEW.plan_id)
                BEGIN SELECT RAISE(ABORT, 'triage_plan is append-only'); END;
            -- One row per canonical member: the Photon logical identity ONLY (no provider handle,
            -- bot r17 P1), the frozen display, the approval-time observed state, the forward target.
            ";

/// `plan_member`'s CREATE TABLE, factored out the way [`MESSAGE_HEADER_TABLE_DDL`] is (see that
/// constant's doc). Its FK (`plan_id ... REFERENCES triage_plan(plan_id)`) names `triage_plan`,
/// never `plan_member`, so `.replacen("plan_member", <temp name>, 1)` always hits this table's
/// own name in `CREATE TABLE IF NOT EXISTS plan_member (`. The vocabulary CHECK on
/// `sender_status` is gone for the same reason; the cross-column shape CHECKs on
/// `sender_addr`/`sender_domain` are unchanged.
const PLAN_MEMBER_TABLE_DDL: &str = "
            CREATE TABLE IF NOT EXISTS plan_member (
                plan_id        TEXT NOT NULL REFERENCES triage_plan(plan_id),
                message_ref    TEXT NOT NULL,
                sender         TEXT NOT NULL,
                subject        TEXT NOT NULL,
                date           TEXT NOT NULL,
                size           INTEGER,
                observed_state TEXT NOT NULL,
                forward_target TEXT NOT NULL,
                -- #75 S1 council r2 (seat 3, S3-1): the member's STRUCTURED sender, frozen at mint
                -- from the header row's `from_status` / `from_addr` / `from_domain` — the status
                -- token, and the addr-spec and its domain, each present exactly when the status is
                -- `ok`. The summary's sender domains are derived from these, never from `sender`
                -- (display text). DEFAULT 'unavailable' for the ALTER-added upgrade population (a
                -- member an earlier build froze has no parse on record). #75 S1 r3 fold class A2
                -- (TAR-PIT Q4): the vocabulary CHECK is gone — `mailbox::SenderStatus`'s closed
                -- token table is the one vocabulary authority; this column keeps only its SHAPE.
                sender_status  TEXT NOT NULL DEFAULT 'unavailable',
                sender_addr    TEXT CHECK ((sender_addr IS NOT NULL) = (sender_status = 'ok')),
                sender_domain  TEXT CHECK ((sender_domain IS NOT NULL) = (sender_status = 'ok')),
                -- #75 S1 r3 fold (class C, seat 1 F1): the address half's OWN frozen display copy,
                -- carried separately from `sender` (the name half) so the row can isolate them
                -- into two `<bdi>`s — never one composed name-plus-address string. DEFAULT ''
                -- for the ALTER-added upgrade population (a member an earlier build froze has no
                -- split address on record; the next mint of that message re-freezes it).
                sender_address TEXT NOT NULL DEFAULT '',
                -- #75 S1 r5 fold (class I2, STRUCTURED-SENDER / NO-REPARSE): the local-part half,
                -- alongside `sender_addr`/`sender_domain` — present exactly when the status is
                -- `ok`, from the SAME grammar tokens `sender_addr` is (see
                -- `ParsedMailbox::local_part`'s own doc), never derived by splitting
                -- `sender_addr` on its `@`. Positioned LAST (after `sender_address`, not beside
                -- its sibling `sender_addr`/`sender_domain`) so a fresh store's column order
                -- matches an upgraded store's: `IN_VERSION_COLUMN_UPGRADES` always `ADD COLUMN`s
                -- at the end of the table, and `schema_fingerprint`'s cid-ordered comparison
                -- (`council_r2_s3_1_the_sender_columns_arrive_in_version_on_an_upgraded_store`)
                -- requires the two to agree column-for-column. DEFAULT NULL for the ALTER-added
                -- upgrade population (a member an earlier build froze has no local-part on record;
                -- the next mint of that message re-freezes it, exactly like
                -- `sender_addr`/`sender_domain` already did for THEIR own upgrade population).
                sender_local   TEXT CHECK ((sender_local IS NOT NULL) = (sender_status = 'ok')),
                PRIMARY KEY (plan_id, message_ref)
            );
            ";

const SCHEMA_DDL_STATIC_TAIL: &str = "
            CREATE TRIGGER IF NOT EXISTS plan_member_no_update BEFORE UPDATE ON plan_member
                BEGIN SELECT RAISE(ABORT, 'plan_member is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS plan_member_no_delete BEFORE DELETE ON plan_member
                BEGIN SELECT RAISE(ABORT, 'plan_member is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS plan_member_no_replace BEFORE INSERT ON plan_member
                WHEN EXISTS (SELECT 1 FROM plan_member WHERE plan_id = NEW.plan_id AND message_ref = NEW.message_ref)
                BEGIN SELECT RAISE(ABORT, 'plan_member is append-only'); END;
            -- A NEW member row for an already-minted plan would edit its member set through an
            -- append-only table (neither the update nor the delete guard sees an INSERT): the plan
            -- row's frozen `member_count` bounds its member rows, so the mint's own N inserts are
            -- the only ones that fit.
            CREATE TRIGGER IF NOT EXISTS plan_member_within_member_count BEFORE INSERT ON plan_member
                WHEN (SELECT COUNT(*) FROM plan_member WHERE plan_id = NEW.plan_id)
                     >= COALESCE((SELECT member_count FROM triage_plan WHERE plan_id = NEW.plan_id), 0)
                BEGIN SELECT RAISE(ABORT, 'plan_member is bounded by the plan member_count'); END;
            -- The positive decision, minted against ONE plan instance (bot r4). One per plan.
            CREATE TABLE IF NOT EXISTS approval_evidence (
                plan_id                  TEXT PRIMARY KEY REFERENCES triage_plan(plan_id),
                approver                 TEXT NOT NULL,
                approved_at              TEXT NOT NULL,
                decision                 TEXT NOT NULL CHECK (decision = 'approved'),
                view_digest              TEXT NOT NULL,
                comprehension            TEXT NOT NULL CHECK (comprehension IN ('per_member','aggregate','bypassed')),
                shape_digest             TEXT,
                sample_k                 INTEGER,
                sample_members           TEXT,
                bypass_config_generation INTEGER
            );
            CREATE TRIGGER IF NOT EXISTS approval_evidence_no_update BEFORE UPDATE ON approval_evidence
                BEGIN SELECT RAISE(ABORT, 'approval_evidence is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS approval_evidence_no_delete BEFORE DELETE ON approval_evidence
                BEGIN SELECT RAISE(ABORT, 'approval_evidence is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS approval_evidence_no_replace BEFORE INSERT ON approval_evidence
                WHEN EXISTS (SELECT 1 FROM approval_evidence WHERE plan_id = NEW.plan_id)
                BEGIN SELECT RAISE(ABORT, 'approval_evidence is append-only'); END;
            -- #75 S1 Part D (design v7 §3, v3 §3): THE EXECUTION EPISODE — one per plan, EVER
            -- (the PRIMARY KEY). The head row: every write bumps `generation` under a
            -- compare-and-set (`UPDATE ... WHERE plan_id = ? AND generation = ?`) and appends one
            -- `episode_journal` row. `status_reason` is the typed reason JSON (`episode.rs`): the
            -- S1 doors write it only with 'invalidated' (none writes 'paused'), and the reader
            -- (`EpisodeStatus::from_columns`) refuses any other pairing. The status CHECK lists are guarded
            -- against `EpisodeStatusToken::ALL` (and the event CHECK against `EpisodeEvent::ALL`)
            -- by episode.rs's `tokens_round_trip_and_the_ddl_check_is_regenerated_from_the_enum`.
            CREATE TABLE IF NOT EXISTS execution_episode (
                plan_id       TEXT PRIMARY KEY REFERENCES triage_plan(plan_id),
                episode_id    TEXT NOT NULL,
                status        TEXT NOT NULL CHECK (status IN ('active','paused','cancelled','completed','invalidated')),
                status_reason TEXT,
                generation    INTEGER NOT NULL CHECK (generation >= 1),
                claim_epoch   INTEGER NOT NULL,
                started_at    TEXT NOT NULL,
                ready_at      TEXT,
                completed_at  TEXT,
                updated_at    TEXT NOT NULL
            );
            -- Every episode write, in generation order. Append-only: the three guards are
            -- `approval_evidence`'s (a REPLACE's implicit DELETE fires no delete trigger under the
            -- default recursive_triggers=off, hence the `_no_replace` guard).
            CREATE TABLE IF NOT EXISTS episode_journal (
                plan_id     TEXT NOT NULL REFERENCES execution_episode(plan_id),
                generation  INTEGER NOT NULL CHECK (generation >= 1),
                status      TEXT NOT NULL CHECK (status IN ('active','paused','cancelled','completed','invalidated')),
                reason      TEXT,
                event       TEXT NOT NULL CHECK (event IN ('start','ready','transition')),
                at          TEXT NOT NULL,
                PRIMARY KEY (plan_id, generation)
            );
            CREATE TRIGGER IF NOT EXISTS episode_journal_no_update BEFORE UPDATE ON episode_journal
                BEGIN SELECT RAISE(ABORT, 'episode_journal is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS episode_journal_no_delete BEFORE DELETE ON episode_journal
                BEGIN SELECT RAISE(ABORT, 'episode_journal is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS episode_journal_no_replace BEFORE INSERT ON episode_journal
                WHEN EXISTS (SELECT 1 FROM episode_journal WHERE plan_id = NEW.plan_id AND generation = NEW.generation)
                BEGIN SELECT RAISE(ABORT, 'episode_journal is append-only'); END;
            -- v8: the control-epoch singleton (design §5.1; bumped only by the stage-4
            -- sever). codex-r9 P1: the row is SEEDED AT BOOTSTRAP ONLY — an
            -- IF-NOT-EXISTS seed here re-ran on every open, so a lost singleton
            -- (corruption, accidental DELETE) silently re-minted epoch 1 and rolled the
            -- sole control fence back below any prior sever. A verified store missing
            -- the row REFUSES at the open chokepoint instead (fail closed).
            CREATE TABLE IF NOT EXISTS control_epoch (
                id    INTEGER PRIMARY KEY CHECK (id = 1),
                epoch INTEGER NOT NULL
            );
            -- v8 (#24 stage 2, design §2.2b/§2.3/§7a): the pre-state journal. The row IS
            -- the PREPARE phase — no `prepared` flag exists anywhere (r3: an independently
            -- writable flag is a second drifting projection). intent_id is NOT NULL (a NULL
            -- FK is 'valid' to SQLite and UNIQUE admits multiple NULLs — codex r13 P2),
            -- UNIQUE (one-to-one attachment), FK → intents.intent_id (NOT NULL UNIQUE since
            -- stage 1). No reverse pointer exists (the v2 cross-attach class stays deleted).
            CREATE TABLE IF NOT EXISTS pre_state (
                journal_id        TEXT NOT NULL UNIQUE,
                intent_id         TEXT NOT NULL UNIQUE REFERENCES intents(intent_id),
                observed          TEXT NOT NULL,
                touched_atom      TEXT NOT NULL,
                resolved_operands TEXT NOT NULL,
                fetched_at        TEXT NOT NULL,
                source            TEXT NOT NULL,
                request_id        TEXT,
                captured_epoch    INTEGER NOT NULL,
                mode_generation   INTEGER NOT NULL,
                undo_offer_until  TEXT NOT NULL,
                -- v8 (#24 stage 4 Task 9, design §5.2a codex r36 P1): WHICH capture this row
                -- is. PREPARE writes generation 1; the ONE narrow exception to §2.2b's
                -- insert-or-nothing rule — the retry-requalification RE-PREPARE — replaces
                -- the row and increments it. The design's word for that replace is
                -- VERSIONED, and this is the version: without it, old-or-new-never-a-blend
                -- is a claim about two rows that spell their difference only in their
                -- content. Monotonic per intent; the row is still one-to-one.
                capture_generation INTEGER NOT NULL DEFAULT 1 CHECK (capture_generation >= 1),
                -- #75 S1 (Task B8): the FULL provider label vector the capture's observe read
                -- returned — the pre-effect vector the ripple check judges against — as the
                -- canonical JSON array `prestate::label_vector_json` spells; NULL = the read
                -- yielded no vector. NOT an atom map (`JournalRow::validate` does not read it).
                -- In-version accretion, like `capture_generation` above.
                observed_label_vector TEXT
            );
            -- v8 (#24 stage 2): expiry tombstones (§6 — DORMANT; retention/destruction is
            -- stage 5). Stage-2's ONLY consumer is the reverse-gap integrity scan's
            -- exclusion (§2.2b codex r6 P2: a legitimately expired row leaves exactly the
            -- required-parent-without-child shape — the tombstone explains it).
            CREATE TABLE IF NOT EXISTS pre_state_tombstone (
                journal_id  TEXT NOT NULL UNIQUE,
                intent_id   TEXT NOT NULL,
                expired_at  TEXT NOT NULL
            );
            -- v8 (#24 stage 3, design §4.4 codex r32 P2): the sticky-Expired latch. ONE
            -- row holding the maximum wall-clock ever observed by an undo evaluation —
            -- RFC-3339 UTC seconds (fixed-width ⇒ lexicographic order IS time order). A
            -- wall-clock rollback can never re-open an expired undo offer: evaluations
            -- use max(now, max_seen) and advance the latch monotonically.
            CREATE TABLE IF NOT EXISTS time_high_water (
                id       INTEGER PRIMARY KEY CHECK (id = 1),
                max_seen TEXT NOT NULL
            );
            -- v8 (#24 stage 4, design §5.2a/§7a): the ONE append-only attempt-fact table —
            -- the CLOSED grammar's durable ledger (v3's five fact tables invited drift; this
            -- is the adopted simpler fixed point). `operation_id` is the IMMUTABLE OWNER (set
            -- at the CLAIM fact, identical on every fact of the attempt — r4: ownership was
            -- underivable without it). `attempt_id` is opaque, minted at the first (CLAIM)
            -- fact. `revision` is the compare-and-append arbiter: UNIQUE (attempt_id,
            -- revision) is the mechanical race referee a lost append reads back through (never
            -- a hand-rolled error). `attempt_ordinal` carries the CLAIM fact's retry ordinal
            -- and is NULL on every other fact kind — SQLite's UNIQUE treats each NULL as
            -- distinct, so only the one CLAIM row per attempt participates in
            -- ATTEMPT-ORDINAL/RETRY-TOTALITY's `UNIQUE (operation_id, attempt_ordinal)` (the
            -- SQL half of the append fn's ordinal/predecessor legality, §5.2a). `fact_kind` is
            -- the 13-member CLOSED grammar (§5.2a transcription) — a 14th kind is a schema
            -- change, never a silent string. `created_at` carries the clamped-monotonic
            -- contract (`max(now_utc, max_persisted)`, Task 2's helper writes it; this column
            -- makes no promise beyond durable text). `payload` is typed-per-kind JSON (ack
            -- detail / reconcile observation / adjudication record ref / retry reason /
            -- predecessor attempt id / the SEND_AUTHORIZED frozen-operand basis).
            -- `prior_revision` is the revision this fact was appended against (NULL for the
            -- first fact of an attempt). Append-only triggers below mirror `engine_config`'s
            -- three-trigger pattern exactly (UPDATE / DELETE / INSERT OR REPLACE all refused)
            -- — the fact chain is the system-of-record for attempt state; a rewritable ledger
            -- is not one.
            CREATE TABLE IF NOT EXISTS attempt_fact (
                operation_id    TEXT NOT NULL,
                attempt_id      TEXT NOT NULL,
                revision        INTEGER NOT NULL,
                fact_kind       TEXT NOT NULL CHECK (fact_kind IN (
                    'claim', 'send_authorized', 'ack_applied', 'ack_refused_no_effect',
                    'failed_pre_send', 'ack_ambiguous', 'reconcile_state_matches',
                    'reconcile_state_differs', 'severed_before_issuance',
                    'adjudicated_unresolved', 'late_ack_applied',
                    'late_ack_refused_no_effect', 'superseded_by'
                )),
                attempt_ordinal INTEGER,
                basis_epoch     INTEGER NOT NULL,
                created_at      TEXT NOT NULL,
                payload         TEXT NOT NULL,
                prior_revision  INTEGER,
                UNIQUE (attempt_id, revision),
                UNIQUE (operation_id, attempt_ordinal)
            );
            CREATE TRIGGER IF NOT EXISTS attempt_fact_no_update
                BEFORE UPDATE ON attempt_fact
                BEGIN SELECT RAISE(ABORT, 'attempt_fact is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS attempt_fact_no_delete
                BEFORE DELETE ON attempt_fact
                BEGIN SELECT RAISE(ABORT, 'attempt_fact is append-only'); END;
            -- codex-r1 P2 pattern (engine_config precedent): recursive_triggers=off means the
            -- implicit DELETE an INSERT OR REPLACE performs on a UNIQUE conflict fires no
            -- delete trigger — closed the same way, on EVERY conflict key the table declares.
            --   BOTH keys, not one (codex-CLI r1 P2, 2026-08-08): this WHEN originally covered
            -- only `(attempt_id, revision)`, the compare-and-append arbiter. An INSERT OR
            -- REPLACE carrying a FRESH (attempt_id, revision) passes that test and then
            -- conflicts on the OTHER constraint — `UNIQUE (operation_id, attempt_ordinal)` —
            -- whose implicit DELETE silently removed the original CLAIM, rewriting the
            -- retry-lineage referee out of an append-only ledger. A guard that covers one of a
            -- table's two unique keys is not a guard.
            --   The DROP is what makes the correction LAND on a dev store created by an
            -- earlier build of this branch: `CREATE TRIGGER IF NOT EXISTS` under the same name
            -- would leave the one-key definition in place forever (the same reason
            -- `idx_intents_native_key` is dropped above). Pre-release accretion, not a
            -- migration — there is no released population, and a trigger holds no data of its
            -- own.
            DROP TRIGGER IF EXISTS attempt_fact_no_replace;
            CREATE TRIGGER IF NOT EXISTS attempt_fact_no_replace
                BEFORE INSERT ON attempt_fact
                WHEN EXISTS (
                    SELECT 1 FROM attempt_fact
                     WHERE attempt_id = NEW.attempt_id AND revision = NEW.revision
                ) OR EXISTS (
                    SELECT 1 FROM attempt_fact
                     WHERE NEW.attempt_ordinal IS NOT NULL
                       AND operation_id = NEW.operation_id
                       AND attempt_ordinal = NEW.attempt_ordinal
                )
                BEGIN SELECT RAISE(ABORT, 'attempt_fact is append-only'); END;
            -- EXP-10's BOUND applied to the FACT CLOCK (codex-CLI r7 P2-2). Every door that
            -- appends a fact clamps its instant against `MAX(created_at)` over this table
            -- (`FACT_CLOCK_HIGH_WATER_SQL`) — the CLAIM, the authorization, every verdict, the
            -- sever, the adjudication, the late ack. This table is append-only and nothing
            -- evicts, so unindexed that read is a full pass over the store's entire history:
            -- the cost of EVERY fact door becomes a function of how much the engine has ever
            -- done, which is the same unbounded-by-history shape the exposure fence had.
            -- SQLite's MIN/MAX optimization turns `MAX(col)` on an indexed col into a single
            -- seek to the last index entry, so this ordinary index closes the whole class —
            -- and closes it WITHOUT a stored high-water row, which would be a second authority
            -- for the clock beside the ledger it is derived from. Same guarded-index
            -- discipline as `idx_exposure_obligation_live`: the `EXPLAIN QUERY PLAN` witness
            -- in the tests below runs the doors' own query text and asserts the plan.
            CREATE INDEX IF NOT EXISTS idx_attempt_fact_created_at
                ON attempt_fact (created_at);
            -- v8 (#24 stage 4, design §7a codex-CLI r4 P2): the durable O(1) projection over
            -- the fact chain, updated in the SAME transaction as every fact append. NOT
            -- append-only — it is a PROJECTION; its §5.2a safety sentence, verbatim:
            --   maintained transactionally with the append (cannot drift) and re-derivable
            --   from the chain (W-ATTEMPT-GRAMMAR asserts head == fold on every probe).
            -- Divergence between this row and the fold over attempt_fact is a fail-loud
            -- open refusal, never silently trusted (the derived restatement — never a
            -- second authority). last_verified_revision + verified_state are the
            -- incremental-verification watermark (O(delta) reverify on open, §5.2a).
            CREATE TABLE IF NOT EXISTS attempt_head (
                attempt_id              TEXT PRIMARY KEY,
                operation_id            TEXT NOT NULL,
                current_revision        INTEGER NOT NULL,
                derived_class           TEXT NOT NULL,
                last_verified_revision  INTEGER NOT NULL,
                verified_state          TEXT NOT NULL
            );
            -- v8 (#24 stage 4, design §5.2d/§7a): the immutable adjudication record — an
            -- authority-gated CONTROL TRANSITION on an already-counted unknown operation, not
            -- a new operation. CLOSED vocabularies throughout (codex r20 P1: the gate is
            -- implementable only over a named enum) — NO free text anywhere (codex r19 P1: a
            -- pasted excerpt would durably store mailbox content while deletion is dormant,
            -- violating the no-content posture). `opaque_reference` is the OPTIONAL
            -- engine-minted-or-FK-validated reference (codex r27 P1): the caller-supplied-
            -- reference channel does not exist at this layer — a build wiring `adjudicate()`
            -- either leaves it NULL, mints it inside the SAME transaction, or FK-validates it
            -- against an existing engine row; this column never accepts free bytes from a
            -- caller. `known_at_snapshot` is fact-derived and content-free by construction
            -- (what was known at decision time). `exposure_key` is the touched-atom exposure
            -- key, derived from the attempt's SEND_AUTHORIZED payload (never re-resolved).
            -- Append-only triggers mirror `engine_config`'s three-trigger pattern — the record,
            -- once written, is immutable; retirement/resolution lives in `attempt_fact`'s
            -- LATE_ACK_* facts and `exposure_obligation.retired_at`, never a rewrite here.
            CREATE TABLE IF NOT EXISTS adjudication_record (
                adjudication_id  TEXT PRIMARY KEY,
                attempt_id       TEXT NOT NULL REFERENCES attempt_head(attempt_id),
                principal_ref    TEXT NOT NULL,
                basis_epoch      INTEGER NOT NULL,
                accepted_risk    TEXT NOT NULL CHECK (accepted_risk IN (
                    'duplicate-effect-possible', 'reversal-possible', 'none-claimed'
                )),
                reason           TEXT NOT NULL CHECK (reason IN (
                    'operator-abandoned-unresolved', 'presumed-transport-loss',
                    'superseding-user-instruction', 'capacity-recovery'
                )),
                opaque_reference TEXT,
                known_at_snapshot TEXT NOT NULL,
                exposure_key     TEXT NOT NULL,
                created_at       TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS adjudication_record_no_update
                BEFORE UPDATE ON adjudication_record
                BEGIN SELECT RAISE(ABORT, 'adjudication_record is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS adjudication_record_no_delete
                BEFORE DELETE ON adjudication_record
                BEGIN SELECT RAISE(ABORT, 'adjudication_record is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS adjudication_record_no_replace
                BEFORE INSERT ON adjudication_record
                WHEN EXISTS (
                    SELECT 1 FROM adjudication_record WHERE adjudication_id = NEW.adjudication_id
                )
                BEGIN SELECT RAISE(ABORT, 'adjudication_record is append-only'); END;
            -- v8 (#24 stage 4, design §5.2d EXP-1/EXP-2/§7a): the durable EXP-2 obligation — a
            -- possibly-effectful attempt whose historical attribution remains UNKNOWN after
            -- adjudication creates one row per primitive atom it may have touched (capture-off
            -- does not exempt it). EXP-1 identity key: account/provider scope + the
            -- provider-native primitive touched atom + effect direction (where direction
            -- matters) + generation (EXP-9: a later independent unresolved episode on the SAME
            -- atom is a NEW generation — old rows never authorize or contaminate it).
            --   THE SCOPE IS THE PROVIDER'S (codex-CLI r1 P1, 2026-08-08): `provider_scope`
            -- carries the operation's frozen `native_resource_key`, NOT the Photon-local
            -- account handle this column used to hold. Two local handles resolving to one
            -- provider account produced identical `primitive_atom` values under different
            -- local handles, and a join that included the local column MISSED the live
            -- obligation. `primitive_atom` is `exposure_atom_key(native_resource_key, atom)` —
            -- already fully provider-scoped through the crate's one injective encoding — so it
            -- is the whole identity that the uniqueness and every lookup key on;
            -- `provider_scope` is the durable audit scope EXP-1 names, never a join column.
            -- `contributor_attempt_id` is the FK to the attempt that created the obligation.
            -- `retired_at` is nullable (EXP-8: retirement is driven by the historical axis and
            -- acceptance settlement, never a separate counter's arithmetic) — MUTABLE
            -- (retirement UPDATEs this one column; not append-only, unlike the two ledgers
            -- above).
            CREATE TABLE IF NOT EXISTS exposure_obligation (
                obligation_id          TEXT PRIMARY KEY,
                provider_scope         TEXT NOT NULL,
                primitive_atom         TEXT NOT NULL,
                direction              TEXT NOT NULL,
                generation             INTEGER NOT NULL,
                contributor_attempt_id TEXT NOT NULL REFERENCES attempt_head(attempt_id),
                created_at             TEXT NOT NULL,
                retired_at             TEXT,
                UNIQUE (primitive_atom, direction, generation, contributor_attempt_id)
            );
            -- EXP-10's BOUND, made structural (codex-CLI r1 P2, 2026-08-08): the EXP-3 fence's
            -- absence-proof asks whether ANY obligation on this atom is still LIVE. On the
            -- UNIQUE index alone that walks every row the atom ever had — and nothing evicts,
            -- so the retired history only grows, making the fence's cost a function of history
            -- length, which is exactly what EXP-10 forbids. This PARTIAL index indexes only the
            -- live rows, so the proof is O(live) and independent of settled history. Same
            -- guarded-index discipline as `idx_intents_native_key_guarded`: the WHERE clause is
            -- the index's own, and the fence's query text implies it (`EXPLAIN QUERY PLAN`
            -- witness in the tests below asserts the real query rides it).
            CREATE INDEX IF NOT EXISTS idx_exposure_obligation_live
                ON exposure_obligation (primitive_atom)
                WHERE retired_at IS NULL;
            -- …AND THE RETIRED-BUT-OVERLAPPING HALF (codex-CLI r14 P2-3). EXP-7's contributor
            -- scan asks a WIDER question than the fence does: an episode counts if it was live
            -- at the applying attempt's own effect-release boundary, so a RETIRED row still
            -- qualifies when it retired at-or-after that instant. Written as one predicate
            -- (`retired_at IS NULL OR retired_at >= ?`), SQLite could index NEITHER arm — an OR
            -- is only indexable when every arm is — and the plan walked the atom's whole
            -- retired history through the UNIQUE constraint's autoindex prefix, inside the
            -- SETTLING WRITER TRANSACTION. `EXPOSURE_CONTRIBUTORS_SQL` is now a UNION of two
            -- indexable arms; this is the second arm's index, and it is PARTIAL for the same
            -- reason its sibling is — it holds only the rows that arm can match, so it does not
            -- duplicate the live index's entries and it is not paid for by a row that has never
            -- retired. `retired_at` is the second key column so the retirement bound is a range
            -- seek, not a filter over the atom. Same guarded-index discipline: the arm's own
            -- WHERE names `retired_at IS NOT NULL` so the implication is provable, and the
            -- `EXPLAIN QUERY PLAN` witness below runs the real query text.
            CREATE INDEX IF NOT EXISTS idx_exposure_obligation_retired
                ON exposure_obligation (primitive_atom, retired_at)
                WHERE retired_at IS NOT NULL;
            -- EXP-10's BOUND, once more, at the GENERATION mint's fallback (codex-CLI r19
            -- P2-1): once the live-obligation probe above comes back empty,
            -- `EXPOSURE_GENERATION_HIGH_WATER_SQL` asks MAX(generation) over the atom's WHOLE
            -- history (EXP-9: nothing evicts a retired row, so the next generation is
            -- max-over-everything + 1). `UNIQUE (primitive_atom, direction, generation,
            -- contributor_attempt_id)` puts `direction` BETWEEN the constrained `primitive_atom`
            -- and the aggregated `generation`, so SQLite's MIN/MAX single-row optimization
            -- cannot fire on that autoindex — `EXPLAIN QUERY PLAN` still labels the step
            -- `SEARCH … (primitive_atom=?)`, not `SCAN` (the autoindex prefix genuinely bounds
            -- the walk to one atom), so this is a scan of the atom's whole history WEARING a
            -- SEARCH label. This is an ORDINARY (non-partial) index — unlike its two siblings
            -- above, this read's own domain IS the whole history, live and retired, so there is
            -- no narrower WHERE to key a partial index off. `generation` sits immediately after
            -- the constrained `primitive_atom`, which is what the MIN/MAX optimization needs to
            -- turn the walk into a real seek. Same guarded-index discipline: the `EXPLAIN QUERY
            -- PLAN` witness in the tests below runs the real query text.
            CREATE INDEX IF NOT EXISTS idx_exposure_obligation_generation
                ON exposure_obligation (primitive_atom, generation);
            -- EXP-10's BOUND at EXP-8's RETIREMENT write (codex-CLI r19 P2-2).
            -- `EXPOSURE_RETIREMENT_BY_CONTRIBUTOR_SQL` runs once per late ack, inside the writer
            -- transaction that also appends the fact: `UPDATE … WHERE contributor_attempt_id =
            -- ?1 AND retired_at IS NULL`. No existing index on this table starts with
            -- `contributor_attempt_id` — every one keys off `primitive_atom` first — so the
            -- query landed on `idx_exposure_obligation_live` (its `retired_at IS NULL` arm is
            -- implied) but as a SCAN restricted to the live partition: every live obligation the
            -- store has ever carried, not just this one attempt's, and nothing ever deletes a
            -- row out of that partition. This PARTIAL index is keyed on
            -- `contributor_attempt_id` under the SAME `WHERE retired_at IS NULL`, turning the
            -- scan into a seek on the one contributor the late ack names — and it is partial for
            -- the same reason `idx_exposure_obligation_live` is: a retired row can never again
            -- match this `UPDATE`'s own `WHERE`, so indexing it would be pure write cost with no
            -- reader it could ever serve. Same guarded-index discipline: the `EXPLAIN QUERY
            -- PLAN` witness in the tests below runs the real `UPDATE` text (`EXPLAIN QUERY PLAN`
            -- plans `UPDATE` statements the same way it plans `SELECT`).
            CREATE INDEX IF NOT EXISTS idx_exposure_obligation_contributor
                ON exposure_obligation (contributor_attempt_id)
                WHERE retired_at IS NULL;
            -- v8 (#24 stage 4 Task 10, design §5.2d/§5.2a): the append-only ANNOTATION ledger
            -- of an adjudication record. `adjudication_record` is IMMUTABLE by trigger, and both
            -- things §5.2d says must never be silent become true strictly AFTER it is written:
            -- the CONTRADICTORY-second-late-ack anomaly (§5.2a: durably recorded as an anomaly
            -- annotation ON the adjudication record) and EXP-7's materialization notice (a
            -- durable notice exists and is discoverable from the relevant adjudication
            -- records). A sibling keyed by `adjudication_id` is the only shape that satisfies
            -- both sentences without making the record rewritable.
            --   …and the THIRD thing the same §5.2a paragraph says must never be silent
            -- (codex-CLI r5 P2-4): a late NON-DEFINITIVE observation lives in the adjudication
            -- record ANCILLARY AUDIT TRAIL, never the closed grammar. Same reason, same
            -- shape, same ledger — `late-ambiguous-observation`. IN-VERSION accretion (the
            -- `IN_VERSION_COLUMN_UPGRADES` premise above, verbatim: this table is one THIS
            -- branch created, `origin/main` stores create it whole from this DDL, and a store
            -- from an earlier commit OF THIS BRANCH carries the narrower CHECK and fails loud —
            -- acceptable, because branch-local dev stores are resettable). The version stays 8.
            --   `kind` is the CLOSED vocabulary of `crate::attempt::AnomalyKind` (guard test
            -- below regenerates this CHECK list from the enum). `related_attempt_id` is an
            -- ENGINE id (the contradicting/other-contributor attempt), never free bytes;
            -- `atom_key` is the content-free EXP-1 atom identity. Both are NULL where the kind
            -- does not carry them. There is NO free-text column, here either.
            CREATE TABLE IF NOT EXISTS adjudication_annotation (
                annotation_id      TEXT PRIMARY KEY,
                adjudication_id    TEXT NOT NULL REFERENCES adjudication_record(adjudication_id),
                kind               TEXT NOT NULL CHECK (kind IN (
                    'contradictory-late-ack', 'applied-over-unresolved', 'exposure-materialized',
                    'late-ambiguous-observation'
                )),
                related_attempt_id TEXT,
                atom_key           TEXT,
                created_at         TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS adjudication_annotation_no_update
                BEFORE UPDATE ON adjudication_annotation
                BEGIN SELECT RAISE(ABORT, 'adjudication_annotation is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS adjudication_annotation_no_delete
                BEFORE DELETE ON adjudication_annotation
                BEGIN SELECT RAISE(ABORT, 'adjudication_annotation is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS adjudication_annotation_no_replace
                BEFORE INSERT ON adjudication_annotation
                WHEN EXISTS (
                    SELECT 1 FROM adjudication_annotation
                     WHERE annotation_id = NEW.annotation_id
                )
                BEGIN SELECT RAISE(ABORT, 'adjudication_annotation is append-only'); END;
            -- EXP-10's BOUND at the MATERIALIZATION HALF-TRACE read (codex-CLI r19 P2-3).
            -- `adjudication_annotation` is indexed only by its own `PRIMARY KEY`
            -- (`annotation_id`); every other column, including `adjudication_id`, has no index
            -- at all, so `ADJUDICATION_ANNOTATION_HALF_TRACE_SQL`'s `WHERE adjudication_id = ?1
            -- AND kind = ?2` planned a full `SCAN adjudication_annotation` — a pass over every
            -- annotation the store has EVER written, inside the late-ack writer transaction, on
            -- every APPLIED late ack whose attempt is itself adjudicated. This table is
            -- append-only (the three triggers above), so nothing evicts an annotation and that
            -- cost grows with total annotation history — the same unbounded-by-history shape
            -- EXP-10 forbids everywhere else in this file. An ORDINARY (non-partial) two-column
            -- index: the query's own equality prefix names both columns unconditionally, so
            -- there is no narrower WHERE to key a partial index off. Same guarded-index
            -- discipline: the `EXPLAIN QUERY PLAN` witness in the tests below runs the real
            -- query text.
            CREATE INDEX IF NOT EXISTS idx_adjudication_annotation_lookup
                ON adjudication_annotation (adjudication_id, kind);
            -- v8 (#24 stage 4, design §5.1): THE SEVER WITNESS. One row per sever, written in
            -- the sever's own transaction (with the epoch bump and the member closures), and
            -- carrying the COMPLETE ADR-P008 element-(3) minimum, verbatim from §5.1: the
            -- post-sever epoch · the sever timestamp · the seizing-authority REFERENCE · the
            -- member count · the member set · the digest. The design's reason for demanding all
            -- six in ONE row (codex r3 P1): if the post-sever audit is lost, this row is the
            -- ONLY surviving evidence — so an epoch-only or membership-only witness FAILS
            -- reconciliation (`verify_sever_witness`, lib.rs).
            --   `epoch` is UNIQUE: the sever is the ONLY writer of `control_epoch`, it bumps
            -- once per sever inside this same transaction, so the post-sever epoch identifies
            -- the sever event. `member_set` is the canonical JSON transcription of §5.1's
            -- TAGGED UNION, members in the canonical (bytewise-over-fully-encoded) order the
            -- digest is computed in; `digest` is the SHA-384 of §5.1's canonical encoding, in
            -- lowercase hex. Both are re-derivable from each other by a third party holding
            -- only this row — that is what makes the reconciliation mechanical.
            --   CONTENT-BLIND BY CONSTRUCTION: every id in this table is an opaque engine id
            -- (`intents.intent_id`, `attempt_fact.attempt_id`), never an idempotency key, a
            -- message handle, a header or a body byte. The accepted residual is named in §5.1
            -- itself: the witness necessarily exposes COUNT, timing and id-linkability —
            -- content-blind is not traffic/metadata-blind, and that metadata IS the witness's
            -- job.
            -- Append-only triggers mirror `engine_config`'s three-trigger pattern exactly: a
            -- rewritable witness is not evidence.
            CREATE TABLE IF NOT EXISTS sever_witness (
                witness_id    TEXT PRIMARY KEY,
                epoch         INTEGER NOT NULL UNIQUE,
                severed_at    TEXT NOT NULL,
                authority_ref TEXT NOT NULL,
                member_count  INTEGER NOT NULL CHECK (member_count >= 0),
                member_set    TEXT NOT NULL,
                digest        TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS sever_witness_no_update
                BEFORE UPDATE ON sever_witness
                BEGIN SELECT RAISE(ABORT, 'sever_witness is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS sever_witness_no_delete
                BEFORE DELETE ON sever_witness
                BEGIN SELECT RAISE(ABORT, 'sever_witness is append-only'); END;
            -- codex-r1 P2 pattern: `INSERT OR REPLACE`'s implicit DELETE fires no delete
            -- trigger under `recursive_triggers=off`. Guarded on BOTH conflict keys — either
            -- one would let a recorded witness be rewritten in place.
            CREATE TRIGGER IF NOT EXISTS sever_witness_no_replace
                BEFORE INSERT ON sever_witness
                WHEN EXISTS (
                    SELECT 1 FROM sever_witness
                     WHERE witness_id = NEW.witness_id OR epoch = NEW.epoch
                )
                BEGIN SELECT RAISE(ABORT, 'sever_witness is append-only'); END;
";

/// What a fresh-bootstrap attempt did. Losing the install race is a normal, expected outcome of
/// two openers racing on the same absent path, not a failure: the store the loser wanted now
/// exists, and the caller must reopen the winner's store. A distinct value rather than an `Err`
/// keeps the loser openable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootstrapOutcome {
    /// This call built the store and installed it at `dest`.
    Installed,
    /// Another opener installed `dest` first; nothing of ours was written over it.
    LostRace,
}

/// Atomic fresh bootstrap: init a temp sibling fully (schema, stamps, first-run act), then
/// checkpoint, close and fsync it, no-replace rename under a destination-scoped init lock, then
/// directory fsync (unix). A crash leaves no destination or a complete store.
/// The directory that holds `dest`, normalized for the empty-parent trap: `Path::parent()` of a
/// bare filename like `photon.db` is `Some("")`, and `File::open("")` fails with ENOENT. A bare
/// relative destination's directory is `.`, and every consumer (lock path, temp sibling,
/// directory fsync) must agree on it.
fn destination_dir(dest: &Path) -> &Path {
    match dest.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// The aliased-family check at reopen (fresh bootstrap already refuses any occupied family
/// name): a family member that is one of multiple hard links to an inode, or a symlinked
/// sidecar, makes our open write through the alias. SQLite truncates or rewrites a pre-existing
/// `-shm` on open, recovery rewrites or deletes `-wal`/`-journal`, and a main's pages propagate
/// to every alias (sqlite.org/howtocorrupt.html §2.6 names multi-link database files as a
/// corruption cause). The name-domain contract already refuses symlinked mains; a hard link is
/// the same aliasing by a mechanism only the link count can see. The realistic non-adversarial
/// actor is a hardlink-farm backup restore materializing aliased family members. Residual: the
/// count is check-then-open, so an on-box actor re-linking inside the window defeats it (out of
/// scope: code already running on the user's machine with the user's privileges).
fn refuse_aliased_family(main: &Path) -> Result<(), rusqlite::Error> {
    let [wal, shm, journal] = sidecar_paths(main);
    for p in [main, wal.as_path(), shm.as_path(), journal.as_path()] {
        match alias_state_of(p)? {
            AliasState::Absent | AliasState::SingleName => {}
            AliasState::NonRegular => {
                // A singly linked FIFO, socket, device, or directory at a family name yields an
                // unusable SQLite connection (first WAL write IOERR) or a device access: refused
                // here, never opened, never unlinked.
                return Err(refusal(format!(
                    "{} exists but is not a regular file — refused; a store family \
                     member must be a regular file, and a non-regular node is never \
                     opened or unlinked",
                    p.display()
                )));
            }
            AliasState::Symlink => {
                // The main was already refused at `classify_store_path`; this arm names symlinked
                // sidecars, governed by this classification alone.
                return Err(refusal(format!(
                    "{} is a symbolic link — refused: an aliased family member makes \
                     this open write through the alias (sqlite.org howtocorrupt \
                     §multiple-links); open a singly-named family",
                    p.display()
                )));
            }
            AliasState::MultiplyLinked(n) => {
                return Err(refusal(format!(
                    "{} has {n} hard links — refused: multiple names for one file make \
                     this open corrupt the other alias (sqlite.org howtocorrupt \
                     §multiple-links); open a singly-linked family",
                    p.display()
                )));
            }
        }
    }
    Ok(())
}

enum AliasState {
    Absent,
    SingleName,
    NonRegular,
    Symlink,
    MultiplyLinked(u64),
}

#[cfg(unix)]
fn alias_state_of(p: &Path) -> Result<AliasState, rusqlite::Error> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => Ok(AliasState::Symlink),
        Ok(m) if !m.is_file() => Ok(AliasState::NonRegular),
        Ok(m) if m.nlink() > 1 => Ok(AliasState::MultiplyLinked(m.nlink())),
        Ok(_) => Ok(AliasState::SingleName),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AliasState::Absent),
        Err(e) => Err(refusal(format!(
            "cannot classify {}: {e} — failing closed",
            p.display()
        ))),
    }
}

#[cfg(windows)]
fn alias_state_of(p: &Path) -> Result<AliasState, rusqlite::Error> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    // std's Metadata does not expose the link count on Windows (`windows_by_handle` is
    // unstable), so ask the kernel directly: a metadata-only handle (`FILE_READ_ATTRIBUTES`)
    // that does not follow reparse points, then `GetFileInformationByHandle`'s
    // `nNumberOfLinks`.
    #[repr(C)]
    #[allow(non_snake_case)]
    struct ByHandleFileInformation {
        dwFileAttributes: u32,
        ftCreationTime: [u32; 2],
        ftLastAccessTime: [u32; 2],
        ftLastWriteTime: [u32; 2],
        dwVolumeSerialNumber: u32,
        nFileSizeHigh: u32,
        nFileSizeLow: u32,
        nNumberOfLinks: u32,
        nFileIndexHigh: u32,
        nFileIndexLow: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(h: isize, out: *mut ByHandleFileInformation) -> i32;
    }
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    let f = match std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(p)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(AliasState::Absent),
        Err(e) => {
            return Err(refusal(format!(
                "cannot classify {}: {e} — failing closed",
                p.display()
            )))
        }
    };
    let mut info = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle() as isize, &mut info) } == 0 {
        return Err(refusal(format!(
            "cannot classify {}: {} — failing closed",
            p.display(),
            std::io::Error::last_os_error()
        )));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(AliasState::Symlink);
    }
    // A directory at a family name is the realistic Windows non-regular shape (unix FIFOs,
    // sockets and devices have no ordinary-path analogue here; reserved device names are closed
    // upstream by the name-domain contract, see `windows_name_domain_defect`).
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Ok(AliasState::NonRegular);
    }
    if info.nNumberOfLinks > 1 {
        return Ok(AliasState::MultiplyLinked(info.nNumberOfLinks as u64));
    }
    Ok(AliasState::SingleName)
}

/// Bound the stem of the auxiliary names (init lock and temp family) so a store filename near a
/// filesystem's 255-byte component limit still bootstraps. The destination itself only grows by
/// SQLite's own `-wal`/`-shm`/`-journal` suffixes, but the `.photon-init-tmp.<pid>.<n>` suffix
/// is much longer and would make every fresh open of a long-but-valid name fail before
/// bootstrap. Truncation only, deliberately no hash: a hashed stem would make the lock's mutual
/// exclusion depend on hash stability across processes and std versions, while truncation at
/// worst over-serializes (two stores sharing a 120-byte prefix share one lock, a liveness cost,
/// never a correctness one), and the temp reservation's `create_new` already makes cross-store
/// name collisions safe (a taken candidate is skipped, never adopted).
fn bounded_aux_stem(file_name: &str) -> &str {
    const MAX_STEM_BYTES: usize = 120;
    let mut end = file_name.len().min(MAX_STEM_BYTES);
    while end > 0 && !file_name.is_char_boundary(end) {
        end -= 1;
    }
    &file_name[..end]
}

pub(crate) fn bootstrap_fresh(dest: &Path) -> rusqlite::Result<BootstrapOutcome> {
    reject_special_name(dest)?;
    let dir = destination_dir(dest);
    // A destination without a file name (e.g. "", SQLite's own temporary-database name)
    // refuses instead of unwinding: a Photon store is a durable file family, and a temp db
    // cannot carry one.
    let file_name = dest
        .file_name()
        .ok_or_else(|| {
            refusal(format!(
                "destination '{}' has no file name — a Photon store is a durable file \
                 family; SQLite temporary/in-memory database names are refused",
                dest.display()
            ))
        })?
        .to_string_lossy()
        .into_owned();
    let aux_stem = bounded_aux_stem(&file_name);
    let lock_path = dir.join(format!("{aux_stem}.photon-init.lock"));
    // The temp sibling is atomically reserved per attempt: a name is ours only when
    // `create_new` succeeds, so a stale temp from a killed bootstrap (PID reuse included) is
    // skipped, never adopted, never deleted. Residual: a hard-killed bootstrap leaks one inert
    // `.photon-init-tmp.*` family, never adopted and never deleted by us (the reset path removes
    // `<db>` and the three sidecars only); removing it is a manual operator step. Since the
    // install primitive renames (the tmp name is consumed on success), the leak window is a kill
    // before the rename, and the leaked temp holds only a never-installed store.
    let tmp_path = {
        static TMP_N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let start = TMP_N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        reserve_tmp_sibling(
            dir,
            &format!("{aux_stem}.photon-init-tmp.{}", std::process::id()),
            start,
        )?
    };
    // Cleanup guard armed only after ownership is proven by the atomic reservation. It sweeps
    // the whole reserved family (all four names were minted by `create_new`; SQLite may already
    // have deleted -wal/-shm on clean close, and re-removal is a no-op).
    struct TmpGuard(PathBuf);
    impl Drop for TmpGuard {
        fn drop(&mut self) {
            let base = self.0.as_os_str().to_os_string();
            for ext in ["", "-wal", "-shm", "-journal"] {
                let mut o = base.clone();
                o.push(ext);
                let _ = std::fs::remove_file(PathBuf::from(o));
            }
        }
    }
    let _tmp_guard = TmpGuard(tmp_path.clone());

    // Destination-scoped init lock: serialize bootstrap per destination.
    let _lock = InitLock::acquire(&lock_path)?;

    // Revalidate the destination inside the lock, through the same fail-closed classifier as
    // preflight: a symlink, non-regular node, or unclassifiable path refuses here too, never
    // unlinked and never installed over.
    #[cfg(unix)]
    let mut preserved_perms: Option<std::fs::Permissions> = None;
    match classify_store_path(dest)? {
        StorePathState::EmptyRegular => {
            if persistent_sidecar(dest)? {
                return Err(refusal(format!(
                    "damaged store family: orphaned -wal/-journal beside empty {} — \
                     refusing; reset removes the whole file family",
                    dest.display()
                )));
            }
            refuse_occupied_shm_name(dest)?;
            // A caller-provisioned zero-length store may carry restrictive permissions (0600).
            // The mode is captured here, but the placeholder is not unlinked yet: unlinking before
            // the build would lose the placeholder and its provisioned perms on any mid-build
            // failure (including a copied 0400 mode breaking the build itself), so a retry would
            // install default-umask. The unlink happens after the temp is fully built and fsynced,
            // immediately before install, under this same lock, and the mode is applied to the temp
            // at that late point too, so a restrictive provision cannot break the build it
            // protects. Residuals: unix mode only (ownership transfer needs privilege; Windows
            // ACLs have no std model, and a READONLY Windows destination fails its unlink, the
            // fail-closed arm); the temp's bytes carry default-umask perms for the build's
            // duration under an unpredictable name; and a crash in the one-syscall gap between the
            // late unlink and the rename loses the placeholder, so a retry bootstraps
            // default-umask.
            #[cfg(unix)]
            {
                preserved_perms = std::fs::symlink_metadata(dest).ok().map(|m| m.permissions());
                // A provision that denies its owner read+write would publish a store no reopen can
                // use (unlink and rename succeed on directory permissions alone, then every open
                // fails at the WAL step). Refuse the unusable provision before building anything.
                if let Some(perms) = &preserved_perms {
                    use std::os::unix::fs::PermissionsExt;
                    if perms.mode() & 0o600 != 0o600 {
                        return Err(refusal(format!(
                            "the provisioned mode {:o} on {} denies its owner \
                             read+write — refusing to install a store that could never \
                             be reopened; adjust the placeholder's permissions",
                            perms.mode() & 0o7777,
                            dest.display()
                        )));
                    }
                }
            }
        }
        StorePathState::Populated => {
            // A non-empty destination appeared while we waited for the lock: the winner
            // installed its store. Nothing of ours was written; the caller reopens theirs.
            return Ok(BootstrapOutcome::LostRace);
        }
        StorePathState::Absent => {
            // The family can change while we wait for the lock. A -wal/-journal orphan appearing
            // beside the still-absent main is the damaged-family case, and installing a fresh main
            // beside it would let SQLite replay that orphan's (foreign or pre-v8) state over the
            // new store. The preflight's family check re-runs here, under the lock.
            if persistent_sidecar(dest)? {
                return Err(refusal(format!(
                    "damaged store family: -wal/-journal appeared beside absent {} \
                     while waiting for the init lock — refusing; reset removes the whole \
                     file family",
                    dest.display()
                )));
            }
            refuse_occupied_shm_name(dest)?;
        }
    }

    {
        // The reserved temp file exists (`create_new` minted it empty, a valid new db), so even
        // this path opens with no CREATE and no URI (the name-domain contract).
        let conn = rusqlite::Connection::open_with_flags(&tmp_path, existing_store_flags())?;
        pin_durability_profile(&conn)?;
        activate_fk_gate(&conn)?;
        // Degenerate on a store that does not exist yet (see the reopen site for the live case),
        // and called anyway so the schema sites cannot drift.
        refuse_duplicate_placement_identity(&conn)?;
        conn.execute_batch(&schema_ddl())?;
        // Degenerate here (this connection just created every table at the current shape), and
        // called anyway so the two schema sites cannot drift, as `schema_ddl()` itself does.
        upgrade_in_version_columns(&conn)?;
        // After the column-add loop (a store old enough to need `sender_address` must have it
        // before this copies it): catches a store whose `from_status`/`sender_status` CHECK is
        // stale because the column already existed (so the ALTER above was skipped) even though
        // its CHECK text is not what this build writes today. Degenerate here (a fresh store's
        // two tables carry no vocabulary CHECK) and called anyway, to avoid drift.
        rebuild_status_check_tables(&conn)?;
        // The ingest-revision high water, after the ALTER that can add the column it reads.
        // Degenerate here (an empty `message_header` seeds 0) and called anyway. See
        // [`seed_ingest_revision_seq`].
        seed_ingest_revision_seq(&conn)?;
        // The control-epoch fence's one seed site: a plain INSERT at bootstrap, never an
        // IF-NOT-EXISTS self-heal on reopen, which would roll a severed fence back to epoch 1.
        conn.execute("INSERT INTO control_epoch (id, epoch) VALUES (1, 1);", [])?;
        conn.pragma_update(None, "application_id", APPLICATION_ID)?;
        conn.pragma_update(None, "user_version", CURRENT_VERSION)?;
        write_first_run_config_act(&conn)?;
        // The stamp may live only in the temp -wal: checkpoint it into the main file so the
        // renamed store is self-contained.
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |_| Ok(()))?;
    } // close cleanly
    // fsync the temp store's bytes before it is installed into place. The handle must be
    // writable: on Windows `FlushFileBuffers` over a read-only handle fails with
    // ERROR_ACCESS_DENIED (os error 5), which would brick every bootstrap there.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&tmp_path)
        .map_err(io_err)?;
    // The provisioned mode lands on the finished temp now: after the build (a restrictive
    // provision can no longer break it; unusable modes were refused at capture), applied while
    // the write handle above is open (a mode change never affects an already-open handle's
    // rights) and before its `sync_all`, so the fsync makes the mode durable along with the
    // bytes and the rename publishes an entry whose inode metadata is already on disk.
    #[cfg(unix)]
    if let Some(perms) = preserved_perms {
        std::fs::set_permissions(&tmp_path, perms).map_err(io_err)?;
    }
    f.sync_all().map_err(io_err)?;
    drop(f);
    // The late unlink of the zero-length placeholder, the one sanctioned unlink, still under
    // the init lock and still type-gated by the re-classification: the placeholder and its
    // provisioned permissions survive every failure up to here. Zero bytes in a regular file
    // means SQLite never committed a page, so it is bootstrappable.
    match classify_store_path(dest)? {
        StorePathState::EmptyRegular => {
            std::fs::remove_file(dest).map_err(io_err)?;
        }
        StorePathState::Populated => return Ok(BootstrapOutcome::LostRace),
        StorePathState::Absent => {}
    }

    // Accepted residual: check-then-install is TOCTOU (no atomic multi-file namespace
    // operation exists), and a third family recheck immediately before the install would narrow
    // a window it cannot close. The realistic actor materializing files in the store directory
    // during this locked bootstrap is a cloud-sync, backup or AV agent: real and
    // non-adversarial, not the box owner. What such an agent triggers is the corruption class of
    // sqlite.org/howtocorrupt.html §1.2 (backup/restore of a database while in use) and §1.4
    // (mispairing database files and hot journals). The damage is bounded: crash artifacts
    // already on disk are closed by preflight and the under-lock recheck above, and the install
    // below never replaces an existing destination, so a sync-agent file landing at `dest` in
    // this window surfaces as an explicit LostRace/refusal on the reopen path, never a silent
    // overwrite. A sidecar minted in this window rides beside the fresh store until the next
    // open refuses or recovers it. A possible future knob: warn when the store directory
    // resolves under a known sync-managed root.
    match install_no_replace(&tmp_path, dest)? {
        InstallOutcome::Installed => {}
        // EEXIST from the no-replace rename is the precise race signal: the destination exists,
        // so the caller reopens whatever installed there, and the preflight on that pass
        // classifies it honestly.
        InstallOutcome::DestinationExists => return Ok(BootstrapOutcome::LostRace),
    }

    // Directory fsync is unix only: Windows cannot open a directory as a `File`, so the
    // none-or-complete-across-power-loss guarantee is unix-scoped, while process-crash safety
    // holds everywhere. Both errors propagate: swallowing them would silently downgrade the
    // guarantee to process-crash-only and return success anyway, leaving the caller unable to
    // tell a synced install from an unsynced one.
    #[cfg(unix)]
    {
        let d = std::fs::File::open(dir).map_err(io_err)?;
        d.sync_all().map_err(io_err)?;
    }
    Ok(BootstrapOutcome::Installed)
}

fn io_err(e: std::io::Error) -> rusqlite::Error {
    refusal(format!("bootstrap I/O failure: {e}"))
}

/// What the no-replace install did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallOutcome {
    /// tmp was renamed to dest as one namespace operation; tmp's name no longer exists.
    Installed,
    /// dest already exists (the EEXIST class): the install race was lost. tmp is left
    /// untouched; the caller's guard owns the sweep.
    DestinationExists,
}

fn install_err(dest: &Path, e: &std::io::Error) -> rusqlite::Error {
    refusal(format!(
        "bootstrap could not install {}: {e} — an existing destination reports as a \
         lost race (EEXIST), so this is a genuine install failure (permissions, disk, \
         or an unsupported destination filesystem)",
        dest.display()
    ))
}

/// Install the fully built temp store at `dest` without ever replacing an existing destination,
/// as one atomic namespace operation wherever the platform has one. The earlier primitive
/// (`hard_link` plus `remove_file`) had three defects: a kill between the two calls left two
/// live names for the store, and the documented reset path (`<db>` and 3 sidecars) never
/// removes the alias, so a "reset" database's bytes stayed readable under the tmp name;
/// `CreateHardLinkW` is NTFS-only, so FAT32/exFAT/SMB destinations could never bootstrap; and
/// a post-commit `remove_file` failure was returned as an install failure on a store that
/// installed fine.
///
/// Sources: MoveFileExW (learn.microsoft.com; without `MOVEFILE_REPLACE_EXISTING` it fails on
/// an existing destination), renameat2(2) (man7.org; `RENAME_NOREPLACE` gives EEXIST on an
/// existing destination, EINVAL from a filesystem without support, ENOSYS from a pre-3.15
/// kernel), and rename(2) on macOS (`renamex_np` `RENAME_EXCL` gives EEXIST, ENOTSUP where the
/// filesystem lacks `VOL_CAP_INT_RENAME_EXCL`; macOS 10.12+).
///
/// It is adopted as a primitive, not a crate: tempfile documents the two-hard-link crash
/// residue as accepted `persist_noclobber` behavior, atomicwrites falls back to
/// linkat+unlinkat on unix, and either drags rustix/windows-sys/fastrand into a rusqlite+serde
/// crate.
///
/// The FFI boundary must speak extended-length paths itself: `std::fs` auto-applies the `\\?\`
/// verbatim prefix for long paths, so a >MAX_PATH store survives preflight, reservation, and
/// the SQLite build, then would die at the raw `MoveFileExW` call with ERROR_PATH_NOT_FOUND.
/// Disk-absolute paths get `\\?\` (with `/` normalized to `\`, since the verbatim form does not
/// interpret forward slashes), UNC paths get `\\?\UNC\`, and already-prefixed or relative paths
/// pass through (`\\?\` requires an absolute path). The verbatim form disables dot-segment
/// resolution, so `.`/`..` are resolved lexically before prefixing (a `C:\root\sub\..\photon.db`
/// destination would otherwise build its whole temp store and then fail the install with error
/// 123). Lexical-vs-filesystem `..` divergence through a symlinked intermediate directory stays
/// inside the on-box TOCTOU residual noted in preflight (LWN 899543).
#[cfg(windows)]
fn wide_verbatim(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Component, Prefix};
    // Component-wise rebuild: resolves `.`/`..` lexically and normalizes `/` to `\`
    // (`PathBuf::push` joins with the platform separator).
    fn lexically_resolved(p: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for c in p.components() {
            match c {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                other => out.push(other),
            }
        }
        out
    }
    let mut out: Vec<u16> = match p.components().next() {
        Some(Component::Prefix(pr)) => match pr.kind() {
            Prefix::Disk(_) if p.is_absolute() => {
                let mut v: Vec<u16> = r"\\?\".encode_utf16().collect();
                v.extend(lexically_resolved(p).as_os_str().encode_wide());
                v
            }
            Prefix::UNC(_, _) => {
                // \\server\share\... → \\?\UNC\server\share\...
                let mut v: Vec<u16> = r"\\?\UNC".encode_utf16().collect();
                v.extend(lexically_resolved(p).as_os_str().encode_wide().skip(1));
                v
            }
            // VerbatimDisk / VerbatimUNC / Verbatim / DeviceNS: already extended-length
            _ => p.as_os_str().encode_wide().collect(),
        },
        _ => p.as_os_str().encode_wide().collect(),
    };
    out.push(0);
    out
}

#[cfg(windows)]
fn install_no_replace(tmp: &Path, dest: &Path) -> Result<InstallOutcome, rusqlite::Error> {
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let (from, to) = (wide_verbatim(tmp), wide_verbatim(dest));
    // dwFlags = 0: no `MOVEFILE_REPLACE_EXISTING` (the no-replace semantic) and no copy
    // fallback, since tmp is a same-directory sibling, so this is a same-volume rename.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } != 0 {
        return Ok(InstallOutcome::Installed);
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        return Ok(InstallOutcome::DestinationExists);
    }
    Err(install_err(dest, &e))
}

#[cfg(target_os = "linux")]
fn install_no_replace(tmp: &Path, dest: &Path) -> Result<InstallOutcome, rusqlite::Error> {
    use std::os::unix::ffi::OsStrExt;
    // The raw syscall, not glibc's `renameat2` wrapper: the wrapper symbol exists only from
    // glibc 2.28, so importing it fails at dynamic load on older systems (Rust's GNU target
    // baseline is glibc 2.17) and the ENOSYS fallback below could never run. `syscall(2)`
    // reaches the kernel on every glibc/musl; a pre-3.15 kernel answers ENOSYS and an
    // unsupporting filesystem EINVAL, both taking the documented fallback. libc supplies the
    // per-arch `SYS_renameat2` number.
    let c = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| refusal(format!("store path {} contains a NUL byte", p.display())))
    };
    let (from, to) = (c(tmp)?, c(dest)?);
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(InstallOutcome::Installed);
    }
    let e = std::io::Error::last_os_error();
    match e.kind() {
        std::io::ErrorKind::AlreadyExists => Ok(InstallOutcome::DestinationExists),
        // EINVAL: the filesystem does not support `RENAME_NOREPLACE`; ENOSYS: pre-3.15 kernel.
        // Both take the documented fallback.
        std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported => {
            install_link_unlink_fallback(tmp, dest)
        }
        _ => Err(install_err(dest, &e)),
    }
}

#[cfg(target_os = "macos")]
fn install_no_replace(tmp: &Path, dest: &Path) -> Result<InstallOutcome, rusqlite::Error> {
    use std::ffi::{c_char, c_int, c_uint};
    use std::os::unix::ffi::OsStrExt;
    extern "C" {
        fn renamex_np(from: *const c_char, to: *const c_char, flags: c_uint) -> c_int;
    }
    // XNU `bsd/sys/stdio.h`: `RENAME_EXCL = 0x00000004`; available macOS 10.12+.
    const RENAME_EXCL: c_uint = 0x0000_0004;
    let c = |p: &Path| {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| refusal(format!("store path {} contains a NUL byte", p.display())))
    };
    let (from, to) = (c(tmp)?, c(dest)?);
    if unsafe { renamex_np(from.as_ptr(), to.as_ptr(), RENAME_EXCL) } == 0 {
        return Ok(InstallOutcome::Installed);
    }
    let e = std::io::Error::last_os_error();
    match e.kind() {
        std::io::ErrorKind::AlreadyExists => Ok(InstallOutcome::DestinationExists),
        // ENOTSUP: the filesystem lacks `VOL_CAP_INT_RENAME_EXCL` (Apple's man page names the
        // errno); EINVAL: a flags problem. Both take the documented fallback.
        std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput => {
            install_link_unlink_fallback(tmp, dest)
        }
        _ => Err(install_err(dest, &e)),
    }
}

/// Any other unix: no no-replace rename is known, so the fallback is the primitive there.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn install_no_replace(tmp: &Path, dest: &Path) -> Result<InstallOutcome, rusqlite::Error> {
    install_link_unlink_fallback(tmp, dest)
}

/// The documented fallback where no no-replace rename exists (pre-3.15 Linux kernels,
/// filesystems answering EINVAL/ENOTSUP, other unix): POSIX `link(2)` fails with EEXIST on an
/// existing destination (the no-replace semantic), then the source name is unlinked. Residual
/// (fallback-only, accepted): a kill between the two calls leaves the tmp alias live, the
/// earlier primitive's residue, now confined to platforms without the atomic primitive. A
/// follow-on unlink failure is not an install failure: the store is installed, and the caller's
/// `TmpGuard` retries the sweep on drop.
#[cfg(unix)]
fn install_link_unlink_fallback(tmp: &Path, dest: &Path) -> Result<InstallOutcome, rusqlite::Error> {
    match std::fs::hard_link(tmp, dest) {
        Ok(()) => {
            let _ = std::fs::remove_file(tmp);
            Ok(InstallOutcome::Installed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(InstallOutcome::DestinationExists)
        }
        Err(e) => Err(install_err(dest, &e)),
    }
}

/// The first-run config act: the out-of-box defaults are generation-1 recorded configuration,
/// not silence (capture ON, retention dormant), with the verified durability profile and the
/// bundled SQLite version pinned alongside it.
fn write_first_run_config_act(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let sqlite_version: String = conn.query_row("SELECT sqlite_version();", [], |r| r.get(0))?;
    let fullfsync = cfg!(target_os = "macos");
    // The recorded version derives from the one authority; a literal here would silently lie in
    // the durable config record on the next `SCHEMA_VERSION` bump.
    let payload = format!(
        "{{\"capture\":\"on\",\"retention\":\"dormant\",\"schema_version\":{CURRENT_VERSION},\
         \"durability_profile\":{{\"journal_mode\":\"wal\",\"synchronous\":\"full\",\
         \"fullfsync\":{fullfsync},\"busy_timeout_ms\":5000}},\
         \"sqlite_version\":\"{sqlite_version}\"}}"
    );
    conn.execute(
        "INSERT INTO engine_config (generation, recorded_at, kind, payload)
         VALUES (1, strftime('%s','now'), 'first_run', ?1);",
        rusqlite::params![payload],
    )?;
    Ok(())
}

/// A verified connection and the writer gate for the file it has open, minted together at one
/// entry point.
///
/// The pair is a type, not a convention, because the gate must exist before the first
/// persistent writer touches the file. `pin_durability_profile` runs `PRAGMA journal_mode=WAL`,
/// which is a write to the store; if it ran before any gate existed, the first thing every
/// connection did would be an ungated write. Establishing identity and gate at the top of
/// [`open_verified_connection`] and handing the caller a pair it cannot take apart means no
/// consumer can hold a connection to a Photon store without holding that store's arbiter too.
///
/// The write entry points are [`GatedConnection::with_immediate_tx`] (multi-statement,
/// explicit transaction) and [`GatedConnection::with_enrolled_write`] (a single autocommit
/// statement). `Deref` gives read access to the connection; there is deliberately no
/// `DerefMut`, and `Connection::transaction_with_behavior` needs `&mut Connection`, so an
/// ungated write transaction is unreachable through this type except through the explicitly
/// named escape [`GatedConnection::ungated_conn_mut`]. Every production caller
/// (`ReadCoordinator`'s three write transactions) uses `with_immediate_tx`; the escape's
/// remaining callers are `#[cfg(test)]` tests that want a raw, unenrolled transaction, such as
/// the preflight-lock-lifecycle tests that hold a plain read transaction to probe SQLite's own
/// lock survival.
pub(crate) struct GatedConnection {
    conn: rusqlite::Connection,
    gate: crate::writer_gate::WriterGate,
}

impl std::ops::Deref for GatedConnection {
    type Target = rusqlite::Connection;
    /// Read access only; see the type doc for why `DerefMut` is absent.
    fn deref(&self) -> &rusqlite::Connection {
        &self.conn
    }
}

impl GatedConnection {
    /// The arbiter for the store file this connection has open. `authorize_send` reads it
    /// through this pair to capture a `Clone`d handle before `with_immediate_tx` borrows the
    /// connection mutably (see that method's doc for why the capture has to happen here rather
    /// than inside its own enrolled closure).
    pub(crate) fn gate(&self) -> &crate::writer_gate::WriterGate {
        &self.gate
    }

    /// The connection, for reads. (`Deref` is the ergonomic form; this is the explicit one.)
    ///
    /// `ReadCoordinator::refresh_reconcile`'s first phase materializes its removal work list
    /// outside any enrollment, and it names this accessor rather than leaning on `Deref`
    /// because "this is a read, and it takes no writer slot" is the load-bearing claim of that
    /// phase. Every other projection read goes through `Deref`, which is fine where the gating
    /// question is not the point of the line.
    pub(crate) fn conn(&self) -> &rusqlite::Connection {
        &self.conn
    }

    /// The named escape. `&mut Connection` is the capability `transaction_with_behavior` needs,
    /// so handing it out hands out the ability to write ungated. Every production caller
    /// (`ReadCoordinator`'s three write transactions) uses [`Self::with_immediate_tx`]; the
    /// escape exists only for `#[cfg(test)]` code that wants an unenrolled transaction (raw fault
    /// injection, or a probe about SQLite's own locking rather than this gate), so every remaining
    /// caller is a countable, named debt rather than an invisible one.
    #[allow(dead_code)] // every remaining caller is #[cfg(test)] (lib.rs's preflight-lock-
    // lifecycle tests); a lib-only `cargo build` sees zero callers.
    pub(crate) fn ungated_conn_mut(&mut self) -> &mut rusqlite::Connection {
        &mut self.conn
    }

    /// The enrolled write path: one `BEGIN IMMEDIATE` transaction, bracketed by one enrollment
    /// that spans it.
    ///
    /// Ordering is the compiler's job, not the reader's. A `(WriteScope, Transaction)` pair does
    /// not enforce teardown-before-release: tuple members drop separably, and by declaration
    /// order the scope would be released first, leaving a live transaction outside the gate. Here:
    ///
    /// - `scope` is a local of this function and is never handed to the closure, so nothing the
    ///   caller writes can drop it early;
    /// - the `Transaction` is a local of the inner function [`GatedConnection::run_immediate`]
    ///   and cannot outlive that call, so its commit-or-rollback has already happened by the time
    ///   control returns here.
    ///
    /// So "transaction teardown precedes enrollment release" is what ownership permits: no
    /// expressible program ends the scope first, and reordering the two statements below cannot
    /// break it either.
    ///
    /// Commit on `Ok`; on `Err` the transaction's own `Drop` rolls back (rusqlite's default) and
    /// the error propagates unchanged.
    ///
    /// Residual: SQLite's `COMMIT` can itself return `SQLITE_BUSY` and leave the transaction
    /// active. rusqlite's consuming `commit()` plus WAL make it rare, and the enrollment flag
    /// tracks this guard, not the connection's transaction state.
    pub(crate) fn with_immediate_tx<T, E>(
        &mut self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<crate::writer_gate::GateError> + From<rusqlite::Error>,
    {
        // Enroll first. `scope` is owned by this frame and nothing else, so the only place it can
        // be released is the end of this function, after the call below has returned and the
        // transaction has been committed or rolled back.
        let scope = self.gate.enroll().map_err(E::from)?;
        let outcome = GatedConnection::run_immediate(&mut self.conn, f);
        // `scope` drops here, written as an explicit drop-after-outcome rather than left
        // implicit. Ownership, not this line, enforces the ordering.
        drop(scope);
        outcome
    }

    /// The sever service's write path. Identical to [`Self::with_immediate_tx`] in ownership and
    /// ordering; the only difference is which enrollment it takes.
    ///
    /// A sever leader cannot use `with_immediate_tx`: that path calls
    /// [`WriterGate::enroll`](crate::writer_gate::WriterGate::enroll), whose predicate includes
    /// `sever_pending == 0`, and the leader's own raised ticket makes that false. The leader takes
    /// [`WriterGate::enroll_service`](crate::writer_gate::WriterGate::enroll_service) instead:
    /// the ticket blocks everyone except its holder.
    ///
    /// The ownership argument is `with_immediate_tx`'s: `scope` is a local of this frame and is
    /// never handed to `f`, and the `Transaction` is a local of [`Self::run_immediate`], so the
    /// commit-or-rollback has already happened when `scope` drops. `entry` is borrowed, never
    /// consumed: the leader still owns its service and calls `complete` after this returns (an
    /// outcome resolved before the commit would promise joiners an epoch that might still roll
    /// back).
    pub(crate) fn with_service_tx<T, E>(
        &mut self,
        entry: &crate::writer_gate::SeverEntry,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<crate::writer_gate::GateError> + From<rusqlite::Error>,
    {
        let scope = self.gate.enroll_service(entry).map_err(E::from)?;
        let outcome = GatedConnection::run_immediate(&mut self.conn, f);
        drop(scope);
        outcome
    }

    /// The transaction half, in its own frame: the `Transaction` it creates is a local here, so
    /// it is torn down before this function returns (see [`GatedConnection::with_immediate_tx`]
    /// for why that framing is the whole ownership argument).
    fn run_immediate<T, E>(
        conn: &mut rusqlite::Connection,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<rusqlite::Error>,
    {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(E::from)?;
        let value = f(&tx)?;
        tx.commit().map_err(E::from)?;
        Ok(value)
    }

    /// The enrolled autocommit write path. A store whose write is a single autocommit statement,
    /// with no explicit `BEGIN`, still must not run ungated: the sever-priority invariant is "at
    /// most one writer to this file, ever", not "at most one writer inside an explicit
    /// transaction". This enrolls one [`WriteScope`](crate::writer_gate::WriteScope) around
    /// exactly `f`'s execution and releases it.
    ///
    /// Deliberately narrower than [`Self::with_immediate_tx`]: there is no transaction for the
    /// enrollment to span, because SQLite's own autocommit brackets the one statement `f` runs.
    /// Reusing `with_immediate_tx` would open a needless nested transaction around a caller who
    /// never asked for multi-statement atomicity (`record_optimistic_placement`,
    /// `correct_placement` and `record_header` are each one statement). A single autocommit
    /// statement is a bounded enrollment by construction: it starts immediately before the
    /// statement and ends immediately after it returns.
    ///
    /// The ownership argument is `with_immediate_tx`'s: `scope` is a local of this function and
    /// is never handed to `f`, so the earliest it can be released is after `f` has returned.
    ///
    /// Takes `&self` rather than `&mut self`: the gate's
    /// [`enroll`](crate::writer_gate::WriterGate::enroll) only needs `&WriterGate`, and a single
    /// `Connection::execute`/`query_row` needs no `&mut Connection`, so the read-only `Deref`
    /// this type exposes is enough for `f` to reach the connection.
    pub(crate) fn with_enrolled_write<T, E>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<crate::writer_gate::GateError>,
    {
        let scope = self.gate.enroll().map_err(E::from)?;
        let outcome = f(&self.conn);
        drop(scope);
        outcome
    }
}

/// This store's current capacity bounds, read off a fresh, version-verified connection at
/// open, before any writer needs the arbiter (unlike [`crate::read_effective_bounds`], which
/// reads inside the admission transaction). It uses the same `capacity::effective_bounds`
/// derivation over the ledger's two act families (`kind='capacity'` and
/// `kind='capacity_activated'`), so the open-time snapshot and the admission-time read cannot
/// disagree about what "current" means.
///
/// **One snapshot, not two statements.** Reading the two act families as two autocommit
/// statements gives two snapshots: a `record_capacity_config` committing between them would
/// make the pair describe a store state that never existed, with the activation read naming a
/// generation the capacity read did not contain. `effective_bounds` correctly refuses that
/// pair, and the refusal would be swallowed into `capacity::DEFAULT` for the whole lifetime of
/// the handle. `read_capacity_snapshot` takes both reads inside one `BEGIN DEFERRED` read
/// transaction. It is ungated on purpose: it writes nothing, so it takes no writer slot and
/// enrolls in nothing (the same standing as `GatedConnection::conn`'s read path).
///
/// **A failed read is an error.** Absence still yields [`crate::capacity::DEFAULT`]: a fresh
/// bootstrap's `engine_config` carries only its `kind='first_run'` row, and `effective_bounds`
/// returns that default as an `Ok`. Failure is different. `unwrap_or(DEFAULT)` could not tell
/// the two apart, so an unreadable ledger would open silently at bounds nobody configured, in
/// contradiction of the admission read, which refuses an unreadable capacity act by name
/// (`read_effective_bounds`), and of the activation trigger's guarded `WHEN` clause, which
/// never activates one.
///
/// So there is one retry on a fresh snapshot (the right remedy for the only failure this
/// path can recover from, an inconsistent or contended read), and then the open is refused,
/// carrying both attempts' reasons. Opening "successfully" on a store whose capacity ledger is
/// unreadable buys no access, since `record` refuses every write anyway; it only hides why. A
/// deterministic defect (a corrupt payload) fails both attempts and is reported here; a
/// transient interleaving is gone by the second.
fn capacity_config_at_open(
    conn: &rusqlite::Connection,
) -> rusqlite::Result<crate::capacity::CapacityConfig> {
    match read_capacity_snapshot(conn, || {}) {
        Ok(cfg) => Ok(cfg),
        Err(first) => match read_capacity_snapshot(conn, || {}) {
            Ok(cfg) => Ok(cfg),
            Err(second) => Err(refusal(format!(
                "the store's capacity ledger could not be read consistently at open, twice — \
                 first attempt: {first}; retry: {second}. The capacity domain is never assumed \
                 (design §5.3 CONFIGURATION-DOMAIN-PINNING): opening at the compiled default \
                 over an unreadable ledger would contradict the admission read, which refuses \
                 the same bytes"
            ))),
        },
    }
}

/// [`capacity_config_at_open`]'s read, as one `BEGIN DEFERRED` snapshot over the ledger's two
/// act families. Separate from its caller so the retry is spelled once and the interleaving
/// this closes is testable: `between_reads` runs between the snapshot's two read steps (after
/// the activation row is read and before the act lookups, since the activation row names which
/// acts to fetch) and is a no-op closure in production. A test passes a closure that commits a
/// competing `capacity` + `capacity_activated` pair from a second connection; with two
/// autocommit reads that produced the mis-derivation described on the caller, and inside one
/// read transaction the write is simply not in this snapshot.
///
/// The `Transaction` is a local here and is never committed, so it rolls back on drop, the
/// correct disposal for a read: nothing was written, and the snapshot is released when the
/// derivation is done.
///
/// Both act families are parsed in Rust by the shared authorities:
/// `crate::capacity::CapacityConfig::from_engine_payload` inside `effective_bounds`, and
/// `crate::capacity::parse_activation_pointer` for the activation pointer. A copy of the
/// `CAST(json_extract(payload,'$.activates_generation') AS INTEGER)` +
/// `Option<i64>`/`.flatten()` shape would read a present-but-null pointer as "never activated"
/// and open the compiled default over a store whose ledger says otherwise. See
/// `crate::capacity`'s "ONE STRICT PARSE AUTHORITY" section.
fn read_capacity_snapshot(
    conn: &rusqlite::Connection,
    between_reads: impl FnOnce(),
) -> Result<crate::capacity::CapacityConfig, String> {
    use rusqlite::OptionalExtension;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("capacity snapshot begin: {e}"))?;
    // `Option<(generation, payload)>` carries the two facts SQL may answer here: whether a
    // `capacity_activated` row exists, and where in the ledger it sits. What it says is Rust's
    // business, and the row's own generation is load-bearing: discarding it would skip the
    // names-its-own-past refusal and let a filled forward reservation open the store at
    // never-fitted bounds. Both ordering refusals live in `capacity::effective_bounds`.
    let activation_row: Option<(i64, String)> = tx
        .query_row(
            "SELECT generation, payload FROM engine_config WHERE kind = 'capacity_activated'
              ORDER BY generation DESC LIMIT 1;",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("activation read: {e}"))?;
    let activation: Option<(i64, i64)> = match activation_row {
        None => None,
        Some((row_generation, payload)) => Some((
            row_generation,
            crate::capacity::parse_activation_pointer(&payload)
                // Lossless: the parser refuses anything past `i64::MAX` because
                // `engine_config.generation` is an INTEGER PRIMARY KEY.
                .map(|g| g as i64)
                .map_err(|e| format!("{e}"))?,
        )),
    };
    between_reads();
    // The same bounded two-row selection as the admission reader: the activation row names the
    // at most two acts `effective_bounds` can ever parse (the pointed act, a PK lookup; the
    // newest act past the pointer, an indexed DESC LIMIT 1), so the open does not materialize
    // the entire append-only capacity history (open time and memory would grow with every
    // `record_capacity_config` ever recorded). Semantics are unchanged: the strict-greater
    // filter is the one `effective_bounds` applies to the full set, an activation naming a
    // missing act still arrives as an empty lookup and refuses by name, and a superseded act
    // stays unparsed (`a_superseded_malformed_act_stays_unparsed_by_the_open_read`).
    let mut capacity_acts: Vec<(i64, String)> = Vec::with_capacity(2);
    if let Some((_, pointer)) = activation {
        let current_act: Option<(i64, String)> = tx
            .query_row(
                "SELECT generation, payload FROM engine_config
                  WHERE kind = 'capacity' AND generation = ?1;",
                rusqlite::params![pointer],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|e| format!("capacity-acts read: {e}"))?;
        if let Some(row) = current_act {
            capacity_acts.push(row);
        }
    }
    let newest_pending: Option<(i64, String)> = tx
        .query_row(
            "SELECT generation, payload FROM engine_config
              WHERE kind = 'capacity' AND generation > ?1
              ORDER BY generation DESC LIMIT 1;",
            rusqlite::params![activation.map(|(_, p)| p).unwrap_or(0)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|e| format!("capacity-acts read: {e}"))?;
    if let Some(row) = newest_pending {
        capacity_acts.push(row);
    }
    crate::capacity::effective_bounds(&capacity_acts, activation)
        .map(|eb| eb.current)
        .map_err(|e| format!("{e}"))
}

/// The one way to open a connection to an existing, verified store: the close of the
/// unverified-connection class at its chokepoint. The intent log's own connection and the
/// projection constructors used to run the persistent WAL flip on stores nobody had verified,
/// and mint zero-id databases on absent paths; the class closes here, shared by every consumer,
/// never with another per-constructor edit. It refuses an absent or empty path without
/// creating anything: bootstrap belongs to the intent log alone.
pub(crate) fn open_verified_connection(path: &Path) -> rusqlite::Result<GatedConnection> {
    // The open path runs alone per identity: preflight, connection open, persistent profile and
    // the caller's DDL never interleave with a second open of the same store file. Reentrant, so
    // `SqliteIntentLog::open` can hold it across this call.
    let _open_serialization = crate::writer_gate::serialize_open_path(path)?;
    // The full preflight tree runs here, not a metadata shortcut. Raw-header ownership decides
    // foreign without a connection (a PRAGMA read on a hot store runs journal recovery, which
    // deleted a foreign writer's WAL before refusal in the failing test), and a hot owned store
    // recovers under the non-persistent probe profile before any version read.
    match preflight(path)? {
        Preflight::FreshBootstrap => {
            return Err(refusal(format!(
                "no store exists at {} — open the intent log first (it owns bootstrap); \
                 this constructor never creates or adopts a store file",
                path.display()
            )))
        }
        Preflight::OpenVerifiedSupported => {}
        Preflight::RecoveryProbe => {
            let probe = rusqlite::Connection::open_with_flags(path, existing_store_flags())?;
            pin_probe_profile(&probe)?;
            let verdict = verify_owned_supported_version(&probe);
            drop(probe); // close before acting; refusal leaves the RECOVERED state (§7a c)
            verdict?;
        }
    }
    let conn = rusqlite::Connection::open_with_flags(path, existing_store_flags())?;
    verify_owned_supported_version(&conn)?;
    // The gate comes before the first persistent writer. `pin_durability_profile` below runs
    // `PRAGMA journal_mode=WAL`, a write to the store file; if the gate were established after
    // it, every connection's first act would be an ungated write. Identity and arbiter are
    // established here from the live connection, and an unobtainable identity refuses the open:
    // there is no path-string fallback key, because two spellings of one file would then get two
    // gates and "at most one writer" would be silently false.
    let gate = crate::writer_gate::WriterGate::for_connection(&conn, path)?;
    // `for_connection` above hard-codes `capacity::DEFAULT` (a handle minted at the connection
    // entry point has no transaction to read the ledger through), but this caller already holds
    // the verified connection and a plain read needs no transaction. Re-mint via `with_config`
    // so every ordinary `with_immediate_tx`/`with_enrolled_write` scope opened through this path
    // sees the store's configured `writer_chunk_budget_ms`, not the compiled default. Residual
    // (also on `writer_gate`'s module doc): this is an open-time snapshot, so a capacity act that
    // lands and activates afterward governs gate handles minted afterward, and a live handle
    // keeps the budget it opened with. Only the sever service re-reads per service
    // (`WriterGate::with_config` at the sever entry point).
    // Fallible: an unreadable or inconsistent capacity ledger refuses the open (after one retry)
    // rather than silently defaulting. See the function's doc.
    let gate = gate.with_config(capacity_config_at_open(&conn)?);
    // `pin_durability_profile`'s persistent `PRAGMA journal_mode=WAL` is a write to the store
    // file, and the per-identity open serializer above excludes only other opens, not an
    // already-enrolled writer or a ticketed sever. A second open of a live store would run this
    // write outside the arbiter's view and could take SQLite's writer lock ahead of a sever that
    // had already ticketed (`sever_pending > 0`). So enroll exactly around the profile call,
    // narrowly, and release before returning: the caller's own DDL transaction (e.g.
    // `SqliteIntentLog::open`'s `with_immediate_tx` version stamp) takes its own enrollment
    // afterward. Holding this scope across that later transaction would be a second, nested
    // enrollment on the same thread, which the no-reentrant-enrollment rule refuses.
    //
    // No caller of `open_verified_connection` reaches this already holding a `WriteScope`:
    // `SqliteIntentLog::open` is the one fresh-path bootstrap/reopen entry (nothing above it on
    // the call stack enrolls first), and every other caller (`message_store`, `message_header`,
    // `read_coordinator`, and this module's own test helpers) opens a plain, freshly derived
    // connection the same way. If that ever stopped being true, `enroll()`'s thread-local
    // `HELD_SCOPES` check would refuse with `GateError::ReentrantEnrollment` rather than
    // deadlock (see the module doc's no-reentrant-enrollment invariant).
    let scope = gate.enroll()?;
    pin_durability_profile(&conn)?;
    drop(scope);
    activate_fk_gate(&conn)?;
    // The control-epoch fence must exist on every verified store (bootstrap is its one seed
    // site). A missing singleton is a damaged fence: it refuses here and is never re-minted,
    // because re-seeding epoch 1 would roll the sole control fence back below any prior sever
    // (fail-open).
    let fence_rows: i64 =
        conn.query_row("SELECT COUNT(*) FROM control_epoch;", [], |r| r.get(0))?;
    if fence_rows != 1 {
        return Err(refusal(format!(
            "the store at {} has no control_epoch fence row — damaged store; a fence is \
             never re-minted on open (a re-seed would silently roll a severed epoch \
             back); reset or restore the store",
            path.display()
        )));
    }
    Ok(GatedConnection { conn, gate })
}

/// Atomically reserve a uniquely named sibling file. A candidate name is owned only when
/// `create_new` succeeds: an existing file at a candidate (a stale temp from a killed
/// bootstrap, PID reuse included) is skipped, never adopted, never deleted. No file this
/// function did not atomically mint is ever touched.
fn reserve_tmp_sibling(dir: &Path, prefix: &str, start_n: u64) -> rusqlite::Result<PathBuf> {
    let mut n = start_n;
    'candidate: loop {
        let candidate = dir.join(format!("{prefix}.{n}"));
        n += 1;
        // The whole SQLite family must be ours: a stale hot -wal/-journal at the candidate name
        // would be replayed by SQLite over our fresh temp store. Reserve main and every sidecar
        // name via `create_new`; any member already existing means the candidate is dirty, so
        // remove only what we just created and move on.
        let family: [PathBuf; 4] = {
            let base = candidate.as_os_str().to_os_string();
            let mk = |ext: &str| {
                let mut o = base.clone();
                o.push(ext);
                PathBuf::from(o)
            };
            [candidate.clone(), mk("-wal"), mk("-shm"), mk("-journal")]
        };
        let mut created: Vec<&PathBuf> = Vec::with_capacity(4);
        for member in &family {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(member)
            {
                Ok(_) => created.push(member),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    for ours in created {
                        let _ = std::fs::remove_file(ours);
                    }
                    continue 'candidate;
                }
                Err(e) => {
                    // Windows answers `create_new` over a directory with PermissionDenied, not
                    // AlreadyExists, so an occupied name (proven by lstat) is a collision and the
                    // candidate is skipped like any other; only a failure on a genuinely absent
                    // name is a real error (ACLs, disk) and propagates.
                    let occupied = std::fs::symlink_metadata(member).is_ok();
                    for ours in created {
                        let _ = std::fs::remove_file(ours);
                    }
                    if occupied {
                        continue 'candidate;
                    }
                    return Err(io_err(e));
                }
            }
        }
        return Ok(candidate);
    }
}

/// Destination-scoped bootstrap mutex. The lock file is only an address; the lock is an OS
/// advisory file lock (`std::fs::File::lock`, flock/LockFileEx) that the kernel releases on
/// process death, so a crashed holder's leftover file is never a held lock and a later
/// first-open proceeds instead of erroring until someone hand-deletes it (a `create_new` design
/// would make the file's existence the lock, which a kill -9 turns into a permanent wedge).
/// Two consequences: (a) the zero-byte `.photon-init.lock` sibling is left in place, since
/// unlinking a lock file while another process holds or waits on it splits the lock across two
/// inodes on unix (the classic unlink-lockfile race), so one inert sibling per store is the
/// cost; (b) the wait is blocking, since the holder is a live process mid-bootstrap
/// (sub-second), and a holder hung on dead storage is the same storage-fault class as a stalled
/// fsync, surfaced by the caller's own timeout discipline, not by racing the lock.
struct InitLock {
    file: std::fs::File,
}
impl InitLock {
    fn acquire(path: &Path) -> rusqlite::Result<Self> {
        // (a) Classify the lock address with lstat first: a FIFO, or a symlink to one, blocked
        // the write-only open before the advisory lock was ever reached and hung first open
        // indefinitely; non-regular entries refuse. Residual: lstat-to-open is check-then-act, so
        // an on-box actor minting a FIFO inside the window still blocks (out of scope: code
        // already running on the user's machine with the user's privileges). (b) The lock file is
        // retained by design and reset omits it, so a stale lock gone read-only (0444, the
        // readonly attribute, a prior service account) must still be acquirable: the advisory
        // lock needs a handle, not write access, so an existing lock that refuses the write open
        // is retried read-only.
        match std::fs::symlink_metadata(path) {
            Ok(m) if !m.is_file() => {
                return Err(refusal(format!(
                    "{} exists but is not a regular file — refused; the init lock \
                     address must be a regular file (a FIFO here would block first \
                     open forever)",
                    path.display()
                )))
            }
            _ => {} // absent (created below) or regular; unclassifiable surfaces at open
        }
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => std::fs::OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(io_err)?,
            Err(e) => return Err(io_err(e)),
        };
        file.lock().map_err(io_err)?;
        Ok(Self { file })
    }
}
impl Drop for InitLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// The persistent durability arm. Every ordinary connection to the store (intent log,
/// projections, maintenance) pins WAL and synchronous=FULL (plus fullfsync on macOS), verifies
/// each by read-back, and refuses the connection otherwise.
pub(crate) fn pin_durability_profile(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL;", [], |r| r.get(0))?;
    if mode.to_lowercase() != "wal" {
        return Err(refusal(format!(
            "durability profile refused: journal_mode read back '{mode}', not 'wal' \
             (design #24 §2.2b — the connection is not usable)"
        )));
    }
    pin_probe_profile(conn)?;
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;
    let bt: i64 = conn.query_row("PRAGMA busy_timeout;", [], |r| r.get(0))?;
    if bt < 1 {
        return Err(refusal(format!(
            "durability profile refused: busy_timeout read back {bt}"
        )));
    }
    Ok(())
}

/// The non-persistent arm (recovery probe): per-connection pragmas only. The probe's
/// checkpoint durability is governed, but a store that may yet be refused is never persistently
/// mutated (`journal_mode` is untouched).
pub(crate) fn pin_probe_profile(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA synchronous=FULL;")?;
    let sync: i64 = conn.query_row("PRAGMA synchronous;", [], |r| r.get(0))?;
    if sync < 2 {
        return Err(refusal(format!(
            "durability profile refused: synchronous read back {sync}, need FULL(2)+"
        )));
    }
    #[cfg(target_os = "macos")]
    {
        conn.execute_batch("PRAGMA fullfsync=ON;")?;
        let ff: i64 = conn.query_row("PRAGMA fullfsync;", [], |r| r.get(0))?;
        if ff != 1 {
            return Err(refusal(
                "durability profile refused: fullfsync read back 0 on macOS".into(),
            ));
        }
    }
    Ok(())
}

/// The foreign-key check: per-connection `foreign_keys=ON` with read-back, plus an open-time
/// `foreign_key_check` (zero rows or refuse).
pub(crate) fn activate_fk_gate(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    let on: i64 = conn.query_row("PRAGMA foreign_keys;", [], |r| r.get(0))?;
    if on != 1 {
        return Err(refusal("FK gate refused: foreign_keys read back 0".into()));
    }
    let violations: i64 =
        conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check;", [], |r| {
            r.get(0)
        })?;
    if violations != 0 {
        return Err(refusal(format!(
            "FK gate refused: foreign_key_check found {violations} violation row(s)"
        )));
    }
    Ok(())
}

/// Open-time integrity evidence (both-direction journal checks, capture-off, frozen-basis, plus
/// boot-quarantine rows). Evidence, not refusal: the store opens, and the caller surfaces these
/// explicitly. A mirror, not a cop: refusing the open would strand an operator from the very
/// rows they must inspect. Read it through [`crate::SqliteIntentLog::integrity_report`].
///
/// The one open-time condition not in this enum is an `attempt_head` that diverges from its
/// fact chain. That is not a fact about a row; it is the engine's own projection becoming a
/// second authority that every dispatch decision reads, so it refuses the open (the boot
/// quarantine's contract, `crate::SqliteIntentLog::open`). Reportable defects live here;
/// unusable-authority conditions do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityEvidence {
    /// A `journal_required=1` forward intent that reached a dispatched status
    /// (`applied`/`undone`/`undoing`) with no `pre_state` row and no explaining tombstone, a
    /// fail-loud class at undo time.
    JournalGapUnexplained {
        /// The affected intent's idempotency key.
        key: String,
    },
    /// A `pre_state` row whose parent was admitted with `journal_required=0`: illegal, since the
    /// capture-off direction owes no row and may not own one.
    CaptureOffRow {
        /// The affected intent's idempotency key.
        key: String,
    },
    /// A `journal_required=1` forward intent that terminalized `failed` with no `pre_state` row
    /// and no explaining tombstone. Conservative, and worded honestly: `failed` is ambiguous
    /// after the fact. A pre-dispatch dead-letter legitimately has no row, while an
    /// applied-then-undo-dead-lettered row's missing restoration evidence is exactly the gap the
    /// arm above reports. The store cannot reconstruct which lineage produced `failed`, so the
    /// absence is surfaced at this degraded confidence rather than dropped or overclaimed as a
    /// proven gap. Without this arm a failed undo would silently erase live
    /// `JournalGapUnexplained` evidence.
    JournalAbsentAtFailure {
        /// The affected intent's idempotency key.
        key: String,
    },
    /// A non-terminal intent whose `frozen_basis` is missing or malformed: the tail-ordering key
    /// cannot be trusted for that row.
    FrozenBasisMissing {
        /// The affected intent's idempotency key.
        key: String,
    },
    /// A stored `sever_witness` row that does not reconcile: a missing field, a count that
    /// disagrees with its member set, or a digest that does not recompute from that member set
    /// through the canonical encoding.
    ///
    /// Evidence, never a refusal: the record is audit substrate (the surviving record of a
    /// seizure), not a dispatch check, and nothing in the engine reads it to decide anything.
    /// Refusing the open over one would lock an operator out of the very rows the broken record
    /// is about.
    SeverWitnessUnreconciled {
        /// The affected witness row's id.
        witness_id: String,
        /// Why it failed to reconcile, from the reconciliation authority
        /// (`crate::verify_sever_witness`).
        reason: String,
    },
    /// The boot quarantine closed a non-terminal attempt from its facts before any dispatch: it
    /// was claimed under an epoch that is no longer current and never authorized, so it
    /// terminalized `SEVERED_BEFORE_ISSUANCE`.
    ///
    /// Not a defect report: a durable, operator-visible record that the boot classification
    /// acted. Closing work silently at open is what the sever record's discipline exists to
    /// forbid.
    AttemptSeveredAtBoot {
        /// The closed attempt's opaque id.
        attempt_id: String,
        /// The epoch it was claimed under, which is no longer the current one.
        claim_epoch: i64,
    },
    /// The exposure capacity posture, surfaced: how many `exposure_obligation` rows are
    /// unretired, and how many the table holds in total.
    ///
    /// Persistent exposure materialization carries an explicit finite capacity posture: capacity
    /// pressure surfaces, and unresolved obligations are never silently evicted. This build's
    /// posture is the simplest honest one: nothing evicts, the exposure check fails closed on
    /// every overlap, and the growth is reported here so an operator sees it accumulating instead
    /// of discovering it as a mystery refusal. The check's own cost is unaffected, since it is a
    /// keyed join per touched atom, not a scan.
    ///
    /// Reported whenever any obligation is unretired: an unresolved exposure is a live condition
    /// that gates dispatches, so it belongs in the operator's view of the store even though it is
    /// not a defect.
    UnresolvedExposureOutstanding {
        /// Rows with no `retired_at` — the ones the EXP-3 gate joins against.
        unretired: i64,
        /// Every row ever written, retired or not (nothing is evicted, so this only grows).
        total: i64,
    },
    /// A scanned row whose own identity could not be read (`idempotency_key` is not TEXT), so the
    /// defect cannot be attributed to a key. Reported by SQLite `rowid` instead, because
    /// propagating the column-type error would close the store over one bad row, inverting the
    /// rule that integrity evidence never refuses an open.
    UnreadableRow {
        /// The affected row's SQLite `rowid`; `intents` is a rowid table, so this always locates
        /// it even when no other column can be trusted.
        rowid: i64,
    },
    /// Live occupancy exceeds the effective capacity bounds. A store can legitimately carry more
    /// active operations than the current bounds admit (an earlier build admitted with no
    /// capacity substrate at all, and a same-version reopen runs no migration hook that could
    /// confront the population), so the admission paths simply refuse new work until the drain
    /// paths (adjudication, sever) bring occupancy back inside. That self-correction was silent,
    /// leaving an operator watching admissions refuse with no record of why. This is evidence,
    /// never a refusal and never a mutation: severing or clamping a legitimate historical
    /// population at open would be the cop posture this enum forbids. Reported when either
    /// admission inequality is violated: `active_forward > max_active_ops - undo_reserve` (the
    /// protected undo headroom is consumed) or `active_forward + active_undo > max_active_ops`
    /// (the total cap is exceeded), the two inequalities `capacity::admission_check` enforces.
    OccupancyExceedsBounds {
        /// Live forward (non-compensating) non-terminal intents.
        active_forward: i64,
        /// Live undo (compensating) non-terminal intents.
        active_undo: i64,
        /// The CURRENT effective `max_active_ops` the doors admit against.
        max_active_ops: u32,
        /// The CURRENT effective `undo_reserve`.
        undo_reserve: u32,
    },
}

/// The identity of a scanned `intents` row: its `idempotency_key` when column 1 is readable
/// TEXT, otherwise `Err(rowid)` from column 0. Never an error: an unreadable identity is a fact
/// about the row, and this scan's job is to report facts about rows (see [`integrity_scan`]'s
/// complement rule).
///
/// The `rowid` fallback of `-1` is unreachable for a rowid table (SQLite's `rowid` is always an
/// INTEGER), and is written as a value rather than an `unwrap` so no scanned row can panic the
/// open either.
fn scanned_row_identity(row: &rusqlite::Row<'_>) -> Result<String, i64> {
    let rowid = row
        .get_ref(0)
        .ok()
        .and_then(|v| v.as_i64().ok())
        .unwrap_or(-1);
    match row.get_ref(1).map(|v| v.as_str().map(str::to_string)) {
        Ok(Ok(key)) => Ok(key),
        _ => Err(rowid),
    }
}

/// The evidence a scan attaches to a row it has already decided is defective, given that row's
/// readable key. Named so the verdict travels beside the SQL that selects the rows it judges.
type RowVerdict = fn(String) -> IntegrityEvidence;

/// Turn a scanned row's identity into evidence: the scan's own verdict when the key is readable,
/// [`IntegrityEvidence::UnreadableRow`] when it is not.
fn attributed(identity: Result<String, i64>, verdict: RowVerdict) -> IntegrityEvidence {
    match identity {
        Ok(key) => verdict(key),
        Err(rowid) => IntegrityEvidence::UnreadableRow { rowid },
    }
}

/// The open-time integrity scan. Pure read: it never writes, never refuses, and never repairs;
/// it reports.
///
/// **The complement rule.** The two kinds of failure this function can meet are routed in
/// opposite directions. Any per-row read, decode or parse failure on a scanned column becomes
/// evidence for that row (a defect the operator must see is the reason this scan exists), while
/// only statement-level DB failures propagate as an open error (a failing `prepare` or step
/// means the store is untrustworthy, not that one row is wrong). A per-row defect that closes
/// the store would lock the operator out of the very rows they were meant to inspect. Columns
/// are therefore read through `ValueRef`, which yields a value for any storage class, so a
/// BLOB or INTEGER where TEXT was expected cannot throw.
///
/// Child-without-parent is closed by the FK check itself: [`activate_fk_gate`] runs
/// `PRAGMA foreign_key_check` at every open and refuses on a violation, so a `pre_state` row
/// with no `intents` parent can never reach this function.
pub(crate) fn integrity_scan(
    conn: &rusqlite::Connection,
) -> Result<Vec<IntegrityEvidence>, rusqlite::Error> {
    let mut out = Vec::new();
    // The two whole-row scans: every row they return is evidence, so only its attribution can
    // fail. Same shape, same complement rule, written once over the pair.
    //
    // The reverse gap, tombstone-excluded and forward-only. It is scoped to the
    // journal-required dispatched-parent statuses, the ones that imply the wire was reachable: a
    // `failed` pre-dispatch terminal never dispatched, so it legitimately has no row and is not
    // evidence of anything.
    //
    // This is deliberately not the non-terminal domain (`NON_TERMINAL_STATUS_SQL`): it is a
    // different axis, "did this row reach the wire?", not "is this row settled?". They overlap
    // (`undoing` is both non-terminal and dispatched) without either containing the other, and
    // `evidence_snapshot_written` is correctly absent: that phase is "ready to dispatch", so it
    // has not reached the wire and owes no journal row yet.
    //
    // Two later dispatched terminals are included, because a row can only reach them from
    // beyond the capture:
    //
    // * `adjudicated`: closes the operational axis of an attempt whose issuance is unknown, and
    //   an attempt is only ISSUANCE_UNKNOWN after it was send-authorized, which is after
    //   PREPARE. Such an operation owed its journal row;
    // * `externally_satisfied`: retry requalification runs at the head of a retry, so the
    //   operation captured on its first pass and is re-deciding `C` against it.
    //
    // Without them a `journal_required=1` row that lost its journal row would open silently
    // under either status.
    //
    // `severed` is deliberately excluded. A sever closes every non-terminal member, including
    // one that never reached PREPARE (a `pending` operation with no attempt is an
    // `OperationMember` and legitimately owes nothing). The status alone cannot tell that member
    // from one severed after capture, and this scan reports proven gaps: including `severed`
    // would mint a false `JournalGapUnexplained` for every pre-PREPARE kill-switch victim. The
    // degraded-confidence route for an ambiguous status already exists (see
    // `JournalAbsentAtFailure`), and no `severed` twin of it is needed.
    //
    // And the capture-off direction: a row that must not exist.
    let whole_row_scans: [(&str, RowVerdict); 3] = [
        (
            "SELECT i.rowid, i.idempotency_key FROM intents i
              WHERE i.kind = 'forward' AND i.journal_required = 1
                AND i.status IN ('applied','undone','undoing',
                                 'adjudicated','externally_satisfied')
                AND NOT EXISTS (SELECT 1 FROM pre_state p WHERE p.intent_id = i.intent_id)
                AND NOT EXISTS (SELECT 1 FROM pre_state_tombstone t
                                 WHERE t.intent_id = i.intent_id);",
            |key| IntegrityEvidence::JournalGapUnexplained { key },
        ),
        // The `failed` companion to the arm above: a dead-lettered undo moves an anomalous
        // Applied-without-row intent through Undoing to Failed, which would silently erase its
        // live gap evidence. `failed` cannot prove dispatch after the fact, so these rows carry
        // their own degraded-confidence variant: surfaced, never dropped, never overclaimed (see
        // the variant's doc for the two indistinguishable lineages).
        (
            "SELECT i.rowid, i.idempotency_key FROM intents i
              WHERE i.kind = 'forward' AND i.journal_required = 1
                AND i.status = 'failed'
                AND NOT EXISTS (SELECT 1 FROM pre_state p WHERE p.intent_id = i.intent_id)
                AND NOT EXISTS (SELECT 1 FROM pre_state_tombstone t
                                 WHERE t.intent_id = i.intent_id);",
            |key| IntegrityEvidence::JournalAbsentAtFailure { key },
        ),
        (
            "SELECT i.rowid, i.idempotency_key FROM intents i
               JOIN pre_state p ON p.intent_id = i.intent_id
              WHERE i.journal_required = 0;",
            |key| IntegrityEvidence::CaptureOffRow { key },
        ),
    ];
    for (sql, verdict) in whole_row_scans {
        // `prepare` and `next` (the step) are the statement level, and those propagate.
        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            out.push(attributed(scanned_row_identity(row), verdict));
        }
    }
    // Frozen-basis well-formedness on every non-terminal intent (the rows still to be ordered
    // and dispatched; a terminal row's basis is history). The domain comes from
    // `crate::NON_TERMINAL_STATUS_SQL`, derived from `IntentStatus::is_terminal`: a
    // hand-enumerated list had already dropped `evidence_snapshot_written`, hiding exactly the
    // rows this scan exists to surface.
    let mut stmt = conn.prepare(&format!(
        "SELECT rowid, idempotency_key, frozen_basis FROM intents
          WHERE status IN {};",
        crate::NON_TERMINAL_STATUS_SQL
    ))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        // Every way this column can disappoint us (absent, not TEXT at all, or TEXT that is not
        // a parseable basis) is the same verdict: the tail-ordering key cannot be trusted for
        // this row. Read as a `ValueRef` so the non-TEXT case is a value we judge, not a
        // conversion error that ends the open.
        let well_formed = row
            .get_ref(2)
            .ok()
            .and_then(|v| v.as_str().ok())
            .is_some_and(|s| crate::prestate::FrozenBasis::from_json(s).is_ok());
        if !well_formed {
            out.push(attributed(scanned_row_identity(row), |key| {
                IntegrityEvidence::FrozenBasisMissing { key }
            }));
        }
    }
    // The over-cap mirror. The current bounds are derived as the admission read derives them
    // (never activated means the compiled DEFAULT; otherwise the act the newest activation
    // pointer names, parsed by the one strict authority). A ledger this derivation cannot read
    // contributes no row here, deliberately: every admission read already refuses the same
    // unreadable ledger by name, and this scan's contract is that evidence never refuses, so it
    // must neither turn that refusal into a failure to open nor report against bounds it cannot
    // read. Statement-level DB failures still propagate, per the complement rule above.
    {
        use rusqlite::OptionalExtension as _;
        // One snapshot for the whole arm. If the bounds read and the occupancy count were
        // separate autocommit statements, under WAL a concurrent writer (another process; this
        // process's writes are gated) could activate new bounds between them, and the arm would
        // compare an occupancy from one snapshot against bounds from another, manufacturing
        // false evidence. A read transaction pins every statement below to one WAL snapshot;
        // `unchecked_transaction` because this scan holds `&conn` (read-only, so the
        // drop-rollback is a no-op).
        let tx = conn.unchecked_transaction()?;
        let activation_row: Option<(i64, String)> = tx
            .query_row(
                "SELECT generation, payload FROM engine_config
                  WHERE kind = 'capacity_activated'
                  ORDER BY generation DESC LIMIT 1;",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let bounds: Option<crate::capacity::CapacityConfig> = match activation_row {
            None => Some(crate::capacity::DEFAULT),
            Some((row_generation, p)) => match crate::capacity::parse_activation_pointer(&p) {
                Err(_) => None,
                // A pointer that does not name its own past is the planted-reservation shape. The
                // admission read refuses it by name (`capacity::effective_bounds`), and this scan
                // reports nothing against bounds that read would never honor.
                Ok(gen) if gen as i64 >= row_generation => None,
                Ok(gen) => {
                    // Same disposition as the arm above: an act stranded between the pointer and
                    // its own activation row is a shape the admission read refuses by name, and
                    // this scan reports nothing against bounds that read would never honor.
                    let newest_cap: Option<i64> = tx.query_row(
                        "SELECT MAX(generation) FROM engine_config WHERE kind = 'capacity';",
                        [],
                        |r| r.get::<_, Option<i64>>(0),
                    )?;
                    if newest_cap.is_some_and(|n| (gen as i64) < n && n < row_generation) {
                        None
                    } else {
                        tx.query_row(
                            "SELECT payload FROM engine_config
                              WHERE kind = 'capacity' AND generation = ?1;",
                            rusqlite::params![gen as i64],
                            |r| r.get::<_, String>(0),
                        )
                        .optional()?
                        .and_then(|payload| {
                            crate::capacity::CapacityConfig::from_engine_payload(&payload).ok()
                        })
                    }
                }
            },
        };
        if let Some(cfg) = bounds {
            let (active_forward, active_undo): (i64, i64) = tx.query_row(
                &format!(
                    "SELECT COUNT(*) FILTER (WHERE compensates IS NULL),
                            COUNT(*) FILTER (WHERE compensates IS NOT NULL)
                       FROM intents WHERE status IN {};",
                    crate::NON_TERMINAL_STATUS_SQL
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let forward_bound = i64::from(cfg.max_active_ops) - i64::from(cfg.undo_reserve);
            let total_cap = i64::from(cfg.max_active_ops);
            if active_forward > forward_bound || active_forward + active_undo > total_cap {
                out.push(IntegrityEvidence::OccupancyExceedsBounds {
                    active_forward,
                    active_undo,
                    max_active_ops: cfg.max_active_ops,
                    undo_reserve: cfg.undo_reserve,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// minted by the ONE guard (`crate::test_temp`) — pid + nanos + a
    /// per-process counter (it was pid + counter only: a reused pid re-opened a previous run's
    /// leftover), the path removed on `Drop` with its store siblings whatever the test put there
    /// (a file, a directory, a socket), and a leak a loud failure.
    fn scratch(tag: &str) -> crate::test_temp::TempFile {
        crate::test_temp::TempFile::new(&format!("aruna-preflight-{tag}"), "")
    }

    /// A minimal fake SQLite header: magic + user_version at 60 + application_id at 68.
    fn fake_db_bytes(user_version: u32, application_id: u32) -> Vec<u8> {
        let mut b = vec![0u8; 100];
        b[..16].copy_from_slice(b"SQLite format 3\0");
        b[60..64].copy_from_slice(&user_version.to_be_bytes());
        b[68..72].copy_from_slice(&application_id.to_be_bytes());
        b
    }

    #[test]
    fn absent_file_no_sidecars_is_fresh_bootstrap() {
        let p = scratch("absent");
        assert_eq!(preflight(&p).unwrap(), Preflight::FreshBootstrap);
    }

    #[test]
    fn zero_length_main_no_sidecars_is_fresh_bootstrap() {
        let p = scratch("zerolen");
        std::fs::write(&p, b"").unwrap();
        assert_eq!(preflight(&p).unwrap(), Preflight::FreshBootstrap);
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn orphaned_sidecar_beside_absent_main_refuses_damaged() {
        let p = scratch("orphan");
        std::fs::write(format!("{}-wal", p.display()), b"stale").unwrap();
        let err = preflight(&p).unwrap_err();
        assert!(format!("{err}").contains("damaged"), "{err}");
        std::fs::remove_file(format!("{}-wal", p.display())).unwrap();
    }

    #[test]
    fn sidecar_free_current_version_with_registered_id_opens_verified() {
        let p = scratch("curowned");
        std::fs::write(&p, fake_db_bytes(CURRENT_VERSION, APPLICATION_ID)).unwrap();
        assert_eq!(preflight(&p).unwrap(), Preflight::OpenVerifiedSupported);
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn the_supported_version_band_is_admitted_and_its_floor_is_exact() {
        // V9 is the first version with an in-place upgrade, so the preflight stopped
        // being an equality test and became a BAND test. Both edges are pinned here, in terms
        // of the constants rather than literals, so a future bump inherits the witness: every
        // version from the upgradable floor up to current is ADMITTED (the open chokepoint
        // upgrades it), and the version one below the floor is still the §7a Option A refusal.
        for v in MIN_UPGRADABLE_VERSION..=CURRENT_VERSION {
            let p = scratch(&format!("band-{v}"));
            std::fs::write(&p, fake_db_bytes(v, APPLICATION_ID)).unwrap();
            assert_eq!(
                preflight(&p).unwrap(),
                Preflight::OpenVerifiedSupported,
                "schema version {v} is inside the supported band and must be admitted"
            );
            std::fs::remove_file(&p).unwrap();
        }
        let p = scratch("below-floor");
        std::fs::write(
            &p,
            fake_db_bytes(MIN_UPGRADABLE_VERSION - 1, APPLICATION_ID),
        )
        .unwrap();
        let err = preflight(&p).unwrap_err();
        assert!(format!("{err}").contains("pre-v8"), "{err}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn sidecar_free_zero_id_refuses_as_pre_v8_even_when_version_reads_8() {
        // A zero-id store is a legacy candidate, REFUSAL-ONLY — a genuine
        // Photon v8 store always carries the registered id.
        let p = scratch("zeroid8");
        std::fs::write(&p, fake_db_bytes(8, 0)).unwrap();
        let err = preflight(&p).unwrap_err();
        assert!(format!("{err}").contains("pre-v8"), "{err}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn sidecar_free_foreign_id_refuses_as_foreign_store() {
        let p = scratch("foreign");
        std::fs::write(&p, fake_db_bytes(8, 0xDEAD_BEEF)).unwrap();
        let err = preflight(&p).unwrap_err();
        assert!(format!("{err}").contains("foreign"), "{err}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn sidecar_free_future_version_refuses() {
        // Stated as CURRENT_VERSION + 1, not a literal: this gate is about "one version past
        // whatever this binary is", and hardcoding the number made it silently stop testing
        // the newer-binary arm the moment SCHEMA_VERSION reached it (it had frozen
        // at 9 and went green-for-the-wrong-reason at the 8→9 bump).
        let p = scratch("future");
        std::fs::write(&p, fake_db_bytes(CURRENT_VERSION + 1, APPLICATION_ID)).unwrap();
        let err = preflight(&p).unwrap_err();
        assert!(format!("{err}").contains("newer"), "{err}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn non_sqlite_bytes_refuse_as_foreign_store() {
        let p = scratch("notdb");
        std::fs::write(&p, b"this is not a sqlite database, it is a text file....................................................").unwrap();
        let err = preflight(&p).unwrap_err();
        assert!(format!("{err}").contains("foreign"), "{err}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn sidecar_bearing_foreign_id_refuses_without_probe() {
        // Ownership decided from the RAW header BEFORE any connection.
        let p = scratch("sidecar-foreign");
        std::fs::write(&p, fake_db_bytes(8, 0xDEAD_BEEF)).unwrap();
        std::fs::write(format!("{}-wal", p.display()), b"hot").unwrap();
        let err = preflight(&p).unwrap_err();
        assert!(format!("{err}").contains("foreign"), "{err}");
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_file(format!("{}-wal", p.display())).unwrap();
    }

    #[test]
    fn sidecar_bearing_owned_or_legacy_id_routes_to_recovery_probe() {
        // Owner-matched AND 0-id legacy candidates proceed to the probe.
        for id in [APPLICATION_ID, 0u32] {
            let p = scratch("sidecar-probe");
            std::fs::write(&p, fake_db_bytes(7, id)).unwrap();
            std::fs::write(format!("{}-journal", p.display()), b"hot").unwrap();
            assert_eq!(preflight(&p).unwrap(), Preflight::RecoveryProbe);
            std::fs::remove_file(&p).unwrap();
            std::fs::remove_file(format!("{}-journal", p.display())).unwrap();
        }
    }

    /// Stamp a real SQLite file with the given ownership/version pair and hand back the path.
    fn stamped_store(tag: &str, application_id: u32, user_version: u32) -> crate::test_temp::TempFile {
        let p = scratch(tag);
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch("CREATE TABLE t(x);").unwrap();
        // SQLite's `application_id` is a 32-bit SIGNED header field: a value above 2^31-1
        // must be handed over as its i32 bit pattern (passing the u32 widened to i64 makes
        // SQLite store 0, which would have silently turned this foreign-store arm into a
        // zero-id arm).
        c.pragma_update(None, "application_id", application_id as i32)
            .unwrap();
        c.pragma_update(None, "user_version", user_version).unwrap();
        drop(c);
        p
    }

    fn cleanup(p: &Path) {
        for f in sidecar_paths(p) {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn verify_owned_supported_version_refuses_a_future_version_through_the_connection() {
        // The raw preflight closes BEFORE `Connection::open`, so the connection
        // that actually gets the persistent WAL flip + DDL was never itself verified. The
        // ownership/version rule must be re-applied THROUGH the final connection.
        let p = stamped_store("verify-future", APPLICATION_ID, CURRENT_VERSION + 1);
        let conn = rusqlite::Connection::open(&p).unwrap();
        let err = verify_owned_supported_version(&conn).unwrap_err();
        assert!(format!("{err}").contains("newer"), "{err}");
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn verify_owned_supported_version_refuses_a_zero_id_legacy_candidate_through_the_connection() {
        let p = stamped_store("verify-zeroid", 0, 8);
        let conn = rusqlite::Connection::open(&p).unwrap();
        let err = verify_owned_supported_version(&conn).unwrap_err();
        assert!(format!("{err}").contains("pre-v8"), "{err}");
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn verify_owned_supported_version_refuses_a_foreign_id_through_the_connection() {
        let p = stamped_store("verify-foreign", 0xDEAD_BEEF, 8);
        let conn = rusqlite::Connection::open(&p).unwrap();
        let err = verify_owned_supported_version(&conn).unwrap_err();
        assert!(format!("{err}").contains("foreign"), "{err}");
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn verify_owned_supported_version_accepts_a_bootstrapped_store() {
        let p = scratch("verify-ok");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        verify_owned_supported_version(&conn).unwrap();
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn full_profile_pins_and_reads_back_wal_full() {
        let p = scratch("profile");
        let conn = rusqlite::Connection::open(&p).unwrap();
        pin_durability_profile(&conn).unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        let sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        assert!(sync >= 2, "synchronous must read back FULL(2) or EXTRA(3), got {sync}");
        drop(conn);
        for f in sidecar_paths(&p) {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn full_profile_refuses_when_it_cannot_be_honored() {
        // A read-only connection cannot flip journal_mode to WAL — the gate must REFUSE,
        // never proceed on an unverified profile (design §2.2b: read-back or refuse).
        let p = scratch("profile-ro");
        {
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE t(x);").unwrap();
        }
        let conn =
            rusqlite::Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap();
        assert!(pin_durability_profile(&conn).is_err());
        drop(conn);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn probe_profile_never_touches_journal_mode() {
        let p = scratch("probe-profile");
        {
            let c = rusqlite::Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE t(x);").unwrap();
        } // default journal_mode (delete)
        let conn = rusqlite::Connection::open(&p).unwrap();
        pin_probe_profile(&conn).unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .unwrap();
        assert_ne!(mode.to_lowercase(), "wal", "the probe must not flip a store to WAL");
        let sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        assert!(sync >= 2);
        drop(conn);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn special_colon_names_are_refused_at_every_door() {
        // + sqlite.org/uri.html's own guidance: names beginning with ':' are
        // SQLite special names (":memory:" opens an in-memory database REGARDLESS of the
        // URI flag) — a Photon store is a durable file family, so the name domain refuses
        // them outright at preflight and bootstrap.
        for name in [":memory:", ":weird"] {
            let p = std::path::Path::new(name);
            let err = match preflight(p) {
                Err(e) => e,
                Ok(o) => panic!("preflight of {name} must refuse, got {o:?}"),
            };
            assert!(format!("{err}").contains("special"), "{err}");
            let err = match bootstrap_fresh(p) {
                Err(e) => e,
                Ok(o) => panic!("bootstrap of {name} must refuse, got {o:?}"),
            };
            assert!(format!("{err}").contains("special"), "{err}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_symlinked_store_path_is_refused() {
        // Multiple names (hard or soft links) for one database file split
        // its journal family — sqlite.org/howtocorrupt.html names this as a corruption
        // cause. The name domain accepts only the real FINAL component; enforcement is
        // the lstat classification at every door (the NOFOLLOW belt was removed —
        // whole-path semantics broke macOS, see existing_store_flags).
        let real = scratch("symlink-real");
        bootstrap_fresh(&real).unwrap();
        let link = scratch("symlink-link");
        match std::os::windows::fs::symlink_file(&real, &link) {
            Ok(()) => {}
            Err(e) => {
                // Symlink creation needs privilege on some Windows configs — soft-skip
                // with a visible note rather than a false green.
                eprintln!("SKIP a_symlinked_store_path_is_refused: cannot create symlink: {e}");
                for f in sidecar_paths(&real) { let _ = std::fs::remove_file(f); }
                let _ = std::fs::remove_file(&real);
                return;
            }
        }
        let err = match open_verified_connection(&link) {
            Err(e) => e,
            Ok(_) => panic!("a symlinked store path must refuse"),
        };
        assert!(format!("{err}").to_lowercase().contains("symbolic"), "{err}");
        std::fs::remove_file(&link).unwrap();
        for f in sidecar_paths(&real) { let _ = std::fs::remove_file(f); }
        std::fs::remove_file(&real).unwrap();
    }

    #[test]
    fn tmp_reservation_requires_the_whole_family_to_be_clean() {
        // Reserving only the temp MAIN leaves its -wal/-journal names
        // unowned — a stale hot sidecar at the candidate name would be REPLAYED by SQLite
        // over our fresh temp store. A candidate is usable only when the WHOLE family was
        // atomically created by us; a dirty family member skips the candidate untouched.
        // a private guarded directory, never the shared temp root.
        let dir = crate::test_temp::TempDir::new("aruna-resv-fam");
        let prefix = format!("aruna-resv-fam-{}-t9", std::process::id());
        let stale_wal = dir.join(format!("{prefix}.7-wal"));
        std::fs::write(&stale_wal, b"hot frames from a killed run").unwrap();
        let reserved = reserve_tmp_sibling(&dir, &prefix, 7).unwrap();
        assert_ne!(
            reserved,
            dir.join(format!("{prefix}.7")),
            "a candidate with ANY dirty family member is never used"
        );
        assert_eq!(std::fs::read(&stale_wal).unwrap(), b"hot frames from a killed run");
        // the winning candidate's whole family is ours (created empty)
        for ext in ["", "-wal", "-shm", "-journal"] {
            let member = std::path::PathBuf::from(format!("{}{ext}", reserved.display()));
            assert!(member.exists(), "family member {ext} must be reserved");
            let _ = std::fs::remove_file(member);
        }
        std::fs::remove_file(&stale_wal).unwrap();
    }

    #[test]
    fn a_destination_without_a_file_name_refuses_instead_of_panicking() {
        // `open("")` reached file_name.unwrap. SQLite itself treats ""
        // as a TEMPORARY database — a name the store contract refuses outright (a Photon
        // store is a durable file FAMILY; a temp db cannot carry one).
        let err = match bootstrap_fresh(std::path::Path::new("")) {
            Err(e) => e,
            Ok(o) => panic!("an empty destination must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("file name"), "{err}");
    }

    #[test]
    fn chokepoint_refuses_a_foreign_hot_store_without_touching_it() {
        // (A repeat of the unverified-connection class — the
        // chokepoint skipped the §7a preflight/probe branch): a PRAGMA read on a
        // sidecar-bearing store triggers SQLite journal recovery, so a FOREIGN hot store
        // was touched before refusal. The complete chokepoint decides ownership from the
        // RAW header — no connection, no recovery, byte-stable family.
        let p = stamped_store("choke-foreign-hot", 0xDEAD_BEEF, 8);
        let wal = format!("{}-wal", p.display());
        std::fs::write(&wal, b"garbage wal bytes from a foreign writer").unwrap();
        let main_before = std::fs::read(&p).unwrap();
        let wal_before = std::fs::read(&wal).unwrap();
        assert!(
            open_verified_connection(&p).is_err(),
            "a foreign hot store must refuse"
        );
        assert_eq!(main_before, std::fs::read(&p).unwrap(), "main must be untouched");
        assert_eq!(
            wal_before,
            std::fs::read(&wal).unwrap(),
            "the sidecar must be untouched — refusal happens from the raw header, \
             before any connection exists to run recovery"
        );
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_file(&wal).unwrap();
    }

    #[test]
    fn chokepoint_opens_an_owned_hot_store_through_the_probe() {
        // Companion regression arm: an OWNED store with a hot WAL routes through the
        // probe (non-persistent profile pinned BEFORE the version read) and opens.
        let p = scratch("choke-owned-hot");
        bootstrap_fresh(&p).unwrap();
        {
            let c = rusqlite::Connection::open(&p).unwrap();
            pin_durability_profile(&c).unwrap();
            c.execute_batch("PRAGMA wal_autocheckpoint=0;").unwrap();
            c.execute(
                "INSERT INTO engine_config (generation, recorded_at, kind, payload)
                 VALUES (2, strftime('%s','now'), 'test_act', '{\"capture\":\"on\"}');",
                [],
            )
            .unwrap();
            let copy = scratch("choke-owned-hot-copy");
            std::fs::copy(&p, &copy).unwrap();
            std::fs::copy(format!("{}-wal", p.display()), format!("{}-wal", copy.display()))
                .unwrap();
            let conn = open_verified_connection(&copy);
            assert!(conn.is_ok(), "an owned hot store must open: {:?}", conn.err());
            drop(conn);
            for f in sidecar_paths(&copy) {
                let _ = std::fs::remove_file(f);
            }
            let _ = std::fs::remove_file(&copy);
        }
        for f in sidecar_paths(&p) {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn projection_constructors_refuse_an_unverified_store_unmutated() {
        // 2nd appearance of the unverified-connection class (closed it
        // for the intent log): a projection constructor ran the PERSISTENT WAL flip on a
        // store nobody verified, and on an absent path minted a zero-id database that
        // bricked the subsequent intent-log open.
        let p = stamped_store("proj-foreign", 0xDEAD_BEEF, 8);
        let before = std::fs::read(&p).unwrap();
        assert!(
            crate::message_store::SqliteMessageStore::open(&p).is_err(),
            "a foreign store must refuse"
        );
        assert_eq!(before, std::fs::read(&p).unwrap(), "the refusal must be byte-stable");
        std::fs::remove_file(&p).unwrap();

        let absent = scratch("proj-absent");
        assert!(
            crate::message_store::SqliteMessageStore::open(&absent).is_err(),
            "an absent path must refuse — projections never bootstrap"
        );
        assert!(!absent.exists(), "a refused projection open must not mint a file");

        let p2 = stamped_store("proj-foreign-hdr", 0xDEAD_BEEF, 8);
        assert!(crate::message_header::SqliteMessageHeaderStore::open(&p2).is_err());
        std::fs::remove_file(&p2).unwrap();
    }

    #[test]
    fn tmp_reservation_skips_a_stale_candidate_it_did_not_create() {
        // 2nd appearance of the unowned-deletion class: under PID
        // reuse, the name-only uniqueness scheme ADOPTED a stale temp file and the guard
        // deleted it on error. Reservation must be an atomic create_new: an existing
        // candidate is skipped, never adopted, never deleted.
        // a private guarded directory, never the shared temp root.
        let dir = crate::test_temp::TempDir::new("aruna-resv");
        let prefix = format!("aruna-resv-{}-t777", std::process::id());
        let stale = dir.join(format!("{prefix}.7"));
        std::fs::write(&stale, b"stale bytes from a killed bootstrap, not ours").unwrap();
        let reserved = reserve_tmp_sibling(&dir, &prefix, 7).unwrap();
        assert_ne!(reserved, stale, "an existing candidate is never adopted");
        assert_eq!(
            std::fs::read(&stale).unwrap(),
            b"stale bytes from a killed bootstrap, not ours"
        );
        assert!(reserved.exists(), "the reserved name was atomically created by us");
        std::fs::remove_file(&stale).unwrap();
        std::fs::remove_file(&reserved).unwrap();
    }

    #[test]
    fn bootstrap_rechecks_the_file_family_under_the_lock() {
        // A -wal/-journal orphan can APPEAR beside the still-absent main while
        // this call waits for the init lock; installing a fresh main beside it would let
        // SQLite replay that orphan OVER the new v8 store. The family check must re-run
        // under the lock, not only at preflight.
        let p = scratch("lock-sidecar");
        std::fs::write(format!("{}-wal", p.display()), b"orphan").unwrap();
        let err = match bootstrap_fresh(&p) {
            Err(e) => e,
            Ok(o) => panic!("bootstrap beside an orphaned sidecar must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("damaged"), "{err}");
        assert!(!p.exists(), "nothing may be installed beside the orphan");
        std::fs::remove_file(format!("{}-wal", p.display())).unwrap();
    }

    #[test]
    fn a_stale_lock_file_from_a_dead_process_never_wedges_bootstrap() {
        // The lock must be an OS advisory lock the KERNEL releases on process
        // death — a crashed holder's leftover lock FILE is just an address, never a held
        // lock, so a later first-open proceeds instead of erroring until manual deletion.
        let p = scratch("stale-lock");
        std::fs::write(format!("{}.photon-init.lock", p.display()), b"").unwrap();
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::Installed);
        for f in sidecar_paths(&p) { let _ = std::fs::remove_file(f); }
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn bootstrap_never_deletes_a_sibling_it_did_not_create() {
        // The fixed-name stale-temp cleanup deleted `<dest>.photon-init-tmp`
        // without proving ownership — an unrelated user file at that name was destroyed
        // by merely opening the store.
        let p = scratch("no-sibling-delete");
        let sibling = std::path::PathBuf::from(format!("{}.photon-init-tmp", p.display()));
        std::fs::write(&sibling, b"unrelated user bytes, not ours to delete").unwrap();
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::Installed);
        assert_eq!(
            std::fs::read(&sibling).unwrap(),
            b"unrelated user bytes, not ours to delete",
            "bootstrap must never unlink a file it did not create"
        );
        std::fs::remove_file(&sibling).unwrap();
        for f in sidecar_paths(&p) { let _ = std::fs::remove_file(f); }
        std::fs::remove_file(&p).unwrap();
    }

    // ==================================================================================
    // The WINDOWS NAME-DOMAIN close: names Windows silently maps OUT of the
    // ordinary filesystem namespace. Primary source (opened + swept 2026-08-08):
    // learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file — the reserved set is
    // CON PRN AUX NUL COM1-9 COM¹²³ LPT1-9 LPT¹²³, "also avoid these names followed
    // immediately by an extension; for example, NUL.txt and NUL.tar.gz are both
    // equivalent to NUL"; ':' is a reserved character (the ADS address form); "do not
    // end a file or directory name with a space or a period" (Win32 strips them).
    // ==================================================================================

    #[cfg(windows)]
    #[test]
    fn an_ads_name_is_refused_before_any_stream_touches_the_carrier() {
        // executed probe: bootstrap on `carrier.db:photon` minted the stream
        // `carrier.db:photon.photon-init.lock:$DATA` ON the carrier file before failing,
        // and raw SQLite writes a whole database into the ADS with the carrier's visible
        // size unchanged. The name must refuse at the contract — before any lock or temp
        // sibling is DERIVED from it.
        let carrier = scratch("ads-carrier");
        std::fs::write(&carrier, b"carrier bytes, not ours").unwrap();
        let ads = std::path::PathBuf::from(format!("{}:photon", carrier.display()));
        let err = match bootstrap_fresh(&ads) {
            Err(e) => e,
            Ok(o) => panic!("an ADS name must refuse at bootstrap, got {o:?}"),
        };
        assert!(format!("{err}").contains("alternate data stream"), "{err}");
        let perr = match preflight(&ads) {
            Err(e) => e,
            Ok(p) => panic!("an ADS name must refuse at preflight, got {p:?}"),
        };
        assert!(format!("{perr}").contains("alternate data stream"), "{perr}");
        // The carrier is byte-identical and carries NO derived lock stream: opening the
        // stream name the pre- code minted must fail (stream absent).
        assert_eq!(std::fs::read(&carrier).unwrap(), b"carrier bytes, not ours");
        let lock_stream = format!("{}:photon.photon-init.lock", carrier.display());
        assert!(
            std::fs::File::open(&lock_stream).is_err(),
            "no lock ADS may exist on the carrier"
        );
        std::fs::remove_file(&carrier).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn reserved_device_names_are_refused_with_nothing_materialized() {
        // executed probes: `CON` and `COM1` produced real 69,632-byte stores the
        // documented reset path (Explorer/cmd deletion) cannot delete; `NUL` failed with
        // a misleading message. The reserved set — extensions included, per the primary
        // — must refuse at the contract with NOTHING created: no store, no lock, no temp.
        let dir = crate::test_temp::TempDir::new("aruna-57-devices"); // guarded, unique
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["CON", "com1", "COM¹", "NUL", "con.db", "NUL.tar.gz", "lpt9.txt"] {
            let dest = dir.join(name);
            let err = match bootstrap_fresh(&dest) {
                Err(e) => e,
                Ok(o) => panic!("{name}: a reserved device name must refuse, got {o:?}"),
            };
            assert!(format!("{err}").contains("reserved"), "{name}: {err}");
            let perr = match preflight(&dest) {
                Err(e) => e,
                Ok(p) => panic!("{name}: preflight must refuse, got {p:?}"),
            };
            assert!(format!("{perr}").contains("reserved"), "{name}: {perr}");
        }
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            0,
            "a refused name must materialize nothing"
        );
        std::fs::remove_dir(&dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn trailing_dot_or_space_names_are_refused() {
        // Win32 silently STRIPS trailing dots and spaces at creation — the file
        // that appears is a DIFFERENT name than the one preflighted, locked, and fsynced.
        let dir = crate::test_temp::TempDir::new("aruna-57-trail"); // guarded, unique
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["trail.db.", "trail.db "] {
            let dest = dir.join(name);
            let err = match bootstrap_fresh(&dest) {
                Err(e) => e,
                Ok(o) => panic!("{name:?}: a trailing-dot/space name must refuse, got {o:?}"),
            };
            assert!(format!("{err}").contains("dot or space"), "{name:?}: {err}");
        }
        assert!(
            !dir.join("trail.db").exists(),
            "the stripped sibling name must never appear"
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn the_windows_name_domain_predicate_matches_microsofts_documented_set() {
        // Pure-predicate witness, runs on EVERY platform/CI leg (the door tests above
        // are Windows-only; this pins the set itself everywhere). Out-of-domain side:
        for bad in [
            "CON", "con", "PRN", "AUX", "NUL", "COM1", "com9", "COM¹", "COM²", "COM³",
            "LPT1", "lpt9", "LPT¹", "con.db", "NUL.tar.gz", "Com1.txt", "con .db",
            "carrier.db:photon", "photon.db.", "photon.db ",
        ] {
            assert!(
                windows_name_domain_defect(bad).is_some(),
                "{bad:?} must be out of the ordinary namespace"
            );
        }
        // In-domain side — exactly Microsoft's set, nothing wider:
        for good in [
            "photon.db", "com10.db", "COM0.db", "console.db", "nulx.db", ".temp",
            "aux2.db", "lpt.db", "com.db", "prn1.db", "LPT0.txt", "¹.db",
        ] {
            assert!(
                windows_name_domain_defect(good).is_none(),
                "{good:?} is an ordinary name and must stay in domain"
            );
        }
    }

    #[test]
    fn near_miss_names_stay_in_domain() {
        // Over-refusal guard (the SQLITE_OPEN_NOFOLLOW lesson: a belt broader than the
        // hazard refused every legitimate store on one OS): COM0, COM10, CONSOLE, NULX,
        // AUX2 and a leading dot are ORDINARY names on every platform — the refused set
        // is exactly Microsoft's documented one, nothing wider.
        let dir = crate::test_temp::TempDir::new("aruna-57-ok"); // guarded, unique
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["com10.db", "COM0.db", "console.db", "nulx.db", ".temp57", "aux2.db"] {
            let dest = dir.join(name);
            assert_eq!(
                bootstrap_fresh(&dest).expect(name),
                BootstrapOutcome::Installed,
                "{name} is in the ordinary namespace and must bootstrap"
            );
            for f in sidecar_paths(&dest) {
                let _ = std::fs::remove_file(f);
            }
            let _ = std::fs::remove_file(format!("{}.photon-init.lock", dest.display()));
            std::fs::remove_file(&dest).unwrap();
        }
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn destination_dir_of_a_bare_filename_is_dot() {
        // `Path::parent()` of "photon.db" is Some("") — the unix directory
        // fsync then opens "" and ENOENTs AFTER the store was installed.
        assert_eq!(destination_dir(std::path::Path::new("photon.db")), std::path::Path::new("."));
        // An absolute path under a guarded (never created) directory — the parent is
        // that directory, exactly as it was the temp root itself before.
        let root = crate::test_temp::TempDir::uncreated("aruna-destdir");
        let abs = root.join("x.db");
        assert_eq!(destination_dir(&abs), root.path());
    }

    #[test]
    fn first_run_act_records_the_current_schema_version_not_a_literal() {
        // The payload hardcoded 8 beside the CURRENT_VERSION authority.
        let p = scratch("act-version");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        let payload: String = conn
            .query_row("SELECT payload FROM engine_config WHERE generation=1;", [], |r| r.get(0))
            .unwrap();
        assert!(
            payload.contains(&format!("\"schema_version\":{CURRENT_VERSION}")),
            "the first-run act must record the one version authority: {payload}"
        );
        drop(conn);
        for f in sidecar_paths(&p) { let _ = std::fs::remove_file(f); }
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn fresh_bootstrap_produces_a_complete_self_contained_current_version_store() {
        let p = scratch("bootstrap");
        bootstrap_fresh(&p).unwrap();
        // Raw header carries both stamps (checkpointed into the main file — no sidecar dependency).
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(&bytes[..16], SQLITE_MAGIC);
        assert_eq!(
            u32::from_be_bytes(bytes[60..64].try_into().unwrap()),
            CURRENT_VERSION
        );
        assert_eq!(
            u32::from_be_bytes(bytes[68..72].try_into().unwrap()),
            APPLICATION_ID
        );
        // First-run config act: generation 1, capture on, retention dormant (design §6).
        let conn = rusqlite::Connection::open(&p).unwrap();
        let (generation, kind, payload): (i64, String, String) = conn
            .query_row(
                "SELECT generation, kind, payload FROM engine_config ORDER BY generation LIMIT 1;",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(generation, 1);
        assert_eq!(kind, "first_run");
        assert!(payload.contains("\"capture\":\"on\""), "{payload}");
        assert!(payload.contains("\"retention\":\"dormant\""), "{payload}");
        assert!(payload.contains("\"journal_mode\":\"wal\""), "{payload}");
        // control_epoch singleton initialized.
        let epoch: i64 = conn
            .query_row("SELECT epoch FROM control_epoch WHERE id=1;", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(epoch, 1);
        drop(conn);
        for f in sidecar_paths(&p) {
            let _ = std::fs::remove_file(f);
        }
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn engine_config_is_append_only_by_trigger() {
        let p = scratch("appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        assert!(conn
            .execute("UPDATE engine_config SET payload='x' WHERE generation=1;", [])
            .is_err());
        assert!(conn
            .execute("DELETE FROM engine_config WHERE generation=1;", [])
            .is_err());
        drop(conn);
        for f in sidecar_paths(&p) {
            let _ = std::fs::remove_file(f);
        }
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn engine_config_append_only_survives_insert_or_replace() {
        // `engine_config_no_delete` / `_no_update` do NOT cover
        // `INSERT OR REPLACE`. With SQLite's default `recursive_triggers=off`, the implicit
        // DELETE that REPLACE performs on the conflicting row fires NO delete trigger — so a
        // recorded config act (the generation-1 first-run act that admission provenance points
        // at) could be rewritten in place, silently, through an append-only ledger.
        let p = scratch("replace-appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        let before: String = conn
            .query_row(
                "SELECT payload FROM engine_config WHERE generation=1;",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let attempt = conn.execute(
            "INSERT OR REPLACE INTO engine_config (generation, recorded_at, kind, payload)
             VALUES (1, strftime('%s','now'), 'rewritten', '{\"capture\":\"off\"}');",
            [],
        );
        assert!(
            attempt.is_err(),
            "INSERT OR REPLACE over a recorded generation must be refused, got {attempt:?}"
        );
        let after: String = conn
            .query_row(
                "SELECT payload FROM engine_config WHERE generation=1;",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after, "the recorded act must be byte-identical");
        drop(conn);
        cleanup(&p);
    }

    // the sever_attribution CHILD table (design:799-820) --------------

    /// Seed the parent witness row a `sever_attribution` child hangs off. Hand-written SQL on
    /// purpose: this witness is about the DDL's own constraints, not about the sever door.
    fn seed_sever_witness(conn: &rusqlite::Connection, epoch: i64) {
        conn.execute(
            "INSERT INTO sever_witness
                (witness_id, epoch, severed_at, authority_ref, member_count, member_set, digest)
             VALUES (?1, ?2, '2026-08-10T00:00:00Z', 'authority:test', 0, '[]', 'deadbeef');",
            rusqlite::params![format!("w-{epoch}"), epoch],
        )
        .unwrap();
    }

    fn insert_attribution(
        conn: &rusqlite::Connection,
        epoch: i64,
        requester_ref: &str,
        kind: &str,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO sever_attribution (epoch, requester_ref, kind, created_at)
             VALUES (?1, ?2, ?3, strftime('%s','now'));",
            rusqlite::params![epoch, requester_ref, kind],
        )
    }

    #[test]
    fn sever_attribution_is_a_non_unique_append_only_child_of_the_witness() {
        // (design:799-820;: `sever_witness.epoch` is UNIQUE, so
        // attribution can NEVER ride that table's rows — it lives HERE, and `sever_witness`
        // itself stays byte-identical). The child's contract, all of it:
        //   · `epoch` is a FK to the witness and is deliberately NOT unique — many requesters
        //     coalesce into ONE service and therefore into ONE epoch;
        //   · `kind` is closed over the three windows the design names;
        //   · the table is append-only (UPDATE / DELETE / REPLACE all refused).
        let p = scratch("sever-attribution");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        seed_sever_witness(&conn, 2);

        // MANY ROWS, ONE EPOCH — the whole reason this is a child table.
        insert_attribution(&conn, 2, "authority:a", "in-snapshot").unwrap();
        insert_attribution(&conn, 2, "authority:b", "overflow-joiner").unwrap();
        insert_attribution(&conn, 2, "authority:c", "post-snapshot").unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sever_attribution WHERE epoch = 2;",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 3, "epoch is NOT unique on the child table");

        // The FK: an attribution against an epoch no witness records is not attribution.
        assert!(
            insert_attribution(&conn, 99, "authority:d", "in-snapshot").is_err(),
            "an attribution row must reference a real sever_witness epoch"
        );
        // The CHECK: the three windows, closed.
        assert!(
            insert_attribution(&conn, 2, "authority:e", "joiner").is_err(),
            "kind is closed over the design's three windows"
        );

        // APPEND-ONLY, the engine_config three-trigger pattern.
        assert!(conn
            .execute("UPDATE sever_attribution SET requester_ref='x';", [])
            .is_err());
        assert!(conn
            .execute("DELETE FROM sever_attribution WHERE epoch = 2;", [])
            .is_err());
        let rowid: i64 = conn
            .query_row("SELECT MIN(rowid) FROM sever_attribution;", [], |r| r.get(0))
            .unwrap();
        assert!(
            conn.execute(
                "INSERT OR REPLACE INTO sever_attribution (rowid, epoch, requester_ref, kind,
                                                           created_at)
                 VALUES (?1, 2, 'rewritten', 'in-snapshot', 0);",
                rusqlite::params![rowid],
            )
            .is_err(),
            "INSERT OR REPLACE over a recorded rowid must be refused — REPLACE's implicit \
             DELETE fires no delete trigger under recursive_triggers=off"
        );
        let survivors: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sever_attribution WHERE requester_ref = 'rewritten';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(survivors, 0);

        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn sever_witness_schema_is_untouched_by_the_attribution_child() {
        // regression fence, at the SCHEMA byte: the child table arrives beside
        // `sever_witness`, never inside it. Column list, order, types and the UNIQUE epoch are
        // exactly what the dispatch stage froze.
        let p = scratch("sever-witness-frozen");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        let mut stmt = conn
            .prepare("SELECT name, type, \"notnull\" FROM pragma_table_info('sever_witness');")
            .unwrap();
        let cols: Vec<(String, String, i64)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            cols,
            vec![
                ("witness_id".to_string(), "TEXT".to_string(), 0),
                ("epoch".to_string(), "INTEGER".to_string(), 1),
                ("severed_at".to_string(), "TEXT".to_string(), 1),
                ("authority_ref".to_string(), "TEXT".to_string(), 1),
                ("member_count".to_string(), "INTEGER".to_string(), 1),
                ("member_set".to_string(), "TEXT".to_string(), 1),
                ("digest".to_string(), "TEXT".to_string(), 1),
            ],
            "sever_witness is UNTOUCHED, full stop (r2 fold)"
        );
        drop(stmt);
        let sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='sever_witness';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            sql.contains("epoch         INTEGER NOT NULL UNIQUE"),
            "the UNIQUE epoch is the constraint that forced attribution into a child table: {sql}"
        );
        drop(conn);
        cleanup(&p);
    }

    // (design §5.2a/§5.2d/§7a): attempt_fact / adjudication_record DDL ----

    /// Seed one valid `attempt_fact` CLAIM row + its `attempt_head` projection row — the
    /// minimal shape `adjudication_record`'s FK and the append-only witnesses below build on.
    fn seed_attempt(conn: &rusqlite::Connection, attempt_id: &str, operation_id: &str) {
        conn.execute(
            "INSERT INTO attempt_fact
                (operation_id, attempt_id, revision, fact_kind, attempt_ordinal, basis_epoch,
                 created_at, payload, prior_revision)
             VALUES (?1, ?2, 1, 'claim', 1, 1, '2026-08-08T00:00:00Z', '{}', NULL);",
            rusqlite::params![operation_id, attempt_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO attempt_head
                (attempt_id, operation_id, current_revision, derived_class,
                 last_verified_revision, verified_state)
             VALUES (?1, ?2, 1, 'issued_or_unknown', 0, '{}');",
            rusqlite::params![attempt_id, operation_id],
        )
        .unwrap();
    }

    #[test]
    fn attempt_fact_is_append_only_by_trigger() {
        // Mirrors `engine_config_is_append_only_by_trigger` exactly (store_open.rs:583-599
        // recon anchor, design §5.2a: the fact chain is the system-of-record for attempt
        // state — a rewritable ledger is not one).
        let p = scratch("attempt-fact-appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        assert!(conn
            .execute(
                "UPDATE attempt_fact SET payload='x' WHERE attempt_id='att-1' AND revision=1;",
                []
            )
            .is_err());
        assert!(conn
            .execute(
                "DELETE FROM attempt_fact WHERE attempt_id='att-1' AND revision=1;",
                []
            )
            .is_err());
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn attempt_fact_append_only_survives_insert_or_replace() {
        // pattern (engine_config precedent): `_no_update`/`_no_delete` do not
        // cover `INSERT OR REPLACE`'s implicit delete under `recursive_triggers=off`.
        let p = scratch("attempt-fact-replace-appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        let before: String = conn
            .query_row(
                "SELECT payload FROM attempt_fact WHERE attempt_id='att-1' AND revision=1;",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let attempt = conn.execute(
            "INSERT OR REPLACE INTO attempt_fact
                (operation_id, attempt_id, revision, fact_kind, attempt_ordinal, basis_epoch,
                 created_at, payload, prior_revision)
             VALUES ('op-1', 'att-1', 1, 'claim', 1, 999, '2026-08-08T00:00:00Z',
                     '{\"rewritten\":true}', NULL);",
            [],
        );
        assert!(
            attempt.is_err(),
            "INSERT OR REPLACE over a recorded (attempt_id, revision) must be refused, got {attempt:?}"
        );
        let after: String = conn
            .query_row(
                "SELECT payload FROM attempt_fact WHERE attempt_id='att-1' AND revision=1;",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after, "the recorded fact must be byte-identical");
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn attempt_fact_append_only_survives_insert_or_replace_on_the_ordinal_key() {
        // `attempt_fact` carries TWO unique constraints, and the
        // era `_no_replace` trigger guarded only ONE of them. An `INSERT OR REPLACE`
        // carrying a FRESH `(attempt_id, revision)` sails past the trigger's `WHEN`, and then
        // the SECOND constraint — `UNIQUE (operation_id, attempt_ordinal)` — resolves the
        // conflict with an implicit DELETE that fires no delete trigger under
        // `recursive_triggers=off`. The original CLAIM vanishes: the retry-lineage referee
        // rewritten out of an append-only ledger.
        let p = scratch("attempt-fact-replace-ordinal");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        let attempt = conn.execute(
            "INSERT OR REPLACE INTO attempt_fact
                (operation_id, attempt_id, revision, fact_kind, attempt_ordinal, basis_epoch,
                 created_at, payload, prior_revision)
             VALUES ('op-1', 'att-2', 1, 'claim', 1, 999, '2026-08-08T00:00:00Z',
                     '{\"rewritten\":true}', NULL);",
            [],
        );
        assert!(
            attempt.is_err(),
            "INSERT OR REPLACE over a recorded (operation_id, attempt_ordinal) must be \
             refused, got {attempt:?}"
        );
        let survivors: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM attempt_fact WHERE attempt_id = 'att-1';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            survivors, 1,
            "the original CLAIM must still be there — the ordinal key is a conflict channel too"
        );
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn attempt_fact_fact_kind_check_refuses_a_14th_kind() {
        // The 13-kind CLOSED grammar (§5.2a transcription) — a kind outside the set must be
        // refused at the DDL boundary, never silently accepted as a free string.
        let p = scratch("attempt-fact-check");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        let attempt = conn.execute(
            "INSERT INTO attempt_fact
                (operation_id, attempt_id, revision, fact_kind, attempt_ordinal, basis_epoch,
                 created_at, payload, prior_revision)
             VALUES ('op-1', 'att-1', 1, 'not_a_real_kind', 1, 1, '2026-08-08T00:00:00Z', '{}', NULL);",
            [],
        );
        assert!(
            attempt.is_err(),
            "a fact_kind outside the 13-member grammar must be refused, got {attempt:?}"
        );
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn attempt_fact_unique_attempt_revision_is_the_compare_and_append_arbiter() {
        // UNIQUE (attempt_id, revision) — the mechanical race referee a lost compare-and-append
        // reads back through (§5.2a).
        let p = scratch("attempt-fact-unique-revision");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        let dup = conn.execute(
            "INSERT INTO attempt_fact
                (operation_id, attempt_id, revision, fact_kind, attempt_ordinal, basis_epoch,
                 created_at, payload, prior_revision)
             VALUES ('op-1', 'att-1', 1, 'send_authorized', NULL, 1, '2026-08-08T00:00:01Z', '{}', 1);",
            [],
        );
        assert!(
            dup.is_err(),
            "a second fact at an already-recorded (attempt_id, revision) must be refused, got {dup:?}"
        );
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn attempt_fact_unique_operation_ordinal_rejects_a_duplicate_claim_ordinal() {
        // UNIQUE (operation_id, attempt_ordinal) — ATTEMPT-ORDINAL/RETRY-TOTALITY's SQL half
        // (§5.2a): two CLAIM facts under the same operation may never carry the same ordinal.
        // Non-CLAIM facts carry a NULL ordinal, and SQLite's UNIQUE treats every NULL as
        // distinct — proven by the second insert below, which is NOT an ordinal collision and
        // must succeed.
        let p = scratch("attempt-fact-unique-ordinal");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        let dup_ordinal = conn.execute(
            "INSERT INTO attempt_fact
                (operation_id, attempt_id, revision, fact_kind, attempt_ordinal, basis_epoch,
                 created_at, payload, prior_revision)
             VALUES ('op-1', 'att-2', 1, 'claim', 1, 1, '2026-08-08T00:00:01Z', '{}', NULL);",
            [],
        );
        assert!(
            dup_ordinal.is_err(),
            "a second CLAIM at an already-recorded (operation_id, attempt_ordinal) must be \
             refused, got {dup_ordinal:?}"
        );
        let null_ordinal = conn.execute(
            "INSERT INTO attempt_fact
                (operation_id, attempt_id, revision, fact_kind, attempt_ordinal, basis_epoch,
                 created_at, payload, prior_revision)
             VALUES ('op-1', 'att-1', 2, 'send_authorized', NULL, 1, '2026-08-08T00:00:01Z', '{}', 1);",
            [],
        );
        assert!(
            null_ordinal.is_ok(),
            "a NULL-ordinal non-CLAIM fact must never collide with the CLAIM's ordinal, got {null_ordinal:?}"
        );
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn adjudication_record_is_append_only_by_trigger() {
        let p = scratch("adjudication-record-appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        conn.execute(
            "INSERT INTO adjudication_record
                (adjudication_id, attempt_id, principal_ref, basis_epoch, accepted_risk, reason,
                 opaque_reference, known_at_snapshot, exposure_key, created_at)
             VALUES ('adj-1', 'att-1', 'principal-1', 1, 'none-claimed',
                     'operator-abandoned-unresolved', NULL, '{}', 'exposure-key-1',
                     '2026-08-08T00:00:00Z');",
            [],
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE adjudication_record SET principal_ref='someone-else' \
                 WHERE adjudication_id='adj-1';",
                []
            )
            .is_err());
        assert!(conn
            .execute(
                "DELETE FROM adjudication_record WHERE adjudication_id='adj-1';",
                []
            )
            .is_err());
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn adjudication_record_append_only_survives_insert_or_replace() {
        let p = scratch("adjudication-record-replace-appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        conn.execute(
            "INSERT INTO adjudication_record
                (adjudication_id, attempt_id, principal_ref, basis_epoch, accepted_risk, reason,
                 opaque_reference, known_at_snapshot, exposure_key, created_at)
             VALUES ('adj-1', 'att-1', 'principal-1', 1, 'none-claimed',
                     'operator-abandoned-unresolved', NULL, '{}', 'exposure-key-1',
                     '2026-08-08T00:00:00Z');",
            [],
        )
        .unwrap();
        let before: String = conn
            .query_row(
                "SELECT principal_ref FROM adjudication_record WHERE adjudication_id='adj-1';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let attempt = conn.execute(
            "INSERT OR REPLACE INTO adjudication_record
                (adjudication_id, attempt_id, principal_ref, basis_epoch, accepted_risk, reason,
                 opaque_reference, known_at_snapshot, exposure_key, created_at)
             VALUES ('adj-1', 'att-1', 'someone-else', 1, 'none-claimed',
                     'operator-abandoned-unresolved', NULL, '{}', 'exposure-key-1',
                     '2026-08-08T00:00:00Z');",
            [],
        );
        assert!(
            attempt.is_err(),
            "INSERT OR REPLACE over a recorded adjudication_id must be refused, got {attempt:?}"
        );
        let after: String = conn
            .query_row(
                "SELECT principal_ref FROM adjudication_record WHERE adjudication_id='adj-1';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after, "the recorded record must be byte-identical");
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn adjudication_record_closed_vocab_checks_refuse_free_text() {
        // NO free text anywhere: `accepted_risk` and `reason` are each a CLOSED
        // enum at the DDL boundary — an out-of-vocabulary value (a pasted excerpt, e.g.) must
        // be refused, never silently accepted.
        let p = scratch("adjudication-record-closed-vocab");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        let bad_risk = conn.execute(
            "INSERT INTO adjudication_record
                (adjudication_id, attempt_id, principal_ref, basis_epoch, accepted_risk, reason,
                 opaque_reference, known_at_snapshot, exposure_key, created_at)
             VALUES ('adj-1', 'att-1', 'principal-1', 1, 'the customer emailed to say sorry',
                     'operator-abandoned-unresolved', NULL, '{}', 'exposure-key-1',
                     '2026-08-08T00:00:00Z');",
            [],
        );
        assert!(bad_risk.is_err(), "a free-text accepted_risk must be refused, got {bad_risk:?}");
        let bad_reason = conn.execute(
            "INSERT INTO adjudication_record
                (adjudication_id, attempt_id, principal_ref, basis_epoch, accepted_risk, reason,
                 opaque_reference, known_at_snapshot, exposure_key, created_at)
             VALUES ('adj-2', 'att-1', 'principal-1', 1, 'none-claimed',
                     'the operator felt like it', NULL, '{}', 'exposure-key-1',
                     '2026-08-08T00:00:00Z');",
            [],
        );
        assert!(bad_reason.is_err(), "a free-text reason must be refused, got {bad_reason:?}");
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn exposure_obligation_accepts_the_exp_1_key_and_retires_by_update() {
        // exposure_obligation is the durable EXP-2 obligation home — MUTABLE (unlike the two
        // append-only ledgers above): retirement is a single-column UPDATE (EXP-8).
        let p = scratch("exposure-obligation-shape");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_attempt(&conn, "att-1", "op-1");
        conn.execute(
            "INSERT INTO exposure_obligation
                (obligation_id, provider_scope, primitive_atom, direction, generation,
                 contributor_attempt_id, created_at, retired_at)
             VALUES ('obl-1', 'jmap:[\"acct\",\"msg\"]', 'label:INBOX', 'set-true', 1, 'att-1',
                     '2026-08-08T00:00:00Z', NULL);",
            [],
        )
        .unwrap();
        let retired_before: Option<String> = conn
            .query_row(
                "SELECT retired_at FROM exposure_obligation WHERE obligation_id='obl-1';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retired_before, None);
        conn.execute(
            "UPDATE exposure_obligation SET retired_at='2026-08-09T00:00:00Z' \
             WHERE obligation_id='obl-1';",
            [],
        )
        .unwrap();
        let retired_after: Option<String> = conn
            .query_row(
                "SELECT retired_at FROM exposure_obligation WHERE obligation_id='obl-1';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retired_after.as_deref(), Some("2026-08-09T00:00:00Z"));
        drop(conn);
        cleanup(&p);
    }

    /// Seed one `sever_witness` row — the shape the append-only witnesses below mutate at.
    fn seed_witness(conn: &rusqlite::Connection, witness_id: &str, epoch: i64) {
        conn.execute(
            "INSERT INTO sever_witness
                (witness_id, epoch, severed_at, authority_ref, member_count, member_set, digest)
             VALUES (?1, ?2, '2026-08-08T00:00:00Z', 'authority-ref-1', 0, '[]', 'deadbeef');",
            rusqlite::params![witness_id, epoch],
        )
        .unwrap();
    }

    #[test]
    fn sever_witness_is_append_only_by_trigger() {
        // §5.1: "if the post-sever audit is lost, this row is the only surviving evidence" —
        // so it mirrors `engine_config`/`attempt_fact`'s three-trigger pattern exactly. A
        // rewritable witness is not evidence.
        let p = scratch("sever-witness-appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_witness(&conn, "w-1", 2);
        assert!(conn
            .execute("UPDATE sever_witness SET digest='x' WHERE witness_id='w-1';", [])
            .is_err());
        assert!(conn
            .execute("DELETE FROM sever_witness WHERE witness_id='w-1';", [])
            .is_err());
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn sever_witness_append_only_survives_insert_or_replace_on_either_key() {
        // Both conflict keys are guarded: `witness_id` AND `epoch`. Either one alone would let
        // a recorded witness be rewritten in place through the implicit DELETE that
        // `INSERT OR REPLACE` performs under `recursive_triggers=off`.
        let p = scratch("sever-witness-replace-appendonly");
        bootstrap_fresh(&p).unwrap();
        let conn = rusqlite::Connection::open(&p).unwrap();
        seed_witness(&conn, "w-1", 2);
        let by_id = conn.execute(
            "INSERT OR REPLACE INTO sever_witness
                (witness_id, epoch, severed_at, authority_ref, member_count, member_set, digest)
             VALUES ('w-1', 99, '2026-08-08T00:00:00Z', 'other', 0, '[]', 'rewritten');",
            [],
        );
        assert!(by_id.is_err(), "REPLACE on a recorded witness_id must be refused, got {by_id:?}");
        let by_epoch = conn.execute(
            "INSERT OR REPLACE INTO sever_witness
                (witness_id, epoch, severed_at, authority_ref, member_count, member_set, digest)
             VALUES ('w-2', 2, '2026-08-08T00:00:00Z', 'other', 0, '[]', 'rewritten');",
            [],
        );
        assert!(
            by_epoch.is_err(),
            "REPLACE on a recorded epoch must be refused too, got {by_epoch:?}"
        );
        let digest: String = conn
            .query_row("SELECT digest FROM sever_witness WHERE witness_id='w-1';", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(digest, "deadbeef", "the recorded witness must be byte-identical");
        drop(conn);
        cleanup(&p);
    }

    #[test]
    fn bootstrap_loser_reopens_the_winners_store_never_clobbers() {
        // The no-replace rename refuses if the destination appeared. The
        // loser now reports that as an OUTCOME, not an error — losing the
        // install race is a normal result whose meaning is "reopen the winner's store".
        let p = scratch("noclobber");
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::Installed);
        let before = std::fs::read(&p).unwrap();
        // destination exists and is non-empty: the loser must not replace it
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::LostRace);
        assert_eq!(before, std::fs::read(&p).unwrap());
        for f in sidecar_paths(&p) {
            let _ = std::fs::remove_file(f);
        }
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn projection_store_connections_carry_the_full_profile() {
        // Design §2.2b: the gate applies to EVERY connection to the one
        // file — ANY connection can be the one that checkpoints or last-closes the WAL.
        let p = scratch("projection-profile");
        crate::SqliteIntentLog::open(&p).unwrap();

        let store = crate::message_store::SqliteMessageStore::open(&p).unwrap();
        let sync: i64 = store
            .conn_for_test()
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        assert!(sync >= 2, "projection connection must carry FULL, got {sync}");
        let fk: i64 = store
            .conn_for_test()
            .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1, "projection connection must carry the FK gate");
        // The DISCRIMINATING arm on this build: rusqlite's bundled SQLite already defaults
        // synchronous=FULL and (via -DSQLITE_DEFAULT_FOREIGN_KEYS=1) foreign_keys=ON, so
        // those two assertions hold even on an UNGATED connection. `busy_timeout` defaults
        // to 0 and is set only by the profile — it is what proves the gate actually ran.
        let bt: i64 = store
            .conn_for_test()
            .query_row("PRAGMA busy_timeout;", [], |r| r.get(0))
            .unwrap();
        assert!(bt >= 1, "projection connection must carry busy_timeout, got {bt}");

        let headers = crate::message_header::SqliteMessageHeaderStore::open(&p).unwrap();
        let sync: i64 = headers
            .conn_for_test()
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .unwrap();
        assert!(sync >= 2, "header connection must carry FULL, got {sync}");
        let fk: i64 = headers
            .conn_for_test()
            .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1, "header connection must carry the FK gate");
        let bt: i64 = headers
            .conn_for_test()
            .query_row("PRAGMA busy_timeout;", [], |r| r.get(0))
            .unwrap();
        assert!(bt >= 1, "header connection must carry busy_timeout, got {bt}");

        drop(store);
        drop(headers);
        for f in sidecar_paths(&p) {
            let _ = std::fs::remove_file(f);
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn projection_store_constructors_pin_the_profile_rather_than_inheriting_it() {
        // The DISCRIMINATING witness. On rusqlite's bundled build a bare `Connection::open`
        // ALREADY reads back synchronous=FULL, foreign_keys=ON
        // (libsqlite3-sys builds with -DSQLITE_DEFAULT_FOREIGN_KEYS=1) and busy_timeout=5000
        // (rusqlite's own default) — so none of those read-backs can tell a gated connection
        // from an ungated one, and neither can journal_mode over a file the intent log
        // already flipped to WAL. Over a DELETE-mode file it can: only a constructor that
        // actually RUNS the gate pins WAL. One file per store (the first pin is persistent).
        // (fixture recut: the chokepoint now — correctly — refuses an unstamped
        // version-0 file, so the DELETE-mode fixture must be a REAL v8 store: bootstrap
        // it, then persistently flip it OFF WAL through a raw ungated connection. The
        // discriminating property is unchanged: only a constructor that RUNS the gate
        // flips it back.)
        for which in ["placement", "headers"] {
            let p = scratch(&format!("projection-nonwal-{which}"));
            bootstrap_fresh(&p).unwrap();
            {
                let c = rusqlite::Connection::open(&p).unwrap();
                let m: String = c
                    .query_row("PRAGMA journal_mode=DELETE;", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(m.to_lowercase(), "delete", "fixture must start OFF wal");
            }
            let mode: String = match which {
                "placement" => crate::message_store::SqliteMessageStore::open(&p)
                    .unwrap()
                    .conn_for_test()
                    .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
                    .unwrap(),
                _ => crate::message_header::SqliteMessageHeaderStore::open(&p)
                    .unwrap()
                    .conn_for_test()
                    .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
                    .unwrap(),
            };
            assert_eq!(
                mode.to_lowercase(),
                "wal",
                "the {which} store's constructor must pin the §2.2b profile itself"
            );
            for f in sidecar_paths(&p) {
                let _ = std::fs::remove_file(f);
            }
            let _ = std::fs::remove_file(&p);
        }
    }

    #[test]
    fn an_occupied_shm_name_refuses_fresh_bootstrap_byte_untouched() {
        // FC-2 relaxed a lone -shm to FreshBootstrap (tempfiles.html §2.3: it
        // cannot resurrect refused state — still true); / then priced the
        // relaxation: bootstrap installed a main whose WAL open OVERWROTE whatever sat
        // at `<db>-shm` (foreign user bytes destroyed), or bricked on a non-regular
        // node. The recut refuses ANY occupied family name at fresh bootstrap — an
        // installed store owns its family namespace, an absent store owns nothing. The
        // refusal is loud, actionable, and leaves the stray file byte-untouched.
        let p = scratch("lone-shm");
        let shm = format!("{}-shm", p.display());
        std::fs::write(&shm, b"stale shm bytes from a killed run").unwrap();
        let err = match preflight(&p) {
            Err(e) => e,
            Ok(o) => panic!("an occupied -shm name must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("occupied"), "{err}");
        assert!(bootstrap_fresh(&p).is_err());
        assert!(!p.exists(), "nothing may be installed beside an occupied -shm name");
        assert_eq!(
            std::fs::read(&shm).unwrap(),
            b"stale shm bytes from a killed run",
            "the stray file must be byte-untouched"
        );
        std::fs::remove_file(&shm).unwrap();
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn a_zero_length_destination_bootstraps_in_place() {
        // The late-unlink recut must keep design §7a case (a) intact: a zero-length
        // REGULAR file at the destination (a crashed first open's artifact) is
        // bootstrappable — the placeholder now survives until the temp is fully built.
        let p = scratch("zerolen-boot");
        std::fs::write(&p, b"").unwrap();
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::Installed);
        let bytes = std::fs::read(&p).unwrap();
        assert_eq!(&bytes[..16], SQLITE_MAGIC);
        cleanup(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn aux_names_stay_bounded_for_long_store_filenames() {
        // (portable arm): for a 255-byte store filename every auxiliary
        // name — the init lock, the temp main, and the temp's longest sidecar — must
        // stay within a 255-byte component limit. The unix arm below runs the real
        // bootstrap end-to-end.
        let long = "x".repeat(255);
        let stem = bounded_aux_stem(&long);
        let lock = format!("{stem}.photon-init.lock");
        assert!(lock.len() <= 255, "lock name {} bytes", lock.len());
        let tmp_longest =
            format!("{stem}.photon-init-tmp.{}.{}-journal", u32::MAX, u64::MAX);
        assert!(tmp_longest.len() <= 255, "tmp name {} bytes", tmp_longest.len());
        // and truncation never splits a multi-byte char
        let multi = "é".repeat(200);
        let stem = bounded_aux_stem(&multi);
        assert!(multi.is_char_boundary(stem.len()));
    }

    #[cfg(unix)]
    #[test]
    fn a_long_but_valid_store_filename_bootstraps() {
        // (end-to-end arm, unix — ext4/tmpfs enforce the 255-BYTE
        // component limit without Windows' MAX_PATH total-path constraint): a
        // 246-byte filename leaves room for SQLite's own -journal suffix (254) yet
        // pre-fix the temp reservation's `.photon-init-tmp.<pid>.<n>` suffix pushed
        // past 255 and ENAMETOOLONG'd every fresh open of a perfectly valid name.
        let dir = crate::test_temp::TempDir::new("aruna-longname"); // guarded, unique
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(format!("{}.db", "x".repeat(243)));
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::Installed);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dangling_wal_symlink_is_never_read_as_absent() {
        // FC-2: `Path::exists()` follows symlinks and maps a dangling link to
        // false — so a dangling -wal symlink read as "absent" and a fresh store installed
        // beside it. The sidecar presence check must see the NAME occupied (lstat).
        let p = scratch("dangle-wal");
        let target = scratch("dangle-wal-target"); // never created
        let wal = std::path::PathBuf::from(format!("{}-wal", p.display()));
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&target, &wal);
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&target, &wal);
        if let Err(e) = made {
            eprintln!("SKIP a_dangling_wal_symlink_is_never_read_as_absent: cannot create symlink: {e}");
            return;
        }
        let err = match preflight(&p) {
            Err(e) => e,
            Ok(o) => panic!("a dangling -wal symlink must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("damaged"), "{err}");
        assert!(
            bootstrap_fresh(&p).is_err(),
            "bootstrap must refuse beside a dangling -wal symlink"
        );
        assert!(!p.exists(), "nothing may be installed beside the dangling symlink");
        std::fs::remove_file(&wal).unwrap();
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn an_unclassifiable_store_path_refuses_instead_of_reading_fresh() {
        // FC-2: `metadata(main).…ok()` collapsed PermissionDenied and every other
        // I/O error into "absent ⇒ FRESH". Only NotFound may mean absent. Here the path
        // routes THROUGH a regular file: unix reports ENOTDIR (a non-NotFound error the
        // classifier must refuse). Windows maps this probe to plain NotFound (os error 3)
        // at the OS level — the classifier honestly reads "absent" there, so the Windows
        // arm asserts the bound that matters: bootstrap still fails loudly and installs
        // NOTHING through such a path.
        let file = scratch("classify-through-file");
        std::fs::write(&file, b"i am a file, not a directory").unwrap();
        let p = file.join("child.db");
        #[cfg(unix)]
        {
            let r = preflight(&p);
            assert!(
                r.is_err(),
                "a path through a regular file must refuse (ENOTDIR ≠ NotFound), got {r:?}"
            );
        }
        assert!(
            bootstrap_fresh(&p).is_err(),
            "bootstrap through a regular file must fail"
        );
        assert!(!p.exists(), "nothing may be installed through a regular file");
        std::fs::remove_file(&file).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_permission_denied_store_path_refuses_instead_of_reading_fresh() {
        // FC-2, the literal defect: PermissionDenied collapsed into "absent ⇒
        // FRESH". A parent directory with mode 000 makes the child's metadata read EACCES
        // — the classifier must refuse, never bootstrap. (Skipped when running as root,
        // where chmod 000 does not deny.)
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("classify-eacces-dir");
        std::fs::create_dir(&dir).unwrap();
        let p = dir.join("child.db");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = preflight(&p);
        let restore = || {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        match std::fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let err = match r {
                    Err(e) => e,
                    Ok(o) => {
                        restore();
                        panic!("a PermissionDenied store path must refuse, got {o:?}");
                    }
                };
                assert!(format!("{err}").contains("cannot classify"), "{err}");
            }
            _ => {
                // running as root: EACCES not reproducible — visible skip, not a false green
                eprintln!("SKIP a_permission_denied_store_path_refuses: chmod 000 did not deny");
            }
        }
        restore();
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn a_directory_at_the_store_path_refuses_with_its_type() {
        // FC-2: the fresh-bootstrap branch tested LENGTH, not TYPE.
        // On Windows a directory's metadata len is 0, so a DIRECTORY at the store path
        // classified as "zero-length ⇒ fresh" and bootstrap then tried to unlink it.
        // A non-regular node at the store path refuses and is never unlinked.
        let p = scratch("dir-at-path");
        std::fs::create_dir(&p).unwrap();
        let err = match preflight(&p) {
            Err(e) => e,
            Ok(o) => panic!("a directory at the store path must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("regular file"), "{err}");
        assert!(bootstrap_fresh(&p).is_err());
        assert!(p.is_dir(), "the directory must never be unlinked");
        std::fs::remove_dir(&p).unwrap();
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[cfg(unix)]
    #[test]
    fn a_socket_at_the_store_path_is_refused_and_never_unlinked() {
        // FC-2: on unix the length-not-type test let bootstrap `remove_file`
        // a FIFO/socket/device node at the destination — unlink succeeds on those, so a
        // foreign endpoint was silently destroyed and replaced by a database.
        let p = scratch("socket-at-path");
        let _listener = std::os::unix::net::UnixListener::bind(&p).unwrap();
        let err = match preflight(&p) {
            Err(e) => e,
            Ok(o) => panic!("a socket at the store path must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("regular file"), "{err}");
        assert!(bootstrap_fresh(&p).is_err());
        assert!(
            std::fs::symlink_metadata(&p).is_ok(),
            "the socket must never be unlinked"
        );
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn a_directory_at_the_shm_name_refuses_before_install() {
        // With -shm out of the damaging set, a DIRECTORY at `<db>-shm`
        // classified the family as fresh; bootstrap installed the main database and the
        // WAL reopen then failed ("unable to open database file") — a brick AFTER
        // install, strictly worse than refusing before it. The -shm relaxation is
        // type-gated: only NotFound or a regular file is bootstrappable.
        let p = scratch("shm-dir");
        let shm = format!("{}-shm", p.display());
        std::fs::create_dir(&shm).unwrap();
        let err = match preflight(&p) {
            Err(e) => e,
            Ok(o) => panic!("an unusable -shm name must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("occupied"), "{err}");
        assert!(
            bootstrap_fresh(&p).is_err(),
            "bootstrap must refuse beside an unusable -shm name"
        );
        assert!(!p.exists(), "nothing may be installed beside an unusable -shm name");
        std::fs::remove_dir(&shm).unwrap();
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn a_missing_control_epoch_row_refuses_instead_of_reseeding() {
        // The control-epoch fence seed lived in SCHEMA_DDL, which re-runs
        // on EVERY open — so a store whose singleton was lost (corruption, accidental
        // DELETE) silently re-seeded epoch 1 on the next open, rolling the sole control
        // fence back below any prior sever. Fail closed: the seed is bootstrap-only and
        // a verified store missing the row REFUSES.
        let p = scratch("epoch-missing");
        crate::SqliteIntentLog::open(&p).unwrap();
        {
            let raw = rusqlite::Connection::open(&p).unwrap();
            raw.execute("DELETE FROM control_epoch;", []).unwrap();
        }
        let reopen = crate::SqliteIntentLog::open(&p);
        assert!(
            reopen.is_err(),
            "a verified store with no control_epoch row must refuse, got Ok"
        );
        let raw = rusqlite::Connection::open(&p).unwrap();
        let rows: i64 = raw
            .query_row("SELECT COUNT(*) FROM control_epoch;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "the refusal must not re-mint the fence row");
        drop(raw);
        cleanup(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[cfg(unix)]
    #[test]
    fn a_pre_created_empty_destination_keeps_its_mode() {
        // Unlinking a caller-provisioned zero-length store discarded its
        // permissions — the installed temp carried default-umask creation metadata
        // (0600 provisioned → 0644 installed). The bootstrap now transfers the
        // destination's mode to the temp BEFORE the build writes any content.
        use std::os::unix::fs::PermissionsExt;
        let p = scratch("keep-mode");
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::Installed);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "a provisioned store's mode must survive the install"
        );
        cleanup(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[cfg(windows)]
    #[test]
    fn wide_verbatim_prefixes_disk_absolute_paths_only() {
        // contract: disk-absolute → \\?\ (slash-normalized), UNC →
        // \\?\UNC\, already-verbatim and relative → unchanged.
        let w = |p: &str| {
            let v = wide_verbatim(std::path::Path::new(p));
            String::from_utf16(&v[..v.len() - 1]).unwrap()
        };
        assert_eq!(w(r"C:\dir\store.db"), r"\\?\C:\dir\store.db");
        assert_eq!(w(r"C:/dir/store.db"), r"\\?\C:\dir\store.db");
        assert_eq!(w(r"\\?\C:\dir\store.db"), r"\\?\C:\dir\store.db");
        assert_eq!(w(r"\\server\share\store.db"), r"\\?\UNC\server\share\store.db");
        assert_eq!(w(r"relative\store.db"), r"relative\store.db");
        // The \\?\ form disables dot-segment resolution, so the segments
        // must be lexically resolved BEFORE prefixing — unresolved, MoveFileExW fails
        // with error 123 after the whole temp store was built.
        assert_eq!(w(r"C:\root\sub\..\photon.db"), r"\\?\C:\root\photon.db");
        assert_eq!(w(r"C:\root\.\photon.db"), r"\\?\C:\root\photon.db");
    }

    #[test]
    fn a_dot_segmented_destination_bootstraps() {
        // (end-to-end): a valid absolute destination containing `..`
        // reached the verbatim branch unchanged and the install step failed after the
        // temp was fully built.
        let root = crate::test_temp::TempDir::new("aruna-dotdot"); // guarded, unique
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let p = root.join("sub").join("..").join("photon.db");
        match bootstrap_fresh(&p) {
            Ok(BootstrapOutcome::Installed) => {}
            Ok(o) => panic!("expected Installed, got {o:?}"),
            Err(e) => panic!("a dot-segmented destination must bootstrap: {e}"),
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_directory_at_a_tmp_candidate_name_is_skipped_not_fatal() {
        // Windows answers `create_new` over a DIRECTORY with
        // PermissionDenied, not AlreadyExists — a stale directory at candidate .0
        // aborted the whole first bootstrap though candidate .1 was free. An occupied
        // name is a COLLISION (skip); only a failure on a genuinely absent name
        // propagates.
        // a private guarded directory, never the shared temp root.
        let dir = crate::test_temp::TempDir::new("aruna-resv-dir");
        let prefix = format!("aruna-resv-dir-{}-t5", std::process::id());
        let squatter = dir.join(format!("{prefix}.5"));
        std::fs::create_dir(&squatter).unwrap();
        let reserved = reserve_tmp_sibling(&dir, &prefix, 5).unwrap();
        assert_ne!(reserved, squatter, "a directory-occupied candidate is skipped");
        assert!(squatter.is_dir(), "the squatting directory is untouched");
        for ext in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(std::path::PathBuf::from(format!(
                "{}{ext}",
                reserved.display()
            )));
        }
        std::fs::remove_dir(&squatter).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn a_store_path_beyond_max_path_bootstraps() {
        // (end-to-end): std::fs auto-verbatims long paths and Rust test
        // binaries are longPathAware, so a >MAX_PATH store survived preflight, the
        // reservation, and the SQLite build — then died at the one raw MoveFileExW
        // call with ERROR_PATH_NOT_FOUND.
        let root = crate::test_temp::TempDir::new("aruna-longpath"); // guarded, unique
        let dir = root.join("d".repeat(120)).join("e".repeat(120));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("photon.db");
        assert!(
            p.as_os_str().len() > 280,
            "fixture must exceed MAX_PATH, got {}",
            p.as_os_str().len()
        );
        // Environment probe: SQLite's own VFS does no verbatim prefixing, so building
        // the temp store at a >MAX_PATH path needs the OS long-path opt-in
        // (LongPathsEnabled + the binary's longPathAware manifest). Where that is off,
        // the failure under test (OUR raw MoveFileExW install step) is unreachable —
        // soft-skip visibly rather than fail on SQLite's environment constraint.
        let probe = dir.join("probe.db");
        match rusqlite::Connection::open(&probe) {
            Ok(c) => {
                drop(c);
                let _ = std::fs::remove_file(&probe);
            }
            Err(e) => {
                eprintln!(
                    "SKIP a_store_path_beyond_max_path_bootstraps: no long-path support \
                     at the SQLite layer in this environment: {e}"
                );
                let _ = std::fs::remove_dir_all(&root);
                return;
            }
        }
        match bootstrap_fresh(&p) {
            Ok(BootstrapOutcome::Installed) => {}
            Ok(o) => panic!("expected Installed, got {o:?}"),
            Err(e) => panic!("a >MAX_PATH store must bootstrap: {e}"),
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_owner_unwritable_provision_refuses_before_building() {
        // Honoring a 0400/0000 provision published a store no reopen
        // could ever use — unlink and rename need only directory permissions, then
        // every open fails at the WAL gate. The unusable mode refuses at capture,
        // before anything is built, and the placeholder survives the refusal.
        use std::os::unix::fs::PermissionsExt;
        let p = scratch("mode-0400");
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o400)).unwrap();
        let err = match bootstrap_fresh(&p) {
            Err(e) => e,
            Ok(o) => panic!("an owner-unwritable provision must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("denies its owner"), "{err}");
        assert!(
            std::fs::symlink_metadata(&p).is_ok(),
            "the placeholder must survive the refusal"
        );
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644));
        cleanup(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn an_aliased_family_member_is_refused_at_reopen() {
        // A `<db>-shm` that is one of MULTIPLE hard links to an inode let
        // the reopen truncate/rewrite the OTHER alias — an unrelated file — while the
        // store opened successfully. Aliasing of any family member (hard link count > 1,
        // or a symlinked sidecar) refuses before SQLite ever opens; sqlite.org
        // howtocorrupt §multiple-links names the class, and the name-domain contract
        // already refuses symlinked MAINS — a hard link is the same aliasing by a
        // mechanism only the link count can see.
        let p = scratch("aliased-shm");
        bootstrap_fresh(&p).unwrap();
        let victim = scratch("aliased-victim");
        std::fs::write(&victim, b"unrelated user bytes an open must not touch").unwrap();
        let shm = format!("{}-shm", p.display());
        std::fs::hard_link(&victim, &shm).unwrap();
        let err = match open_verified_connection(&p) {
            Err(e) => e,
            Ok(_) => panic!("an aliased -shm must refuse"),
        };
        assert!(format!("{err}").contains("hard links"), "{err}");
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"unrelated user bytes an open must not touch",
            "the alias target must be byte-untouched"
        );
        std::fs::remove_file(&shm).unwrap();
        std::fs::remove_file(&victim).unwrap();
        cleanup(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn a_non_regular_sidecar_beside_a_real_store_refuses_before_sqlite() {
        // (completes the reopen family-classification matrix): a singly
        // linked non-regular node (directory, FIFO, socket, device) at `<db>-wal` or
        // `<db>-shm` beside a REAL v8 store classified as SingleName and preflight
        // proceeded into SQLite — an unusable connection (first WAL write IOERR) or a
        // device access. Present family members must be REGULAR as well as singly
        // named, decided before any SQLite door opens.
        let p = scratch("nonreg-wal");
        bootstrap_fresh(&p).unwrap();
        let wal = format!("{}-wal", p.display());
        std::fs::create_dir(&wal).unwrap();
        let err = match open_verified_connection(&p) {
            Err(e) => e,
            Ok(_) => panic!("a non-regular -wal beside a real store must refuse"),
        };
        assert!(format!("{err}").contains("regular"), "{err}");
        std::fs::remove_dir(&wal).unwrap();
        cleanup(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    #[test]
    fn a_readonly_stale_lock_file_never_wedges_bootstrap() {
        // The lock file is retained BY DESIGN and the documented reset
        // omits it — so a stale lock gone read-only (mode 0444 / the readonly
        // attribute) wedged every future bootstrap at the write-only open, though the
        // advisory lock needs a handle, not write access.
        let p = scratch("ro-lock");
        let lock = format!("{}.photon-init.lock", p.display());
        std::fs::write(&lock, b"").unwrap();
        let mut perms = std::fs::metadata(&lock).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&lock, perms).unwrap();
        assert_eq!(bootstrap_fresh(&p).unwrap(), BootstrapOutcome::Installed);
        let mut perms = std::fs::metadata(&lock).unwrap().permissions();
        // test-fixture cleanup only — the scratch lock must be deletable again
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&lock, perms).unwrap();
        cleanup(&p);
        std::fs::remove_file(&lock).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_non_regular_lock_address_refuses_instead_of_hanging() {
        // A FIFO at the lock address blocked the write-only open BEFORE
        // the advisory lock was ever reached — first open hung indefinitely and leaked
        // the reserved temp family. (A unix socket exercises the same non-regular
        // refusal without mkfifo: open(2) on a socket cannot block — it fails — and
        // pre-fix that surfaced as a raw I/O error, not a classification.)
        let p = scratch("sock-lock");
        let lock = format!("{}.photon-init.lock", p.display());
        let _l = std::os::unix::net::UnixListener::bind(&lock).unwrap();
        let err = match bootstrap_fresh(&p) {
            Err(e) => e,
            Ok(o) => panic!("a non-regular lock address must refuse, got {o:?}"),
        };
        assert!(format!("{err}").contains("regular"), "{err}");
        let _ = std::fs::remove_file(&lock);
    }

    #[test]
    fn a_store_under_a_symlinked_directory_opens() {
        // The macOS-fleet regression (run 31181912965, 86 executed failures = the regression
        // for this fix): SQLITE_OPEN_NOFOLLOW has WHOLE-PATH semantics ("the database
        // filename is not allowed to CONTAIN a symbolic link" — sqlite.org/c3ref/open),
        // so every store under macOS's `/var` → `/private/var` temp root refused to
        // open. The name-domain contract restricts only the FINAL component; a store
        // reached THROUGH a symlinked directory is legitimate and must work.
        // BOTH are ours, both are guarded — the target directory and
        // the link (minted, not created). The link's guard unlinks it and never enters it; the
        // old `remove_file(&link)` could not remove a Windows DIRECTORY link at all, and the
        // `let _ =` hid it (217 `aruna-symdir-*` leftovers in the 2026-09-24/25 sweep).
        let real = crate::test_temp::TempDir::new("aruna-symdir-real");
        std::fs::create_dir_all(&real).unwrap();
        let link = crate::test_temp::TempDir::uncreated("aruna-symdir-link");
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_dir(&real, &link);
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&real, &link);
        if let Err(e) = made {
            eprintln!("SKIP a_store_under_a_symlinked_directory_opens: cannot create dir symlink: {e}");
            let _ = std::fs::remove_dir_all(&real);
            return;
        }
        let p = link.join("photon.db");
        assert_eq!(
            bootstrap_fresh(&p).unwrap(),
            BootstrapOutcome::Installed,
            "a store under a symlinked DIRECTORY must bootstrap"
        );
        let conn = open_verified_connection(&p);
        assert!(
            conn.is_ok(),
            "a store under a symlinked DIRECTORY must reopen: {:?}",
            conn.err()
        );
        drop(conn);
        let _ = std::fs::remove_file(link.join("photon.db.photon-init.lock"));
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn install_no_replace_reports_an_existing_destination_as_lost_never_clobbers() {
        // FC-1 contract: an existing destination is the EEXIST class ⇒
        // DestinationExists; the destination is byte-stable and the source is left for
        // the caller's guard — never adopted into the destination, never deleted here.
        let dest = scratch("inr-dest");
        std::fs::write(&dest, b"the winner's store bytes").unwrap();
        let tmp = scratch("inr-tmp");
        std::fs::write(&tmp, b"the loser's fully-built temp").unwrap();
        assert_eq!(
            install_no_replace(&tmp, &dest).unwrap(),
            InstallOutcome::DestinationExists
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"the winner's store bytes");
        assert_eq!(std::fs::read(&tmp).unwrap(), b"the loser's fully-built temp");
        std::fs::remove_file(&dest).unwrap();
        std::fs::remove_file(&tmp).unwrap();
    }

    #[test]
    fn install_no_replace_consumes_the_source_name() {
        // FC-1 contract: the install is a RENAME — after success exactly ONE name
        // holds the store. The hard_link primitive this replaced created a second live
        // name whose crash residue the documented reset path (`<db>` + 3 sidecars) never
        // removed — the EXECUTED probe read all 69,632 bytes of a "reset"
        // database back through the leftover alias (data remanence).
        let dest = scratch("inr-rename-dest");
        let tmp = scratch("inr-rename-tmp");
        std::fs::write(&tmp, b"store bytes").unwrap();
        assert_eq!(
            install_no_replace(&tmp, &dest).unwrap(),
            InstallOutcome::Installed
        );
        assert!(
            std::fs::symlink_metadata(&tmp).is_err(),
            "the source name must be consumed by the rename"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"store bytes");
        std::fs::remove_file(&dest).unwrap();
    }

    #[test]
    fn fk_gate_pins_and_reads_back() {
        let p = scratch("fkgate");
        let conn = rusqlite::Connection::open(&p).unwrap();
        activate_fk_gate(&conn).unwrap();
        let on: i64 = conn
            .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
            .unwrap();
        assert_eq!(on, 1);
        drop(conn);
        let _ = std::fs::remove_file(&p);
    }

    /// Bootstrap a fresh store through the public open chokepoint (`SqliteIntentLog::open`
    /// owns bootstrap) and hand back BOTH the log and a second connection taken through
    /// `open_verified_connection` — the one door that pins the durability profile and
    /// ACTIVATES THE FK GATE. A raw `Connection::open` would leave `foreign_keys=off`
    /// (the pragma is per-connection), so an orphan-refusal arm taken on a raw connection
    /// would be testing nothing.
    fn fresh_open_store(tag: &str) -> (crate::test_temp::TempFile, GatedConnection, crate::SqliteIntentLog) {
        let p = scratch(tag);
        let log = crate::SqliteIntentLog::open(&p).expect("bootstrap + open the store");
        let conn = open_verified_connection(&p).expect("FK-gated connection to the same store");
        (p, conn, log)
    }

    /// Drop order matters on Windows: every connection to the store must be closed before
    /// the file (and its sidecars) can be unlinked.
    fn drop_open_store(p: crate::test_temp::TempFile, conn: GatedConnection, log: crate::SqliteIntentLog) {
        drop(conn);
        drop(log);
        cleanup(&p);
        let _ = std::fs::remove_file(format!("{}.photon-init.lock", p.display()));
    }

    /// The admission-test command literal (mirrors `record_binds_admission_provenance_columns`).
    fn test_command(key: &str, message_ref: &str) -> crate::Command {
        crate::Command::new(
            key,
            "acct",
            crate::Facet::Mail,
            crate::Action::Archive {
                message_ref: message_ref.to_string(),
            },
        )
    }

    /// A minimal well-formed frozen basis (BASIS-1/-3/-4 shape) for the native key under test.
    fn test_basis(native_resource_key: &str) -> crate::prestate::FrozenBasis {
        crate::prestate::FrozenBasis {
            native_resource_key: native_resource_key.to_string(),
            touched_atoms: [("membership:INBOX".to_string(), "INBOX".to_string())]
                .into_iter()
                .collect(),
            atom_targets: [("membership:INBOX".to_string(), false)].into_iter().collect(),
            role_bindings: std::collections::BTreeMap::new(),
            freshness: crate::prestate::Freshness::ImmutableConstants,
        }
    }

    #[test]
    fn w_prestate_fk_valid_insert_succeeds_then_orphan_and_duplicate_refuse() {
        // W-PRESTATE-FK FIRST arm (design §2.2b): a VALID insert must succeed
        // — a literal schema without a UNIQUE parent would reject every insert with
        // `foreign key mismatch`, so the valid arm comes BEFORE the orphan arms.
        let (p, conn, mut log) = fresh_open_store("w-prestate-fk");
        // Admit one forward intent so a real parent intent_id exists. BASIS-5 freezes the
        // basis inside that same admission transaction, so the row under the FK arms carries
        // the shape the engine really writes — no hand-set column.
        let cmd = test_command("k-fk-1", "msg-1");
        crate::IntentLog::record(&mut log, &cmd, &test_basis("prov:acct/msg-1")).unwrap();
        let intent_id: String = conn
            .query_row(
                "SELECT intent_id FROM intents WHERE idempotency_key='k-fk-1';",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // 1. VALID insert succeeds.
        conn.execute(
            "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom, resolved_operands,
                                    fetched_at, source, captured_epoch, mode_generation, undo_offer_until)
             VALUES ('j-1', ?1, '{}', '{}', '{}', '1970-01-01T00:00:00Z', 'live_read', 1, 1,
                     '1970-01-08T00:00:00Z');",
            rusqlite::params![intent_id],
        )
        .expect("a valid pre_state insert must succeed (W-PRESTATE-FK first arm)");
        // 2. ORPHAN insert (no such parent) goes RED under the stage-1 FK gate.
        let orphan = conn.execute(
            "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom, resolved_operands,
                                    fetched_at, source, captured_epoch, mode_generation, undo_offer_until)
             VALUES ('j-2', 'no-such-intent', '{}', '{}', '{}', '1970-01-01T00:00:00Z', 'live_read',
                     1, 1, '1970-01-08T00:00:00Z');",
            [],
        );
        assert!(
            orphan.is_err(),
            "an orphan pre_state row must be refused by FK enforcement"
        );
        // 3. A SECOND row for the same intent refuses (one-to-one attachment; UNIQUE).
        let dup = conn.execute(
            "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom, resolved_operands,
                                    fetched_at, source, captured_epoch, mode_generation, undo_offer_until)
             VALUES ('j-3', ?1, '{}', '{}', '{}', '1970-01-01T00:00:00Z', 'live_read', 1, 1,
                     '1970-01-08T00:00:00Z');",
            rusqlite::params![intent_id],
        );
        assert!(
            dup.is_err(),
            "pre_state.intent_id is UNIQUE — the attachment is one-to-one"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn pre_state_intent_id_refuses_null() {
        // SQLite treats a NULL FK as valid and UNIQUE admits multiple NULLs —
        // NOT NULL is load-bearing, not styling.
        let (p, conn, log) = fresh_open_store("w-prestate-null");
        let null_fk = conn.execute(
            "INSERT INTO pre_state (journal_id, intent_id, observed, touched_atom, resolved_operands,
                                    fetched_at, source, captured_epoch, mode_generation, undo_offer_until)
             VALUES ('j-n', NULL, '{}', '{}', '{}', '1970-01-01T00:00:00Z', 'live_read', 1, 1,
                     '1970-01-08T00:00:00Z');",
            [],
        );
        // The refusal must be the NOT NULL constraint ITSELF: a bare `is_err()` here is
        // satisfied by `no such table: pre_state`, so it could never witness RED against
        // a schema that lacks the column constraint.
        let err = null_fk.expect_err("NULL intent_id must be refused (NOT NULL)");
        assert!(
            format!("{err}").contains("NOT NULL"),
            "the refusal must be the NOT NULL constraint, got: {err}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn native_key_expression_index_exists_and_is_usable() {
        // §7a: "with an index on the native resource key (the native-keyed tail reads it)".
        let (p, conn, log) = fresh_open_store("native-key-idx");
        // The predicate interpolates `NATIVE_KEY_EXPR_SQL` — the SAME text the index was built
        // with. SQLite matches expression indexes TEXTUALLY, so hand-writing the expression here
        // would test a query no consumer runs and pass while every real one scanned.
        let plan: String = conn
            .query_row(
                &format!(
                    "EXPLAIN QUERY PLAN SELECT seq FROM intents
                     WHERE {NATIVE_KEY_EXPR_SQL} = 'x';"
                ),
                [],
                |r| r.get::<_, String>(3),
            )
            .unwrap();
        assert!(
            plan.to_uppercase().contains("USING INDEX"),
            "the native-key lookup must ride the expression index, got plan: {plan}"
        );
        drop_open_store(p, conn, log);
    }

    /// Every `EXPLAIN QUERY PLAN` detail line for `sql`, joined — the whole plan, not just the
    /// first step. A predicate that plans as two subqueries has more than one row, and asserting
    /// on row 0 alone would miss the lane that scans.
    fn full_plan(conn: &rusqlite::Connection, sql: &str) -> String {
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("prepare plan");
        // The plan is fixed at PREPARE; the bound values are irrelevant to it, so bind NULLs to
        // whatever placeholder count this shape carries (4 or 5) and read the plan out.
        let binds: Vec<rusqlite::types::Value> = (0..stmt.parameter_count())
            .map(|_| rusqlite::types::Value::Null)
            .collect();
        let rows: Vec<String> = stmt
            .query_map(rusqlite::params_from_iter(binds), |r| r.get::<_, String>(3))
            .expect("plan rows")
            .map(|r| r.expect("plan row"))
            .collect();
        rows.join(" | ")
    }

    #[test]
    fn the_real_head_predecessor_predicate_never_plans_a_table_scan() {
        // Regression test. The previous witness EXPLAINed a bare
        // `WHERE <native_key_expr> = ?` — a query NO consumer runs. The predicate admissions and
        // recovery actually run is the head-predecessor check, whose native-key term sat inside an
        // OR with the NULL-basis fallback:
        //
        //     AND (<native_key_expr> = ?3 OR (frozen_basis IS NULL AND message_ref = ?4))
        //
        // SQLite cannot use an index for one arm of an OR unless EVERY arm is independently
        // indexable, so it planned `SCAN intents` — the head check, run on every admission and on
        // every recovery pass, was O(total intents) while an index sat there unused. Splitting the
        // OR into two independently-indexable EXISTS lanes is the fix; this witness runs the REAL
        // shape (from the ONE fragment both call sites use) and covers BOTH lanes.
        //
        // revisited the EXPECTATION, not the property: lane 2 dropped its
        // `frozen_basis IS NULL` restriction, so the PARTIAL index it used to ride
        // (`idx_intents_null_basis_msgref`) can no longer serve it — SQLite may only use a partial
        // index for a query whose WHERE provably implies the index's own. The plain
        // `idx_intents_account_msgref` replaces it. The assertion is now POSITIVE and NAMED: each
        // lane must plan a `SEARCH` on the index it is supposed to ride, so a future edit that
        // silently re-plans one lane onto the other's index (or onto nothing) fails HERE.
        let (p, conn, log) = fresh_open_store("head-predicate-plan");
        for exclude_self in [true, false] {
            let plan = full_plan(&conn, &crate::non_terminal_native_predecessor_sql(exclude_self));
            assert!(
                !plan.to_uppercase().contains("SCAN INTENTS"),
                "the head-predecessor predicate must never plan a full table scan \
                 (exclude_self={exclude_self}), got plan: {plan}"
            );
            for index in [
                "SEARCH intents USING INDEX idx_intents_native_key_guarded",
                "SEARCH intents USING INDEX idx_intents_account_msgref",
            ] {
                assert!(
                    plan.contains(index),
                    "the head-predecessor predicate must plan `{index}` \
                     (exclude_self={exclude_self}), got plan: {plan}"
                );
            }
            // Exactly two lanes, exactly two searches — no third step crept in unindexed.
            assert_eq!(
                plan.matches("SEARCH intents").count(),
                2,
                "both lanes must SEARCH, and nothing else may touch `intents` \
                 (exclude_self={exclude_self}), got plan: {plan}"
            );
        }
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_live_exposure_obligation_lookup_rides_its_partial_index() {
        // EXP-10: "gate/recovery cost is bounded INDEPENDENTLY of
        // unresolved-history length". The EXP-3 fence's absence-proof is a lookup for a LIVE
        // obligation on one atom; without a partial index it had to walk every RETIRED row on
        // that atom to prove the absence — and nothing evicts, so that history only grows.
        //
        // The predicate interpolates `EXPOSURE_OVERLAP_SQL`, the SAME text the fence runs, so
        // this can never pass while the real query plans differently.
        let (p, conn, log) = fresh_open_store("exposure-live-idx");
        let plan = full_plan(&conn, crate::EXPOSURE_OVERLAP_SQL);
        assert!(
            plan.contains("USING INDEX idx_exposure_obligation_live"),
            "the fence's live-obligation lookup must ride the partial index, got plan: {plan}"
        );
        assert!(
            !plan.to_uppercase().contains("SCAN EXPOSURE_OBLIGATION"),
            "…and must never plan a table scan, got plan: {plan}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_materialization_contributor_scan_rides_indexes_on_both_arms() {
        // EXP-10 again, at the OTHER exposure lookup. EXP-7's
        // overlapping-contributor scan asked
        //
        //     WHERE primitive_atom = ?1 AND contributor_attempt_id <> ?2
        //       AND (retired_at IS NULL OR retired_at >= ?3)
        //
        // and SQLite cannot use an index for one arm of an OR unless EVERY arm is independently
        // indexable — the same rule `non_terminal_native_predecessor_sql` was split for. So the
        // partial index built for exactly this table (`idx_exposure_obligation_live`) sat
        // unused and the plan fell back to the UNIQUE constraint's autoindex prefix, walking
        // every row the atom ever had, live and RETIRED. Nothing evicts an obligation, so that
        // history only grows — "gate/recovery cost is bounded INDEPENDENTLY of
        // unresolved-history length" was false at this lookup, and it runs INSIDE the settling
        // writer transaction, per touched atom.
        //
        // The split is a UNION of two independently-indexable arms; this witness runs the REAL
        // text and asserts each arm plans a SEARCH on the index it is supposed to ride, so a
        // future edit that re-plans one arm onto nothing fails HERE.
        let (p, conn, log) = fresh_open_store("exposure-contributor-idx");
        let plan = full_plan(&conn, crate::EXPOSURE_CONTRIBUTORS_SQL);
        for index in [
            "SEARCH exposure_obligation USING INDEX idx_exposure_obligation_live",
            "SEARCH exposure_obligation USING INDEX idx_exposure_obligation_retired",
        ] {
            assert!(
                plan.contains(index),
                "the contributor scan must plan `{index}`, got plan: {plan}"
            );
        }
        assert!(
            !plan.to_uppercase().contains("SCAN EXPOSURE_OBLIGATION"),
            "…and must never plan a table scan, got plan: {plan}"
        );
        assert!(
            !plan.contains("sqlite_autoindex_exposure_obligation"),
            "…and must never fall back to the UNIQUE constraint's autoindex, whose prefix walks \
             the atom's whole retired history, got plan: {plan}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_fact_clock_high_water_read_rides_its_index() {
        // THE FACT CLOCK'S OWN EXP-10 SHAPE. Every door that appends
        // an attempt fact clamps its instant against `MAX(created_at)` over `attempt_fact` —
        // the CLAIM, the authorization, every verdict, the sever, the adjudication, the late
        // ack. `attempt_fact` is append-only and nothing evicts, so unindexed that read is a
        // full pass over the store's whole history: the cost of every fact door grows with how
        // much the engine has ever done. Same defect the exposure fence had, same close.
        //
        // The witness interpolates `FACT_CLOCK_HIGH_WATER_SQL`, the SAME text the doors run
        // (SQLite matches indexes against the text it is given), and asserts the MIN/MAX
        // optimization actually lands on the index — a seek to the last entry, not a walk.
        let (p, conn, log) = fresh_open_store("fact-clock-idx");
        let plan = full_plan(&conn, crate::FACT_CLOCK_HIGH_WATER_SQL);
        assert!(
            plan.contains("USING COVERING INDEX idx_attempt_fact_created_at"),
            "the fact clock's high-water read must ride the `created_at` index, got plan: {plan}"
        );
        assert!(
            !plan.to_uppercase().contains("SCAN ATTEMPT_FACT"),
            "…and must never plan a table scan, got plan: {plan}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_retry_successor_probe_never_scans_the_whole_ledger() {
        // EXP-10's bound at the LAST unindexed fact read. The
        // single-successor referee asked
        //
        //     WHERE fact_kind = 'claim'
        //       AND json_extract(payload, '$.predecessor_attempt_id') = ?
        //
        // over the whole ledger — no equality term any index could serve — and planned
        //
        //     SCAN CONSTANT ROW | SCALAR SUBQUERY 1 | SCAN attempt_fact
        //
        // a full pass over every fact the engine has ever appended, inside the CLAIM
        // transaction that holds the write lock, on every retry. `attempt_fact` is append-only
        // and nothing evicts, so the cost of claiming a retry grew with total history.
        //
        // The close is the rule's own domain (`retry_lineage_legal` refuses a cross-operation
        // predecessor before it consults this answer), which is also an indexed column: the
        // `UNIQUE (operation_id, attempt_ordinal)` autoindex bounds the walk to ONE operation's
        // facts. No new index, no new write cost. The witness runs the REAL text.
        let (p, conn, log) = fresh_open_store("retry-successor-idx");
        let plan = full_plan(&conn, crate::RETRY_SUCCESSOR_SQL);
        assert!(
            plan.contains("SEARCH attempt_fact USING INDEX sqlite_autoindex_attempt_fact_2 (operation_id=?)"),
            "the successor probe must ride the (operation_id, attempt_ordinal) autoindex on its \
             `operation_id` prefix, got plan: {plan}"
        );
        assert!(
            !plan.contains("SCAN attempt_fact"),
            "…and must never plan a pass over the whole fact ledger, got plan: {plan}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_superseded_partial_message_ref_index_is_dropped_on_reopen() {
        // Pre-release accretion has to actually LAND on a dev store that already carries the
        // partial index — an `IF NOT EXISTS` under a new name would happily leave the dead one
        // beside it, charging every INSERT/UPDATE for an index no query can use. The DROP is what
        // makes the supersession real; this is its witness.
        let (p, conn, log) = fresh_open_store("superseded-partial-idx");
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_intents_null_basis_msgref
                 ON intents (account, message_ref) WHERE frozen_basis IS NULL;",
        )
        .expect("simulate an r3-era store carrying the partial index");
        drop(conn);
        drop(log);
        let log = crate::SqliteIntentLog::open(&p).expect("reopen applies the accretion");
        let conn = open_verified_connection(&p).expect("verified connection");
        let names: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'intents';")
            .expect("prepare")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("rows")
            .map(|r| r.expect("row"))
            .collect();
        assert!(
            !names.iter().any(|n| n == "idx_intents_null_basis_msgref"),
            "the superseded partial index must be DROPPED, got: {names:?}"
        );
        assert!(
            names.iter().any(|n| n == "idx_intents_account_msgref"),
            "…and replaced by the plain one the widened lane 2 can ride, got: {names:?}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_generation_high_water_read_rides_its_own_index() {
        // EXP-10 at the generation mint's fallback half. Once the
        // live-obligation probe above comes back empty, `obligation_generation` asks
        // `EXPOSURE_GENERATION_HIGH_WATER_SQL` — MAX(generation) over the atom's WHOLE history
        // (EXP-9: retired rows never evict, so the next generation is max-over-everything + 1).
        //
        // `UNIQUE (primitive_atom, direction, generation, contributor_attempt_id)` puts
        // `direction` BETWEEN the constrained `primitive_atom` and the aggregated `generation`,
        // so SQLite's MIN/MAX single-row optimization cannot fire — but `EXPLAIN QUERY PLAN`
        // still LABELS the step `SEARCH … (primitive_atom=?)`, not `SCAN`, because the autoindex
        // prefix genuinely bounds the walk to one atom. It is a scan of that atom's whole
        // history wearing a SEARCH label: asserting only `!contains("SCAN")` would pass on the
        // broken shape, so this witness asserts the INDEX NAME instead — the autoindex before
        // the fix, the purpose-built `(primitive_atom, generation)` index after it, where
        // `generation` sits immediately after the constrained prefix and the seek is real.
        let (p, conn, log) = fresh_open_store("generation-highwater-idx");
        let plan = full_plan(&conn, crate::EXPOSURE_GENERATION_HIGH_WATER_SQL);
        assert!(
            plan.contains("USING COVERING INDEX idx_exposure_obligation_generation (primitive_atom=?)"),
            "the generation high-water read must ride the purpose-built (primitive_atom, \
             generation) index, not the UNIQUE autoindex whose `direction` column defeats the \
             MIN/MAX seek, got plan: {plan}"
        );
        assert!(
            !plan.contains("sqlite_autoindex_exposure_obligation"),
            "…and must never fall back to the UNIQUE constraint's autoindex, whose `direction` \
             column between the atom and the generation makes every 'search' on it a walk of \
             the atom's whole history, got plan: {plan}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_contributor_retirement_rides_its_partial_index() {
        // EXP-10 at EXP-8's retirement write. `record_late_ack` runs
        // `EXPOSURE_RETIREMENT_BY_CONTRIBUTOR_SQL` once per late ack, inside the writer
        // transaction that also appends the fact — an `UPDATE`, so this witness also proves
        // `EXPLAIN QUERY PLAN` plans `UPDATE` statements the same way it plans `SELECT`.
        //
        // No existing `exposure_obligation` index starts with `contributor_attempt_id` — every
        // one keys off `primitive_atom` first — so the query used to land on
        // `idx_exposure_obligation_live` (its `retired_at IS NULL` arm is implied) but as a
        // `SCAN` restricted to the live partition: every live obligation the store has ever
        // carried, not just this one attempt's, and nothing ever deletes a row out of that
        // partition. `idx_exposure_obligation_contributor` is a NEW partial index keyed on
        // `contributor_attempt_id` under the SAME `WHERE retired_at IS NULL`, so the scan
        // becomes a seek on the one contributor this late ack names.
        let (p, conn, log) = fresh_open_store("contributor-retirement-idx");
        let plan = full_plan(&conn, crate::EXPOSURE_RETIREMENT_BY_CONTRIBUTOR_SQL);
        assert!(
            plan.contains("SEARCH exposure_obligation USING INDEX idx_exposure_obligation_contributor (contributor_attempt_id=?)"),
            "the contributor retirement UPDATE must ride the partial contributor index, got \
             plan: {plan}"
        );
        assert!(
            !plan.to_uppercase().contains("SCAN"),
            "…and must never plan a scan of the live partition (or the whole table), got plan: \
             {plan}"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_annotation_half_trace_rides_its_index() {
        // EXP-10 at the materialization half-trace read.
        // `adjudication_annotation` is indexed only by its `PRIMARY KEY` (`annotation_id`), so
        // `ADJUDICATION_ANNOTATION_HALF_TRACE_SQL` — `adjudication_id = ?1 AND kind = ?2` —
        // planned a full table scan: append-only, nothing evicts, so the cost of every APPLIED
        // late ack whose attempt is itself adjudicated grew with the store's total annotation
        // history. `idx_adjudication_annotation_lookup` is a plain (non-partial) two-column
        // index matching the query's own equality prefix.
        let (p, conn, log) = fresh_open_store("annotation-half-trace-idx");
        let plan = full_plan(&conn, crate::ADJUDICATION_ANNOTATION_HALF_TRACE_SQL);
        assert!(
            plan.contains(
                "SEARCH adjudication_annotation USING COVERING INDEX \
                 idx_adjudication_annotation_lookup (adjudication_id=? AND kind=?)"
            ),
            "the materialization half-trace read must ride the (adjudication_id, kind) index \
             (COVERING, since `COUNT(*)` needs no column the index does not already carry), got \
             plan: {plan}"
        );
        assert!(
            !plan.to_uppercase().contains("SCAN"),
            "…and must never plan a table scan, got plan: {plan}"
        );
        drop_open_store(p, conn, log);
    }

    // the OPEN door propagates the store's configured writer budget ──

    #[test]
    fn open_verified_connection_propagates_the_stores_configured_writer_budget() {
        // `WriterGate::for_connection` hard-codes `capacity::DEFAULT` (its own doc: "a handle
        // minted at the connection door has no transaction to read the ledger through") — but
        // `open_verified_connection` is a DIFFERENT door: it already holds the verified
        // connection, so it can (and, post-fix, does) re-mint the handle via `with_config` off
        // a plain read of the ledger's newest activated `capacity` act.
        //
        // `writer_chunk_budget_ms` is domain-gated to `>= 1` (`CapacityConfig::validate`
        // refuses 0), so this proves propagation with a small LEGAL value distinct from
        // `DEFAULT`'s 50 — read back deterministically via `WriteScope::budget_ms()` (the
        // module's own documented timing-free witness for exactly this), never a sleep or an
        // observer race.
        let p = scratch("f1-writer-budget");
        let mut log = crate::SqliteIntentLog::open(&p).expect("bootstrap");
        let configured = crate::capacity::CapacityConfig {
            writer_chunk_budget_ms: 3,
            ..crate::capacity::DEFAULT
        };
        crate::IntentLog::record_capacity_config(&mut log, configured)
            .expect("a zero-occupancy store activates its own capacity act immediately");

        let conn = open_verified_connection(&p).expect("reopen through the connection door");
        let scope = conn.gate().enroll().expect("enroll");
        assert_eq!(
            scope.budget_ms(),
            3,
            "the gate minted at OPEN must carry the store's CONFIGURED budget, not \
             capacity::DEFAULT's 50ms — pre-fix this reads 50 because `for_connection` hard-\
             codes DEFAULT and nothing re-reads the ledger at the connection door"
        );
        drop(scope);
        drop_open_store(p, conn, log);
    }

    // the WAL profile write must ENROLL, so a SECOND open of a live
    // store yields to a pending sever instead of racing its ungated PRAGMA ahead of it ──

    #[test]
    fn f1_a_second_open_yields_its_wal_profile_write_to_a_pending_sever() {
        // `pin_durability_profile`'s persistent `PRAGMA journal_mode=WAL` used to
        // run UNGATED inside `open_verified_connection` — the per-identity OPEN serializer
        // (`serialize_open_path`) excludes only other OPENS, never the writer-gate arbiter, so
        // a second open of an already-live store could take the profile write while a sever was
        // ticketed and PENDING (`sever_pending > 0`, `active_writer == false` — the exact state
        // `WriterGate::enroll`'s predicate is built to make every ordinary writer YIELD to,
        // counted by `enroll_yields_to_sever`).
        //
        // The witness drives the gate into precisely that window with two parked threads (A
        // holds the writer slot, then releases; S has already ticketed a sever and is parked
        // BEFORE it completes, so `sever_pending` stays raised) and then opens the SAME store a
        // second time from a third thread. The two mutually exclusive, individually observable
        // outcomes:
        //   (a) the second open COMPLETES while the sever is still pending — `o_opened` flips
        //       true before the gate ever records a waiter (pre-fix: the profile write never
        //       touches the gate, so nothing blocks it), or
        //   (b) the second open PARKS in `WriterGate::enroll` — `enroll_waiters` reaches 1 —
        //       and only completes once the sever's `complete()` clears `sever_pending`.
        // Anti-hang: `spin_until`'s own hang guard turns a wedged build into a diagnosable
        // panic, never an indefinite block; the property is checked as an ASSERTION on which
        // of (a)/(b) was observed, never inferred from timing.
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        use std::thread;
        use std::time::{Duration, Instant};

        const HANG_GUARD: Duration = Duration::from_secs(15);
        fn spin_until(label: &str, mut cond: impl FnMut() -> bool) {
            let started = Instant::now();
            while !cond() {
                assert!(
                    started.elapsed() <= HANG_GUARD,
                    "HANG GUARD: `{label}` never became true — the gate is wedged"
                );
                thread::yield_now();
            }
        }

        let (p, conn, log) = fresh_open_store("f1-open-vs-sever");
        let g = conn.gate().clone();

        // ── A: take the writer slot, then park until released ──
        let a_enrolled = Arc::new(AtomicBool::new(false));
        let release_a = Arc::new(AtomicBool::new(false));
        let ta = {
            let (g, a_enrolled, release_a) =
                (g.clone(), Arc::clone(&a_enrolled), Arc::clone(&release_a));
            thread::spawn(move || {
                let scope = g.enroll().expect("A enrolls");
                a_enrolled.store(true, Ordering::SeqCst);
                spin_until("A released", || release_a.load(Ordering::SeqCst));
                drop(scope);
            })
        };
        spin_until("A enrolled", || a_enrolled.load(Ordering::SeqCst));

        // ── S: ticket a sever (blocks behind A), then park BEFORE completing it ──
        let release_s = Arc::new(AtomicBool::new(false));
        let ts = {
            let (g, release_s) = (g.clone(), Arc::clone(&release_s));
            thread::spawn(move || {
                let mut entry = g.begin_sever("authority:f1-witness").expect("begin_sever");
                assert!(entry.is_leader());
                spin_until("S released", || release_s.load(Ordering::SeqCst));
                entry
                    .complete(crate::writer_gate::SeverOutcome::Served { epoch: 1 })
                    .expect("complete");
            })
        };
        spin_until("the sever holds a ticket", || {
            g.snapshot().expect("snapshot").sever_pending == 1
        });

        // Release A: the gate becomes writer-FREE while the sever is still PENDING — exactly
        // the state a new enrollment must yield to.
        release_a.store(true, Ordering::SeqCst);
        spin_until("the gate is free of writers, sever still pending", || {
            let s = g.snapshot().expect("snapshot");
            !s.active_writer && s.sever_pending == 1
        });

        // ── O: a SECOND open of the SAME store, started only now ──
        let o_opened: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let o_result: Arc<Mutex<Option<GatedConnection>>> = Arc::new(Mutex::new(None));
        let to = {
            let (p, o_opened, o_result) = (p.to_path_buf(), Arc::clone(&o_opened), Arc::clone(&o_result));
            thread::spawn(move || {
                let conn2 = open_verified_connection(&p).expect("second open of a live store");
                *o_result.lock().expect("o_result") = Some(conn2);
                o_opened.store(true, Ordering::SeqCst);
            })
        };

        spin_until(
            "the second open either completed already or parked waiting to enroll",
            || {
                o_opened.load(Ordering::SeqCst)
                    || g.snapshot().expect("snapshot").enroll_waiters >= 1
            },
        );
        assert!(
            !o_opened.load(Ordering::SeqCst),
            "the second open's persistent WAL-profile write raced a PENDING SEVER instead of \
             yielding to it — pre-fix `pin_durability_profile` never touches the gate, so \
             nothing blocks `open_verified_connection` while `sever_pending == 1`; post-fix the \
             profile write enrolls and must park (`enroll_waiters == 1`) until the sever \
             completes"
        );
        assert_eq!(
            g.snapshot().expect("snapshot").sever_pending,
            1,
            "the sever must still be pending at the moment the second open is observed parked"
        );

        // Let the sever complete; the parked second open must then proceed.
        release_s.store(true, Ordering::SeqCst);
        ts.join().expect("sever thread");
        to.join().expect("second-open thread");
        assert!(
            o_opened.load(Ordering::SeqCst),
            "the second open completes once the sever clears sever_pending"
        );
        let conn2 = o_result
            .lock()
            .expect("o_result")
            .take()
            .expect("the second open produced a connection");

        ta.join().expect("A thread");
        drop(conn2);
        drop_open_store(p, conn, log);
    }

    // ═══════════════════════════════════════════════════════════════════════════════════════
    // the open-time capacity read is ONE snapshot, and a failed read is
    // LOUD.
    // ═══════════════════════════════════════════════════════════════════════════════════════

    /// Append a raw `engine_config` act at the next generation and return that generation —
    /// the ledger is append-only, so a NEW act, never a rewrite. Raw on purpose: these
    /// witnesses are about how the OPEN reads the ledger, not about how the API writes it.
    fn append_engine_act(path: &Path, kind: &str, payload: &str) -> i64 {
        let c = rusqlite::Connection::open(path).expect("raw open");
        pin_durability_profile(&c).expect("durability profile");
        c.execute(
            "INSERT INTO engine_config (generation, recorded_at, kind, payload)
             VALUES ((SELECT MAX(generation) + 1 FROM engine_config),
                     strftime('%s','now'), ?1, ?2);",
            rusqlite::params![kind, payload],
        )
        .expect("append engine_config act");
        c.query_row("SELECT MAX(generation) FROM engine_config;", [], |r| r.get(0))
            .expect("read back generation")
    }

    /// A valid `kind='capacity'` payload naming `max_active_ops` — the other fields are held at
    /// the compiled default's own values so `max_active_ops` alone identifies which act a read
    /// resolved to.
    fn capacity_act_payload(max_active_ops: u32) -> String {
        format!(
            "{{\"capture\":\"on\",\"capacity\":{{\"max_active_ops\":{max_active_ops},\
             \"undo_reserve\":64,\"writer_chunk_budget_ms\":50,\"sever_watchdog_ms\":5000,\
             \"sever_joiner_cap\":16}}}}"
        )
    }

    /// Seed `path` with a capacity act at `max_active_ops`, ACTIVATED — i.e. a store whose
    /// CURRENT bounds are that act's, not [`crate::capacity::DEFAULT`]'s.
    fn seed_activated_capacity(path: &Path, max_active_ops: u32) -> i64 {
        let gen = append_engine_act(path, "capacity", &capacity_act_payload(max_active_ops));
        append_engine_act(
            path,
            "capacity_activated",
            &format!("{{\"activates_generation\":{gen}}}"),
        );
        gen
    }

    /// **THE PRE-FIX READ SHAPE, FROZEN** — the two act families read as
    /// two AUTOCOMMIT statements, which is two snapshots. Kept as a LOCAL COPY rather than
    /// shared with the production text for the same reason
    /// `unbounded_activation_fit_predicate_sql` is (lib.rs): a reference that drifts with the
    /// thing it references proves nothing. This is what makes the witness below ANTI-VACUOUS —
    /// it shows the injected interleaving really does mis-derive, so the production form's
    /// surviving it is a property of the transaction and not of the injection being inert.
    fn split_autocommit_capacity_read(
        conn: &rusqlite::Connection,
        between_reads: impl FnOnce(),
    ) -> Result<crate::capacity::CapacityConfig, String> {
        use rusqlite::OptionalExtension;
        let capacity_acts: Vec<(i64, String)> = {
            let mut stmt = conn
                .prepare("SELECT generation, payload FROM engine_config WHERE kind = 'capacity';")
                .map_err(|e| format!("capacity-acts prepare: {e}"))?;
            let acts = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| format!("capacity-acts read: {e}"))?
                .collect::<Result<Vec<_>, rusqlite::Error>>()
                .map_err(|e| format!("capacity-acts read: {e}"))?;
            acts
        };
        between_reads();
        let activated_generation: Option<i64> = conn
            .query_row(
                "SELECT CAST(json_extract(payload, '$.activates_generation') AS INTEGER)
                   FROM engine_config WHERE kind = 'capacity_activated'
                  ORDER BY generation DESC LIMIT 1;",
                [],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|e| format!("activation read: {e}"))?
            .flatten();
        crate::capacity::effective_bounds(
            &capacity_acts,
            // The FROZEN pre-fix shape never fetched the activation row's own generation, so
            // `i64::MAX` stands in: a real row generation can never reach it, which keeps the
            // ordering checks (which this frozen copy predates) out of this witness's
            // path — its refusal fires at the missing-act lookup, before any ordering
            // question.
            activated_generation.map(|g| (i64::MAX, g)),
        )
        .map(|eb| eb.current)
        .map_err(|e| format!("{e}"))
    }

    #[test]
    fn a_split_open_capacity_read_mis_derives_under_an_interleaved_commit() {
        // THE ANTI-VACUITY HALF: the injected `record_capacity_config`-shaped commit is REAL,
        // and against the pre-fix (two-autocommit-statement) shape it produces exactly the
        // failure the finding describes — an activation naming a generation the capacity read
        // never saw, which `effective_bounds` refuses, and which `unwrap_or(DEFAULT)` used to
        // swallow into the compiled default for the handle's whole lifetime.
        let (p, conn, log) = fresh_open_store("r4-f2-split-mis-derives");
        let gen_a = seed_activated_capacity(&p, 128);

        let injected = || {
            seed_activated_capacity(&p, 256);
        };
        let derived = split_autocommit_capacity_read(conn.conn(), injected);

        let reason = derived.expect_err(
            "two autocommit reads across an interleaved capacity commit must NOT derive a \
             coherent config — that is the whole finding",
        );
        assert!(
            reason.contains("but no kind='capacity' act at that generation"),
            "the split read must fail exactly as `effective_bounds` says an incoherent pair \
             does (activation naming an act the capacity read did not carry); got: {reason}"
        );
        assert!(gen_a > 0);
        drop_open_store(p, conn, log);
    }

    #[test]
    fn the_open_capacity_read_takes_one_snapshot() {
        // THE PROPERTY: the SAME injection, against the production read. One `BEGIN DEFERRED`
        // read transaction spans both act-family reads, so the competing commit is simply not
        // in this snapshot — the derivation is the coherent pre-commit state, never the
        // never-existed pair, and never the silent default.
        let (p, conn, log) = fresh_open_store("r4-f2-one-snapshot");
        seed_activated_capacity(&p, 128);

        let injected = || {
            seed_activated_capacity(&p, 256);
        };
        let derived = read_capacity_snapshot(conn.conn(), injected)
            .expect("one snapshot derives a coherent config across the interleaved commit");
        assert_eq!(
            derived.max_active_ops, 128,
            "the read must resolve the act that was current WHEN THE SNAPSHOT OPENED"
        );

        // ANTI-VACUITY, the other half: the injected commit really did land — a read taken
        // AFTER the snapshot closed sees it. Without this the witness above would pass just as
        // well against an injection that never wrote anything.
        let after = read_capacity_snapshot(conn.conn(), || {})
            .expect("the post-injection state is itself coherent");
        assert_eq!(
            after.max_active_ops, 256,
            "the injected capacity act must be durable — otherwise the snapshot proved nothing"
        );
        drop_open_store(p, conn, log);
    }

    #[test]
    fn an_unreadable_capacity_ledger_refuses_the_open_instead_of_defaulting() {
        // THE FAIL-LOUD HALF. A malformed `capacity` act is refused by the admission read and
        // is inert to the activation trigger; the open must not be the one door
        // that silently `capacity::DEFAULT` over the same bytes.
        let (p, conn, log) = fresh_open_store("r4-f2-unreadable-refuses");
        let gen = append_engine_act(&p, "capacity", "{\"capture\":\"on\",\"capacity\":");
        append_engine_act(
            &p,
            "capacity_activated",
            &format!("{{\"activates_generation\":{gen}}}"),
        );

        let err = capacity_config_at_open(conn.conn())
            .expect_err("an unreadable capacity ledger must refuse, not default");
        let text = format!("{err}");
        assert!(
            text.contains("could not be read consistently at open, twice"),
            "the refusal must name the retry it already spent; got: {text}"
        );

        // And it refuses AT THE DOOR: a fresh open of the same store fails rather than handing
        // back a connection whose gate carries bounds nobody configured.
        let reopened = open_verified_connection(&p);
        assert!(
            reopened.is_err(),
            "the open chokepoint must propagate the capacity refusal"
        );
        drop_open_store(p, conn, log);
    }

    /// CLOSE A — the OPEN-side half of the one-strict-parse-authority
    /// close. `read_capacity_snapshot` carried the same fail-open activation read `lib.rs`'s
    /// `read_effective_bounds` did (`json_extract` → `Option<i64>` → `.flatten()`), so a
    /// `kind='capacity_activated'` act whose pointer is PRESENT and JSON `null` read as
    /// **never activated** and the open ed `capacity::DEFAULT` over a store whose ledger
    /// says 128. Two doors, one bug, one authority: `capacity::parse_activation_pointer`.
    #[test]
    fn a_null_activation_pointer_refuses_the_open_capacity_read() {
        let (p, conn, log) = fresh_open_store("r5-null-activation-pointer");
        seed_activated_capacity(&p, 128);

        // ANTI-VACUITY: the ledger really does say 128 before the fault lands.
        assert_eq!(
            read_capacity_snapshot(conn.conn(), || {})
                .expect("the seeded ledger is readable")
                .max_active_ops,
            128,
            "the seeded 128-slot act must be CURRENT before the null pointer is appended"
        );

        // THE FAULT: a NEWER activation act whose pointer is present and null. Raw, because
        // the API writes this act through `json_object` and never emits one.
        append_engine_act(&p, "capacity_activated", "{\"activates_generation\":null}");

        // Pre-fix this is `Ok(DEFAULT)` — max_active_ops 1024 over a store configured at 128.
        let snapshot_err = read_capacity_snapshot(conn.conn(), || {}).expect_err(
            "a PRESENT-but-null activation pointer must REFUSE the snapshot read, never read \
             as `no activation` and fall back to the compiled default",
        );
        assert!(
            snapshot_err.contains("activates_generation"),
            "the refusal must name the pointer it could not read; got: {snapshot_err}"
        );

        // …and the door refuses too, spending (and naming) its one retry.
        let err = capacity_config_at_open(conn.conn())
            .expect_err("an unreadable activation pointer must refuse the open, not default");
        let text = format!("{err}");
        assert!(
            text.contains("could not be read consistently at open, twice"),
            "the refusal must name the retry it already spent; got: {text}"
        );
        let reopened = open_verified_connection(&p);
        assert!(
            reopened.is_err(),
            "the open chokepoint must propagate the capacity refusal"
        );
        drop_open_store(p, conn, log);
    }

    /// **A FORWARD ACTIVATION POINTER MUST REFUSE THE OPEN, NOT SEAT A
    /// NEVER-FITTED ACT.** The close taught the ADMISSION read that an activation
    /// pointer must name its own past (`lib.rs`), but THIS door kept discarding the activation
    /// row's own generation — so the identical planted ledger read CLEAN here: once the
    /// reserved generation is filled by a capacity act, the open configured the writer gate
    /// from bounds that never passed either fit authority. Same shape, another door; the
    /// ordering checks now live in the ONE authority (`capacity::effective_bounds`) so no
    /// door can carry a private copy again.
    #[test]
    fn a_forward_activation_pointer_refuses_the_open_capacity_read() {
        let (p, conn, log) = fresh_open_store("r14-f1-forward-pointer-open");
        seed_activated_capacity(&p, 128);

        // ANTI-VACUITY: the honest ledger reads 128 before the plant.
        assert_eq!(
            read_capacity_snapshot(conn.conn(), || {})
                .expect("the seeded ledger is readable")
                .max_active_ops,
            128,
            "the seeded 128-slot act must be CURRENT before the plant"
        );

        // THE PLANT: a well-formed activation row whose pointer names the generation AFTER
        // its own — the future. Raw is the only door: both honest writers point at an act
        // that already exists.
        let next_gen: i64 = {
            let c = rusqlite::Connection::open(&p).expect("raw open");
            c.query_row("SELECT MAX(generation) + 1 FROM engine_config;", [], |r| r.get(0))
                .expect("read next generation")
        };
        append_engine_act(
            &p,
            "capacity_activated",
            &format!("{{\"activates_generation\":{}}}", next_gen + 1),
        );
        // THE RESERVATION FILLED: a VALID capacity act lands at exactly the reserved
        // generation (raw — the restored/synced-ledger adversary; only the ORDERING is
        // dishonest). An 8192 enlargement, the doc's own worst case.
        let planted_act = append_engine_act(&p, "capacity", &capacity_act_payload(8192));
        assert_eq!(
            planted_act,
            next_gen + 1,
            "the act must land at exactly the reserved generation"
        );

        // Pre-fix this is `Ok` with max_active_ops 8192 — bounds no fit authority ever
        // passed, ed by the open.
        let snapshot_err = read_capacity_snapshot(conn.conn(), || {}).expect_err(
            "a forward activation pointer must REFUSE the snapshot read once its reserved \
             generation is filled — honoring it seats a never-fitted act as CURRENT",
        );
        assert!(
            snapshot_err.contains("not in its own past"),
            "the refusal names the forward-pointer shape; got: {snapshot_err}"
        );

        // …and the door refuses too, spending (and naming) its one retry.
        let err = capacity_config_at_open(conn.conn())
            .expect_err("a forward activation pointer must refuse the open, not default");
        let text = format!("{err}");
        assert!(
            text.contains("could not be read consistently at open, twice"),
            "the refusal must name the retry it already spent; got: {text}"
        );
        let reopened = open_verified_connection(&p);
        assert!(
            reopened.is_err(),
            "the open chokepoint must propagate the capacity refusal"
        );
        drop_open_store(p, conn, log);
    }

    /// the OPEN read adopts the admission reader's bounded two-row
    /// selection (lib.rs), ending the whole-history materialization at every
    /// connection open. Not a failing-first test for the bound itself (same disposition as lib.rs's
    /// the corresponding `lib.rs` test: the bound is visible in the SQL — a PK lookup + a `LIMIT 1`);
    /// this pins the semantics the recut claims to preserve.
    #[test]
    fn a_superseded_malformed_act_stays_unparsed_by_the_open_read() {
        let (p, conn, log) = fresh_open_store("r15-f2-superseded-unparsed-open");
        seed_activated_capacity(&p, 128);
        // A MALFORMED act — then a newer ACTIVATED one that supersedes it, so the malformed
        // act sits between activations: superseded, never selected, never parsed.
        append_engine_act(&p, "capacity", "{ this is not json");
        seed_activated_capacity(&p, 256);

        let derived = read_capacity_snapshot(conn.conn(), || {}).expect(
            "a malformed SUPERSEDED act must not refuse the open read — it was never parsed \
             under the whole-ledger fetch and must stay unparsed under the two-row one",
        );
        assert_eq!(derived.max_active_ops, 256, "the superseding act is CURRENT");

        // The CONTROL: the same malformed shape as the NEWEST (pending) act — and refuses,
        // exactly as the whole-ledger fetch always did.
        append_engine_act(&p, "capacity", "{ this is not json");
        let err = read_capacity_snapshot(conn.conn(), || {}).expect_err(
            "a malformed PENDING act must refuse the open read by name",
        );
        assert!(
            err.contains("not a readable config act"),
            "the refusal names the unreadable act; got: {err}"
        );
        drop_open_store(p, conn, log);
    }
}
