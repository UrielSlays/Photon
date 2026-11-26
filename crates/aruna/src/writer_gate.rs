//! The sever-priority writer gate: a process-wide, per-file-identity enrollment state machine.
//!
//! This is the crate's first process-global shared-mutable state, so it brings a concurrency
//! model. Read the invariants below before changing anything here.
//!
//! ## What the gate is
//!
//! SQLite is one-writer-per-file and its busy machinery retries and errors with no priority
//! (sqlite.org lang_transaction §2.1-2.2, c3ref/busy_timeout), so a sever cannot out-rank an
//! ordinary writer at the SQLite layer. The gate is the application-level mutex/condvar that
//! SQLite's own guidance recommends: every writer to the store file [`enroll`](WriterGate::enroll)s
//! first, at most one enrollment is live at a time, and a raised sever ticket blocks new
//! enrollment, so the sever service sees at most one in-flight writer.
//!
//! Two state machines share one [`Condvar`]:
//!
//! - **enrollment**: `active_writer: bool`; the wait predicate is
//!   `!active_writer && sever_pending == 0`, re-evaluated on every wake. A writer that slept
//!   behind another writer must yield if a sever ticketed while it slept.
//! - **the sever service**: `next_ticket`/`serving_ticket` (a bare count would let epoch bumps
//!   land out of authority order) plus a [`JoinWindow`] implementing the coalescing windows.
//!
//! ## Scope, and what the gate does not claim
//!
//! - **Process scope.** The registry binds one process. A second engine process over the same
//!   file contends only on SQLite's busy machinery, which grants no priority and, after
//!   `busy_timeout` (5000 ms), makes the in-process sever's `BEGIN IMMEDIATE` **fail with
//!   SQLITE_BUSY rather than wait**. The watchdog cannot see that contention. A process-level
//!   kill remains the lever.
//! - **Identity false positives.** Two paths that resolve to one file share one gate
//!   (`two_spellings_of_one_store_share_one_gate`). The inverse is the caveat: an identity can be
//!   reused (unix inode reuse after unlink; a FAT file index across renames) or non-unique
//!   (ReFS's 64-bit basic ID), so two different files could key one gate. That costs liveness,
//!   never correctness.
//! - **Fairness.** Severs are FIFO by ticket. Writers are unordered: `notify_all` plus a
//!   predicate loop means a writer can be overtaken repeatedly and, under sustained churn,
//!   starve. The gate bounds the sever's wait, not a writer's.
//! - **Storage liveness.** The chunk budget bounds work, not elapsed time: a stalled fsync under
//!   `synchronous=FULL` can hold one chunk open indefinitely. The watchdog reports that and
//!   keeps waiting; it never preempts.
//! - **Config propagation is open-time, not live.** [`WriterGate::for_connection`] always mints
//!   `capacity::DEFAULT`. `store_open::open_verified_connection` then re-reads the store's newest
//!   activated `capacity` act and re-mints the handle via [`WriterGate::with_config`], so a
//!   scope carries the configured `writer_chunk_budget_ms`, but only as of the moment its
//!   `GatedConnection` was opened. A live handle keeps the budget it opened with. Only the sever
//!   service re-reads bounds per service.
//! - **No checkpoint attribution.** The budget-overrun message reports the overrun and says
//!   "checkpoint contribution UNDETERMINED": a passive `wal_checkpoint` probe performs
//!   checkpoint work and reports only present state, so no causal claim is honest. See
//!   [`writer_budget_overrun_message`].
//! - **Registry eviction.** The registry never evicts. It is bounded in practice by one store
//!   file per app, and a store reset mints a new identity.
//! - **The shell's session mutex.** The shell's `with_session` holds one mutex around a whole
//!   command. A write that parks inside [`WriterGate::enroll`] behind a pending sever holds it for
//!   the whole park, so reads block for the sever's duration too. A typed-refusal pre-check
//!   (peek `sever_raised` before taking the session mutex) is future work.
//!
//! ## Write-path bound census
//!
//! The unbounded-hold shape appeared twice (the raw `begin()`/`commit()` bulk loader and
//! `ReadCoordinator::refresh_reconcile`), so this table lists every production write path with
//! the work one enrollment may perform. A new path is a new row, and a row that cannot state a
//! bound is a defect. Read it as: what does a pending sever wait behind, at worst, if it ticks
//! while this path holds the slot?
//!
//! | write path | per-enrollment work |
//! |---|---|
//! | `IntentLog::record` (the admission transaction) | 1 `intents` row + the activation trigger's own LIMIT-bounded probes |
//! | `set_status_if` · `settle_attempt` · `claim_attempt` · `prepare` · `adjudicate` · `authorize_send` · `undo_context` · `verify_undo_pair` · `replace_journal_row` · `dead_letter_if_quiescent` · `charge_and_dead_letter_if_quiescent` · `record_late_ack` · `annotate_late_ambiguous_observation` · `record_capacity_config` | O(1) rows per call: each names one operation/attempt and writes its own row(s) |
//! | `ReadCoordinator::ingest_row` | 1 header row + 1 placement row |
//! | `ReadCoordinator::ingest_page` | N enrollments of one row each: the atomic unit is the row, not the page |
//! | `ReadCoordinator::apply_verb_delta` | ≤ 2 rows (placement + header), one enrollment |
//! | `ReadCoordinator::refresh_reconcile` | **chunked**: the read runs ungated; the apply is `read_coordinator::REMOVALS_PER_CHUNK` removals per enrollment |
//! | `SqliteMessageHeaderStore::bulk_load_headers` | **chunked**: `rows_per_chunk` rows per enrollment, derived by the caller from `writer_chunk_budget_ms` |
//! | `record_header` · `record_optimistic_placement` · `correct_placement` | 1 autocommit statement ([`WriterGate::enroll`] via `with_enrolled_write`) |
//! | the sever service (`lead_sever_service`) | one kill transaction over the whole active pool, bounded by `max_active_ops` (1024 default, 8192 ceiling). Deliberately not chunked: it is the atomic unit the sever's guarantee is made of, and no sever waits behind it (it is the service) |
//! | the WAL-profile write at open (`pin_durability_profile`'s enrolled arm) | 1 pragma statement |
//!
//! Two rows cannot state a bound, both at open time. `boot_quarantine` runs one transaction that
//! walks `attempt_fact`, every `attempt_head`, and every stored sever witness (history-sized).
//! `SqliteIntentLog::open`'s migration transaction is O(1) on a current store, but on an upgrade
//! it runs `refuse_duplicate_placement_identity` (a full `message_placement` aggregate) and
//! `normalize_legacy_display_headers` (every `message_header` row, once). Neither is chunked: a
//! store must not be published half-migrated or half-classified. What bounds the exposure is when
//! they run: once per open, inside the per-identity serializer, before that handle exists for
//! anyone to use. A sever raised by another live handle to the same file while this one opens
//! does wait; no bound is claimed for that case.
//!
//! ## No reentrant enrollment
//!
//! A [`WriteScope`] may not be held across any call that enrolls. One gate per store makes a
//! nested enroll a self-deadlock, so a thread-local held-scope count turns it into an explicit
//! [`GateError::ReentrantEnrollment`] (`nested_enrollment_fails_loud`). The check is
//! gate-agnostic: it refuses a nested enroll on any gate, since a lock-order cycle across two
//! store gates is the same hazard. [`WriterGate::begin_sever`] carries the same refusal.
//!
//! ## The retained-descriptor / preflight contract
//!
//! On unix, closing any descriptor to a file cancels the process's POSIX advisory locks on it
//! (sqlite.org howtocorrupt §2.2), so the store's raw preflight (`read_raw_header`) must not open
//! and drop a bare `std::fs::File` while another connection may hold WAL locks. Instead there is
//! **one registry-owned descriptor per identity, opened once under this registry's serialization
//! and reused with positioned reads** ([`read_retained_header_at`]). A duplicate opened anyway is
//! retained for the process lifetime, never dropped. The open path is serialized per identity by
//! [`serialize_open_path`]. Nothing in this module opens the store as a database, and on unix
//! [`FileIdentity::of_path`] opens no descriptor at all.
//!
//! ## Lock order
//!
//! Four locks: the per-identity **open-path serializer** ([`serialize_open_path`]), the **gate
//! state mutex** (taken by [`WriterGate::enroll`] and released before it parks), the
//! **retained-header keeper mutex**, and **SQLite's own** file locking.
//!
//! 1. **Writers take the gate, then SQLite.** `with_immediate_tx` enrolls before `BEGIN
//!    IMMEDIATE` and holds nothing else.
//! 2. **The open path takes the serializer, then the keeper (briefly), then the gate.** The
//!    reverse edge (a [`WriteScope`] held while entering the open path) cannot form a cycle: the
//!    reentrancy check refuses that thread's second enrollment before it can wait.
//! 3. **The keeper mutex is a leaf.** It is released before the positioned read and never waits
//!    on the gate or SQLite.
//! 4. **The belt reads gate state inside a SQLite transaction** (SQLite, then gate), the one
//!    inversion of (1). It is safe because a waiting sever parks on the condvar with the state
//!    mutex released, and [`WriterGate::sever_raised`] takes it for a single field read.
//!
//! ## What is wired
//!
//! `SqliteIntentLog::sever` calls [`WriterGate::begin_sever`], takes its service enrollment through
//! [`WriterGate::enroll_service`], closes the join window with [`SeverEntry::close_snapshot`] and
//! publishes through [`SeverEntry::complete`], while every coalesced requester awaits
//! [`SeverEntry::await_outcome`]. The belt reads [`WriterGate::sever_raised`]; the open path uses
//! [`WriterGate::for_connection`], [`read_retained_header_at`] and [`serialize_open_path`];
//! writers use [`WriterGate::enroll`]. The remaining `#[allow(dead_code)]` marks are individually
//! named: a temporary allowance ([`WriterGate::for_path`]) or a test-only surface
//! ([`GateSnapshot`], [`SeverEntry::is_leader`], [`SeverEntry::ticket`]).

use std::cell::Cell;
use std::collections::HashMap;
use std::fmt;
use std::io::Write; // `writeln!` on `std::io::Stderr` — see [`LoggingStallObserver`].
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use crate::capacity::CapacityConfig;

#[cfg(not(any(unix, windows)))]
compile_error!(
    "writer_gate: PROVEN FILE IDENTITY is implemented for unix (st_dev/st_ino) and windows \
     (FILE_ID_INFO) only — there is deliberately NO path-string fallback, so a new platform \
     must add a real identity source here before the store can open on it."
);

/// The condvar slice the sever's turn-wait uses. It is not a timeout on the wait (the loop
/// always re-checks its predicate); it exists only so the watchdog can fire while waiting.
const SEVER_WAIT_SLICE: Duration = Duration::from_millis(25);

// Proven file identity

/// The gate's registry key: a file's identity as the kernel reports it, never a path string.
///
/// The variants are representation-tagged: a Windows extended 128-bit `FILE_ID_INFO` identity
/// and a basic 64-bit `GetFileInformationByHandle` identity are different questions asked of
/// different APIs, so they never compare equal. Mixing them could falsely merge two gates, the
/// one identity error that costs correctness rather than liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FileIdentity {
    /// unix: `st_dev` + `st_ino` from a `stat` of the path. Residuals: the stat-versus-open
    /// TOCTOU window, and inode reuse after unlink.
    #[cfg(unix)]
    Unix { dev: u64, ino: u64 },
    /// Windows: `GetFileInformationByHandleEx(FileIdInfo)`, the 128-bit `FILE_ID_INFO`
    /// (volume serial + 128-bit file id). The preferred, wide, stable form.
    #[cfg(windows)]
    WindowsExt { volume_serial: u64, file_id: u128 },
    /// Windows fallback: the 64-bit `GetFileInformationByHandle` pair, reachable only when the
    /// extended query fails with an explicitly-unsupported error. Documented non-unique on ReFS
    /// and unstable across FAT renames, a per-filesystem residual.
    #[cfg(windows)]
    WindowsBasic { volume_serial: u32, file_index: u64 },
}

/// How a Windows extended (`FileIdInfo`) identity query failed. Only the explicitly-unsupported
/// class may fall back to the 64-bit pair.
///
/// The Windows-identity classification family below (`ExtendedQueryError`,
/// [`BasicIdentityVerdict`], the `ERROR_*` codes, [`is_unsupported_extended_query`],
/// [`classify_basic`]) is `allow(dead_code)` on non-Windows builds on purpose: its production
/// caller is `#[cfg(windows)]`, while the classification is a pure function exercised by
/// cross-platform tests, which gating the family would break.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtendedQueryError {
    /// The filesystem/OS does not implement the extended class (see
    /// [`is_unsupported_extended_query`]).
    Unsupported { code: i32 },
    /// Anything else: access denied, handle revoked, device error. Not a licence to widen the
    /// trust in a narrower identity.
    Other { code: i32 },
}

/// The verdict on a Windows basic (64-bit) identity, once the extended query has failed.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BasicIdentityVerdict {
    /// A usable basic identity.
    Accept { volume_serial: u32, file_index: u64 },
    /// Microsoft's own handle-comparison guidance: a basic file index of `0` or
    /// `0xFFFF_FFFF_FFFF_FFFF` is a sentinel the filesystem returns when it has no stable id to
    /// give. It is not an identity; refuse as unobtainable.
    RefuseSentinel { file_index: u64 },
    /// The extended query failed for a reason other than "unsupported", so refuse: such a
    /// failure says nothing about whether the narrower id is trustworthy.
    RefuseExtendedQueryFailed { code: i32 },
}

/// `ERROR_INVALID_FUNCTION`: a filesystem that implements no extended info classes.
#[cfg_attr(not(windows), allow(dead_code))]
const ERROR_INVALID_FUNCTION: i32 = 1;
/// `ERROR_NOT_SUPPORTED`: the class is not supported here.
#[cfg_attr(not(windows), allow(dead_code))]
const ERROR_NOT_SUPPORTED: i32 = 50;
/// `ERROR_INVALID_PARAMETER` — what pre-`FileIdInfo` filesystems (FAT/exFAT, some network
/// redirectors) return for an info class they do not implement.
#[cfg_attr(not(windows), allow(dead_code))]
const ERROR_INVALID_PARAMETER: i32 = 87;

/// The explicitly-unsupported error class, the only one that may fall back to the 64-bit
/// identity. Everything else refuses. The list is closed on purpose: widening it is a
/// deliberate act, not an accident of a new error code appearing in the wild.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn is_unsupported_extended_query(code: i32) -> bool {
    matches!(
        code,
        ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER
    )
}

/// The Windows fallback-validity decision, as a pure function.
///
/// The four cases `{zero, all-ones, unsupported, ordinary-error}` are tested directly: the
/// classification is exercised without a ReFS/FAT volume, on every platform.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn classify_basic(
    ext_err: ExtendedQueryError,
    volume_serial: u32,
    file_index: u64,
) -> BasicIdentityVerdict {
    match ext_err {
        ExtendedQueryError::Other { code } => {
            BasicIdentityVerdict::RefuseExtendedQueryFailed { code }
        }
        ExtendedQueryError::Unsupported { .. } => {
            if file_index == 0 || file_index == u64::MAX {
                BasicIdentityVerdict::RefuseSentinel { file_index }
            } else {
                BasicIdentityVerdict::Accept {
                    volume_serial,
                    file_index,
                }
            }
        }
    }
}

#[cfg(unix)]
impl FileIdentity {
    /// unix identity: `std::fs::metadata`, a `stat` of the path.
    ///
    /// **No file descriptor is opened or closed here, and that is a correctness requirement.**
    /// Closing any descriptor to a file cancels the whole process's POSIX advisory locks on it
    /// (sqlite.org's "How To Corrupt An SQLite Database File" §2.2), so an independent
    /// open/close of the store while a connection holds locks silently destroys SQLite's
    /// locking. `stat` touches no descriptor table.
    ///
    /// Residuals: the stat-versus-open TOCTOU window and inode reuse after unlink. A custom VFS
    /// would give a true live-handle identity; it was not adopted.
    pub(crate) fn of_path(path: &Path) -> Result<FileIdentity, GateError> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).map_err(|e| GateError::IdentityUnobtainable {
            source: path.display().to_string(),
            detail: format!("stat failed: {e}"),
        })?;
        Ok(FileIdentity::Unix {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
}

#[cfg(windows)]
impl FileIdentity {
    /// Windows identity, via a brief metadata-only handle.
    ///
    /// On unix a brief open/close would cancel the process's POSIX advisory locks, so identity
    /// there is taken by `stat`. Windows has no POSIX advisory locks (SQLite's Windows VFS uses
    /// `LockFileEx` byte-range locks on its own handle, which an unrelated handle cannot
    /// affect), so a second handle for the length of this call is safe. It is opened for
    /// `FILE_READ_ATTRIBUTES` only and keeps std's default full share mode, so it cannot deny
    /// SQLite anything.
    ///
    /// The connection entry point uses the live native handle instead
    /// (`SQLITE_FCNTL_WIN32_GET_HANDLE`, via [`FileIdentity::of_raw_handle`]); this
    /// path-addressed constructor is for the standalone gate and the preflight.
    pub(crate) fn of_path(path: &Path) -> Result<FileIdentity, GateError> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        /// Metadata only, never `GENERIC_READ`: this handle must not be able to read a byte.
        const FILE_READ_ATTRIBUTES: u32 = 0x80;
        let source = path.display().to_string();
        let file = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .open(path)
            .map_err(|e| GateError::IdentityUnobtainable {
                source: source.clone(),
                detail: format!("cannot open a metadata handle: {e}"),
            })?;
        FileIdentity::of_raw_handle(file.as_raw_handle() as isize, &source)
    }

    /// Identity from an already-live Windows handle, as the connection entry point passes it the
    /// live SQLite handle. It answers the question about the very handle SQLite is writing
    /// through, closing the TOCTOU window the path form leaves open.
    ///
    /// Tries the 128-bit `GetFileInformationByHandleEx(FileIdInfo)` first (the basic 64-bit ID is
    /// non-unique on ReFS and unstable across FAT renames), and falls back to the 64-bit pair
    /// only through [`classify_basic`].
    pub(crate) fn of_raw_handle(handle: isize, source: &str) -> Result<FileIdentity, GateError> {
        #[repr(C)]
        #[allow(non_snake_case)]
        struct FileIdInfoRaw {
            VolumeSerialNumber: u64,
            FileId: [u8; 16],
        }
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
        // A small vendored declaration rather than a new dependency, matching the precedent in
        // `store_open.rs`.
        #[link(name = "kernel32")]
        extern "system" {
            fn GetFileInformationByHandleEx(
                h: isize,
                class: i32,
                out: *mut std::ffi::c_void,
                size: u32,
            ) -> i32;
            fn GetFileInformationByHandle(h: isize, out: *mut ByHandleFileInformation) -> i32;
        }
        /// `FileIdInfo` in `FILE_INFO_BY_HANDLE_CLASS`.
        const FILE_ID_INFO_CLASS: i32 = 18;

        let mut ext = unsafe { std::mem::zeroed::<FileIdInfoRaw>() };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FILE_ID_INFO_CLASS,
                (&mut ext as *mut FileIdInfoRaw).cast::<std::ffi::c_void>(),
                std::mem::size_of::<FileIdInfoRaw>() as u32,
            )
        };
        if ok != 0 {
            return Ok(FileIdentity::WindowsExt {
                volume_serial: ext.VolumeSerialNumber,
                file_id: u128::from_le_bytes(ext.FileId),
            });
        }

        let os_err = std::io::Error::last_os_error();
        let code = os_err.raw_os_error().unwrap_or(0);
        let ext_err = if is_unsupported_extended_query(code) {
            ExtendedQueryError::Unsupported { code }
        } else {
            ExtendedQueryError::Other { code }
        };

        let mut basic = unsafe { std::mem::zeroed::<ByHandleFileInformation>() };
        if unsafe { GetFileInformationByHandle(handle, &mut basic) } == 0 {
            return Err(GateError::IdentityUnobtainable {
                source: source.to_string(),
                detail: format!(
                    "FileIdInfo failed ({os_err}) and the 64-bit fallback failed too ({})",
                    std::io::Error::last_os_error()
                ),
            });
        }
        let file_index =
            (u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow);
        match classify_basic(ext_err, basic.dwVolumeSerialNumber, file_index) {
            BasicIdentityVerdict::Accept {
                volume_serial,
                file_index,
            } => Ok(FileIdentity::WindowsBasic {
                volume_serial,
                file_index,
            }),
            BasicIdentityVerdict::RefuseSentinel { file_index } => {
                Err(GateError::IdentityUnobtainable {
                    source: source.to_string(),
                    detail: format!(
                        "FileIdInfo unsupported ({os_err}) and the 64-bit file index is the \
                         SENTINEL {file_index:#x} — the filesystem has no stable identity to \
                         give, so this is unobtainable, not an identity"
                    ),
                })
            }
            BasicIdentityVerdict::RefuseExtendedQueryFailed { code } => {
                Err(GateError::IdentityUnobtainable {
                    source: source.to_string(),
                    detail: format!(
                        "FileIdInfo failed with OS error {code} ({os_err}) — that is NOT the \
                         explicitly-unsupported class, so the 64-bit fallback is not licensed"
                    ),
                })
            }
        }
    }
}

/// Proven file identity for the file a live connection has open. See
/// [`WriterGate::for_connection`] for the per-platform contract and why the Windows arm
/// refuses rather than degrading to the path form.
pub(crate) fn identity_of_connection(
    conn: &rusqlite::Connection,
    path: &Path,
) -> Result<FileIdentity, GateError> {
    #[cfg(unix)]
    {
        // `conn` is deliberately unused on unix: asking the live handle would require a
        // custom VFS (not adopted), and `stat` must not be replaced by an open/close here
        // (howtocorrupt §2.2).
        let _ = conn;
        FileIdentity::of_path(path)
    }
    #[cfg(windows)]
    {
        let source = path.display().to_string();
        // The live `HANDLE` SQLite writes through, via `sqlite3_file_control` with
        // `SQLITE_FCNTL_WIN32_GET_HANDLE` (=29, re-exported by libsqlite3-sys).
        // SAFETY: `conn.handle()` is live for the borrow, the db name is a NUL-terminated
        // literal, and the out-pointer is a properly aligned `isize` we own. The handle is
        // borrowed and never closed here; closing SQLite's own handle would corrupt locking.
        let mut handle: isize = 0;
        let rc = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                conn.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
                (&mut handle as *mut isize).cast::<std::ffi::c_void>(),
            )
        };
        if rc != rusqlite::ffi::SQLITE_OK || handle == 0 || handle == -1 {
            return Err(GateError::IdentityUnobtainable {
                source,
                detail: format!(
                    "SQLITE_FCNTL_WIN32_GET_HANDLE returned rc={rc} handle={handle:#x} — the \
                     live database handle is the only identity source licensed at the \
                     connection door, and there is no path-string fallback"
                ),
            });
        }
        FileIdentity::of_raw_handle(handle, &source)
    }
}

// The retained preflight descriptor

/// The keeper: one `std::fs::File` per file identity, opened once, **never closed while the
/// process lives**.
///
/// On unix, closing any descriptor to a file cancels the process's POSIX advisory locks on it
/// (sqlite.org howtocorrupt §2.2). The raw preflight reads 100 header bytes, and a bare
/// open/read/close while another connection holds WAL locks would destroy SQLite's locking.
/// The close is the hazard, not the open, so the keeper simply owns the descriptor.
struct HeaderKeeper {
    /// The one retained descriptor per identity. `Arc` so a read can proceed with the keeper
    /// mutex released (a positioned read takes `&File`).
    by_identity: HashMap<FileIdentity, Arc<std::fs::File>>,
    /// The fallback contract: a descriptor this keeper opened that turned out to name an
    /// identity it already holds (the stat-versus-open TOCTOU arm) is pushed here and never
    /// dropped. Dropping it is precisely the cancellation.
    retained_duplicates: Vec<std::fs::File>,
    /// How many real `File::open` syscalls this keeper has performed per identity. The reuse
    /// test's oracle; kept unconditionally (8 bytes per store) so the number the test reads is
    /// the number production produced.
    opens: HashMap<FileIdentity, u64>,
}

static HEADER_KEEPER: OnceLock<Mutex<HeaderKeeper>> = OnceLock::new();

fn header_keeper() -> &'static Mutex<HeaderKeeper> {
    HEADER_KEEPER.get_or_init(|| {
        Mutex::new(HeaderKeeper {
            by_identity: HashMap::new(),
            retained_duplicates: Vec::new(),
            opens: HashMap::new(),
        })
    })
}

/// The identity of an already-open file, asked of the descriptor itself: `fstat` on unix (no
/// new descriptor, no close), the live handle on Windows.
fn identity_of_open_file(file: &std::fs::File, source: &str) -> Result<FileIdentity, GateError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().map_err(|e| GateError::IdentityUnobtainable {
            source: source.to_string(),
            detail: format!("fstat of the retained descriptor failed: {e}"),
        })?;
        Ok(FileIdentity::Unix {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        FileIdentity::of_raw_handle(file.as_raw_handle() as isize, source)
    }
}

/// Read from the one retained descriptor for `path`'s identity with a positioned read
/// (`pread`/`seek_read`), opening it exactly once for the whole process. Returns how many
/// bytes were read (a short count means EOF, as with `read`).
///
/// Positioned reads are why one shared descriptor is enough: they take `&File` and carry their
/// own offset, so concurrent preflights cannot disturb each other. The keeper mutex is released
/// before the read; it guards the map, not the I/O.
pub(crate) fn read_retained_header_at(
    path: &Path,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, GateError> {
    let source = path.display().to_string();
    // The stat-derived key is a guess (the stat-versus-open TOCTOU residual). It is only used
    // to avoid an open; the descriptor is filed under the identity the open file itself
    // reports, so a stale guess can never make us read one file believing it is another.
    let guess = FileIdentity::of_path(path)?;
    let file = {
        let mut keeper = header_keeper().lock().map_err(|_| GateError::Poisoned {
            what: "the retained-header keeper",
        })?;
        match keeper.by_identity.get(&guess) {
            Some(f) => Arc::clone(f),
            None => {
                // Opened under the keeper mutex: two threads preflighting one identity cannot
                // both open, so "one descriptor per identity" is a property of this lock, not
                // of a caller remembering to serialize.
                let opened =
                    std::fs::File::open(path).map_err(|e| GateError::HeaderUnreadable {
                        source: source.clone(),
                        detail: format!("cannot open the store to read its header: {e}"),
                    })?;
                let truth = identity_of_open_file(&opened, &source)?;
                // Counted at the syscall, before any branch: the oracle must be "how many times
                // did we open this file", not "how many descriptors did we decide to keep". A
                // duplicate that is opened and retained is still an open.
                *keeper.opens.entry(truth).or_insert(0) += 1;
                if let Some(existing) = keeper.by_identity.get(&truth) {
                    // The guess was stale (the path was replaced between the stat and the
                    // open) and we now hold a duplicate descriptor to a file we already have.
                    // Retain it: dropping it here is the exact close howtocorrupt §2.2
                    // forbids. It costs one descriptor for the life of the process.
                    let existing = Arc::clone(existing);
                    keeper.retained_duplicates.push(opened);
                    existing
                } else {
                    let shared = Arc::new(opened);
                    keeper.by_identity.insert(truth, Arc::clone(&shared));
                    shared
                }
            }
        }
    };
    positioned_read(&file, offset, buf).map_err(|e| GateError::HeaderUnreadable {
        source,
        detail: format!("positioned read at offset {offset} failed: {e}"),
    })
}

/// Fill `buf` from `offset` with positioned reads, looping over short reads; stops at EOF.
fn positioned_read(
    file: &std::fs::File,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, std::io::Error> {
    #[cfg(unix)]
    use std::os::unix::fs::FileExt;
    #[cfg(windows)]
    use std::os::windows::fs::FileExt;
    let mut done = 0usize;
    while done < buf.len() {
        #[cfg(unix)]
        let n = file.read_at(&mut buf[done..], offset + done as u64)?;
        #[cfg(windows)]
        let n = file.seek_read(&mut buf[done..], offset + done as u64)?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

#[cfg(test)]
pub(crate) fn retained_header_opens_for_test(path: &Path) -> u64 {
    let Ok(identity) = FileIdentity::of_path(path) else {
        return 0;
    };
    let keeper = header_keeper().lock().expect("keeper");
    keeper.opens.get(&identity).copied().unwrap_or(0)
}

/// How many descriptors the fallback contract has retained (duplicates opened despite the
/// reuse path). A healthy run leaves this at 0; it is never allowed to be a drop.
#[cfg(test)]
pub(crate) fn retained_duplicates_for_test() -> usize {
    header_keeper().lock().expect("keeper").retained_duplicates.len()
}

#[cfg(test)]
pub(crate) fn retained_header_descriptors_for_test(path: &Path) -> usize {
    let Ok(identity) = FileIdentity::of_path(path) else {
        return 0;
    };
    let keeper = header_keeper().lock().expect("keeper");
    usize::from(keeper.by_identity.contains_key(&identity))
}

// Per-identity serialization of the open path

/// A per-identity reentrant mutex. Reentrancy is required: `SqliteIntentLog::open` holds the
/// serialization across its whole body and then calls `store_open::open_verified_connection`,
/// which takes it again at its own entry point (it is also public in its own right, for the
/// projection stores). A plain mutex would self-deadlock on that nesting; a reentrant one
/// keeps a single contract, "the open path for this identity runs alone", instead of two
/// half-contracts that depend on the call graph.
struct OpenSerializer {
    inner: Mutex<OpenOwner>,
    cv: Condvar,
}

struct OpenOwner {
    owner: Option<ThreadId>,
    depth: u32,
}

static OPEN_SERIALIZERS: OnceLock<Mutex<HashMap<FileIdentity, Arc<OpenSerializer>>>> =
    OnceLock::new();

fn open_serializers() -> &'static Mutex<HashMap<FileIdentity, Arc<OpenSerializer>>> {
    OPEN_SERIALIZERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Holds the open-path serialization for one identity. Released on `Drop`, including on
/// unwind, so a panicking open cannot wedge every later open of that store.
pub(crate) struct OpenPathGuard {
    serializer: Arc<OpenSerializer>,
}

impl Drop for OpenPathGuard {
    fn drop(&mut self) {
        let mut owner = match self.serializer.inner.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        owner.depth = owner.depth.saturating_sub(1);
        if owner.depth == 0 {
            owner.owner = None;
            drop(owner);
            self.serializer.cv.notify_all();
        }
    }
}

/// Serialize the whole open path for this store's identity (preflight, connection open,
/// persistent profile, DDL), so two opens never interleave their header reads,
/// `journal_mode=WAL` flips, or DDL transactions.
///
/// Returns `Ok(None)` when the path has no identity yet (an absent path about to be
/// bootstrapped): there is nothing to serialize against, and the fresh-install race is
/// serialized by the destination's own `InitLock` file lock. The caller re-enters on its second
/// preflight pass, when the file exists.
pub(crate) fn serialize_open_path(path: &Path) -> Result<Option<OpenPathGuard>, GateError> {
    let Ok(identity) = FileIdentity::of_path(path) else {
        return Ok(None);
    };
    let serializer = {
        let mut map = open_serializers().lock().map_err(|_| GateError::Poisoned {
            what: "the open-path serializer registry",
        })?;
        Arc::clone(map.entry(identity).or_insert_with(|| {
            Arc::new(OpenSerializer {
                inner: Mutex::new(OpenOwner {
                    owner: None,
                    depth: 0,
                }),
                cv: Condvar::new(),
            })
        }))
    };
    let me = std::thread::current().id();
    let mut owner = serializer.inner.lock().map_err(|_| GateError::Poisoned {
        what: "an open-path serializer",
    })?;
    loop {
        match owner.owner {
            None => {
                owner.owner = Some(me);
                owner.depth = 1;
                break;
            }
            Some(holder) if holder == me => {
                owner.depth += 1;
                break;
            }
            Some(_) => {
                owner = serializer.cv.wait(owner).map_err(|_| GateError::Poisoned {
                    what: "an open-path serializer",
                })?;
            }
        }
    }
    drop(owner);
    Ok(Some(OpenPathGuard { serializer }))
}

// Errors

/// Every way the gate refuses. There is no silent path: an unobtainable identity refuses the
/// open (no path-string fallback key exists), a poisoned mutex refuses every call, and a
/// reentrant enrollment is refused with an error instead of deadlocking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GateError {
    /// Proven file identity could not be obtained. `source` is the path (or a description of
    /// the handle) the identity was asked about. **The store open refuses on this**: the gate
    /// never falls back to a path string, because two spellings of one file would then get two
    /// gates and the one-writer invariant would be silently false.
    IdentityUnobtainable { source: String, detail: String },
    /// A thread panicked while holding gate state. A gate whose state may be torn cannot
    /// honestly answer "is there an active writer?".
    Poisoned { what: &'static str },
    /// Reentrant enrollment: this thread already holds a [`WriteScope`].
    ReentrantEnrollment { detail: &'static str },
    /// A leader-only operation ([`SeverEntry::close_snapshot`] / [`SeverEntry::complete`])
    /// was called on a joiner, or on a leader whose service is already over.
    NotTheServiceLeader { role: SeverRole },
    /// The retained preflight descriptor could not be opened or read
    /// ([`read_retained_header_at`]). Distinct from an unobtainable identity: the identity
    /// answered, the bytes did not.
    HeaderUnreadable { source: String, detail: String },
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::IdentityUnobtainable { source, detail } => write!(
                f,
                "writer gate: proven file identity is unobtainable for {source} — {detail}; \
                 the store open REFUSES (there is no path-string fallback)"
            ),
            GateError::Poisoned { what } => write!(
                f,
                "writer gate: {what} is POISONED — a thread panicked while holding it; the \
                 gate cannot answer for the writer state"
            ),
            GateError::ReentrantEnrollment { detail } => write!(
                f,
                "writer gate: re-entrant enrollment refused — {detail}"
            ),
            GateError::NotTheServiceLeader { role } => write!(
                f,
                "writer gate: this operation belongs to the service LEADER; this entry is \
                 {role:?}"
            ),
            GateError::HeaderUnreadable { source, detail } => write!(
                f,
                "writer gate: the retained preflight descriptor for {source} could not be \
                 read — {detail}"
            ),
        }
    }
}

impl std::error::Error for GateError {}

/// The bridge every gated write needs: the store's own error type is `rusqlite::Error`
/// (`SqliteIntentLog::open`) or `LogError` (every write method). A gate refusal is not an
/// SQLite fault, so it is rendered as an application-level `SqliteFailure` carrying the gate's
/// own message verbatim, never swallowed or downgraded to a bare "database is locked".
impl From<GateError> for rusqlite::Error {
    fn from(e: GateError) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
            Some(e.to_string()),
        )
    }
}

// The stall surfaces

/// The budget-overrun message. It makes no causal checkpoint attribution: differential tests
/// showed autocheckpoint-on and -off histories indistinguishable after the fact, and the probe
/// itself performs checkpoint work. The message reports the overrun and says so.
pub(crate) fn writer_budget_overrun_message(elapsed: Duration, budget_ms: u32) -> String {
    format!(
        "photon.writer-gate: an enrolled write held the gate for {} ms, over the {} ms writer \
         chunk budget — a pending sever waits at least that long behind it. WAL/checkpoint \
         state is not visible from the gate (Task 6's connection wiring supplies it), and no \
         causal claim is made either way: checkpoint contribution UNDETERMINED.",
        elapsed.as_millis(),
        budget_ms
    )
}

/// The sever watchdog message. The watchdog reports a stall and never preempts.
pub(crate) fn sever_stall_message(elapsed: Duration) -> String {
    format!(
        "photon.writer-gate: a sever has waited {} ms for its turn, past the watchdog \
         threshold — it KEEPS WAITING (the watchdog surfaces, it never preempts; §5.5's \
         process-level kill is the unblockable lever). The elapsed bound is honest only on \
         LIVE STORAGE, and cross-PROCESS contention is invisible here.",
        elapsed.as_millis()
    )
}

/// The injectable stall surface.
///
/// An implementation is foreign code and the gate assumes nothing about it:
///
/// - it is invoked without the gate's state mutex held, so an observer may call back into any
///   gate method (`WriterGate::begin_sever`'s watchdog drops the guard, calls, re-acquires, and
///   re-evaluates its predicate);
/// - it may panic. Every gate resource live across the call is owned by a guard whose `Drop`
///   releases it, so an unwinding observer releases the sever ticket, clears the join window and
///   resolves the shared outcome as [`SeverOutcome::Failed`] instead of wedging enrollment. The
///   panic propagates to the caller.
///
/// An implementation must return: the watchdog reports and never preempts, and an observer that
/// blocks forever blocks the sever it is reporting on.
pub(crate) trait StallObserver: Send + Sync {
    /// An enrolled write held the gate longer than `writer_chunk_budget_ms`.
    fn writer_budget_exceeded(&self, elapsed: Duration, budget_ms: u32);
    /// A sever has been waiting for its turn past `sever_watchdog_ms`. Fired once per crossing
    /// of each successive watchdog interval; the sever keeps waiting.
    fn sever_stalled(&self, elapsed: Duration);
}

/// The default surface: stderr. Deliberately not a tracing subsystem.
///
/// **Non-panicking on purpose.** `eprintln!` panics if the write to stderr fails, which is
/// reachable in production (a GUI launch with no console, a full-disk redirect, a broken pipe).
/// `writeln!` returns the error instead, and it is swallowed here on purpose: there is nowhere
/// left to report "I could not report".
pub(crate) struct LoggingStallObserver;

impl StallObserver for LoggingStallObserver {
    fn writer_budget_exceeded(&self, elapsed: Duration, budget_ms: u32) {
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            writer_budget_overrun_message(elapsed, budget_ms)
        );
    }
    fn sever_stalled(&self, elapsed: Duration) {
        let _ = writeln!(std::io::stderr(), "{}", sever_stall_message(elapsed));
    }
}

// Sever roles and the outcome rendezvous

/// Which part a sever requester plays in the one service its request coalesced into.
///
/// The gate hands out roles and a rendezvous; durability of the attribution rows is the store's
/// concern (the `sever_attribution` table). In-snapshot joiners are written inside the leader's
/// transaction; overflow and post-snapshot requesters append their own row against the
/// already-bumped epoch after the leader commits, and return `Ok` only once it is durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SeverRole {
    /// This request minted the ticket and serves. Its transaction performs the one epoch bump
    /// every coalesced requester shares.
    Leader { ticket: u64 },
    /// Arrived while the leader's witness snapshot was still open and inside
    /// `sever_joiner_cap`; the leader carries this `join_id` into its own transaction.
    InSnapshotJoiner { join_id: u64 },
    /// Arrived while the snapshot was open but the cap was already full. No second bump and no
    /// new ticket; it owns its own attribution append.
    OverflowJoiner,
    /// Arrived after the snapshot closed but before the service completed. A joiner cannot be
    /// added to a running transaction, so: no second bump, no new ticket, own attribution
    /// append.
    PostSnapshot,
}

/// What a completed sever service produced. Opaque to the gate, which only relays it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SeverOutcome {
    /// The leader's kill transaction committed, bumping the control epoch to `epoch`.
    Served { epoch: u64 },
    /// The service did not complete. Every coalesced requester learns this as a value;
    /// silence is never an outcome here.
    Failed { detail: String },
}

/// The shared outcome slot one service hands to every requester that coalesced into it. Held
/// by `Arc` from each [`SeverEntry`], so it outlives the join window in [`GateInner`] exactly
/// as long as someone still needs to read it.
#[derive(Debug)]
struct SeverOutcomeSlot {
    slot: Mutex<Option<SeverOutcome>>,
    cv: Condvar,
}

impl SeverOutcomeSlot {
    fn new() -> SeverOutcomeSlot {
        SeverOutcomeSlot {
            slot: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    /// First writer wins: a leader that both completes and is then dropped resolves once.
    /// Poison is recovered here deliberately (`into_inner`): a poisoned outcome slot must not
    /// strand every joiner on the condvar forever. The gate's own state mutex keeps its poison
    /// (see [`WriteScope::drop`]).
    fn resolve(&self, outcome: SeverOutcome) {
        let mut slot = match self.slot.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if slot.is_none() {
            *slot = Some(outcome);
        }
        drop(slot);
        self.cv.notify_all();
    }
}

// Gate state

/// The in-flight sever service's coalescing window.
#[derive(Debug)]
struct JoinWindow {
    /// The leader's ticket: the service's identity, and the slot the epoch bump lands in.
    leader_ticket: u64,
    /// The joiner cap this service runs under, captured from the leader's handle when the window
    /// opened. Not re-read per arrival: each requester's handle carries whatever the ledger said
    /// when it read it, and using the arriving handle's cap could bound one join window by two
    /// different numbers if a capacity act landed mid-flight. One service, one cap.
    joiner_cap: u32,
    /// In-snapshot joiners as `(join_id, requester_ref)`, bounded by [`Self::joiner_cap`] (an
    /// unbounded payload would grow the kill transaction's write work past its time bound). The
    /// `requester_ref` is carried here because the leader, not the joiner, writes these rows
    /// inside its own transaction, so the store must be able to turn a frozen join id back into
    /// the authority reference that asked for it.
    joiners: Vec<(u64, String)>,
    /// Arrivals that found the joiner list at cap while the snapshot was still open.
    overflow_joiners: u32,
    /// Arrivals after the snapshot closed, before completion.
    post_snapshot: u32,
    /// Set by [`SeverEntry::close_snapshot`], the join window's closing edge. Witness metadata
    /// commits atomically, so a joiner cannot be added to a running transaction.
    snapshot_closed: bool,
    /// Monotonic within the service.
    next_join_id: u64,
    /// The outcome every requester in this service shares.
    outcome: Arc<SeverOutcomeSlot>,
}

/// The arbiter's state. One instance per file identity, for the life of the process.
#[derive(Debug)]
struct GateInner {
    /// `active_writer: 0|1`.
    active_writer: bool,
    /// A count with per-sever tickets, never a shared Boolean. Enrollment is blocked while it
    /// is greater than 0. Coalescing keeps it at most 1 in practice; it stays a count because
    /// the enrollment predicate is `== 0` everywhere.
    sever_pending: u32,
    /// The next ticket a service will take.
    next_ticket: u64,
    /// Only the holder of this ticket may serve — epoch bumps therefore land in ticket order.
    serving_ticket: u64,
    /// `Some` exactly while a service is pending or serving.
    join: Option<JoinWindow>,
    /// Instrumentation (not protocol state): how many threads are parked inside
    /// [`WriterGate::enroll`]'s predicate loop.
    enroll_waiters: u32,
    /// Instrumentation (not protocol state): how many times a parked writer evaluated its
    /// predicate when **no writer was active and a sever was pending, and kept waiting anyway**.
    /// That event is exactly the re-check-on-wake property, and it is unambiguous (the other
    /// reason to keep waiting, an active writer, is excluded), so a test that sees this counter
    /// advance needs no clock.
    enroll_yields_to_sever: u64,
}

impl GateInner {
    fn new() -> GateInner {
        GateInner {
            active_writer: false,
            sever_pending: 0,
            next_ticket: 1,
            serving_ticket: 1,
            join: None,
            enroll_waiters: 0,
            enroll_yields_to_sever: 0,
        }
    }
}

/// The registry-owned per-identity state: one mutex, one condvar, shared by every
/// [`WriterGate`] handle that resolved to this file.
struct GateState {
    inner: Mutex<GateInner>,
    cv: Condvar,
}

impl GateState {
    fn new() -> GateState {
        GateState {
            inner: Mutex::new(GateInner::new()),
            cv: Condvar::new(),
        }
    }
}

fn lock_inner(state: &GateState) -> Result<MutexGuard<'_, GateInner>, GateError> {
    state.inner.lock().map_err(|_| GateError::Poisoned {
        what: "the writer gate's state mutex",
    })
}

/// **The crate's first process-global shared-mutable state.** Keyed on proven file identity,
/// never evicted (see the module doc's registry-eviction note).
static REGISTRY: OnceLock<Mutex<HashMap<FileIdentity, Arc<GateState>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<FileIdentity, Arc<GateState>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

thread_local! {
    /// How many [`WriteScope`]s this thread holds, for the no-reentrant-enrollment check.
    /// Deliberately gate-agnostic; see the module doc.
    static HELD_SCOPES: Cell<u32> = const { Cell::new(0) };
}

/// How many [`WriteScope`]s the calling thread holds.
///
/// `pub(crate)`: it is the enrollment invariant's own oracle, and a test that a caller-supplied
/// closure runs outside any enrollment has nothing else to ask. It exposes no capability
/// (reading a thread-local counter cannot enroll, release, or block anything), and every
/// enrollment decision still lives in this module.
pub(crate) fn held_scopes() -> u32 {
    HELD_SCOPES.with(Cell::get)
}

/// A read-only view of the arbiter, for the belt and for timing-free tests.
///
/// **The `dead_code` allow is structural, not a temporary allowance:** this is the tests'
/// oracle. Every threaded test in this crate spins on gate state instead of on a clock, and
/// production never reads its own arbiter's counters (the belt reads
/// [`WriterGate::sever_raised`], not this). A production caller would be the surprise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)] // the timing-free witnesses' oracle — see the doc above.
pub(crate) struct GateSnapshot {
    pub(crate) active_writer: bool,
    pub(crate) sever_pending: u32,
    pub(crate) next_ticket: u64,
    pub(crate) serving_ticket: u64,
    pub(crate) service_open: bool,
    pub(crate) snapshot_closed: bool,
    pub(crate) in_snapshot_joiners: u32,
    pub(crate) overflow_joiners: u32,
    pub(crate) post_snapshot_requests: u32,
    pub(crate) enroll_waiters: u32,
    pub(crate) enroll_yields_to_sever: u64,
}

// The gate handle

/// A handle on the arbiter for one store file.
///
/// The state is per-identity and registry-owned; the config and stall observer are per-handle,
/// so a handle governs only its own budget/watchdog/cap readings.
///
/// **`Clone` is a pointer clone, not a registry lookup:** every field is `Copy`
/// (`FileIdentity`, `CapacityConfig`) or an `Arc` (`state`, `observer`). This lets
/// `authorize_send` capture a handle before `with_immediate_tx` borrows `self` mutably and carry
/// it into the enrolled closure for the belt's read.
#[derive(Clone)]
pub(crate) struct WriterGate {
    identity: FileIdentity,
    state: Arc<GateState>,
    config: CapacityConfig,
    observer: Arc<dyn StallObserver>,
}

impl fmt::Debug for WriterGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriterGate")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl WriterGate {
    /// The ordinary constructor: default capacity bounds, the stderr stall surface.
    #[allow(dead_code)] // the connection door mints gates from the CONNECTION; the path door stays for the standalone gate + witnesses.
    pub(crate) fn for_path(path: &Path) -> Result<WriterGate, GateError> {
        WriterGate::for_path_with(
            path,
            crate::capacity::DEFAULT,
            Arc::new(LoggingStallObserver),
        )
    }

    /// The injectable constructor (config + stall observer). The store open uses it to pass the
    /// store's loaded [`CapacityConfig`]; tests use it to make budget and watchdog crossings
    /// deterministic.
    ///
    /// Identity is proven first and an unobtainable identity refuses: there is no path-string
    /// fallback, because two spellings of one file would get two gates and "at most one writer"
    /// would be silently false.
    pub(crate) fn for_path_with(
        path: &Path,
        config: CapacityConfig,
        observer: Arc<dyn StallObserver>,
    ) -> Result<WriterGate, GateError> {
        WriterGate::from_identity(FileIdentity::of_path(path)?, config, observer)
    }

    /// **The connection entry point.** The gate for the store a live connection is about to
    /// write, derived from that connection wherever the platform can answer for the very handle
    /// SQLite writes through.
    ///
    /// - **Windows:** `sqlite3_file_control(SQLITE_FCNTL_WIN32_GET_HANDLE)` gives the live
    ///   `HANDLE`, then [`FileIdentity::of_raw_handle`]. This closes the path-form TOCTOU. A
    ///   file-control failure refuses; degrading to the path form would reintroduce the window.
    /// - **unix:** [`FileIdentity::of_path`], a `stat` with no descriptor opened or closed
    ///   (howtocorrupt §2.2). The live-handle form would need a custom VFS, which was not
    ///   adopted; the TOCTOU window and inode reuse remain residuals.
    ///
    /// Config and observer belong to this handle, never to the identity: [`GateState`], the one
    /// thing shared per file, carries no thresholds. The sever service reads the store's
    /// `capacity` act for its joiner cap; a handle minted here has no transaction to read the
    /// ledger through and must never guess one.
    pub(crate) fn for_connection(
        conn: &rusqlite::Connection,
        path: &Path,
    ) -> Result<WriterGate, GateError> {
        let identity = identity_of_connection(conn, path)?;
        WriterGate::from_identity(
            identity,
            crate::capacity::DEFAULT,
            Arc::new(LoggingStallObserver),
        )
    }

    /// The registry lookup shared by every constructor: one [`GateState`] per identity, for the
    /// life of the process.
    fn from_identity(
        identity: FileIdentity,
        config: CapacityConfig,
        observer: Arc<dyn StallObserver>,
    ) -> Result<WriterGate, GateError> {
        let mut map = registry().lock().map_err(|_| GateError::Poisoned {
            what: "the writer-gate registry",
        })?;
        let state = Arc::clone(map.entry(identity).or_insert_with(|| Arc::new(GateState::new())));
        drop(map);
        Ok(WriterGate {
            identity,
            state,
            config,
            observer,
        })
    }

    /// The same arbiter, read through different thresholds.
    ///
    /// [`Self::for_connection`] mints a handle at the connection entry point, where there is no
    /// transaction to read the `engine_config` ledger through, so it carries
    /// [`crate::capacity::DEFAULT`] and says so. The sever service's joiner cap is a `capacity`
    /// act, and `SqliteIntentLog::sever` reads it off the ledger before it requests a service;
    /// this hands the loaded bounds to a handle without touching the registry (every field is
    /// `Copy` or an `Arc`, so it is a pointer clone).
    ///
    /// [`GateState`], the one thing shared per file identity, deliberately carries no
    /// thresholds, so two handles disagreeing about a budget can never disagree about who holds
    /// the writer slot.
    pub(crate) fn with_config(&self, config: CapacityConfig) -> WriterGate {
        WriterGate {
            identity: self.identity,
            state: Arc::clone(&self.state),
            config,
            observer: Arc::clone(&self.observer),
        }
    }

    #[allow(dead_code)] // /7: identity/state comparison + the belt read + the sever service.
    pub(crate) fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Do two handles govern the same arbiter? Used by the identity test's assertion.
    #[allow(dead_code)] // the identity witness's assertion — see [`GateSnapshot`]'s doc.
    pub(crate) fn shares_state_with(&self, other: &WriterGate) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    #[allow(dead_code)] // the timing-free witnesses' oracle — see [`GateSnapshot`]'s doc.
    pub(crate) fn snapshot(&self) -> Result<GateSnapshot, GateError> {
        let g = lock_inner(&self.state)?;
        Ok(GateSnapshot {
            active_writer: g.active_writer,
            sever_pending: g.sever_pending,
            next_ticket: g.next_ticket,
            serving_ticket: g.serving_ticket,
            service_open: g.join.is_some(),
            snapshot_closed: g.join.as_ref().is_some_and(|w| w.snapshot_closed),
            in_snapshot_joiners: g
                .join
                .as_ref()
                .map_or(0, |w| u32::try_from(w.joiners.len()).unwrap_or(u32::MAX)),
            overflow_joiners: g.join.as_ref().map_or(0, |w| w.overflow_joiners),
            post_snapshot_requests: g.join.as_ref().map_or(0, |w| w.post_snapshot),
            enroll_waiters: g.enroll_waiters,
            enroll_yields_to_sever: g.enroll_yields_to_sever,
        })
    }

    /// The belt's reading: is a sever ticketed right now? `authorize_send` re-reads this as the
    /// first act inside its `BEGIN IMMEDIATE` and answers `EpochFenced` without writing if it is
    /// raised; the pending sever's own transaction then performs the closure. Lock order:
    /// writers take gate-then-SQLite and this read is SQLite-then-gate, which is safe because a
    /// waiting sever parks on the condvar with this mutex released.
    pub(crate) fn sever_raised(&self) -> Result<bool, GateError> {
        Ok(lock_inner(&self.state)?.sever_pending > 0)
    }

    /// Enroll as the writer, blocking until `!active_writer && sever_pending == 0`.
    ///
    /// The predicate loop is spelled out rather than using `Condvar::wait_while` so that the
    /// decision to yield to a pending sever is countable (`enroll_yields_to_sever`). The
    /// semantics are `wait_while`'s: re-evaluate on every wake, spurious ones included.
    ///
    /// Refuses with [`GateError::ReentrantEnrollment`] if this thread already holds a scope.
    pub(crate) fn enroll(&self) -> Result<WriteScope, GateError> {
        if held_scopes() > 0 {
            return Err(GateError::ReentrantEnrollment {
                detail: "this thread already holds a WriteScope; a nested enrollment would \
                         wait for itself (one gate per store). Restructure so the outer scope \
                         ends first — see NO-REENTRANT-ENROLLMENT in the module doc",
            });
        }
        let mut guard = lock_inner(&self.state)?;
        guard.enroll_waiters += 1;
        loop {
            if !guard.active_writer && guard.sever_pending == 0 {
                break;
            }
            if !guard.active_writer && guard.sever_pending > 0 {
                // The gate is free of writers and this thread still keeps waiting: the only
                // reason is the pending sever. This makes the re-check on wake observable.
                guard.enroll_yields_to_sever += 1;
            }
            guard = self.state.cv.wait(guard).map_err(|_| GateError::Poisoned {
                what: "the writer gate's state mutex",
            })?;
        }
        guard.enroll_waiters -= 1;
        guard.active_writer = true;
        drop(guard);
        HELD_SCOPES.with(|c| c.set(c.get() + 1));
        Ok(WriteScope {
            state: Arc::clone(&self.state),
            observer: Arc::clone(&self.observer),
            budget_ms: self.config.writer_chunk_budget_ms,
            started: Instant::now(),
            _not_send: std::marker::PhantomData,
        })
    }

    /// **The service's own writer slot:** the enrollment a sever leader takes for its kill
    /// transaction.
    ///
    /// [`Self::enroll`] cannot serve here: a raised ticket blocks new enrollment, so a leader
    /// calling `enroll()` would wait for its own ticket to clear. The ticket blocks everyone
    /// except its holder, and this method says so once instead of special-casing `enroll`.
    ///
    /// The wait is on `!active_writer` alone, which is not a weakening: [`Self::begin_sever`]
    /// only returns to a leader once `serving_ticket == its ticket && !active_writer`, and from
    /// then no other writer can enroll (the ticket is up) and no other service can exist (the
    /// join window is `Some`). The loop is kept anyway because re-checking is easier to read
    /// than an argument about why it cannot fail.
    ///
    /// Refuses if `entry` is not a leader, belongs to a different store's arbiter, no longer
    /// holds the serving ticket, or if this thread already holds a scope.
    pub(crate) fn enroll_service(&self, entry: &SeverEntry) -> Result<WriteScope, GateError> {
        let SeverRole::Leader { ticket } = entry.role else {
            return Err(GateError::NotTheServiceLeader { role: entry.role });
        };
        if !Arc::ptr_eq(&self.state, &entry.state) {
            return Err(GateError::NotTheServiceLeader { role: entry.role });
        }
        if held_scopes() > 0 {
            return Err(GateError::ReentrantEnrollment {
                detail: "this thread already holds a WriteScope; a sever service cannot enrol \
                         inside another enrolled write",
            });
        }
        let mut guard = lock_inner(&self.state)?;
        if guard.serving_ticket != ticket {
            return Err(GateError::NotTheServiceLeader { role: entry.role });
        }
        while guard.active_writer {
            guard = self.state.cv.wait(guard).map_err(|_| GateError::Poisoned {
                what: "the writer gate's state mutex",
            })?;
        }
        guard.active_writer = true;
        drop(guard);
        HELD_SCOPES.with(|c| c.set(c.get() + 1));
        Ok(WriteScope {
            state: Arc::clone(&self.state),
            observer: Arc::clone(&self.observer),
            budget_ms: self.config.writer_chunk_budget_ms,
            started: Instant::now(),
            _not_send: std::marker::PhantomData,
        })
    }

    /// Request a sever: join the in-flight service, or take a ticket and lead one.
    ///
    /// - a service is pending or serving with its snapshot open: in-snapshot joiner (up to the
    ///   cap) or, at cap, an overflow-joiner marker;
    /// - snapshot closed but the service incomplete: a post-snapshot marker, with no second
    ///   epoch bump and no new ticket;
    /// - no service: take `next_ticket`, raise `sever_pending` (blocking new enrollment) and
    ///   block until `serving_ticket == mine && !active_writer`.
    ///
    /// A new service and ticket therefore exist only for a request arriving after the prior
    /// service completed. `requester_ref` is the caller's seizing-authority reference; an
    /// in-snapshot joiner never writes its own attribution row (the leader does, inside the kill
    /// transaction), so it travels with the join id and [`SeverEntry::close_snapshot`] hands the
    /// frozen pairs back to the leader. The gate never interprets the string.
    pub(crate) fn begin_sever(&self, requester_ref: &str) -> Result<SeverEntry, GateError> {
        if held_scopes() > 0 {
            return Err(GateError::ReentrantEnrollment {
                detail: "this thread holds a WriteScope; raising a sever would wait for its \
                         own enrollment to end",
            });
        }
        let mut guard = lock_inner(&self.state)?;

        // Join an in-flight service.
        if let Some(window) = guard.join.as_mut() {
            let outcome = Arc::clone(&window.outcome);
            let role = if window.snapshot_closed {
                window.post_snapshot += 1;
                SeverRole::PostSnapshot
            } else if (window.joiners.len() as u64) < u64::from(window.joiner_cap) {
                let join_id = window.next_join_id;
                window.next_join_id += 1;
                window.joiners.push((join_id, requester_ref.to_string()));
                SeverRole::InSnapshotJoiner { join_id }
            } else {
                window.overflow_joiners += 1;
                SeverRole::OverflowJoiner
            };
            drop(guard);
            return Ok(SeverEntry {
                state: Arc::clone(&self.state),
                role,
                outcome,
                // A joiner has no service to release: its `Drop` must never advance a ticket.
                completed: true,
            });
        }

        // No service: take a ticket and lead.
        let ticket = guard.next_ticket;
        guard.next_ticket += 1;
        guard.sever_pending += 1;
        let outcome = Arc::new(SeverOutcomeSlot::new());
        guard.join = Some(JoinWindow {
            leader_ticket: ticket,
            joiner_cap: self.config.sever_joiner_cap,
            joiners: Vec::new(),
            overflow_joiners: 0,
            post_snapshot: 0,
            snapshot_closed: false,
            next_join_id: 1,
            outcome: Arc::clone(&outcome),
        });
        // Deliberately no `notify_all` here: raising a ticket only makes the enrollment
        // predicate more restrictive, so it can never release a parked writer. Waking them to
        // re-park would be pure noise that a timing-free test cannot tell from a real wake.

        // Cleanup ownership is established here, before anything can fail. The mutations above
        // (`sever_pending`, the ticket, the join window) are the only ones that raise a service,
        // and from here `SeverEntry`'s `Drop` owns them: it releases the ticket, clears the
        // window, decrements the pending count, notifies the condvar and resolves the shared
        // outcome as `Failed`. Building the entry after the wait loop would leak them on every
        // non-`break` exit: the observer below is foreign code called with the mutex released and
        // can panic, and the loop's two `?`s can return `Poisoned`. `sever_pending > 0` is half
        // the enrollment predicate, so a leak parks every later writer on this file forever.
        //
        // The panic still propagates, so the caller sees that its observer failed (swallowing it
        // would hand back a leader entry for a service nobody ran). See
        // `a_panicking_stall_observer_unwinds_the_sever_ticket`.
        let entry = SeverEntry {
            state: Arc::clone(&self.state),
            role: SeverRole::Leader { ticket },
            outcome,
            completed: false,
        };
        // The state guard is re-bound here, after `entry`, on purpose. Locals drop in reverse
        // declaration order, so the original binding (declared above `entry`) would unwind
        // second, and `SeverEntry::drop` would try to re-acquire a mutex this frame was still
        // holding, turning a panic taken with the lock held into a deadlock instead of a
        // cleanup. Same guard, same continuously held lock, no window opened: only the unwind
        // order changes.
        let mut guard = guard;

        let started = Instant::now();
        let watchdog = Duration::from_millis(u64::from(self.config.sever_watchdog_ms));
        let mut next_alarm = watchdog;
        loop {
            if guard.serving_ticket == ticket && !guard.active_writer {
                break;
            }
            // The watchdog is only consulted when we are about to wait: a sever that gets its
            // turn immediately never fires it, whatever the threshold.
            let elapsed = started.elapsed();
            if elapsed >= next_alarm {
                // The observer is foreign code, so it is called without the state mutex. A
                // caller's observer may do anything: touch this store, take its own lock, or call
                // back into the gate. Holding [`GateInner`] would make a re-entered gate call
                // self-deadlock on a non-reentrant `Mutex`, and a foreign lock taken here would
                // invert against any thread that takes it and then enrolls.
                //
                // So: drop the guard, call, re-acquire, and `continue`. The loop re-evaluates its
                // break predicate from the top, which is required: the state we released the
                // mutex on is stale (`serving_ticket`/`active_writer` can both have moved), and
                // acting on it would be a check-then-act bug.
                drop(guard);
                self.observer.sever_stalled(elapsed);
                // Once per crossing of each successive interval; never a preemption.
                next_alarm = elapsed
                    + if watchdog.is_zero() {
                        SEVER_WAIT_SLICE
                    } else {
                        watchdog
                    };
                guard = lock_inner(&self.state)?;
                continue;
            }
            let (next_guard, _timed_out) = self
                .state
                .cv
                .wait_timeout(guard, SEVER_WAIT_SLICE)
                .map_err(|_| GateError::Poisoned {
                    what: "the writer gate's state mutex",
                })?;
            guard = next_guard;
        }
        drop(guard);
        Ok(entry)
    }

    /// Test seam for `poisoned_gate_fails_loud`: panic while holding [`GateInner`], the only
    /// way to poison the state mutex. (An ordinary enrollee panic does not hold it; that is a
    /// different test.)
    #[cfg(test)]
    pub(crate) fn poison_state_for_test(&self) {
        let _guard = self.state.inner.lock().expect("state mutex");
        panic!("test seam: poisoning GateInner while holding it");
    }
}

// The enrollment scope

/// Live enrollment. **Holding this is holding the one writer slot for the store file.**
///
/// The scope is handed to a closure (`with_immediate_tx`) so that transaction teardown precedes
/// enrollment release by ownership; a tuple spelling would not work, since tuple members drop
/// separably.
///
/// **`!Send`, deliberately.** [`WriterGate::enroll`]/[`WriterGate::enroll_service`] increment the
/// calling thread's `HELD_SCOPES` thread-local, and `Drop` decrements whichever thread's
/// counter runs the drop. Every field is `Send`, so without a marker safe code could enroll on
/// thread A and drop the scope on B: B's counter decrements from 0 (a no-op), A's stays at 1
/// forever, and every later `enroll`/`begin_sever` on A fails with a false
/// `ReentrantEnrollment`. The fix is an invariant `PhantomData<*const ()>` field, as
/// `MutexGuard` uses.
///
/// **The `compile_fail` example is a self-contained stand-in, not a reference to `WriteScope`.**
/// `WriteScope` is `pub(crate)` and a doc-test is compiled as an independent crate that cannot
/// name it. A `compile_fail` block naming a private item reports success unconditionally (the
/// failure is `E0364`, not the property under test), which would be a vacuous test. The example
/// reproduces the same field shape locally, so it discriminates: without the
/// `PhantomData<*const ()>` field it compiles and the block fails; with it, it does not compile.
///
/// ```compile_fail
/// use std::marker::PhantomData;
/// struct ThreadAffineScope {
///     _not_send: PhantomData<*const ()>,
/// }
/// let scope = ThreadAffineScope { _not_send: PhantomData };
/// std::thread::spawn(move || drop(scope)).join().unwrap();
/// ```
pub(crate) struct WriteScope {
    state: Arc<GateState>,
    observer: Arc<dyn StallObserver>,
    budget_ms: u32,
    started: Instant,
    /// Thread-affinity marker only; see the struct doc. Never read.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl WriteScope {
    /// How long this enrollment has been live.
    ///
    /// Unwired structurally: the chunked bulk writer (`bulk_load_headers`) cannot read this
    /// from inside a chunk, because a chunk's `WriteScope` is a local of
    /// `GatedConnection::with_immediate_tx` and is never handed to the enrolled closure (so
    /// nothing the caller writes can drop it early). The chunk budget is instead a
    /// caller-derived row-count parameter. Kept for a future diagnostic reading gate state from
    /// outside an enrolled closure.
    #[allow(dead_code)] // see doc above — unreachable from inside an enrolled closure.
    pub(crate) fn held_for(&self) -> Duration {
        self.started.elapsed()
    }

    /// The budget this scope is measured against. Same caveat as [`Self::held_for`].
    #[allow(dead_code)] // see held_for's doc above — unreachable from inside an enrolled closure.
    pub(crate) fn budget_ms(&self) -> u32 {
        self.budget_ms
    }
}

impl Drop for WriteScope {
    /// The guaranteed-completion path: it runs on the ordinary path and on unwind, so a panic
    /// during enrolled work cannot wedge the gate (`enrollee_panic_cleans_up_without_poisoning`).
    ///
    /// A poisoned state mutex is recovered here with `into_inner`. That does not ignore the
    /// poison: the flag must be cleared or every future writer blocks forever, while the mutex
    /// stays poisoned so the next [`WriterGate::enroll`] still fails with
    /// [`GateError::Poisoned`] (`poisoned_gate_fails_loud`).
    ///
    /// `writer_budget_exceeded` is the gate's second call into foreign observer code and is
    /// outside the state mutex: the guard lives in the explicit block below and is dropped
    /// before the `notify_all` and the observer call. Moving that call into the block would
    /// reintroduce the hazard `begin_sever`'s wait loop was fixed for.
    fn drop(&mut self) {
        HELD_SCOPES.with(|c| c.set(c.get().saturating_sub(1)));
        let elapsed = self.started.elapsed();
        {
            let mut guard = match self.state.inner.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            guard.active_writer = false;
        }
        self.state.cv.notify_all();
        if elapsed > Duration::from_millis(u64::from(self.budget_ms)) {
            self.observer.writer_budget_exceeded(elapsed, self.budget_ms);
        }
    }
}

// The sever service entry

/// One requester's place in one sever service: its role plus the shared-outcome rendezvous.
///
/// The LEADER drives the service: [`close_snapshot`](SeverEntry::close_snapshot) at its
/// witness-snapshot boundary, then [`complete`](SeverEntry::complete). Everyone else
/// [`await_outcome`](SeverEntry::await_outcome)s.
pub(crate) struct SeverEntry {
    state: Arc<GateState>,
    role: SeverRole,
    outcome: Arc<SeverOutcomeSlot>,
    /// Leader-only bookkeeping: has the service been released? Joiners are constructed with it
    /// already `true`, since they own no ticket.
    completed: bool,
}

impl SeverEntry {
    pub(crate) fn role(&self) -> SeverRole {
        self.role
    }

    #[allow(dead_code)] // witness-side role assertion; production MATCHES on `role()`.
    pub(crate) fn is_leader(&self) -> bool {
        matches!(self.role, SeverRole::Leader { .. })
    }

    #[allow(dead_code)] // witness-side ticket assertion; the gate itself owns ticket order.
    pub(crate) fn ticket(&self) -> Option<u64> {
        match self.role {
            SeverRole::Leader { ticket } => Some(ticket),
            _ => None,
        }
    }

    /// Close the join window and return the in-snapshot joiners frozen into this service as
    /// `(join_id, requester_ref)`. `SqliteIntentLog::sever` writes exactly these as
    /// `kind='in-snapshot'` `sever_attribution` rows inside the leader's own transaction,
    /// atomically with the witness row; every later arrival becomes a
    /// [`SeverRole::PostSnapshot`] that appends its own row after the commit.
    ///
    /// Named as an action, not a predicate; the predicate is [`GateSnapshot::snapshot_closed`].
    pub(crate) fn close_snapshot(&self) -> Result<Vec<(u64, String)>, GateError> {
        let SeverRole::Leader { ticket } = self.role else {
            return Err(GateError::NotTheServiceLeader { role: self.role });
        };
        let mut guard = lock_inner(&self.state)?;
        let window = guard
            .join
            .as_mut()
            .ok_or(GateError::NotTheServiceLeader { role: self.role })?;
        if window.leader_ticket != ticket {
            return Err(GateError::NotTheServiceLeader { role: self.role });
        }
        window.snapshot_closed = true;
        Ok(window.joiners.clone())
    }

    /// Complete the service: release the ticket (advancing `serving_ticket`), clear the join
    /// window so the next request mints a new ticket, unblock enrollment, and resolve the shared
    /// outcome to every requester that coalesced in. Idempotent.
    pub(crate) fn complete(&mut self, outcome: SeverOutcome) -> Result<(), GateError> {
        let SeverRole::Leader { ticket } = self.role else {
            return Err(GateError::NotTheServiceLeader { role: self.role });
        };
        if self.completed {
            return Ok(());
        }
        {
            let mut guard = lock_inner(&self.state)?;
            guard.join = None;
            guard.serving_ticket = ticket + 1;
            guard.sever_pending = guard.sever_pending.saturating_sub(1);
        }
        self.state.cv.notify_all();
        self.outcome.resolve(outcome);
        self.completed = true;
        Ok(())
    }

    /// Block until this service resolves, then return the shared outcome.
    ///
    /// A leader must [`complete`](SeverEntry::complete) before awaiting: awaiting its own
    /// unfinished service would be waiting for itself.
    pub(crate) fn await_outcome(&self) -> Result<SeverOutcome, GateError> {
        let mut slot = self.outcome.slot.lock().map_err(|_| GateError::Poisoned {
            what: "the sever outcome slot",
        })?;
        while slot.is_none() {
            slot = self
                .outcome
                .cv
                .wait(slot)
                .map_err(|_| GateError::Poisoned {
                    what: "the sever outcome slot",
                })?;
        }
        Ok(slot.clone().expect("the loop exits only on a resolved slot"))
    }
}

impl Drop for SeverEntry {
    /// A leader that unwinds (or simply returns) without completing must not strand its joiners
    /// on the condvar or leave `sever_pending` raised forever, since enrollment would be dead
    /// for the rest of the process. The service is released and resolved as
    /// [`SeverOutcome::Failed`]: silence is never an outcome.
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let SeverRole::Leader { ticket } = self.role else {
            return;
        };
        {
            let mut guard = match self.state.inner.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            guard.join = None;
            guard.serving_ticket = ticket + 1;
            guard.sever_pending = guard.sever_pending.saturating_sub(1);
        }
        self.state.cv.notify_all();
        self.outcome.resolve(SeverOutcome::Failed {
            detail: format!(
                "the sever leader on ticket {ticket} was dropped without completing its \
                 service — no epoch bump is claimed"
            ),
        });
    }
}

// Tests. Threaded where the property is a concurrency property, with no timing assertion
// anywhere: every wait is a spin on gate state (or on a thread's own published flag) with a
// generous hang guard whose only job is to turn a deadlocked build into a diagnosable panic
// instead of a hung CI job. The hang guard is not an assertion about how fast anything runs.
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Barrier;
    use std::thread;

    /// Deadlock diagnostic only — never a latency assertion. A correct build never
    /// approaches it; a wedged one reports WHICH rendezvous never happened.
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

    /// A real on-disk file (identity needs a real inode / file id), in its own
    /// directory so the alternate path SPELLINGS have a `sub` component to bounce off.
    ///
    /// the directory is owned by the ONE guard (`crate::test_temp`) —
    /// unique per call (it was nanos only), removed on `Drop`, a leak a loud failure. Held only
    /// for that `Drop` (fields drop in declaration order; the guard is last).
    struct TempStore {
        path: PathBuf,
        _dir: crate::test_temp::TempDir,
    }

    impl TempStore {
        fn new(tag: &str) -> TempStore {
            let dir = crate::test_temp::TempDir::new(&format!("aruna-gate-{tag}"));
            std::fs::create_dir_all(dir.join("sub")).expect("temp dir");
            let path = dir.join("store.sqlite");
            std::fs::write(&path, b"identity-only: the gate never opens this as a database")
                .expect("temp store file");
            // CI fleet (Linux, PR): the registry keys by (dev, ino) and never
            // evicts, and this file is deleted at Drop — ext4/tmpfs reuse the freed inode, so
            // a later test's TempStore inherited THIS test's gate state (11 accumulated
            // tickets where the fresh gate expects 2; a mutex poisoned by the deliberate
            // panicking-observer test). One leaked descriptor pins the inode for the process
            // lifetime; Drop still unlinks the path. Unix-only: Windows file identities carry
            // a sequence component and do not recycle this way.
            #[cfg(unix)]
            std::mem::forget(std::fs::File::open(&path).expect("pin the temp store's inode"));
            TempStore { path, _dir: dir }
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }

    /// The test capacity profile: a SMALL joiner cap so the overflow branch is
    /// reachable with a handful of threads.
    fn test_config() -> CapacityConfig {
        CapacityConfig {
            sever_joiner_cap: 3,
            ..crate::capacity::DEFAULT
        }
    }

    #[derive(Default)]
    struct RecordingObserver {
        budget_overruns: Mutex<Vec<(Duration, u32)>>,
        sever_stalls: Mutex<Vec<Duration>>,
    }

    impl RecordingObserver {
        fn overruns(&self) -> Vec<(Duration, u32)> {
            self.budget_overruns.lock().expect("observer").clone()
        }
        fn stalls(&self) -> Vec<Duration> {
            self.sever_stalls.lock().expect("observer").clone()
        }
    }

    impl StallObserver for RecordingObserver {
        fn writer_budget_exceeded(&self, elapsed: Duration, budget_ms: u32) {
            self.budget_overruns
                .lock()
                .expect("observer")
                .push((elapsed, budget_ms));
        }
        fn sever_stalled(&self, elapsed: Duration) {
            self.sever_stalls.lock().expect("observer").push(elapsed);
        }
    }

    fn gate(store: &TempStore) -> Arc<WriterGate> {
        Arc::new(WriterGate::for_path(store.path()).expect("identity is obtainable"))
    }

    fn gate_with(
        store: &TempStore,
        config: CapacityConfig,
        observer: Arc<RecordingObserver>,
    ) -> Arc<WriterGate> {
        Arc::new(
            WriterGate::for_path_with(store.path(), config, observer)
                .expect("identity is obtainable"),
        )
    }

    // ── enrollment ───────────────────────────────────────────────────────────

    #[test]
    fn at_most_one_enrolled_writer() {
        // design §5.3: `active_writer: 0|1` — the arbiter admits ONE writer to the
        // one SQLite file. N=8 threads × 25 rounds over a shared counter; the
        // maximum concurrent occupancy observed must be exactly 1 (0→1→0).
        let store = TempStore::new("one-writer");
        let g = gate(&store);
        let inside = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let (g, inside, max_seen, barrier) = (
                Arc::clone(&g),
                Arc::clone(&inside),
                Arc::clone(&max_seen),
                Arc::clone(&barrier),
            );
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..25 {
                    let scope = g.enroll().expect("enroll");
                    let now = inside.fetch_add(1, Ordering::SeqCst) + 1;
                    max_seen.fetch_max(now, Ordering::SeqCst);
                    thread::yield_now();
                    inside.fetch_sub(1, Ordering::SeqCst);
                    drop(scope);
                }
            }));
        }
        for h in handles {
            h.join().expect("writer thread");
        }

        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            1,
            "the gate admits at most ONE enrolled writer at a time"
        );
        assert_eq!(inside.load(Ordering::SeqCst), 0, "every scope released");
        assert!(!g.snapshot().expect("snapshot").active_writer);
    }

    #[test]
    fn a_pending_sever_blocks_new_enrollment() {
        // design §5.3: a raised ticket blocks NEW enrollment. Timing-free: the
        // sever's ticket is taken FIRST, so every writer calls `enroll()` strictly
        // after `sever_pending == 1`; each writer is then either PARKED (gate state)
        // or ENROLLED (its own counter) — we spin until all four are accounted for
        // and assert the enrolled tally is ZERO.
        let store = TempStore::new("sever-blocks");
        let g = gate(&store);
        let mut leader = g.begin_sever("authority:witness").expect("begin_sever");
        assert!(leader.is_leader(), "the first requester leads");
        assert_eq!(g.snapshot().expect("snapshot").sever_pending, 1);

        let enrolled = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let (g, enrolled, start) =
                (Arc::clone(&g), Arc::clone(&enrolled), Arc::clone(&start));
            handles.push(thread::spawn(move || {
                start.wait();
                let scope = g.enroll().expect("enroll");
                enrolled.fetch_add(1, Ordering::SeqCst);
                drop(scope);
            }));
        }
        start.wait();

        spin_until("all four writers parked or enrolled", || {
            let s = g.snapshot().expect("snapshot");
            s.enroll_waiters as usize + enrolled.load(Ordering::SeqCst) == 4
        });
        assert_eq!(
            enrolled.load(Ordering::SeqCst),
            0,
            "a pending sever must block EVERY new enrollment"
        );
        assert!(
            !g.snapshot().expect("snapshot").active_writer,
            "no writer is in flight behind a pending sever"
        );

        leader
            .complete(SeverOutcome::Served { epoch: 1 })
            .expect("complete");
        for h in handles {
            h.join().expect("writer thread");
        }
        // Anti-vacuous: the four DO enroll once the service completes.
        assert_eq!(enrolled.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn a_sleeping_writer_re_checks_the_pending_count_on_wake() {
        // design §5.3: a writer that passed the initial check and then
        // slept behind another writer MUST yield if a sever ticketed while it slept —
        // the condvar predicate is re-evaluated on every wake.
        //
        // The observation is deterministic, not timed. Once A releases, the sleeping
        // writer B must do EXACTLY ONE of two mutually exclusive, individually
        // observable things:
        //   (a) yield to the pending sever  -> `enroll_yields_to_sever` advances
        //       (that counter only moves when NO writer is active and a sever IS
        //       pending, so it cannot be confused with waiting behind A), or
        //   (b) enroll                      -> its own `b_enrolled` flag is set.
        // We spin until either happens and then assert it was (a). A build that drops
        // the `sever_pending` conjunct from the predicate takes (b), so this fails as
        // an ASSERTION, never as a hang.
        let store = TempStore::new("recheck-on-wake");
        let g = gate(&store);

        let a_enrolled = Arc::new(AtomicBool::new(false));
        let release_a = Arc::new(AtomicBool::new(false));
        let b_enrolled = Arc::new(AtomicBool::new(false));
        let release_s = Arc::new(AtomicBool::new(false));

        let ta = {
            let (g, a_enrolled, release_a) =
                (Arc::clone(&g), Arc::clone(&a_enrolled), Arc::clone(&release_a));
            thread::spawn(move || {
                let scope = g.enroll().expect("A enrolls");
                a_enrolled.store(true, Ordering::SeqCst);
                spin_until("A released", || release_a.load(Ordering::SeqCst));
                drop(scope);
            })
        };
        spin_until("A enrolled", || a_enrolled.load(Ordering::SeqCst));

        let tb = {
            let (g, b_enrolled) = (Arc::clone(&g), Arc::clone(&b_enrolled));
            thread::spawn(move || {
                let scope = g.enroll().expect("B enrolls");
                b_enrolled.store(true, Ordering::SeqCst);
                drop(scope);
            })
        };
        spin_until("B parked in enroll", || {
            g.snapshot().expect("snapshot").enroll_waiters == 1
        });

        let ts = {
            let (g, release_s) = (Arc::clone(&g), Arc::clone(&release_s));
            thread::spawn(move || {
                let mut entry = g.begin_sever("authority:witness").expect("begin_sever");
                assert!(entry.is_leader());
                spin_until("S released", || release_s.load(Ordering::SeqCst));
                entry
                    .complete(SeverOutcome::Served { epoch: 9 })
                    .expect("complete");
            })
        };
        spin_until("the sever holds a ticket", || {
            g.snapshot().expect("snapshot").sever_pending == 1
        });

        let yields_before = g.snapshot().expect("snapshot").enroll_yields_to_sever;
        release_a.store(true, Ordering::SeqCst);

        let mut observed = None;
        spin_until("B either yielded to the pending sever or enrolled", || {
            let s = g.snapshot().expect("snapshot");
            if s.enroll_yields_to_sever > yields_before || b_enrolled.load(Ordering::SeqCst) {
                observed = Some(s);
                true
            } else {
                false
            }
        });
        assert!(
            !b_enrolled.load(Ordering::SeqCst),
            "the sleeping writer re-checked sever_pending on wake and must have STAYED \
             PARKED, not enrolled"
        );
        let s = observed.expect("observed snapshot");
        assert_eq!(s.sever_pending, 1, "the service is still pending");
        assert!(
            s.enroll_yields_to_sever > yields_before,
            "the yield to the pending sever is the observed event"
        );

        release_s.store(true, Ordering::SeqCst);
        ts.join().expect("sever thread");
        tb.join().expect("B thread");
        ta.join().expect("A thread");
        // Anti-vacuous: B DOES enroll once the service completes.
        assert!(b_enrolled.load(Ordering::SeqCst));
    }

    #[test]
    fn nested_enrollment_fails_loud() {
        // / NO-REENTRANT-ENROLLMENT: a nested enroll would be a
        // self-deadlock. It must be a LOUD error, never a hang.
        let store = TempStore::new("reentrant");
        let other = TempStore::new("reentrant-other");
        let g = WriterGate::for_path(store.path()).expect("identity");
        let g2 = WriterGate::for_path(other.path()).expect("identity");

        let outer = g.enroll().expect("the first enrollment succeeds");
        assert!(
            matches!(g.enroll(), Err(GateError::ReentrantEnrollment { .. })),
            "a nested enroll on the SAME gate is a loud refusal"
        );
        assert!(
            matches!(g2.enroll(), Err(GateError::ReentrantEnrollment { .. })),
            "the held-scope check is deliberately gate-agnostic"
        );
        assert!(
            matches!(g.begin_sever("authority:witness"), Err(GateError::ReentrantEnrollment { .. })),
            "begin_sever while holding a scope is a loud refusal"
        );
        drop(outer);
        assert!(g.enroll().is_ok(), "the flag clears with the scope");
    }

    // DELETED negative control, named here rather than silently gone: a
    // test `write_scope_moved_cross_thread_corrupts_held_scopes_pre_fix` used to live here. It
    // enrolled on one thread, moved the `WriteScope` to a spawned thread, and dropped it THERE
    // — `WriteScope::drop` decrements whichever thread's `HELD_SCOPES` runs it, so the move
    // corrupted the ENROLLING thread's counter (stuck above zero forever, so every later
    // `enroll`/`begin_sever` on it fails LOUD as a false `ReentrantEnrollment`). Run against the
    // pre-fix code (every `WriteScope` field `Send`) it PASSED, proving the corruption was real.
    // It is deleted, not merely inert, because it no longer COMPILES once `WriteScope` carries
    // the `!Send` marker (`_not_send: PhantomData<*const ()>`) — `thread::spawn`'s `F: Send`
    // bound rejects the closure capturing `scope`, verified with the exact compiler error:
    //
    //   error[E0277]: `*const ()` cannot be sent between threads safely
    //      --> crates\aruna\src\writer_gate.rs:2069:23
    //       |
    //  2069 |     thread::spawn(move || drop(scope)).join().expect("mover thread");
    //       |     ------------- -------^^^^^^^^^^^^
    //       |     |             `*const ()` cannot be sent between threads safely
    //       |     required by a bound introduced by this call
    //
    // A crate that will not build cannot also carry this test, so the negative control could not
    // be kept as a runtime artifact — it is retained only as this comment. The compile-time
    // replacement is [`WriteScope`]'s own doc comment `compile_fail` example.

    #[test]
    fn enrollee_panic_cleans_up_without_poisoning() {
        // A panic during ENROLLED WORK does not hold the state mutex, so the guard's
        // Drop restores the gate and nothing is poisoned.
        let store = TempStore::new("enrollee-panic");
        let g = gate(&store);

        let handle = {
            let g = Arc::clone(&g);
            thread::spawn(move || {
                let _scope = g.enroll().expect("enroll");
                panic!("simulated panic during enrolled work");
            })
        };
        assert!(handle.join().is_err(), "the worker really panicked");

        let s = g.snapshot().expect("the gate is NOT poisoned");
        assert!(!s.active_writer, "the guard's Drop cleared the flag");
        let scope = g.enroll().expect("the next enrollment succeeds");
        assert!(g.snapshot().expect("snapshot").active_writer);
        drop(scope);
    }

    #[test]
    fn poisoned_gate_fails_loud() {
        // A panic WHILE HOLDING GateInner poisons the mutex. Every door must then
        // refuse LOUDLY — never silently ignore the poison.
        let store = TempStore::new("poisoned");
        let g = gate(&store);

        let handle = {
            let g = Arc::clone(&g);
            thread::spawn(move || g.poison_state_for_test())
        };
        assert!(handle.join().is_err(), "the seam really panicked");

        assert!(matches!(g.enroll(), Err(GateError::Poisoned { .. })));
        assert!(matches!(g.snapshot(), Err(GateError::Poisoned { .. })));
        assert!(matches!(g.begin_sever("authority:witness"), Err(GateError::Poisoned { .. })));
        assert!(matches!(g.sever_raised(), Err(GateError::Poisoned { .. })));
    }

    // ── identity ─────────────────────────────────────────────────────────────

    #[test]
    fn two_spellings_of_one_store_share_one_gate() {
        // What this test DISCRIMINATES, bounded to what it actually separates (
        // F-E): several SPELLINGS that alias one file are served by ONE `GateState`. That
        // is the positive control for the ALIAS-SHARING half of the module doc's identity
        // claim, over the four spellings exercised below (absolute, `./`, `sub/../`, and the
        // package-root-relative one) and no further — every one of them normalises to a
        // single canonical path, so nothing here separates "keyed on proven file identity"
        // from "keyed on a canonicalised path string". That the gate keys on `FileIdentity`
        // is established by the PRODUCTION bytes — `WriterGate::for_path_with` proves the
        // identity first (`FileIdentity::of_path`, :1251) and `from_identity` uses it as the
        // registry key (:1296) — not by this test.
        // The identity witness is a file that ALREADY EXISTS and is never written: the
        // manifest of the package THIS TEST PROCESS IS RUNNING FOR, reached through
        // `std::env::var("CARGO_MANIFEST_DIR")` (RUNTIME — see THE
        // TRADE below for why this moved off `env!`). That is the in-repo prior art, not an
        // invention —
        // `crates/aruna/tests/perf_floor_gates.rs:446`,
        // `crates/aruna/tests/capacity_seize_bound.rs:844`,
        // `src-tauri/tests/surface_contract.rs:56` and
        // `crates/aruna-gmail/tests/live_readside.rs:4924`, the last of which has been
        // reviewed and upheld. A created temp store cannot give all three of these
        // at once, and this test needs all three:
        //   1. a RELATIVE spelling always exists, because the witness is the ANCHOR'S OWN
        //      CHILD by construction — it is `Cargo.toml`, with no `..` walk that can fail.
        //      The superseded cwd-relative walk had no spelling at all when cwd and the
        //      target shared no root, which is how `windows-latest` (checkout on
        //      `D:\a\Photon\Photon`, `TEMP` on `C:\Users\RUNNER~1\…`) produced the
        //      2026-08-31 heartbeat failure.
        //   2. NO WRITE is required anywhere, so a read-only source checkout with
        //      `CARGO_TARGET_DIR` pointing elsewhere still runs this test.
        //   3. Nothing is created or deleted, so the (dev, ino) recycling hazard that forced
        //      `TempStore`'s `#[cfg(unix)]` `mem::forget` inode pin cannot arise here at all.
        // THE TRADE, stated because the anchor is NOT free (F-B;
        // CORRECTED here): `env!("CARGO_MANIFEST_DIR")` is a COMPILE-TIME bake — a test
        // binary built in one worktree and judged FRESH in another (the shared-`CARGO_TARGET_DIR`
        // shape, the 2026-09-11 memory feedback) carries the FIRST tree's path and witnesses THAT
        // tree's manifest, the same stale-binary class as the false green
        // (a stale test binary reading another tree's manifest). The moves
        // this from `env!` (compile-time) to `std::env::var` (RUNTIME): Cargo sets
        // `CARGO_MANIFEST_DIR` fresh for every `cargo test`/`cargo nextest` PROCESS it spawns, so
        // a binary reused unrecompiled from another tree now resolves THAT run's own manifest
        // dir, never the one baked in when it was compiled. This does NOT reopen cwd
        // defect below: Cargo derives this value from the MANIFEST IT IS BUILDING, never from
        // the test process's OWN `cwd` at run time — the two false-green reproductions found
        // (a decoy cwd at the workspace root; a run-wrapper launched from an unrelated directory)
        // both worked by changing cwd, and neither touches what Cargo puts in this env var.
        // Identity needs no read access, let alone write: `FileIdentity::of_path` opens with
        // `FILE_READ_ATTRIBUTES` on Windows ("this handle must not be able to read a byte")
        // and stats on unix.
        //
        // THE ANCHOR (F-A). The witness is the manifest of the package Cargo
        // actually BUILT — never whatever `Cargo.toml` happens to sit under the process cwd.
        // Deriving it from cwd is what made the false green possible: a harness that supplies
        // a different cwd satisfies every structural check and the test goes GREEN while
        // witnessing a DECOY. Two executed that independently — cwd at the workspace
        // root (virtual manifest plus a committed `src/`), and a nextest run-wrapper launched
        // from an unrelated directory holding a fake `Cargo.toml` and `src/`. Both PASSED.
        // The anchor REMOVES that dependency instead of adding a check that detects it: no
        // read of cwd decides what this test witnesses — a RUNTIME env-var read does not
        // change that (see the paragraph above).
        let manifest_dir = std::path::PathBuf::from(
            std::env::var("CARGO_MANIFEST_DIR")
                .expect("cargo sets CARGO_MANIFEST_DIR for every test binary it runs"),
        );
        let absolute = manifest_dir.join("Cargo.toml");
        assert!(
            absolute.is_file(),
            "the identity witness must be an existing file: {} — it is the manifest of the \
             package this test binary was COMPILED from, so its absence means the source tree \
             moved out from under a stale binary (see the compile-time-bake trade above)",
            absolute.display()
        );
        // The `sub/../` spelling's precondition, stated and ASSERTED where the anchor now
        // puts it (F-D). `src/` must EXIST for `<pkg>/src/../Cargo.toml` to
        // resolve on unix, where `..` is resolved by walking and stat'ing each component;
        // Windows strips `..` LEXICALLY in its path normalizer and never looks at `src` at
        // all. That asymmetry made the precondition unix-only and undeclared — the loud
        // assert above covered the manifest and nothing else. Anchoring makes `src/` a
        // property of the BUILT PACKAGE (a lib crate has one by definition — this very file
        // lives in it) rather than of cwd, so it is now assertable, and it is asserted.
        let src_dir = manifest_dir.join("src");
        assert!(
            src_dir.is_dir(),
            "the `sub/../` spelling needs an existing `src/` on unix, where `..` is resolved \
             by stat'ing each component rather than stripped lexically: {}",
            src_dir.display()
        );
        let dotted = manifest_dir.join(".").join("Cargo.toml");
        let dotdotted = src_dir.join("..").join("Cargo.toml");

        let a = WriterGate::for_path(&absolute).expect("absolute");
        let b = WriterGate::for_path(&dotted).expect("./ spelling");
        let c = WriterGate::for_path(&dotdotted).expect("sub/../ spelling");
        assert!(a.shares_state_with(&b), "`./` spelling shares ONE GateState");
        assert!(
            a.shares_state_with(&c),
            "`sub/../` spelling shares ONE GateState"
        );
        assert_eq!(a.identity(), c.identity());

        // The RELATIVE spelling (the plan's "relative + absolute at minimum"), derived FROM
        // the anchored absolute rather than from cwd (F-A): it is the
        // manifest's path relative to its own package root, which is `Cargo.toml` and
        // nothing else. The cwd is neither read nor MUTATED to produce it — mutating it is
        // process-global state and would race every other test in this binary.
        let relative = absolute
            .strip_prefix(manifest_dir)
            .expect("the witness is the manifest dir's own child by construction");
        assert!(relative.is_relative(), "the computed spelling is relative");

        // This is the ONE spelling the OS resolves against the process cwd, so it is where
        // Cargo's cwd contract — "a unit-test binary runs with cwd at the package root" —
        // becomes EXECUTABLE instead of assumed, and it is the acceptance witness this fold
        // was gated on: a harness that supplies a different cwd now FAILS LOUD here rather
        // than passing on a decoy. Note what is compared: FILE IDENTITY, not a path string,
        // so a legitimate junction/symlink alias of the package root stays GREEN.
        //
        // HONEST DIAGNOSTIC (F-C). Exactly two causes are distinguishable
        // here, and neither arm asserts one the bytes do not establish:
        //   - the relative spelling names NO file          -> `for_path` refuses, below;
        //   - it names a DIFFERENT file (a cwd that has a `Cargo.toml` of its own)
        //                                                  -> the identity comparison fails.
        // The cwd itself is read ONLY to REPORT it, and a failure to read it is printed as
        // that failure rather than swallowed, `.expect`ed, or blamed on either cause above.
        let cwd = std::env::current_dir();
        let d = WriterGate::for_path(relative).unwrap_or_else(|e| {
            panic!(
                "the package-root-relative spelling {} named no file, resolved against \
                 cwd {cwd:?}: {e} — cargo runs a unit-test binary with cwd at the package \
                 root, so a harness that supplied a different cwd is the cause this arm \
                 can establish; the anchored witness {} is unaffected either way",
                relative.display(),
                absolute.display()
            )
        });
        assert!(
            a.shares_state_with(&d),
            "the relative spelling {} must resolve to the ANCHORED witness {} and share ONE \
             GateState — resolved against cwd {cwd:?} it named a DIFFERENT FILE, so the \
             harness supplied a cwd that is not this package's root",
            relative.display(),
            absolute.display()
        );
    }

    #[test]
    fn unobtainable_identity_refuses_the_open() {
        // "identity unobtainable ⇒ GateError, the open REFUSES — no fallback key
        // exists" (plan). A path-string gate would silently "work" here.
        // A guarded, never-created name — absent by construction, owned all the same.
        let missing = crate::test_temp::TempFile::sqlite("aruna-gate-absent");
        assert!(!missing.exists());
        let refused = WriterGate::for_path(&missing);
        assert!(
            matches!(refused, Err(GateError::IdentityUnobtainable { .. })),
            "an unobtainable identity refuses the open, got {refused:?}"
        );
    }

    #[test]
    fn a_basic_windows_file_index_of_zero_is_a_sentinel_not_an_identity() {
        // Microsoft's own handle-comparison guidance. Syscall-seam witness
        // 1/4 — no exotic filesystem required.
        assert_eq!(
            classify_basic(ExtendedQueryError::Unsupported { code: 50 }, 0xDEAD_BEEF, 0),
            BasicIdentityVerdict::RefuseSentinel { file_index: 0 }
        );
    }

    #[test]
    fn a_basic_windows_file_index_of_all_ones_is_a_sentinel_not_an_identity() {
        // Syscall-seam witness 2/4.
        assert_eq!(
            classify_basic(
                ExtendedQueryError::Unsupported { code: 87 },
                0xDEAD_BEEF,
                u64::MAX
            ),
            BasicIdentityVerdict::RefuseSentinel {
                file_index: u64::MAX
            }
        );
    }

    #[test]
    fn an_explicitly_unsupported_extended_query_falls_back_to_the_basic_pair() {
        // Syscall-seam witness 3/4: the ONLY error class that may fall back.
        for code in [1, 50, 87] {
            assert_eq!(
                classify_basic(ExtendedQueryError::Unsupported { code }, 7, 42),
                BasicIdentityVerdict::Accept {
                    volume_serial: 7,
                    file_index: 42
                },
                "code {code} is the documented unsupported class"
            );
        }
    }

    #[test]
    fn an_ordinary_extended_query_error_refuses_rather_than_falling_back() {
        // Syscall-seam witness 4/4: ERROR_ACCESS_DENIED is NOT "unsupported".
        assert_eq!(
            classify_basic(ExtendedQueryError::Other { code: 5 }, 7, 42),
            BasicIdentityVerdict::RefuseExtendedQueryFailed { code: 5 }
        );
        assert!(!is_unsupported_extended_query(5));
        assert!(is_unsupported_extended_query(87));
    }

    #[test]
    fn extended_and_basic_windows_identities_never_compare_equal() {
        // Representation TAGGING: the two widths are different questions, so a
        // basic pair that happens to numerically match an extended one is NOT the
        // same key. Unix carries the same tagging property by having one variant.
        #[cfg(windows)]
        {
            let ext = FileIdentity::WindowsExt {
                volume_serial: 9,
                file_id: 5,
            };
            let basic = FileIdentity::WindowsBasic {
                volume_serial: 9,
                file_index: 5,
            };
            assert_ne!(ext, basic);
        }
        #[cfg(unix)]
        {
            let a = FileIdentity::Unix { dev: 9, ino: 5 };
            let b = FileIdentity::Unix { dev: 9, ino: 6 };
            assert_ne!(a, b);
            assert_eq!(a, FileIdentity::Unix { dev: 9, ino: 5 });
        }
    }

    // ── sever service: tickets + coalescing ──────────────────────────────────

    #[test]
    fn concurrent_sever_requests_coalesce_to_one_service() {
        // design :786-820. K=6 concurrent requests, joiner cap 3: exactly ONE leader;
        // the other five join the SAME service (3 in-snapshot + 2 overflow, since the
        // leader holds the snapshot open until every arrival is accounted for); every
        // entry resolves the SAME shared outcome.
        let store = TempStore::new("coalesce");
        let observer = Arc::new(RecordingObserver::default());
        let g = gate_with(&store, test_config(), observer);

        let barrier = Arc::new(Barrier::new(6));
        let leaders = Arc::new(AtomicUsize::new(0));
        let roles = Arc::new(Mutex::new(Vec::new()));
        let outcomes = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for _ in 0..6 {
            let (g, barrier, leaders, roles, outcomes) = (
                Arc::clone(&g),
                Arc::clone(&barrier),
                Arc::clone(&leaders),
                Arc::clone(&roles),
                Arc::clone(&outcomes),
            );
            handles.push(thread::spawn(move || {
                barrier.wait();
                let mut entry = g.begin_sever("authority:witness").expect("begin_sever");
                roles.lock().expect("roles").push(entry.role());
                if entry.is_leader() {
                    leaders.fetch_add(1, Ordering::SeqCst);
                    spin_until("all five joiners arrived", || {
                        let s = g.snapshot().expect("snapshot");
                        s.in_snapshot_joiners + s.overflow_joiners + s.post_snapshot_requests
                            == 5
                    });
                    let in_snapshot = entry.close_snapshot().expect("close_snapshot");
                    assert_eq!(
                        in_snapshot.len(),
                        3,
                        "the in-snapshot joiner list is bounded by the cap"
                    );
                    entry
                        .complete(SeverOutcome::Served { epoch: 77 })
                        .expect("complete");
                }
                outcomes
                    .lock()
                    .expect("outcomes")
                    .push(entry.await_outcome().expect("shared outcome"));
            }));
        }
        for h in handles {
            h.join().expect("sever requester");
        }

        assert_eq!(
            leaders.load(Ordering::SeqCst),
            1,
            "exactly ONE leader serves the coalesced requests"
        );
        let roles = roles.lock().expect("roles").clone();
        assert_eq!(roles.len(), 6);
        let leader_count = roles
            .iter()
            .filter(|r| matches!(r, SeverRole::Leader { .. }))
            .count();
        let in_snapshot = roles
            .iter()
            .filter(|r| matches!(r, SeverRole::InSnapshotJoiner { .. }))
            .count();
        let overflow = roles
            .iter()
            .filter(|r| matches!(r, SeverRole::OverflowJoiner))
            .count();
        let post = roles
            .iter()
            .filter(|r| matches!(r, SeverRole::PostSnapshot))
            .count();
        assert_eq!((leader_count, in_snapshot, overflow, post), (1, 3, 2, 0));

        let outcomes = outcomes.lock().expect("outcomes").clone();
        assert_eq!(outcomes.len(), 6);
        assert!(
            outcomes
                .iter()
                .all(|o| *o == SeverOutcome::Served { epoch: 77 }),
            "every requester resolves the ONE shared outcome, got {outcomes:?}"
        );
        // ONE service ⇒ ONE ticket consumed.
        let s = g.snapshot().expect("snapshot");
        assert_eq!(s.next_ticket, 2);
        assert_eq!(s.serving_ticket, 2);
        assert_eq!(s.sever_pending, 0);
        assert!(!s.service_open);
    }

    #[test]
    fn a_new_service_begins_only_after_the_prior_completes() {
        // design :786-820 (the corrected ticket witness): a request arriving while a
        // service is pending/serving NEVER mints a ticket — in-snapshot before the
        // snapshot closes, post-snapshot after. A new ticket exists ONLY after the
        // prior service COMPLETES, and it is exactly leader.ticket + 1.
        let store = TempStore::new("one-service");
        let observer = Arc::new(RecordingObserver::default());
        let g = gate_with(&store, test_config(), observer);

        let mut leader = g.begin_sever("authority:witness").expect("begin_sever");
        let leader_ticket = match leader.role() {
            SeverRole::Leader { ticket } => ticket,
            other => panic!("the first requester must lead, got {other:?}"),
        };
        assert_eq!(g.snapshot().expect("snapshot").next_ticket, leader_ticket + 1);

        let joiner = g.begin_sever("authority:witness").expect("begin_sever");
        assert!(matches!(joiner.role(), SeverRole::InSnapshotJoiner { .. }));
        assert_eq!(
            g.snapshot().expect("snapshot").next_ticket,
            leader_ticket + 1,
            "an in-snapshot joiner mints NO ticket"
        );

        let in_snapshot = leader.close_snapshot().expect("close_snapshot");
        assert_eq!(in_snapshot.len(), 1);
        assert!(g.snapshot().expect("snapshot").snapshot_closed);

        let post = g.begin_sever("authority:witness").expect("begin_sever");
        assert_eq!(post.role(), SeverRole::PostSnapshot);
        assert_eq!(
            g.snapshot().expect("snapshot").next_ticket,
            leader_ticket + 1,
            "a post-snapshot requester mints NO ticket and gets NO second bump"
        );

        leader
            .complete(SeverOutcome::Served { epoch: 5 })
            .expect("complete");
        assert_eq!(
            joiner.await_outcome().expect("outcome"),
            SeverOutcome::Served { epoch: 5 }
        );
        assert_eq!(
            post.await_outcome().expect("outcome"),
            SeverOutcome::Served { epoch: 5 }
        );
        drop(joiner);
        drop(post);

        let mut next = g.begin_sever("authority:witness").expect("begin_sever");
        assert_eq!(
            next.role(),
            SeverRole::Leader {
                ticket: leader_ticket + 1
            },
            "the NEXT service takes the next ticket, in order"
        );
        next.complete(SeverOutcome::Served { epoch: 6 })
            .expect("complete");
        let s = g.snapshot().expect("snapshot");
        assert_eq!(s.sever_pending, 0);
        assert_eq!(s.serving_ticket, leader_ticket + 2);
    }

    #[test]
    fn a_leader_dropped_without_completing_resolves_the_shared_outcome() {
        // Liveness: a leader that unwinds must not leave joiners parked forever, and
        // must not wedge the gate against new enrollment.
        let store = TempStore::new("leader-drop");
        let observer = Arc::new(RecordingObserver::default());
        let g = gate_with(&store, test_config(), observer);

        let joiner = {
            let leader = g.begin_sever("authority:witness").expect("begin_sever");
            assert!(leader.is_leader());
            let joiner = g.begin_sever("authority:witness").expect("begin_sever");
            drop(leader);
            joiner
        };
        let outcome = joiner.await_outcome().expect("outcome");
        assert!(
            matches!(outcome, SeverOutcome::Failed { .. }),
            "an abandoned service resolves as Failed, never as silence: {outcome:?}"
        );
        let s = g.snapshot().expect("snapshot");
        assert_eq!(s.sever_pending, 0, "the ticket is released");
        assert!(!s.service_open);
        drop(joiner);
        drop(g.enroll().expect("enrollment is live again"));
    }

    // ── the stall surfaces ───────────────────────────────────────────────────

    #[test]
    fn a_writer_over_the_chunk_budget_is_surfaced_as_undetermined() {
        // The checkpoint-attribution ORACLE IS DELETED. The stall surface reports
        // the overrun and says the checkpoint contribution is UNDETERMINED — fail-loud
        // honesty, no causal claim.
        let store = TempStore::new("budget");
        let observer = Arc::new(RecordingObserver::default());
        let config = CapacityConfig {
            // 0 ms is OUTSIDE `CapacityConfig::validate`'s domain on purpose: the
            // injectable constructor is the test seam, and a zero budget makes the
            // overrun DETERMINISTIC (no timing assertion, no flake).
            writer_chunk_budget_ms: 0,
            ..test_config()
        };
        let g = gate_with(&store, config, Arc::clone(&observer));

        {
            let _scope = g.enroll().expect("enroll");
            thread::sleep(Duration::from_millis(2));
        }
        let overruns = observer.overruns();
        assert_eq!(overruns.len(), 1, "the overrun is surfaced exactly once");
        assert_eq!(overruns[0].1, 0);

        let message = writer_budget_overrun_message(overruns[0].0, overruns[0].1);
        assert!(
            message.contains("checkpoint contribution UNDETERMINED"),
            "the stall surface must refuse a causal checkpoint claim: {message}"
        );
        assert!(message.contains("chunk budget"), "{message}");
    }

    #[test]
    fn a_stalled_sever_surfaces_the_watchdog_and_keeps_waiting() {
        // design: the watchdog SURFACES, it never preempts.
        let store = TempStore::new("watchdog");
        let observer = Arc::new(RecordingObserver::default());
        let config = CapacityConfig {
            // 0 ms: fire on the FIRST wait slice — deterministic, no timing assertion.
            sever_watchdog_ms: 0,
            ..test_config()
        };
        let g = gate_with(&store, config, Arc::clone(&observer));

        let a_enrolled = Arc::new(AtomicBool::new(false));
        let release_a = Arc::new(AtomicBool::new(false));
        let ta = {
            let (g, a_enrolled, release_a) =
                (Arc::clone(&g), Arc::clone(&a_enrolled), Arc::clone(&release_a));
            thread::spawn(move || {
                let scope = g.enroll().expect("enroll");
                a_enrolled.store(true, Ordering::SeqCst);
                spin_until("A released", || release_a.load(Ordering::SeqCst));
                drop(scope);
            })
        };
        spin_until("A enrolled", || a_enrolled.load(Ordering::SeqCst));

        let ts = {
            let g = Arc::clone(&g);
            thread::spawn(move || {
                let mut entry = g.begin_sever("authority:witness").expect("begin_sever");
                entry
                    .complete(SeverOutcome::Served { epoch: 3 })
                    .expect("complete");
            })
        };
        spin_until("the watchdog surfaced the stall", || {
            !observer.stalls().is_empty()
        });
        // It KEEPS WAITING: the writer is still in flight and the sever has not run.
        assert!(g.snapshot().expect("snapshot").active_writer);

        release_a.store(true, Ordering::SeqCst);
        ts.join().expect("sever thread");
        ta.join().expect("writer thread");
        assert!(!observer.stalls().is_empty());
    }

    /// An observer that calls BACK INTO the gate — the smallest possible stand-in for "the
    /// observer is foreign code and the gate cannot know what it does".
    struct ReentrantObserver {
        path: PathBuf,
        returned: AtomicBool,
    }

    impl StallObserver for ReentrantObserver {
        fn writer_budget_exceeded(&self, _elapsed: Duration, _budget_ms: u32) {}
        fn sever_stalled(&self, _elapsed: Duration) {
            // Any gate door that takes the state mutex will do; `snapshot` is the cheapest.
            // Same FILE IDENTITY ⇒ the SAME `GateState` ⇒ the same mutex, on this same thread.
            let g = WriterGate::for_path(&self.path).expect("identity is obtainable");
            let _ = g.snapshot().expect("snapshot");
            self.returned.store(true, Ordering::SeqCst);
        }
    }

    /// Regression test: **the stall observer is invoked WITHOUT the gate's state
    /// mutex.**
    ///
    /// Pre-fix, `begin_sever`'s wait loop called `sever_stalled` while holding [`GateInner`], so
    /// an observer that touched any gate door re-entered a non-reentrant `std::sync::Mutex` on
    /// its own thread and WEDGED — permanently, with no error and no timeout. This witness is
    /// that observer. Post-fix the guard is released across the call, the observer's own gate
    /// read returns, and the loop re-acquires and re-checks its predicate.
    ///
    /// ⚠ Pre-fix this test does not fail with a nice message on the sever thread — that thread
    /// is DEADLOCKED and never comes back. It fails on the main thread's HANG GUARD below, and
    /// the wedged thread is deliberately left leaked (there is nothing to join; that IS the
    /// defect). The `join`s only run on the passing path.
    #[test]
    fn a_reentrant_stall_observer_does_not_wedge_the_gate() {
        let store = TempStore::new("reentrant-observer");
        let observer = Arc::new(ReentrantObserver {
            path: store.path().to_path_buf(),
            returned: AtomicBool::new(false),
        });
        let config = CapacityConfig {
            // 0 ms: fire on the FIRST wait slice — deterministic, no timing assertion.
            sever_watchdog_ms: 0,
            ..test_config()
        };
        let as_trait: Arc<dyn StallObserver> = observer.clone();
        let g = Arc::new(
            WriterGate::for_path_with(store.path(), config, as_trait)
                .expect("identity is obtainable"),
        );

        // A writer holds the slot, so the sever below MUST wait — which is the only way to
        // reach the watchdog call at all.
        let a_enrolled = Arc::new(AtomicBool::new(false));
        let release_a = Arc::new(AtomicBool::new(false));
        let ta = {
            let (g, a_enrolled, release_a) =
                (Arc::clone(&g), Arc::clone(&a_enrolled), Arc::clone(&release_a));
            thread::spawn(move || {
                let scope = g.enroll().expect("enroll");
                a_enrolled.store(true, Ordering::SeqCst);
                spin_until("A released", || release_a.load(Ordering::SeqCst));
                drop(scope);
            })
        };
        spin_until("A enrolled", || a_enrolled.load(Ordering::SeqCst));

        let ts = {
            let g = Arc::clone(&g);
            thread::spawn(move || {
                let mut entry = g.begin_sever("authority:reentrant").expect("begin_sever");
                entry
                    .complete(SeverOutcome::Served { epoch: 7 })
                    .expect("complete");
            })
        };

        // THE DISCRIMINATOR: the observer's own gate call RETURNED. Pre-fix it never does.
        spin_until("the reentrant observer's gate call returned", || {
            observer.returned.load(Ordering::SeqCst)
        });
        // And the gate is still live for everyone else — the observer did not leave the mutex
        // held, and the sever is still waiting rather than having been let through.
        assert!(
            g.snapshot().expect("snapshot").active_writer,
            "the writer still holds the slot: the watchdog SURFACES, it never preempts"
        );

        release_a.store(true, Ordering::SeqCst);
        ts.join().expect("sever thread");
        ta.join().expect("writer thread");
    }

    /// An observer that PANICS at the watchdog crossing — the OTHER half of "the observer is
    /// foreign code and the gate cannot know what it does". The reentrant one above proved the
    /// gate must not hold its mutex across the call; this one proves the gate must not hold an
    /// UNOWNED TICKET across it either.
    struct PanickingObserver;

    impl StallObserver for PanickingObserver {
        fn writer_budget_exceeded(&self, _elapsed: Duration, _budget_ms: u32) {}
        fn sever_stalled(&self, _elapsed: Duration) {
            panic!("test seam: a stall observer that panics at the watchdog crossing");
        }
    }

    /// Regression test: **a panic in the pre-guard window must UNWIND THE
    /// SEVER TICKET, not wedge the gate.**
    ///
    /// `begin_sever` raised `sever_pending`, minted the join window and took a ticket, and only
    /// constructed the [`SeverEntry`] that OWNS their cleanup after the turn-wait loop returned.
    /// Every exit from that loop that is not a normal `break` therefore leaked the ticket: the
    /// injected observer's panic (the case here) and, silently, the two `?` early-returns inside
    /// the loop. `sever_pending > 0` is half the enrollment predicate, so the leak is permanent —
    /// EVERY later writer on this store file parks forever, with no error and no timeout.
    ///
    /// Post-fix the entry is constructed BEFORE any observer can be called, so unwinding through
    /// the loop runs its `Drop`: the ticket advances, the window clears, `sever_pending` returns
    /// to 0, and the shared outcome resolves `Failed` rather than staying silent. The panic
    /// itself still PROPAGATES to the caller — the gate recovers its own invariants and reports
    /// the foreign code's failure; it never swallows it.
    #[test]
    fn a_panicking_stall_observer_unwinds_the_sever_ticket() {
        let store = TempStore::new("panicking-observer");
        let config = CapacityConfig {
            // 0 ms: fire on the FIRST wait slice — deterministic, no timing assertion.
            sever_watchdog_ms: 0,
            ..test_config()
        };
        let as_trait: Arc<dyn StallObserver> = Arc::new(PanickingObserver);
        let g = Arc::new(
            WriterGate::for_path_with(store.path(), config, as_trait)
                .expect("identity is obtainable"),
        );

        // A writer holds the slot, so the sever below MUST wait — the only way to reach the
        // watchdog call at all.
        let a_enrolled = Arc::new(AtomicBool::new(false));
        let release_a = Arc::new(AtomicBool::new(false));
        let ta = {
            let (g, a_enrolled, release_a) =
                (Arc::clone(&g), Arc::clone(&a_enrolled), Arc::clone(&release_a));
            thread::spawn(move || {
                let scope = g.enroll().expect("enroll");
                a_enrolled.store(true, Ordering::SeqCst);
                spin_until("A released", || release_a.load(Ordering::SeqCst));
                drop(scope);
            })
        };
        spin_until("A enrolled", || a_enrolled.load(Ordering::SeqCst));

        let ts = {
            let g = Arc::clone(&g);
            thread::spawn(move || {
                // The panic is EXPECTED and must reach the caller — the gate recovers its
                // invariants, it does not swallow foreign code's failure.
                let _entry = g.begin_sever("authority:panicking");
            })
        };
        let joined = ts.join();
        assert!(
            joined.is_err(),
            "the observer's panic must PROPAGATE out of `begin_sever` — a swallowed panic \
             would hand back a leader entry for a service nobody serviced"
        );

        // THE DISCRIMINATOR, timing-free and read straight off gate state. Pre-fix:
        // `sever_pending == 1` and `service_open == true`, forever.
        let s = g.snapshot().expect("snapshot");
        assert_eq!(
            s.sever_pending, 0,
            "the unwound ticket must be RELEASED — a leaked one is half the enrollment \
             predicate and wedges every later writer on this store file"
        );
        assert!(!s.service_open, "the abandoned join window must be cleared");
        assert_eq!(
            s.serving_ticket, s.next_ticket,
            "the service advanced past the abandoned ticket, so the NEXT request leads"
        );

        // …and the gate really is live again: the held writer releases, and a fresh
        // enrollment goes through instead of parking forever behind the leaked ticket.
        release_a.store(true, Ordering::SeqCst);
        ta.join().expect("writer thread");
        drop(g.enroll().expect("enrollment is live again"));

        // A NEW sever service can still be led, too — the leaked-ticket wedge would have made
        // this one wait behind a service that will never complete.
        let mut next = g.begin_sever("authority:after-the-panic").expect("begin_sever");
        assert!(next.is_leader(), "the next requester LEADS a fresh service");
        next.complete(SeverOutcome::Served { epoch: 11 })
            .expect("complete");
        assert_eq!(g.snapshot().expect("snapshot").sever_pending, 0);
    }

    #[test]
    fn sever_raised_reports_the_pending_count_for_the_belt() {
        // belt reads this INSIDE its transaction; only owns the reading.
        let store = TempStore::new("sever-raised");
        let g = gate(&store);
        assert!(!g.sever_raised().expect("sever_raised"));
        let mut leader = g.begin_sever("authority:witness").expect("begin_sever");
        assert!(g.sever_raised().expect("sever_raised"));
        leader
            .complete(SeverOutcome::Served { epoch: 1 })
            .expect("complete");
        assert!(!g.sever_raised().expect("sever_raised"));
    }
}
