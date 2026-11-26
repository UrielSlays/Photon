//! The read-side optimistic projection store. Durable `(account, message_ref) ->
//! (email_id, placement)` rows in the same SQLite DB as the intent log. Implements the
//! [`MessageRefResolver`] seam.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::jmap::MessageRefResolver;
use crate::read_model::{Placement, ProviderMessageId};
use crate::LogError;

/// SQLite-backed read-side projection. Opens the same DB file as the intent log; the
/// `message_placement` table is created by [`crate::SqliteIntentLog::open`] (one schema owner).
pub struct SqliteMessageStore {
    /// The connection and the store file's writer gate, minted together. Reads go through
    /// `Deref`; this store's writes are single autocommit statements, each enrolled around
    /// itself via `GatedConnection::with_enrolled_write`.
    conn: crate::store_open::GatedConnection,
}

/// Outcome of a correction: `changed` is `true` iff a stored row actually differed from
/// provider truth and was overwritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corrected {
    pub changed: bool,
}

impl SqliteMessageStore {
    /// Open the store over the intent-log DB at `path`. Does not create the table (the intent log
    /// owns the schema), so open the intent log first.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        // The shared open path: ownership and version are verified through the connection
        // before the persistent WAL flip, and the durability profile and foreign-key setting
        // are read back or refused. A projection never mutates an unverified store and never
        // creates one on an absent path (bootstrap belongs to the intent log).
        let conn = crate::store_open::open_verified_connection(path.as_ref())?;
        Ok(Self { conn })
    }

    /// Test-only view of this store's connection, so the open-time checks can be asserted on it.
    /// Not API surface.
    #[cfg(test)]
    pub(crate) fn conn_for_test(&self) -> &Connection {
        &self.conn
    }

    /// Write (or overwrite) the optimistic placement belief for a message. The id is the neutral
    /// provider-opaque [`ProviderMessageId`]; the store never inspects it and round-trips it as
    /// text.
    pub fn record_optimistic_placement(
        &mut self,
        account: &str,
        message_ref: &str,
        email_id: &ProviderMessageId,
        placement: Placement,
    ) -> Result<(), LogError> {
        // The upsert text lives in [`upsert_placement_row`]; the read coordinator runs the same
        // write inside its own transaction.
        //
        // Enrolled: a single autocommit INSERT is still a write to the store file, so
        // `with_enrolled_write` brackets it with exactly one `WriteScope`.
        self.conn
            .with_enrolled_write(|conn| upsert_placement_row(conn, account, message_ref, email_id, placement))
    }

    /// Read the current optimistic placement belief, if a row exists.
    pub fn placement(
        &self,
        account: &str,
        message_ref: &str,
    ) -> Result<Option<Placement>, LogError> {
        // Map only "no row" to None; propagate every other failure (locked/corrupt DB, missing
        // table) as a `LogError` rather than masking it as "no divergence".
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT placement FROM message_placement WHERE account = ?1 AND message_ref = ?2;",
                rusqlite::params![account, message_ref],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("message_store read: {e}")))?;
        raw.map(|s| Placement::from_token(&s)).transpose()
    }

    /// Overwrite the stored placement with provider truth only if it diverges. Returns
    /// `changed: true` only when an actual divergence was corrected. The provider wins; there
    /// is no client-side conflict resolution. A missing row is nothing to correct
    /// (`changed: false`), since no optimistic belief exists that could be wrong.
    pub fn correct_placement(
        &mut self,
        account: &str,
        message_ref: &str,
        provider: Placement,
    ) -> Result<Corrected, LogError> {
        match self.placement(account, message_ref)? {
            Some(current) if current == provider => Ok(Corrected { changed: false }),
            Some(_) => {
                // Enrolled, as in `record_optimistic_placement`: a single autocommit UPDATE is
                // still a write to the store file.
                self.conn.with_enrolled_write(|conn| {
                    conn.execute(
                        "UPDATE message_placement SET placement = ?3
                             WHERE account = ?1 AND message_ref = ?2;",
                        rusqlite::params![account, message_ref, provider.as_str()],
                    )
                    .map_err(|e| LogError(format!("message_store correct: {e}")))
                })?;
                Ok(Corrected { changed: true })
            }
            None => Ok(Corrected { changed: false }),
        }
    }
}

impl SqliteMessageStore {
    /// Fallible email-id lookup for divergence correction. Unlike the [`MessageRefResolver`]
    /// trait (which must return `Option` for the connector seam), this propagates a real store
    /// error (locked/corrupt DB, missing table) instead of masking it as "no row", so
    /// reconciliation fails explicitly and never converges on a swallowed error.
    pub fn resolve_email_id(
        &self,
        account: &str,
        message_ref: &str,
    ) -> Result<Option<ProviderMessageId>, LogError> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT email_id FROM message_placement WHERE account = ?1 AND message_ref = ?2;",
                rusqlite::params![account, message_ref],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("message_store resolve: {e}")))?;
        Ok(raw.map(ProviderMessageId))
    }

    /// The inverse lookup: `(account, email_id) -> message_ref`. Ingest asks this before
    /// minting a ref, so the same provider message arriving on a later page or refresh reuses
    /// the ref it already has instead of minting a second one. The durable half of that rule
    /// is `idx_message_placement_identity`, the `UNIQUE (account, email_id)` index this query
    /// also uses.
    ///
    /// Fallible the same way [`Self::resolve_email_id`] is: only "no row" maps to `None`; a
    /// locked or corrupt store, or a missing table, propagates. A swallowed read error here
    /// would read as "no mapping" and mint a duplicate ref, which the index forbids.
    pub fn resolve_ref_by_email_id(
        &self,
        account: &str,
        id: &ProviderMessageId,
    ) -> Result<Option<String>, LogError> {
        self.conn
            .query_row(
                RESOLVE_REF_BY_EMAIL_ID_SQL,
                rusqlite::params![account, id.0],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LogError(format!("message_store identity resolve: {e}")))
    }
}

/// The inverse-identity lookup as a single text, shared by
/// [`SqliteMessageStore::resolve_ref_by_email_id`] and the read coordinator's in-transaction
/// lookups. SQLite matches an index against the query it is given, and both callers must use
/// `idx_message_placement_identity`.
pub(crate) const RESOLVE_REF_BY_EMAIL_ID_SQL: &str =
    "SELECT message_ref FROM message_placement WHERE account = ?1 AND email_id = ?2;";

/// The placement upsert as a single text: the write behind
/// [`SqliteMessageStore::record_optimistic_placement`] and the read coordinator's atomic
/// ingest. Takes `&Connection` because `rusqlite::Transaction` derefs to it: the coordinator
/// pairs this write with the header write inside one transaction, and a transaction cannot
/// span two connections.
pub(crate) fn upsert_placement_row(
    conn: &Connection,
    account: &str,
    message_ref: &str,
    email_id: &ProviderMessageId,
    placement: Placement,
) -> Result<(), LogError> {
    conn.execute(
        "INSERT INTO message_placement (account, message_ref, email_id, placement)
             VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(account, message_ref)
             DO UPDATE SET email_id = excluded.email_id, placement = excluded.placement;",
        rusqlite::params![account, message_ref, email_id.0, placement.as_str()],
    )
    .map_err(|e| LogError(format!("message_store write: {e}")))?;
    Ok(())
}

impl MessageRefResolver for SqliteMessageStore {
    fn resolve_message(
        &self,
        photon_account: &str,
        message_ref: &str,
    ) -> Result<Option<ProviderMessageId>, LogError> {
        // Delegates to the fallible store lookup: a store read error propagates (the connector
        // maps it to transient) instead of masquerading as an absent mapping.
        self.resolve_email_id(photon_account, message_ref)
    }
}

#[cfg(test)]
mod tests {
    use crate::jmap::MessageRefResolver;
    use crate::message_store::{Corrected, SqliteMessageStore};
    use crate::read_model::{Placement, ProviderMessageId};

    /// minted by the ONE guard (`crate::test_temp`) — unique per call,
    /// the store family removed on `Drop`, a leak a loud failure.
    fn unique_temp_db_path(tag: &str) -> crate::test_temp::TempFile {
        crate::test_temp::TempFile::sqlite(&format!("aruna-store-{tag}"))
    }

    /// Open an intent log (which creates the `message_placement` table) then a store over the same
    /// file. Returns the path's guard FIRST, then the store: a tuple pattern's bindings drop right
    /// to left, so `let (path, s) = store(..)` closes the store before the guard deletes.
    fn store(tag: &str) -> (crate::test_temp::TempFile, SqliteMessageStore) {
        let path = unique_temp_db_path(tag);
        let _log = crate::SqliteIntentLog::open(&path).unwrap();
        let s = SqliteMessageStore::open(&path).unwrap();
        (path, s)
    }

    /// RED: `record_optimistic_placement` is a projection WRITE to the store
    /// file — it must wait behind whatever holds the file's writer-gate scope, exactly like
    /// `SqliteIntentLog`'s enrolled transactions do (`enrollment_spans_the_transaction_not_the_
    /// statement`, `lib.rs`). TIMING-FREE, same shape as that witness: thread A holds a
    /// `WriteScope` (barrier-paused), thread B calls the store write, and the assertion is the
    /// gate's own `enroll_waiters` counter — never a clock. Pre-fix (this store executes
    /// directly on `&Connection`, no `enroll()` anywhere): the write races straight through
    /// while A holds the scope, `enroll_waiters` never reaches 1, and the HANG GUARD fires.
    /// Post-fix (`GatedConnection::with_enrolled_write`): the write parks behind A and only
    /// proceeds once A releases.
    #[test]
    fn a_message_store_write_waits_behind_a_pending_sever() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (path, mut s) = store("write-waits-behind-scope");
        let observer = Arc::new(
            crate::writer_gate::WriterGate::for_path(&path).expect("identity is obtainable"),
        );
        assert!(
            !observer.snapshot().expect("snapshot").active_writer,
            "no writer is enrolled before the held scope starts"
        );

        let paused = Arc::new(Barrier::new(2));
        let release = Arc::new(AtomicBool::new(false));

        let holder = {
            let observer = Arc::clone(&observer);
            let (paused, release) = (Arc::clone(&paused), Arc::clone(&release));
            thread::spawn(move || {
                let scope = observer.enroll().expect("the holder enrolls first");
                paused.wait(); // ── the scope is HELD from here ──
                while !release.load(Ordering::SeqCst) {
                    thread::yield_now();
                }
                drop(scope);
            })
        };
        paused.wait();

        let writer = thread::spawn(move || {
            s.record_optimistic_placement(
                "acct",
                "m1",
                &ProviderMessageId("E1".into()),
                Placement::Inbox,
            )
            .expect("the write eventually succeeds once the scope releases");
            s
        });

        let started = std::time::Instant::now();
        while observer.snapshot().expect("snapshot").enroll_waiters != 1 {
            assert!(
                started.elapsed() <= std::time::Duration::from_secs(15),
                "HANG GUARD: `record_optimistic_placement` never parked behind the held scope \
                 — it ran UNGATED while the store's writer gate was held"
            );
            thread::yield_now();
        }

        release.store(true, Ordering::SeqCst);
        holder.join().expect("holder thread");
        let s = writer.join().expect("writer thread");
        assert_eq!(s.placement("acct", "m1").unwrap(), Some(Placement::Inbox));
        drop(s);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn records_and_reads_optimistic_placement() {
        let (path, mut s) = store("record-read");
        s.record_optimistic_placement("acct", "m1", &ProviderMessageId("E1".into()), Placement::Archive)
            .unwrap();
        assert_eq!(s.placement("acct", "m1").unwrap(), Some(Placement::Archive));
        assert_eq!(
            s.resolve_message("acct", "m1").unwrap(),
            Some(ProviderMessageId("E1".into()))
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_email_id_returns_id_for_present_and_none_for_absent() {
        let (path, mut s) = store("resolve-email-id");
        s.record_optimistic_placement("acct", "m1", &ProviderMessageId("E1".into()), Placement::Inbox)
            .unwrap();
        assert_eq!(s.resolve_email_id("acct", "m1").unwrap(), Some(ProviderMessageId("E1".into())));
        assert_eq!(s.resolve_email_id("acct", "absent").unwrap(), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_ref_by_email_id_is_the_inverse_of_the_tables_own_key() {
        let (path, mut s) = store("resolve-ref-by-email-id");
        s.record_optimistic_placement("acct", "m1", &ProviderMessageId("E1".into()), Placement::Inbox)
            .unwrap();
        assert_eq!(
            s.resolve_ref_by_email_id("acct", &ProviderMessageId("E1".into())).unwrap(),
            Some("m1".to_string())
        );
        // Absent id -> None (not an error).
        assert_eq!(
            s.resolve_ref_by_email_id("acct", &ProviderMessageId("E-absent".into())).unwrap(),
            None
        );
        // The mapping is ACCOUNT-scoped: the same provider id under another account is a miss.
        assert_eq!(
            s.resolve_ref_by_email_id("other", &ProviderMessageId("E1".into())).unwrap(),
            None
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn correct_placement_overwrites_a_diverged_row_and_witnesses_the_change() {
        let (path, mut s) = store("correct-diverged");
        s.record_optimistic_placement("acct", "m1", &ProviderMessageId("E1".into()), Placement::Archive)
            .unwrap();
        // Provider truth says Inbox -> divergence -> must flip + witness true.
        let result = s.correct_placement("acct", "m1", Placement::Inbox).unwrap();
        assert_eq!(result, Corrected { changed: true });
        assert_eq!(s.placement("acct", "m1").unwrap(), Some(Placement::Inbox));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn correct_placement_is_a_noop_when_already_converged() {
        let (path, mut s) = store("correct-converged");
        s.record_optimistic_placement("acct", "m1", &ProviderMessageId("E1".into()), Placement::Archive)
            .unwrap();
        let result = s.correct_placement("acct", "m1", Placement::Archive).unwrap();
        assert_eq!(result, Corrected { changed: false });
        assert_eq!(s.placement("acct", "m1").unwrap(), Some(Placement::Archive));
        std::fs::remove_file(&path).ok();
    }
}
