//! The single mint for every path a test creates under the OS temp directory (in this crate's
//! unit and `tests/` binaries, `aruna-jmap`, `aruna-gmail`, and the `src-tauri` shell tests).
//! Compiled only under `cfg(test)` or the `test-support` feature, which only dev-dependencies
//! enable, so no product build carries it.
//!
//! A test helper that creates a temp file or directory returns a guard that deletes it on
//! `Drop`, SQLite siblings included, under a name unique per call. Before these guards existed,
//! tests leaked tens of thousands of entries over a day and a half of development.
//!
//! **The two guard kinds.** [`TempFile`] owns one path and the store family around it: SQLite's
//! `-wal`, `-shm` and `-journal` and the engine's `.photon-init.lock`
//! ([`STORE_SIBLING_SUFFIXES`]). [`TempDir`] owns a directory tree. The `tempfile` crate is not
//! used: it does not know a store is a family of names, and it is not in the lockfile.
//!
//! **The rules, and the leak each one closes:**
//! 1. **Unique names:** `{stem}-{pid}-{nanos}-{seq}{ext}`. A pid-only name re-opens a previous
//!    run's leftover under a reused pid; a nanos-only name collides under load. The name stays
//!    within [`MAX_FILE_NAME_BYTES`], the engine's bound on the stem its `.photon-init.lock`
//!    sibling is named from, so the sibling this guard removes is the one the engine creates.
//! 2. **The guard drops last.** Windows refuses to delete a file a SQLite connection holds.
//!    Locals drop in reverse declaration order (tuple bindings too), so a test binds the guard
//!    before anything that opens its path, and a helper returning a guard alongside a store
//!    returns the guard first in its tuple.
//! 3. **A guard is never handed away.** A guard does not implement `AsRef<Path>`; only `&guard`
//!    does. Otherwise `SqliteIntentLog::open(guard)` would drop the guard on return while the
//!    connection it just opened lived on, the delete would fail, and the store would leak.
//!    `open(&guard)` is the only spelling that compiles.
//! 4. **No silent failure.** `Drop` never follows a link, keeps retrying a delete that another
//!    process is holding up (antivirus scans and the search indexer open fresh files) for up to
//!    [`REMOVAL_DEADLINE`], and panics naming the path and error if anything it owns is still
//!    there, unless the thread is already unwinding (a second panic would abort the test binary),
//!    where it prints the leak instead.
//! 5. **The census.** `crates/aruna/tests/temp_census.rs` fails, naming file and line, on every
//!    temp-directory spelling in the tree's Rust sources outside this file.
//!
//! Both guards `Deref` to `&Path`. An owned copy is `path.to_path_buf()`, and holding that copy
//! never extends the guard's life.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The names beside a store file that belong to it: SQLite's write-ahead log, its shared-memory
/// index and its rollback journal, and the engine's bootstrap lock (`store_open::bootstrap_fresh`
/// names it `{file name}.photon-init.lock`).
pub const STORE_SIBLING_SUFFIXES: [&str; 4] = ["-wal", "-shm", "-journal", ".photon-init.lock"];

/// The longest file name a guard mints. The engine names the bootstrap lock from the store's file
/// name cut to 120 bytes (`store_open::bounded_aux_stem`); a name within that bound makes
/// `{name}.photon-init.lock` exactly the lock the engine creates. The stem is cut to fit; the
/// unique `-{pid}-{nanos}-{seq}` tail and the extension are never cut.
pub const MAX_FILE_NAME_BYTES: usize = 120;

/// How long `Drop` keeps retrying a delete before it calls the path leaked. SQLite's own Windows
/// delete gives up after ~1.4 s (`winDelete`: 10 retries, 25 ms × n); this is the margin past it.
/// A test that expects the leak shortens it per guard (`with_removal_deadline`), so it never
/// idles a test slot for the full default.
pub const REMOVAL_DEADLINE: Duration = Duration::from_secs(5);

/// `{temp}/{stem}-{pid}-{nanos}-{seq}{ext}`, the stem cut (on a char boundary) so the whole file
/// name fits [`MAX_FILE_NAME_BYTES`].
fn unique_path(stem: &str, ext: &str) -> PathBuf {
    static CALLS: AtomicU64 = AtomicU64::new(0);
    let seq = CALLS.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_nanos();
    let tail = format!("-{}-{nanos}-{seq}{ext}", std::process::id());
    let mut end = stem.len().min(MAX_FILE_NAME_BYTES.saturating_sub(tail.len()));
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    std::env::temp_dir().join(format!("{}{tail}", &stem[..end]))
}

/// Remove whatever is at `path` without following a link. Absent is success. A link (file or
/// directory, symlink or junction) is unlinked itself and never entered (`remove_file`, then
/// `remove_dir` for a Windows directory link; neither recurses). A real directory goes through
/// `std::fs::remove_dir_all`, which per the std docs "does not follow symbolic links and it
/// will simply remove the symbolic link itself" for any link inside the tree.
fn remove_entry(path: &Path) -> std::io::Result<()> {
    let file_type = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if file_type.is_symlink() {
        std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path))
    } else if file_type.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// A read-only file (Windows) or an owner-locked entry (unix) refuses deletion; a test that set
/// that mode and failed before restoring it would leak. Loosen the entry itself, never a link
/// (`set_permissions` follows links and would change the target's mode).
fn loosen(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return };
    if meta.file_type().is_symlink() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(windows)]
    {
        let mut perms = meta.permissions();
        // Windows: clears FILE_ATTRIBUTE_READONLY only (the unix world-writable hazard this
        // lint names does not exist here).
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = std::fs::set_permissions(path, perms);
    }
}

/// Remove every path in `paths`, retrying until each is gone or `within` passes.
/// `Err` names each path still present with the last error its removal returned.
fn remove_all_or_report(paths: &[PathBuf], within: Duration) -> Result<(), String> {
    let deadline = Instant::now() + within;
    let mut pause = Duration::from_millis(5);
    let mut loosened = false;
    loop {
        let mut still: Vec<String> = Vec::new();
        for path in paths {
            if let Err(e) = remove_entry(path) {
                still.push(format!("{} ({e})", path.display()));
            }
        }
        if still.is_empty() {
            return Ok(());
        }
        if !loosened {
            loosened = true;
            paths.iter().for_each(|p| loosen(p));
            continue;
        }
        if Instant::now() >= deadline {
            return Err(still.join("; "));
        }
        std::thread::sleep(pause);
        pause = (pause * 2).min(Duration::from_millis(250));
    }
}

/// The single exit for a failed removal: a panic that names the leak, or, when the thread is
/// already unwinding from a failed test (where a second panic would abort the whole test
/// binary), a line on stderr naming it.
fn leaked(kind: &str, detail: &str, within: Duration) {
    let message = format!(
        "{kind} guard: still present {} ms after the drop — LEAKED (bind the guard before \
         anything that opens its path; see `aruna::test_temp`): {detail}",
        within.as_millis()
    );
    if std::thread::panicking() {
        eprintln!("{message}");
    } else {
        panic!("{message}");
    }
}

/// A file path under the temp directory that this guard owns, with its store family: on `Drop`
/// the path and every [`STORE_SIBLING_SUFFIXES`] name beside it are removed. Nothing is
/// created; the test (or the store it opens) creates what it needs.
///
/// Rule 3, compiled: `&guard` is the one spelling an opener accepts:
///
/// ```
/// let path = aruna::test_temp::TempFile::sqlite("aruna-h5-doc-borrowed");
/// let log = aruna::SqliteIntentLog::open(&path).expect("a fresh store opens");
/// drop(log);
/// ```
///
/// and the guard by value, moved into `open` and dropped there while the store it just opened
/// stays open, does not compile (E0277: the guard is not `AsRef<Path>`):
///
/// ```compile_fail,E0277
/// let path = aruna::test_temp::TempFile::sqlite("aruna-h5-doc-moved");
/// let _log = aruna::SqliteIntentLog::open(path);
/// ```
pub struct TempFile(PathBuf, Duration);

impl TempFile {
    /// `{temp}/{stem}-{pid}-{nanos}-{seq}{ext}`, e.g. `TempFile::new("aruna-rc-plan", ".sqlite")`.
    /// `ext` may be empty.
    pub fn new(stem: &str, ext: &str) -> TempFile {
        TempFile(unique_path(stem, ext), REMOVAL_DEADLINE)
    }

    /// [`TempFile::new`] with the `.sqlite` extension, the store shape.
    pub fn sqlite(stem: &str) -> TempFile {
        TempFile::new(stem, ".sqlite")
    }

    /// The owned path.
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The path and its store siblings: every name this guard removes on `Drop`.
    pub fn family(&self) -> Vec<PathBuf> {
        family_of(&self.0)
    }

    /// How long `Drop` retries before it calls a path leaked (default [`REMOVAL_DEADLINE`]).
    pub fn with_removal_deadline(mut self, within: Duration) -> TempFile {
        self.1 = within;
        self
    }
}

/// `path` and every [`STORE_SIBLING_SUFFIXES`] name beside it.
fn family_of(path: &Path) -> Vec<PathBuf> {
    let mut family = vec![path.to_path_buf()];
    for suffix in STORE_SIBLING_SUFFIXES {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        family.push(PathBuf::from(name));
    }
    family
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Err(detail) = remove_all_or_report(&self.family(), self.1) {
            leaked("TempFile", &detail, self.1);
        }
    }
}

/// A directory under the temp directory that this guard owns: on `Drop` the whole tree is
/// removed (never through a link; see `remove_entry`). A link at the owned path is unlinked,
/// never entered, so a test's directory symlink and its `-real` target each get their own guard.
pub struct TempDir(PathBuf, Duration);

impl TempDir {
    /// `{temp}/{stem}-{pid}-{nanos}-{seq}`, created empty. Panics if the name is already taken:
    /// with a unique name that is a collision, never something to adopt.
    pub fn new(stem: &str) -> TempDir {
        let dir = TempDir(unique_path(stem, ""), REMOVAL_DEADLINE);
        std::fs::create_dir(&dir.0)
            .unwrap_or_else(|e| panic!("TempDir: cannot create {}: {e}", dir.0.display()));
        dir
    }

    /// The same unique name, not created: for a test that must create the path itself (a link,
    /// a directory with its own mode) or needs a path guaranteed absent. Owned all the same;
    /// whatever appears there by `Drop` is removed.
    pub fn uncreated(stem: &str) -> TempDir {
        TempDir(unique_path(stem, ""), REMOVAL_DEADLINE)
    }

    /// The owned path.
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// How long `Drop` retries before it calls the tree leaked (default [`REMOVAL_DEADLINE`]).
    pub fn with_removal_deadline(mut self, within: Duration) -> TempDir {
        self.1 = within;
        self
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(detail) = remove_all_or_report(std::slice::from_ref(&self.0), self.1) {
            leaked("TempDir", &detail, self.1);
        }
    }
}

macro_rules! path_guard_impls {
    ($guard:ty) => {
        impl std::ops::Deref for $guard {
            type Target = Path;
            fn deref(&self) -> &Path {
                &self.0
            }
        }

        /// On the reference only (rule 3): the guard itself does not implement `AsRef<Path>`, so
        /// it can never be moved into an `impl AsRef<Path>` parameter and dropped there.
        impl AsRef<Path> for &$guard {
            fn as_ref(&self) -> &Path {
                &self.0
            }
        }

        impl std::fmt::Debug for $guard {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Debug::fmt(&self.0, f)
            }
        }
    };
}

path_guard_impls!(TempFile);
path_guard_impls!(TempDir);

#[cfg(test)]
mod tests {
    use super::*;

    /// A file guard's family, written by hand (the four siblings included), for the drop witness.
    fn plant_family(guard: &TempFile) -> Vec<PathBuf> {
        let family = guard.family();
        for path in &family {
            std::fs::write(path, b"x").expect("plant a family member");
        }
        family
    }

    // Witness: the file and EVERY sibling are gone once the guard drops.
    // Run first against a mutant with `TempFile::drop`'s body emptied.
    #[test]
    fn h5_a_file_guard_removes_the_file_and_its_store_siblings_on_drop() {
        let family;
        {
            let guard = TempFile::sqlite("aruna-h5-file-witness");
            family = plant_family(&guard);
            assert_eq!(family.len(), 5, "the path and its four siblings");
            assert!(family.iter().all(|p| p.exists()), "precondition: the family exists before the drop");
        }
        for path in &family {
            assert!(!path.exists(), "gone once the guard drops: {}", path.display());
        }
    }

    // RED/GREEN witness: a directory tree (a nested file, a nested directory) is gone once its
    // guard drops. Run first against a mutant with `TempDir::drop`'s body emptied.
    #[test]
    fn h5_a_dir_guard_removes_the_whole_tree_on_drop() {
        let root;
        {
            let dir = TempDir::new("aruna-h5-dir-witness");
            root = dir.to_path_buf();
            std::fs::create_dir_all(dir.join("a").join("b")).unwrap();
            std::fs::write(dir.join("a").join("b").join("store.sqlite"), b"x").unwrap();
            std::fs::write(dir.join("top.txt"), b"x").unwrap();
            assert!(root.join("a").join("b").join("store.sqlite").exists(), "precondition");
        }
        assert!(!root.exists(), "the tree must be gone once the guard drops: {}", root.display());
    }

    // The link rule: a guard over a DIRECTORY LINK removes the link and never enters it — the
    // target's contents survive the link's guard and go only with the target's own guard.
    #[test]
    fn h5_a_dir_guard_over_a_directory_link_removes_the_link_never_the_target() {
        let real = TempDir::new("aruna-h5-link-real");
        std::fs::write(real.join("keep.txt"), b"the target's own file").unwrap();
        let link_path;
        {
            let link = TempDir::uncreated("aruna-h5-link");
            link_path = link.to_path_buf();
            #[cfg(windows)]
            let made = std::os::windows::fs::symlink_dir(real.path(), link.path());
            #[cfg(unix)]
            let made = std::os::unix::fs::symlink(real.path(), link.path());
            if let Err(e) = made {
                eprintln!("SKIP h5_a_dir_guard_over_a_directory_link_removes_the_link_never_the_target: cannot create a directory link: {e}");
                return;
            }
            assert!(link.join("keep.txt").exists(), "precondition: the link resolves to the target");
        }
        assert!(std::fs::symlink_metadata(&link_path).is_err(), "the link itself is gone");
        assert_eq!(
            std::fs::read(real.join("keep.txt")).unwrap(),
            b"the target's own file",
            "the link's guard never entered the target"
        );
    }

    // The link rule, target GONE first (the order a test that binds the link before its target
    // produces): a DANGLING directory link is still removed — `cmd /c rmdir` refuses one ("cannot
    // find the file specified"), which is how dangling `aruna-symdir-link-*` entries outlived a
    // hand cleanup on this box.
    #[test]
    fn h5_a_dangling_directory_link_is_still_removed() {
        let link_path;
        {
            let link = TempDir::uncreated("aruna-h5-dangling-link");
            link_path = link.to_path_buf();
            {
                let real = TempDir::new("aruna-h5-dangling-real");
                #[cfg(windows)]
                let made = std::os::windows::fs::symlink_dir(real.path(), link.path());
                #[cfg(unix)]
                let made = std::os::unix::fs::symlink(real.path(), link.path());
                if let Err(e) = made {
                    eprintln!("SKIP h5_a_dangling_directory_link_is_still_removed: cannot create a directory link: {e}");
                    return;
                }
            } // the target's guard drops FIRST: the link now dangles
            assert!(std::fs::symlink_metadata(&link_path).is_ok(), "precondition: the dangling link is there");
            assert!(!link_path.exists(), "precondition: and it resolves to nothing");
        }
        assert!(std::fs::symlink_metadata(&link_path).is_err(), "the dangling link is gone");
    }

    // Rule 1: two calls in one process never mint one name, and a name never outgrows the bound the
    // engine's lock sibling is named within.
    #[test]
    fn h5_names_are_unique_per_call_and_within_the_lock_bound() {
        let a = TempFile::sqlite("same-stem");
        let b = TempFile::sqlite("same-stem");
        assert_ne!(a.to_path_buf(), b.to_path_buf(), "two calls, two names");
        let long = TempFile::sqlite(&"x".repeat(400));
        let name = long.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.len() <= MAX_FILE_NAME_BYTES, "{} bytes: {name}", name.len());
        assert!(name.ends_with(".sqlite"), "the extension is never cut: {name}");
        let pid = format!("-{}-", std::process::id());
        assert!(name.contains(&pid), "the unique tail is never cut: {name}");
    }

    /// A REAL store on a guarded path, opened the way every test opens one — the engine's own
    /// family (WAL, SHM, the bootstrap lock) is what the guard must clear, and a name at the full
    /// bound proves the lock sibling the engine names is the one the guard removes.
    #[test]
    fn h5_a_real_store_family_is_gone_once_the_store_and_then_the_guard_drop() {
        let family;
        let stem_prefix;
        {
            let guard = TempFile::sqlite(&format!("aruna-h5-real-{}", "y".repeat(200)));
            let name = guard.file_name().unwrap().to_string_lossy().into_owned();
            assert_eq!(name.len(), MAX_FILE_NAME_BYTES, "the fixture sits AT the bound");
            stem_prefix = name[..60].to_string();
            let log = crate::SqliteIntentLog::open(&guard).expect("a fresh store opens");
            family = guard.family();
            assert!(guard.exists(), "precondition: the store exists");
            drop(log);
        }
        for path in &family {
            assert!(!path.exists(), "gone: {}", path.display());
        }
        let left: Vec<String> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(&stem_prefix))
            .collect();
        assert!(left.is_empty(), "no name of this store's family survives: {left:?}");
    }

    /// THE ORDER WITNESS (rule 2), Windows — the platform that refuses to delete an open file. The
    /// guard bound BEFORE the store drops after it: the family is gone. The guard moved into a
    /// binding AFTER the store drops first, while the store is open: the delete is refused for
    /// the whole (here shortened) deadline and the guard PANICS naming the leak — the loud form of the silent
    /// `let _ =` leak this fold closes. The leftover is then cleared by a fresh guard.
    #[cfg(windows)]
    #[test]
    fn h5_a_guard_bound_after_the_store_it_names_is_a_loud_leak_on_windows() {
        // Bound BEFORE: nothing left.
        let before_path;
        {
            let guard = TempFile::sqlite("aruna-h5-order-before");
            before_path = guard.to_path_buf();
            let _log = crate::SqliteIntentLog::open(&guard).expect("open");
        }
        assert!(!before_path.exists(), "guard bound first ⇒ gone after the scope");

        // Bound AFTER: the guard drops while the store is open.
        let after_path = std::sync::Mutex::new(PathBuf::new());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // The leak is EXPECTED here: a short deadline, so the witness never idles a test slot
            // for the full default (see `REMOVAL_DEADLINE`).
            let guard = TempFile::sqlite("aruna-h5-order-after").with_removal_deadline(Duration::from_millis(250));
            *after_path.lock().unwrap() = guard.to_path_buf();
            let _log = crate::SqliteIntentLog::open(&guard).expect("open");
            let _late = guard; // declared AFTER `_log` ⇒ dropped BEFORE it
        }));
        let after_path = after_path.into_inner().unwrap();
        let message = outcome
            .expect_err("a guard dropped under an open store must fail LOUDLY, never leak in silence")
            .downcast::<String>()
            .map(|m| *m)
            .unwrap_or_default();
        assert!(message.contains("LEAKED"), "the panic names the leak: {message}");
        assert!(
            message.contains(&after_path.display().to_string()),
            "the panic names the path: {message}"
        );
        assert!(after_path.exists(), "and the store WAS left behind — the leak itself");
        // Clear the leftover this witness made, through the one mint's own removal.
        remove_all_or_report(&family_of(&after_path), REMOVAL_DEADLINE).expect("the store is closed now; its leftover goes");
    }

    /// THE HOLDER WITNESS (rule 4), Windows: a handle opened WITHOUT delete-sharing — the shape of
    /// an outside scanner holding a fresh file — refuses the delete while it is held. Released
    /// inside the deadline, the guard waits it out and the file is gone; the pre-fix single
    /// unretried attempt left it on disk (the `t7-coalesce` `-wal` leftover's shape).
    #[cfg(windows)]
    #[test]
    fn h5_a_briefly_held_file_is_waited_out_never_left_behind() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        const FILE_SHARE_WRITE: u32 = 0x2;
        let path;
        {
            let guard = TempFile::new("aruna-h5-held", ".sqlite-wal");
            path = guard.to_path_buf();
            std::fs::write(&guard, b"frames").unwrap();
            let holder = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .open(&guard)
                .expect("hold the file without delete-sharing");
            assert!(std::fs::remove_file(&guard).is_err(), "precondition: held ⇒ undeletable");
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(400));
                drop(holder);
            });
        }
        assert!(!path.exists(), "a holder released inside the deadline is waited out");
    }
}
