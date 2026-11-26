//! The OS credential-store custodian of the root commitment key
//! (`aruna::key_custody::KeyCustody`). ADR-P010: "secrets stay in OS-backed credential storage
//! (keyring/DPAPI), never SQLite, never plaintext". It uses Windows Credential Manager, macOS
//! Keychain or Linux secret-service through the `keyring` crate's default stores.
//!
//! The key is stored as its 96-lowercase-hex spelling under a service/user pair derived from the
//! store path, so two stores on one box hold two keys and a store copied to another path does not
//! silently share one (the registry fingerprint check in `root_key_verified` backstops this).
//!
//! CI: the Linux runner has no secret-service, so the OS store itself is exercised only on the
//! dev box (Windows) and by an attended Mac run. CI runs this custodian's load/store contract
//! over keyring-core's in-memory mock credential, and the engine's in-memory twin.

use aruna::key_custody::{CustodyError, KeyCustody};
use aruna::commitment::CommitmentKey;
use std::path::Path;

const SERVICE: &str = "com.moonwalker.photon.commitment-root";

pub struct KeyringCustody {
    entry: keyring::Entry,
}

impl KeyringCustody {
    /// One custodian per store: the keyring "user" is a SHA-384 of the canonical store path, so
    /// the identifier never carries the path itself (a path can hold a username), with one entry
    /// per canonical Unicode store path (a non-Unicode path is refused, never folded onto another
    /// store's entry).
    ///
    /// A platform store that failed to start is refused as `Unavailable` carrying that failure's
    /// own text (`startup_refusal`); keyring v1's `Entry::new` would otherwise report a bare
    /// `NoDefaultStore`. v1 starts the store once and caches the result for the process lifetime
    /// (`keyring` 4.2.0 `src/v1.rs`: a `LazyLock` behind `Entry::store_status`), so a store that
    /// failed at first use stays refused until the process restarts.
    pub fn for_store(store_path: &Path) -> Result<Self, CustodyError> {
        let user = store_user(store_path)?;
        startup_refusal(keyring::Entry::store_status())?;
        let entry = keyring::Entry::new(SERVICE, &user)
            .map_err(|e| CustodyError::Unavailable(format!("keyring entry: {e}")))?;
        Ok(Self { entry })
    }
}

/// `for_store`'s startup check, split out so the refusal's text can be tested on a box whose
/// store starts: a failed start becomes `Unavailable` carrying the failure's own text.
fn startup_refusal(status: &keyring::Result<()>) -> Result<(), CustodyError> {
    match status {
        Ok(()) => Ok(()),
        Err(e) => Err(CustodyError::Unavailable(format!("the OS credential store failed to start: {e}"))),
    }
}

/// `for_store`'s keyring user, split out so the one-entry-per-store scoping can be tested in CI,
/// where no OS credential store runs.
fn store_user(store_path: &Path) -> Result<String, CustodyError> {
    use sha2::{Digest, Sha384};
    let canonical = store_path
        .canonicalize()
        .map_err(|e| CustodyError::Unavailable(format!("store path could not be canonicalized: {e}")))?;
    // `to_str` rather than `to_string_lossy`: for a valid-Unicode path the two yield the same
    // string (so no existing store's entry name changes), while a non-Unicode path, which
    // `to_string_lossy` would fold onto U+FFFD (and so onto another store's entry), is refused.
    let unicode = canonical.to_str().ok_or_else(|| {
        CustodyError::Unavailable("store path is not valid Unicode; its keyring entry cannot be named".into())
    })?;
    Ok(format!("{:x}", Sha384::digest(unicode.as_bytes())))
}

impl KeyCustody for KeyringCustody {
    fn load_root(&self) -> Result<Option<CommitmentKey>, CustodyError> {
        match self.entry.get_password() {
            Ok(hex) => CommitmentKey::from_hex(&hex).map(Some).map_err(CustodyError::Malformed),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CustodyError::Unavailable(format!("keyring read: {e}"))),
        }
    }

    fn store_root(&self, key: &CommitmentKey) -> Result<(), CustodyError> {
        // Never overwrite. `root_key_verified` only stores when nothing is held, but this
        // custodian re-checks so a sequential misuse cannot rotate a key underneath a registry.
        // The re-check is not atomic with the write (the keyring API has no create-only write):
        // two processes racing a first open fall under the engine's documented
        // no-multi-process non-claim (writer_gate.rs "PROCESS SCOPE"), which this custodian does
        // not close.
        match self.entry.get_password() {
            Ok(_) => return Err(CustodyError::Unavailable("a root key is already stored; refusing to overwrite".into())),
            Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(CustodyError::Unavailable(format!("keyring read before store: {e}"))),
        }
        self.entry
            .set_password(&key.hex())
            .map_err(|e| CustodyError::Unavailable(format!("keyring write: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aruna::commitment::CommitmentError;

    /// The custodian spells a key through the ENGINE's one helper (`CommitmentKey::{hex,
    /// from_hex}`): what it writes is `key.hex()` and reads back exactly; an
    /// uppercase or short spelling in the OS store is `Malformed(KeyHex)`, never a byte count.
    #[test]
    fn the_custodian_spells_the_key_through_the_engines_hex_helper() {
        let custody = mock_custody();
        let key = CommitmentKey::from_bytes(&(0u8..48).collect::<Vec<u8>>()).unwrap();
        custody.store_root(&key).unwrap();
        assert_eq!(custody.entry.get_password().unwrap(), key.hex(), "the stored spelling is the engine's");
        assert_eq!(custody.load_root().unwrap(), Some(key));

        let custody = mock_custody();
        custody.entry.set_password(&"A5".repeat(48)).unwrap();
        assert_eq!(custody.load_root(), Err(CustodyError::Malformed(CommitmentError::KeyHex)), "uppercase");
        let custody = mock_custody();
        custody.entry.set_password(&"a5".repeat(47)).unwrap();
        assert_eq!(custody.load_root(), Err(CustodyError::Malformed(CommitmentError::KeyHex)), "94 chars");
    }

    /// A store path that is not valid Unicode has no keyring user — refused, never
    /// folded (the old `to_string_lossy` turned a lone surrogate into U+FFFD, so two stores could
    /// share one entry). A path that really contains U+FFFD is valid Unicode and keeps its user.
    #[cfg(windows)]
    #[test]
    fn a_non_unicode_store_path_is_refused_never_folded_onto_another_stores_entry() {
        use std::os::windows::ffi::OsStringExt;
        let dir = aruna::test_temp::TempDir::new("photon-keyring-nonunicode"); // the ONE guard
        let mut wide: Vec<u16> = "lone-".encode_utf16().collect();
        wide.push(0xD800); // an unpaired high surrogate: legal in an NTFS name, not Unicode
        wide.extend(".sqlite".encode_utf16());
        let lone = dir.join(std::ffi::OsString::from_wide(&wide));
        std::fs::write(&lone, b"").unwrap();
        let replacement = dir.join(format!("lone-{}.sqlite", char::REPLACEMENT_CHARACTER));
        std::fs::write(&replacement, b"").unwrap();
        let lone_user = store_user(&lone);
        let replacement_user = store_user(&replacement);
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(matches!(lone_user, Err(CustodyError::Unavailable(ref why)) if why.contains("not valid Unicode")), "{lone_user:?}");
        assert_eq!(replacement_user.unwrap().len(), 96, "a real U+FFFD in a name is valid Unicode");
    }

    /// The per-store BINDING: `for_store` builds its entry from THIS service and
    /// THIS store's user (not one shared user, not the pair swapped, not another service). The
    /// service is pinned as a LITERAL: renaming it orphans every key already stored under it.
    /// Entry construction does no credential I/O on Windows or macOS
    /// (`windows-native-keyring-store` 1.1.0 `Store::build` → `Cred::build_from_specifiers`;
    /// `apple-native-keyring-store` 1.0.2 `Cred::build`), so this runs without touching the OS
    /// store. A box whose store cannot start (Linux with no session bus) says so LOUDLY and
    /// witnesses that the refusal carries the startup cause instead — never a silent pass.
    #[test]
    fn the_entry_is_bound_to_this_service_and_this_stores_user() {
        let dir = aruna::test_temp::TempDir::new("photon-keyring-binding"); // the ONE guard
        let a = dir.join("a.sqlite");
        let b = dir.join("b.sqlite");
        std::fs::write(&a, b"").unwrap();
        std::fs::write(&b, b"").unwrap();
        if let Err(e) = keyring::Entry::store_status() {
            eprintln!("SKIPPED (binding not witnessed on this box): the OS credential store did not start: {e}");
            let refused = KeyringCustody::for_store(&a).err();
            std::fs::remove_dir_all(&dir).unwrap();
            assert!(
                matches!(refused, Some(CustodyError::Unavailable(ref why)) if why.contains(&e.to_string())),
                "a store that failed to start is refused with its own cause: {refused:?}"
            );
            return;
        }
        let spec_a = KeyringCustody::for_store(&a).unwrap().entry.inner.get_specifiers();
        let spec_b = KeyringCustody::for_store(&b).unwrap().entry.inner.get_specifiers();
        let (user_a, user_b) = (store_user(&a).unwrap(), store_user(&b).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(spec_a, Some(("com.moonwalker.photon.commitment-root".to_string(), user_a)));
        assert_eq!(spec_b, Some(("com.moonwalker.photon.commitment-root".to_string(), user_b)));
    }

    /// One keyring user per STORE (the scoping key_custody's adopt arm rests on): two store
    /// files, two users; one file however it is spelled, one user; a 96-lowercase-hex digest,
    /// never the path; a path that does not resolve has no user.
    #[test]
    fn the_keyring_user_is_one_per_canonical_store_path_and_never_the_path_itself() {
        let dir = aruna::test_temp::TempDir::new("photon-keyring-user"); // the ONE guard
        let a = dir.join("a.sqlite");
        let b = dir.join("b.sqlite");
        std::fs::write(&a, b"").unwrap();
        std::fs::write(&b, b"").unwrap();
        let user_a = store_user(&a).unwrap();
        assert_eq!(user_a.len(), 96);
        assert!(user_a.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')), "a digest, never the path");
        assert_ne!(user_a, store_user(&b).unwrap(), "two stores, two entries");
        assert_eq!(
            user_a,
            store_user(&dir.join(".").join("a.sqlite")).unwrap(),
            "one store, one entry, however its path is spelled"
        );
        assert!(matches!(store_user(&dir.join("absent.sqlite")), Err(CustodyError::Unavailable(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A platform store that failed to START is refused as `Unavailable` carrying
    /// THAT failure's text — keyring v1's own `Entry::new` would drop it into a bare
    /// `NoDefaultStore`. A started store passes through.
    #[test]
    fn a_store_that_failed_to_start_is_refused_with_its_own_cause() {
        assert_eq!(startup_refusal(&Ok(())), Ok(()));
        let failed: keyring::Result<()> = Err(keyring::Error::PlatformFailure("no session bus at /run/user/1000/bus".into()));
        let refused = startup_refusal(&failed).unwrap_err();
        assert!(
            matches!(refused, CustodyError::Unavailable(ref why) if why.contains("no session bus at /run/user/1000/bus")),
            "{refused:?}"
        );
        let bare: keyring::Result<()> = Err(keyring::Error::NoDefaultStore);
        assert!(matches!(startup_refusal(&bare), Err(CustodyError::Unavailable(_))));
        // `for_store` runs the check BEFORE `Entry::new` — a source-text witness, because on a box
        // whose store starts (the Windows dev box) no runtime path reaches the refusal. CRLF is
        // normalized first (a core.autocrlf=true checkout hands include_str! "\r\n").
        let src = include_str!("key_custody_keyring.rs").replace("\r\n", "\n");
        let body = &src[src.find("pub fn for_store").unwrap()..];
        let body = &body[..body.find("\n    }\n").unwrap()];
        let check = body.find("startup_refusal(keyring::Entry::store_status())?;").expect("for_store runs the startup check");
        assert!(check < body.find("keyring::Entry::new(").unwrap(), "the startup check precedes Entry::new");
    }

    /// A custodian over keyring-core's in-memory mock credential: a fresh one per call, holding
    /// nothing. The OS store itself is witnessed by the attended test below.
    fn mock_custody() -> KeyringCustody {
        use keyring_core::api::CredentialStoreApi;
        let inner = keyring_core::mock::Store::new().unwrap().build(SERVICE, "mock-user", None).unwrap();
        KeyringCustody { entry: keyring::Entry { inner } }
    }

    /// The mock's next call fails the way a locked or unreachable OS store does.
    fn fail_next_call(custody: &KeyringCustody) {
        let cred: &keyring_core::mock::Cred = custody.entry.inner.as_any().downcast_ref().unwrap();
        cred.set_error(keyring::Error::PlatformFailure("the credential store is locked".into()));
    }

    /// The custodian contract in CI: nothing stored reads as `None`; a stored key reads back
    /// exactly; a second store is refused and leaves the held key unchanged; a store that cannot
    /// answer is `Unavailable` on both arms, never "nothing stored" and never written through;
    /// material that is not a key is `Malformed`.
    #[test]
    fn the_custodian_contract_holds_over_a_mock_credential() {
        let custody = mock_custody();
        assert_eq!(custody.load_root().unwrap(), None);
        let key = CommitmentKey::from_bytes(&[0x3cu8; 48]).unwrap();
        custody.store_root(&key).unwrap();
        assert_eq!(custody.load_root().unwrap(), Some(key.clone()));
        let other = CommitmentKey::from_bytes(&[0xc3u8; 48]).unwrap();
        assert!(matches!(custody.store_root(&other), Err(CustodyError::Unavailable(_))), "no overwrite");
        assert_eq!(custody.load_root().unwrap(), Some(key), "the held key is unchanged");

        let custody = mock_custody();
        fail_next_call(&custody);
        assert!(matches!(custody.load_root(), Err(CustodyError::Unavailable(_))), "a failed read is never taken for nothing stored");
        fail_next_call(&custody);
        assert!(matches!(custody.store_root(&other), Err(CustodyError::Unavailable(_))), "a failed read refuses the store");
        assert_eq!(custody.load_root().unwrap(), None, "and nothing was written");

        let custody = mock_custody();
        custody.entry.set_password(&"A5".repeat(48)).unwrap();
        assert!(matches!(custody.load_root(), Err(CustodyError::Malformed(_))));
    }

    /// ATTENDED WITNESS — runs only when `PHOTON_KEYRING_IT=1` (the dev box / an attended Mac):
    /// a real round trip through the OS store, on a throwaway store path, cleaned up after.
    #[test]
    fn attended_os_keyring_round_trip() {
        if std::env::var("PHOTON_KEYRING_IT").as_deref() != Ok("1") {
            eprintln!("SKIPPED: set PHOTON_KEYRING_IT=1 to exercise the OS credential store");
            return;
        }
        let dir = aruna::test_temp::TempDir::new("photon-keyring-it"); // the ONE guard
        let store = dir.join("store.sqlite");
        std::fs::write(&store, b"").unwrap();
        let custody = KeyringCustody::for_store(&store).unwrap();
        assert_eq!(custody.load_root().unwrap(), None);
        let key = CommitmentKey::from_bytes(&[0x5au8; 48]).unwrap();
        custody.store_root(&key).unwrap();
        assert_eq!(custody.load_root().unwrap(), Some(key.clone()));
        assert!(custody.store_root(&key).is_err(), "no overwrite");
        // A second store on the same box: its own entry, which A's store never
        // wrote. Read BEFORE cleanup, asserted AFTER it, so a failure leaves no OS entry behind.
        let store_b = dir.join("store-b.sqlite");
        std::fs::write(&store_b, b"").unwrap();
        let custody_b = KeyringCustody::for_store(&store_b).unwrap();
        let b_held = custody_b.load_root();
        // cleanup: delete A's OS entry (and B's, which must not exist), then the temp dir
        custody.entry.delete_credential().unwrap();
        let b_cleanup = custody_b.entry.delete_credential();
        assert_eq!(custody.load_root().unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(b_held, Ok(None), "a second store never reads the first store's key");
        assert!(matches!(b_cleanup, Err(keyring::Error::NoEntry)), "store B never held an entry: {b_cleanup:?}");
    }
}
