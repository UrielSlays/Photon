//! Key custody: who holds the store's root commitment key, and the single function that
//! turns a custodian's answer into a key the store trusts.
//!
//! The custodian (`KeyCustody`) is the OS credential store in the shell
//! (`src-tauri/src/key_custody_keyring.rs`; ADR-P010: secrets stay in OS-backed credential
//! storage, never SQLite, never plaintext) and an in-memory twin here for tests, whose checks
//! are never weaker than production. The store keeps the key's non-secret fingerprint as its
//! registry record (`KeyRegistry`), so a key read back is verified against what was
//! registered: restoring a key is not importing one.
//!
//! Photon differs from the reference implementation in two deliberate ways, which should not
//! be changed to match it. The adopt arm accepts a custodian key when nothing is registered:
//! the OS custodian scopes its entry to the store path, and the registry row is append-only
//! in the same store file as every commitment it protects, so a lost row is an act of whoever
//! controls the machine, which this seam does not defend against. And the mint arm stores
//! before it registers, so a crash between the two writes is recovered by adoption on the next
//! open. Two processes racing a first open over one store file are covered by the engine's
//! no-multi-process non-claim (see the writer gate module docs). The shell's one call is at
//! bus construction: `build_gmail_arm` (`src-tauri/src/lib.rs`) resolves the root key through
//! [`root_key_verified`] over its custodian and refuses the arm when custody refuses. A store
//! whose custodian cannot answer, or answers with a key whose fingerprint is not the
//! registered one, refuses; it never silently gets a fresh key.

use crate::commitment::{
    key_fingerprint, mint_randomizer, CommitmentError, CommitmentKey, COMMITMENT_KEY_BYTES,
    COMMITMENT_RANDOMIZER_BYTES,
};
use std::fmt;
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyError {
    /// The custodian could not be reached or refused (the OS store is locked, absent, denied).
    /// Carries the custodian's own sentence, an operator-facing reason, never key bytes.
    Unavailable(String),
    /// The custodian returned material that is not a valid key.
    Malformed(CommitmentError),
    /// A fingerprint is registered but the custodian holds no key: the store was moved to a
    /// machine (or user) whose keychain does not hold it. Refuse; a fresh key would silently
    /// orphan every existing commitment.
    RegisteredButAbsent { registered_fingerprint: String },
    /// The custodian's key does not match the registered fingerprint. Refuse.
    FingerprintMismatch { registered: String, presented: String },
    /// Minting a fresh key needed OS entropy and got none.
    Entropy,
    /// The registry itself could not be read or written.
    Registry(String),
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustodyError::Unavailable(why) => write!(f, "key custody unavailable: {why}"),
            CustodyError::Malformed(e) => write!(f, "key custody returned malformed material: {e}"),
            CustodyError::RegisteredButAbsent { registered_fingerprint } => write!(f, "a commitment key is registered ({registered_fingerprint}) but the custodian holds none — refusing to mint a fresh key over the registered one"),
            CustodyError::FingerprintMismatch { registered, presented } => write!(f, "the custodian's key fingerprint {presented} does not match the registered {registered}"),
            CustodyError::Entropy => write!(f, "key custody: OS entropy unavailable for a fresh key"),
            CustodyError::Registry(why) => write!(f, "key registry: {why}"),
        }
    }
}

impl std::error::Error for CustodyError {}

/// The custodian of the root key: it loads what it holds and stores a fresh one. Nothing here
/// decides trust; `root_key_verified` does.
pub trait KeyCustody {
    /// The stored root key, if the custodian holds one. `Ok(None)` means nothing is stored.
    fn load_root(&self) -> Result<Option<CommitmentKey>, CustodyError>;
    /// Store a freshly minted root key. Must refuse if one is already stored (no silent overwrite).
    fn store_root(&self, key: &CommitmentKey) -> Result<(), CustodyError>;
}

/// The store's registry record: the root key's non-secret fingerprint, or none yet.
pub trait KeyRegistry {
    fn registered_key_fingerprint(&self) -> Result<Option<String>, CustodyError>;
    fn register_key_fingerprint(&mut self, fingerprint: &str) -> Result<(), CustodyError>;
}

/// Every `IntentLog` is the registry: the fingerprint row lives in the store the commitments
/// live in.
impl<L: crate::IntentLog> KeyRegistry for L {
    fn registered_key_fingerprint(&self) -> Result<Option<String>, CustodyError> {
        crate::IntentLog::registered_key_fingerprint(self).map_err(|e| CustodyError::Registry(e.0))
    }
    fn register_key_fingerprint(&mut self, fingerprint: &str) -> Result<(), CustodyError> {
        crate::IntentLog::register_key_fingerprint(self, fingerprint).map_err(|e| CustodyError::Registry(e.0))
    }
}

/// The single entry point for the root key. Every consumer must go through here and never
/// through `KeyCustody::load_root` directly:
/// - registered + custodian holds a key with that fingerprint: the key;
/// - registered + custodian holds nothing: `RegisteredButAbsent` (refuse);
/// - registered + a different fingerprint: `FingerprintMismatch` (refuse);
/// - nothing registered + custodian holds nothing: mint 48 bytes of OS entropy, store, register, return;
/// - nothing registered + custodian holds a key: register its fingerprint and return it (a
///   first open of a store on a machine that already minted one; adopting the custodian's key
///   is safe because no commitment exists yet to orphan).
pub fn root_key_verified(
    custody: &dyn KeyCustody,
    registry: &mut dyn KeyRegistry,
) -> Result<CommitmentKey, CustodyError> {
    let registered = registry.registered_key_fingerprint()?;
    let held = custody.load_root()?;
    match (registered, held) {
        (Some(registered), Some(key)) => {
            let presented = key_fingerprint(&key);
            if presented != registered {
                return Err(CustodyError::FingerprintMismatch { registered, presented });
            }
            Ok(key)
        }
        (Some(registered_fingerprint), None) => Err(CustodyError::RegisteredButAbsent { registered_fingerprint }),
        (None, Some(key)) => {
            registry.register_key_fingerprint(&key_fingerprint(&key))?;
            Ok(key)
        }
        (None, None) => {
            let key = mint_root_key()?;
            custody.store_root(&key)?;
            registry.register_key_fingerprint(&key_fingerprint(&key))?;
            Ok(key)
        }
    }
}

const _: () = assert!(3 * COMMITMENT_RANDOMIZER_BYTES == COMMITMENT_KEY_BYTES);

/// 48 bytes of OS entropy: generated only, never derived from anything the operator typed.
fn mint_root_key() -> Result<CommitmentKey, CustodyError> {
    // Three 16-byte draws through the scheme's existing entropy source.
    let mut bytes = Vec::with_capacity(COMMITMENT_KEY_BYTES);
    for _ in 0..3 {
        let r = mint_randomizer().map_err(|_| CustodyError::Entropy)?;
        bytes.extend_from_slice(r.as_bytes());
    }
    // Unreachable (the const assert above pins 3 x 16 = 48); mapped to `Entropy` because a
    // length failure here is the mint's own, never the custodian's.
    CommitmentKey::from_bytes(&bytes).map_err(|_| CustodyError::Entropy)
}

/// The tests' twin. Same contract as the OS custodian: a key once stored is never overwritten.
#[derive(Debug, Default)]
pub struct InMemoryCustody {
    key: Mutex<Option<CommitmentKey>>,
    /// Test seam: make `load_root` fail like a locked keychain would.
    unavailable: Mutex<Option<String>>,
    /// Test seam: make `store_root` refuse like an OS store that denies the write.
    store_refused: bool,
}

impl InMemoryCustody {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn holding(key: CommitmentKey) -> Self {
        Self { key: Mutex::new(Some(key)), ..Self::default() }
    }
    /// Test seam: a custodian that holds nothing and whose `store_root` refuses with
    /// `Unavailable("store refused")`, so tests can check the order (store before register).
    pub fn refusing_store() -> Self {
        Self { store_refused: true, ..Self::default() }
    }
    pub fn set_unavailable(&self, why: Option<&str>) {
        *self.unavailable.lock().unwrap() = why.map(str::to_string);
    }
}

impl KeyCustody for InMemoryCustody {
    fn load_root(&self) -> Result<Option<CommitmentKey>, CustodyError> {
        if let Some(why) = self.unavailable.lock().unwrap().clone() {
            return Err(CustodyError::Unavailable(why));
        }
        Ok(self.key.lock().unwrap().clone())
    }
    fn store_root(&self, key: &CommitmentKey) -> Result<(), CustodyError> {
        if self.store_refused {
            return Err(CustodyError::Unavailable("store refused".into()));
        }
        let mut slot = self.key.lock().unwrap();
        if slot.is_some() {
            return Err(CustodyError::Unavailable("a root key is already stored; refusing to overwrite".into()));
        }
        *slot = Some(key.clone());
        Ok(())
    }
}

/// An in-memory registry for tests of the door itself.
#[derive(Debug, Default)]
pub struct InMemoryKeyRegistry {
    fingerprint: Option<String>,
    /// Test seam: make `register_key_fingerprint` refuse like a store whose write fails.
    refuse_registration: bool,
}

impl InMemoryKeyRegistry {
    /// Test seam (like `InMemoryCustody::refusing_store`): a registry that holds nothing and
    /// whose `register_key_fingerprint` refuses with `Registry("registration refused")`, so
    /// tests can check that both registering arms never hand out a key they could not register.
    pub fn refusing() -> Self {
        Self { refuse_registration: true, ..Self::default() }
    }
}

impl KeyRegistry for InMemoryKeyRegistry {
    fn registered_key_fingerprint(&self) -> Result<Option<String>, CustodyError> {
        Ok(self.fingerprint.clone())
    }
    fn register_key_fingerprint(&mut self, fingerprint: &str) -> Result<(), CustodyError> {
        if self.refuse_registration {
            return Err(CustodyError::Registry("registration refused".into()));
        }
        if self.fingerprint.is_some() {
            return Err(CustodyError::Registry("a fingerprint is already registered".into()));
        }
        self.fingerprint = Some(fingerprint.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_open_mints_stores_and_registers_one_key_and_reopens_to_the_same_key() {
        let custody = InMemoryCustody::new();
        let mut registry = InMemoryKeyRegistry::default();
        let first = root_key_verified(&custody, &mut registry).unwrap();
        assert_eq!(registry.registered_key_fingerprint().unwrap().as_deref(), Some(key_fingerprint(&first).as_str()));
        let again = root_key_verified(&custody, &mut registry).unwrap();
        assert_eq!(first, again);
    }

    #[test]
    fn a_registered_store_whose_custodian_holds_nothing_refuses_never_a_fresh_key() {
        let custody = InMemoryCustody::new();
        let mut registry = InMemoryKeyRegistry::default();
        registry.register_key_fingerprint("deadbeef").unwrap();
        let err = root_key_verified(&custody, &mut registry).unwrap_err();
        assert_eq!(err, CustodyError::RegisteredButAbsent { registered_fingerprint: "deadbeef".into() });
        assert!(custody.load_root().unwrap().is_none(), "nothing was minted on refusal");
    }

    #[test]
    fn a_custodian_key_whose_fingerprint_is_not_the_registered_one_refuses() {
        let custody = InMemoryCustody::holding(CommitmentKey::from_bytes(&[1u8; 48]).unwrap());
        let mut registry = InMemoryKeyRegistry::default();
        registry.register_key_fingerprint("not-this-key").unwrap();
        let err = root_key_verified(&custody, &mut registry).unwrap_err();
        assert!(matches!(err, CustodyError::FingerprintMismatch { ref registered, ref presented }
            if registered == "not-this-key"
                && *presented == key_fingerprint(&CommitmentKey::from_bytes(&[1u8; 48]).unwrap())));
    }

    #[test]
    fn an_unregistered_store_adopts_a_key_the_custodian_already_holds_and_registers_it() {
        let held = CommitmentKey::from_bytes(&[2u8; 48]).unwrap();
        let custody = InMemoryCustody::holding(held.clone());
        let mut registry = InMemoryKeyRegistry::default();
        assert_eq!(root_key_verified(&custody, &mut registry).unwrap(), held);
        assert_eq!(registry.registered_key_fingerprint().unwrap(), Some(key_fingerprint(&held)));
    }

    #[test]
    fn an_unavailable_custodian_refuses_with_its_own_sentence_and_registers_nothing() {
        let custody = InMemoryCustody::new();
        custody.set_unavailable(Some("keychain locked"));
        let mut registry = InMemoryKeyRegistry::default();
        assert_eq!(root_key_verified(&custody, &mut registry).unwrap_err(), CustodyError::Unavailable("keychain locked".into()));
        assert!(registry.registered_key_fingerprint().unwrap().is_none());
    }

    #[test]
    fn the_twin_never_overwrites_a_stored_key() {
        let custody = InMemoryCustody::holding(CommitmentKey::from_bytes(&[1u8; 48]).unwrap());
        assert!(custody.store_root(&CommitmentKey::from_bytes(&[2u8; 48]).unwrap()).is_err());
        assert_eq!(custody.load_root().unwrap().unwrap(), CommitmentKey::from_bytes(&[1u8; 48]).unwrap());
    }

    #[test]
    fn a_mint_that_cannot_store_registers_nothing() {
        // Register comes AFTER store, never before: a registry record naming a key the custodian
        // never took would make every later open refuse with RegisteredButAbsent.
        let custody = InMemoryCustody::refusing_store();
        let mut registry = InMemoryKeyRegistry::default();
        assert_eq!(root_key_verified(&custody, &mut registry).unwrap_err(), CustodyError::Unavailable("store refused".into()));
        assert!(registry.registered_key_fingerprint().unwrap().is_none(), "a refused store left a registry record");
        assert!(custody.load_root().unwrap().is_none());
    }

    #[test]
    fn a_key_is_never_handed_out_before_it_is_registered_in_either_registering_arm() {
        // mint arm: store succeeds, register refuses ⇒ Err, and the custodian holds the key so the
        // NEXT open adopts it (store-before-register is what makes the crash window recoverable).
        let custody = InMemoryCustody::new();
        let mut refusing = InMemoryKeyRegistry::refusing();
        assert!(matches!(root_key_verified(&custody, &mut refusing).unwrap_err(), CustodyError::Registry(_)));
        assert!(custody.load_root().unwrap().is_some(), "the minted key was stored before registration was attempted");
        // adopt arm: custodian holds a key, register refuses ⇒ Err, nothing registered.
        let custody = InMemoryCustody::holding(CommitmentKey::from_bytes(&[4u8; 48]).unwrap());
        let mut refusing = InMemoryKeyRegistry::refusing();
        assert!(matches!(root_key_verified(&custody, &mut refusing).unwrap_err(), CustodyError::Registry(_)));
        assert_eq!(refusing.registered_key_fingerprint().unwrap(), None);
    }

    #[test]
    fn minted_root_keys_are_fresh_os_entropy_not_a_constant_or_a_repeated_draw() {
        let a = root_key_verified(&InMemoryCustody::new(), &mut InMemoryKeyRegistry::default()).unwrap();
        let b = root_key_verified(&InMemoryCustody::new(), &mut InMemoryKeyRegistry::default()).unwrap();
        assert_ne!(a, b, "two first-opens must not mint the same key");
        let k = mint_root_key().unwrap();
        let (t1, t2, t3) = (&k.as_bytes()[0..16], &k.as_bytes()[16..32], &k.as_bytes()[32..48]);
        assert!(t1 != t2 && t2 != t3 && t1 != t3, "the three 16-byte draws must be independent");
    }
}
