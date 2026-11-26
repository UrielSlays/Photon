//! The grant ratchet seam.

/// The grant-ratchet check the engine cannot perform itself: the high-water file lives with
/// the credential in the shell. `admits` answers "is this plan's grant identity still the
/// one in force?": generation at or above the ratchet and the principal equal to the
/// credential's. The shell's implementation is `ShellGrantRatchet` (`src-tauri/src/lib.rs`),
/// over `CredentialCoordinator::admits_plan_grant` (`src-tauri/src/credential_cell.rs`).
/// `CommandBus::plan_binding` calls it once per plan child's send authorization and turns a
/// refusal into the content-free [`crate::plan::GrantDenial`]. Tests use
/// [`InMemoryGrantRatchet`].
pub trait GrantRatchet {
    fn admits(&self, grant_generation: u64, provider_principal: &str) -> Result<(), GrantRefusal>;
}

/// Why a grant identity is not admitted. Named, never a bare "no".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantRefusal {
    /// The plan's grant generation is below the ratchet's high-water: a retired grant.
    Retired { generation: u64, high_water: u64 },
    /// The plan was minted under another provider principal than the credential's.
    PrincipalMismatch { plan: String, current: String },
    /// The ratchet could not be consulted (no ratchet wired; the high-water unreadable).
    Unavailable(String),
}

/// A bus with no ratchet cannot admit a plan: it fails closed rather than skipping the
/// check. Its `Unavailable` becomes `GrantDenial::Unavailable`, a held refusal: the child
/// stays in flight until a bus that can consult a ratchet drives it.
pub struct NoGrantRatchet;
impl GrantRatchet for NoGrantRatchet {
    fn admits(&self, _: u64, _: &str) -> Result<(), GrantRefusal> {
        Err(GrantRefusal::Unavailable("no grant ratchet is wired into this bus".into()))
    }
}

/// The test ratchet: a high-water (`None` = nothing retired yet, the shell's answer when no
/// ratchet exists) and the credential's principal.
#[derive(Debug, Clone)]
pub struct InMemoryGrantRatchet {
    pub high_water: Option<u64>,
    pub principal: String,
}
impl GrantRatchet for InMemoryGrantRatchet {
    fn admits(&self, grant_generation: u64, provider_principal: &str) -> Result<(), GrantRefusal> {
        if provider_principal != self.principal {
            return Err(GrantRefusal::PrincipalMismatch { plan: provider_principal.into(), current: self.principal.clone() });
        }
        match self.high_water {
            Some(hw) if grant_generation < hw => Err(GrantRefusal::Retired { generation: grant_generation, high_water: hw }),
            _ => Ok(()),
        }
    }
}
