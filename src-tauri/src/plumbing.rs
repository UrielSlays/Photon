//! Plumbing: the blocking pool, the session lock, and the credential check for provider reads.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::credential::{load_gmail_credential, unix_now, CredentialLoadFailure, GmailCredential};
use crate::credential_cell::{AdmitIo, CredentialCoordinator};
use crate::error::SurfaceError;
use crate::provider::{build_gmail_arm, ArmBuildError, GmailBus, GmailProvider, Provider};
use crate::session::PhotonSession;
use crate::state::PhotonState;
use crate::token_refresh::{
    self, persist_credential, CredentialLock, FileGen, GrantProvenance, RefreshClient,
    RefreshLocalError, CREDENTIAL_FILE_NAME,
};
use crate::SessionConfig;

/// Run store work on the blocking pool with the session mutex held only inside the closure.
///
/// The guard is taken inside the blocking closure and dropped when it returns, so no caller can
/// hold it across an `.await`, which is the only way to hold a lock across provider I/O in an
/// async command.
pub(crate) async fn with_session<T, F>(session: Arc<Mutex<PhotonSession>>, f: F) -> Result<T, SurfaceError>
where
    T: Send + 'static,
    F: FnOnce(&mut PhotonSession) -> Result<T, SurfaceError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let mut guard = session.lock().map_err(|_| SurfaceError::Internal {
            reason: "the session lock is poisoned — a previous store operation panicked"
                .to_string(),
        })?;
        f(&mut guard)
    })
    .await
    .map_err(join_failed)?
}

/// The owned form of the coordinator's I/O, which an async command hands to the blocking pool.
/// It is borrowed into an [`AdmitIo`] on the pool thread so every closure runs inside the
/// critical section and none can touch the async runtime.
pub(crate) struct AdmitIoOwned {
    pub(crate) config: SessionConfig,
    pub(crate) refresh_client: Option<RefreshClient>,
    /// The coordinator this I/O rebuilds arms for, held weakly. A rebuilt arm's bus carries a
    /// [`ShellGrantRatchet`] over it, as the boot arm's does.
    pub(crate) credential: Weak<CredentialCoordinator>,
    /// Test seam: [`PhotonState::admit_provider_sync`] pins the wave's use-time clock to the
    /// test's clock so the whole protocol sees one time. Production never sets it;
    /// [`AdmitIo::now_unix`] reads the wall clock.
    #[cfg(test)]
    pub(crate) now_override: Option<i64>,
}

impl AdmitIo for AdmitIoOwned {
    fn load(&self) -> Result<GmailCredential, CredentialLoadFailure> {
        load_gmail_credential(&self.config.gmail_secrets_dir)
    }

    fn now_unix(&self) -> i64 {
        #[cfg(test)]
        if let Some(n) = self.now_override {
            return n;
        }
        unix_now()
    }

    fn file_gen(&self) -> Result<FileGen, RefreshLocalError> {
        // A read error is preserved as a typed local failure. Absence is already
        // `FileGen::Absent`, so flattening `Err` to "no generation" would turn an unreadable
        // digest into a phantom file change that could release a terminal latch.
        FileGen::of(&self.config.gmail_secrets_dir.join(CREDENTIAL_FILE_NAME)).map_err(|e| {
            RefreshLocalError::FileGenUnreadable {
                reason: token_refresh::LocalIoReason(e.kind()),
            }
        })
    }

    fn exchange(
        &self,
        refresh_token: &str,
        now_unix: i64,
        stored_scopes: &BTreeSet<String>,
    ) -> Result<token_refresh::RefreshOutcome, RefreshLocalError> {
        // Config first: a missing or refused client file is the cure the operator can act on, so
        // it wins over the cached HTTP client's state.
        let cfg = token_refresh::ClientConfig::load(&self.config.gmail_secrets_dir)?;
        // The startup-built client is a fast path, not a dependency: `.ok()` once cached a build
        // failure as a permanent `None` whose `retry_later` cure could never come true. Retry the
        // construction here (milliseconds, against an already-refused read) so the cure the
        // refusal names is one that works.
        let client = match &self.refresh_client {
            Some(c) => c.clone(),
            // A dedicated pre-wire variant: `RebuildFailed`'s sentence claims "renewed and
            // written", which is false before any POST.
            None => RefreshClient::production().map_err(|_| RefreshLocalError::ClientBuild)?,
        };
        // The authority reference is the stored grant, never the compiled constant (RFC 6749 §6).
        // The caller reads it off the credential the wave just loaded.
        Ok(client.exchange(&cfg, refresh_token, now_unix, stored_scopes))
    }

    fn persist(
        &self,
        access: &str,
        survivor: &str,
        expires_at: i64,
        grant: &GrantProvenance,
    ) -> Result<FileGen, RefreshLocalError> {
        persist_credential(
            &self.config.gmail_secrets_dir,
            access,
            survivor,
            expires_at,
            grant,
        )
    }

    fn rebuild(
        &self,
        credential: &GmailCredential,
        held: &CredentialLock,
    ) -> Result<Provider, RefreshLocalError> {
        build_gmail_arm(&self.config, credential, held, &self.credential).map_err(|e| match e {
            // The grant refusal keeps its type across this boundary. Flattening it into
            // `RebuildFailed` would tell the operator "Photon will retry on your next command"
            // for a state only a re-mint cures, and claim the credential "was renewed and
            // written", which is false here.
            ArmBuildError::Grant(typed) => typed,
            ArmBuildError::Construction(reason) => RefreshLocalError::RebuildFailed { reason },
        })
    }

    fn lock(&self, path: &Path, deadline: Duration) -> Result<CredentialLock, RefreshLocalError> {
        CredentialLock::try_acquire(path, deadline)
    }
}

/// The credential check for a provider-reading command: reconcile the file, renew if expired,
/// publish, and return the live arm. All of it runs on the blocking pool, with the writer lock
/// held only inside the coordinator's critical section (never across an `.await`).
///
/// Callers: `refresh_inbox`, `refresh_more_inbox` and `message_body`, right after their pacing
/// check, and `plan_apply`, right after its single-flight claim (a plan run reads the provider at
/// preflight, so it renews an expired token the way the read commands do). The verb and undo
/// paths, the other plan commands and the knob command do not call it: every verb on this arm is
/// refused by the mutation fence before a socket exists. A plan child meets send admission, whose
/// grant row consults `ShellGrantRatchet`. A retired generation refuses at credential load / arm
/// construction, at token refresh and at send admission, not by re-validating a live read arm
/// per command.
pub(crate) async fn admit_provider(state: &PhotonState) -> Result<Arc<GmailProvider>, SurfaceError> {
    if !state.refresh_armed() {
        return state.gmail();
    }
    let owned = state.admit_io();
    let coordinator = state.credential_handle();
    tauri::async_runtime::spawn_blocking(move || {
        coordinator.admit(unix_now(), Instant::now(), &owned)
    })
    .await
    .map_err(join_failed)?
}

/// Run a provider call on the blocking pool. It takes only the provider handle, so no session
/// guard is in scope at any call site.
pub(crate) async fn with_provider<T, F>(provider: Arc<GmailProvider>, f: F) -> Result<T, SurfaceError>
where
    T: Send + 'static,
    F: FnOnce(&GmailProvider) -> Result<T, SurfaceError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || f(&provider))
        .await
        .map_err(join_failed)?
}

fn join_failed(e: tauri::Error) -> SurfaceError {
    SurfaceError::Internal {
        reason: format!("a blocking operation did not complete: {e}"),
    }
}

pub(crate) fn lock_bus(provider: &GmailProvider) -> Result<std::sync::MutexGuard<'_, GmailBus>, SurfaceError> {
    provider.bus.lock().map_err(|_| SurfaceError::Internal {
        reason: "the mutation boundary's lock is poisoned — a previous verb panicked".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::fixtures::gmail_arm_state_expiring;
    use crate::token_refresh::Cure;

    // The OPERATOR'S actionable cure outranks the HTTP-client cache state,
    // and a startup client-build failure is retried per wave rather than cached as a forever-
    // `None` whose `retry_later` cure could never come true.
    #[test]
    fn a_missing_client_config_outranks_a_missing_http_client() {
        let expires_at = unix_now() + 3_600;
        let (dir, mut state) = gmail_arm_state_expiring("cfg-first", expires_at);
        // Simulate the one-time startup TLS failure.
        state.refresh_client = None;

        match state.admit_provider_sync(expires_at + 1) {
            Err(SurfaceError::CredentialExpired { cure, reason, .. }) => {
                assert_eq!(
                    cure,
                    Cure::ClientConfig,
                    "the missing client file is the cure the operator can act on — it must \
                     win over the cached-client state: {reason}"
                );
                assert!(reason.contains("client_secret.json"), "{reason}");
            }
            other => panic!(
                "an expired read with no client file refuses with the CONFIG cure: {:?}",
                other.err()
            ),
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
