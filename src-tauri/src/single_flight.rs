//! The single-flight table and the refresh pacing that bound provider traffic.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::SurfaceError;

/// What is in flight: per kind for whole-mailbox operations, per message for the ones that name
/// a message ("a refresh in flight coalesces/rejects duplicates, per-message body-fetch
/// coalescing").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OperationKind {
    /// One refresh at a time, mailbox-wide.
    RefreshInbox,
    /// One body fetch at a time per message; a second message is not blocked by the first.
    MessageBody(String),
    /// One mutation at a time per message, so a double keypress cannot mint two intents for the
    /// same row before the first one's outcome is known.
    Verb(String),
    /// One undo at a time per undo key.
    Undo(String),
    /// One `plan_apply` run at a time per plan: a second apply of the same plan while the first
    /// drives its members is refused `Busy`, never queued.
    Plan(String),
}

impl OperationKind {
    pub(crate) fn label(&self) -> String {
        match self {
            OperationKind::RefreshInbox => "refresh_inbox".to_string(),
            OperationKind::MessageBody(r) => format!("message_body:{r}"),
            OperationKind::Verb(r) => format!("verb:{r}"),
            OperationKind::Undo(k) => format!("undo:{k}"),
            OperationKind::Plan(id) => format!("plan:{id}"),
        }
    }
}

/// The single-flight table.
///
/// It is not a quota accountant, token bucket, rate limiter or abuse detector. It holds no
/// counters, timestamps or provider quota numbers (two sources cited conflicting Gmail quota
/// tables, so no number is encoded). It answers one question: is an identical operation already
/// running?
#[derive(Debug, Default)]
pub struct InFlight {
    slots: Mutex<HashSet<OperationKind>>,
}

impl InFlight {
    /// Claim the slot for `kind`, or `None` if it is taken (the caller returns typed `Busy`).
    ///
    /// The claim is a guard: the slot is released by [`Drop`], so an early return, a `?` on an
    /// engine error, or a panic inside a command cannot leak a permanently-busy operation.
    pub fn claim(&self, kind: OperationKind) -> Option<InFlightClaim<'_>> {
        let mut slots = self.slots.lock().ok()?;
        if !slots.insert(kind.clone()) {
            return None;
        }
        Some(InFlightClaim { table: self, kind })
    }
}

/// The minimum gap between the completion of one `refresh_inbox` and the admission of the next.
/// Single-flight only stops concurrent refreshes; a caller that waits for the first to finish
/// and asks again would be admitted every time, so a stuck retry loop would run the provider
/// read as fast as the network allows.
///
/// 15 seconds is a floor on how often a human-driven refresh is worth a round trip, not a quota
/// calculation, and is not derived from any provider quota table.
pub const MIN_REFRESH_INTERVAL_MS: u64 = 15_000;

/// How long a recorded provider backoff holds after a 429-class refusal.
///
/// The pause is fixed: the provider's own `Retry-After` is not surfaced through `GmailError` (the
/// variant is a bare `RateLimit`), so there is nothing to honour, and an adaptive schedule would
/// amount to a quota accountant. When the transport carries the provider's own number, this
/// constant should be replaced by it.
pub const PROVIDER_BACKOFF_MS: u64 = 60_000;

/// The pacing state beside [`InFlight`]: two instants and nothing else. When did a refresh last
/// complete, and until when did the provider tell us to stop asking. Like [`InFlight`], it is
/// not a quota accountant: no hit counter, window, per-route budget or quota number.
///
/// The credential renewal has a third floor of the same kind, a minimum interval between
/// token-endpoint attempts (`credential_cell::REFRESH_ATTEMPT_FLOOR`). It lives beside the
/// credential cell it paces rather than in this struct.
///
/// Every method takes `now` as a parameter instead of reading the clock, so the behaviour can be
/// tested at this seam without sleeping (commands pass `Instant::now()`).
#[derive(Debug, Default)]
pub struct Pacing {
    /// When the last `refresh_inbox` finished its provider call; `None` until one has.
    last_refresh_completed: Mutex<Option<Instant>>,
    /// When a recorded provider backoff expires. `None` when no 429-class answer is outstanding.
    provider_backoff_until: Mutex<Option<Instant>>,
}

impl Pacing {
    /// May this operation reach the provider right now? `Ok(())`, or the typed refusal that says
    /// why not and for how long.
    ///
    /// The provider's own backoff is checked first: when both conditions hold it is the truthful
    /// reason, and the caller cannot fix it by waiting out the shorter local floor.
    pub fn admit(&self, kind: &OperationKind, now: Instant) -> Result<(), SurfaceError> {
        if let Some(until) = *self.provider_backoff_until.lock().map_err(poisoned_pacing)? {
            if let Some(left) = remaining_ms(until, now) {
                return Err(SurfaceError::ProviderBackoff {
                    operation: kind.label(),
                    retry_after_ms: left,
                });
            }
        }
        // The cadence floor is a refresh property. A body read is user-directed at one message and
        // already single-flighted per message, so the mailbox-wide floor does not bind it.
        if matches!(kind, OperationKind::RefreshInbox) {
            if let Some(last) = *self.last_refresh_completed.lock().map_err(poisoned_pacing)? {
                let earliest = last + Duration::from_millis(MIN_REFRESH_INTERVAL_MS);
                if let Some(left) = remaining_ms(earliest, now) {
                    return Err(SurfaceError::TooSoon {
                        operation: kind.label(),
                        retry_after_ms: left,
                    });
                }
            }
        }
        Ok(())
    }

    /// Record that a refresh's provider call has finished, success or failure: the round trip
    /// was spent either way and the floor is about traffic, not outcomes.
    pub fn refresh_completed(&self, now: Instant) {
        if let Ok(mut slot) = self.last_refresh_completed.lock() {
            *slot = Some(now);
        }
    }

    /// Record a 429-class provider answer: refuse both read operations until
    /// [`PROVIDER_BACKOFF_MS`] has passed. A later 429 moves the instant forward; there is no
    /// escalation and nothing counts occurrences.
    pub fn provider_asked_us_to_back_off(&self, now: Instant) {
        if let Ok(mut slot) = self.provider_backoff_until.lock() {
            *slot = Some(now + Duration::from_millis(PROVIDER_BACKOFF_MS));
        }
    }
}

/// Milliseconds left until `deadline`, or `None` once it has passed. Saturating, so a clock that
/// hands back an earlier instant cannot produce a huge wait.
fn remaining_ms(deadline: Instant, now: Instant) -> Option<u64> {
    let left = deadline.saturating_duration_since(now);
    (!left.is_zero()).then(|| left.as_millis().min(u64::MAX as u128) as u64)
}

/// A poisoned pacing mutex means a panic inside one of the short critical sections above. There
/// is nothing to recover, so this fails closed as an internal refusal rather than admitting an
/// unpaced provider call.
fn poisoned_pacing<T>(_: std::sync::PoisonError<T>) -> SurfaceError {
    SurfaceError::Internal {
        reason: "the pacing state is poisoned — a previous refresh admission panicked".to_string(),
    }
}

/// A held single-flight slot. Releasing is [`Drop`]'s job; see [`InFlight::claim`].
#[derive(Debug)]
pub struct InFlightClaim<'a> {
    table: &'a InFlight,
    kind: OperationKind,
}

impl Drop for InFlightClaim<'_> {
    fn drop(&mut self) {
        // A poisoned table means a panic inside the short critical section above. Nothing can be
        // recovered or reported from a Drop, so the slot stays claimed rather than the process
        // dying on a second panic.
        if let Ok(mut slots) = self.table.slots.lock() {
            slots.remove(&self.kind);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================================================================
    // The refresh cadence floor + the retained provider backoff.
    //
    // Tested at the SYNC SEAM (the same T9 pattern `session_status_view` uses): `tauri::State` has
    // no constructor outside a running app, so the commands themselves are not unit-testable —
    // [`Pacing`] is the seam they call, and it takes `now` as a parameter precisely so a test can
    // move time without sleeping.
    // ===========================================================================================

    #[test]
    fn the_first_refresh_of_a_session_is_never_too_soon() {
        let pacing = Pacing::default();
        pacing
            .admit(&OperationKind::RefreshInbox, Instant::now())
            .expect("a session that has never refreshed has no floor to violate");
    }

    #[test]
    fn a_refresh_inside_the_cadence_floor_is_refused_with_a_typed_retry_after() {
        let pacing = Pacing::default();
        let t0 = Instant::now();
        pacing.refresh_completed(t0);

        // 1ms after the previous refresh COMPLETED. Single-flight admits this — the first claim
        // was already dropped — which is exactly how a serial refresh loop hammers the provider.
        match pacing.admit(&OperationKind::RefreshInbox, t0 + Duration::from_millis(1)) {
            Err(SurfaceError::TooSoon {
                operation,
                retry_after_ms,
            }) => {
                assert_eq!(operation, "refresh_inbox");
                assert_eq!(
                    retry_after_ms,
                    MIN_REFRESH_INTERVAL_MS - 1,
                    "the refusal tells the caller WHEN, so a UI never has to guess or poll"
                );
            }
            other => panic!("a refresh inside the cadence floor must be refused: {other:?}"),
        }

        // Exactly at the floor it is admitted again — the floor is a wait, not a lockout.
        pacing
            .admit(
                &OperationKind::RefreshInbox,
                t0 + Duration::from_millis(MIN_REFRESH_INTERVAL_MS),
            )
            .expect("once the interval has passed the refresh is admitted");
    }

    #[test]
    fn the_cadence_floor_applies_to_refresh_only_never_to_a_body_read() {
        let pacing = Pacing::default();
        let t0 = Instant::now();
        pacing.refresh_completed(t0);
        pacing
            .admit(
                &OperationKind::MessageBody("m1".to_string()),
                t0 + Duration::from_millis(1),
            )
            .expect("a body read is not a refresh — the mailbox-wide floor does not bind it");
    }

    #[test]
    fn a_recorded_provider_backoff_refuses_both_refresh_and_body_until_the_instant_passes() {
        let pacing = Pacing::default();
        let t0 = Instant::now();
        // The provider answered 429-class (`GmailError::RateLimit`): the shell REMEMBERS it rather
        // than letting the next click re-ask immediately.
        pacing.provider_asked_us_to_back_off(t0);

        for kind in [
            OperationKind::RefreshInbox,
            OperationKind::MessageBody("m1".to_string()),
        ] {
            match pacing.admit(&kind, t0 + Duration::from_millis(1)) {
                Err(SurfaceError::ProviderBackoff {
                    operation,
                    retry_after_ms,
                }) => {
                    assert_eq!(operation, kind.label());
                    assert_eq!(retry_after_ms, PROVIDER_BACKOFF_MS - 1);
                }
                other => panic!("{kind:?} must be refused while the backoff holds: {other:?}"),
            }
        }

        // Once the recorded instant passes, both operations are admitted again — and the refresh
        // is NOT additionally blocked by the cadence floor, because a refused refresh never ran.
        let after = t0 + Duration::from_millis(PROVIDER_BACKOFF_MS);
        pacing
            .admit(&OperationKind::RefreshInbox, after)
            .expect("the backoff expires; it is a pause, not a permanent fence");
        pacing
            .admit(&OperationKind::MessageBody("m1".to_string()), after)
            .expect("the backoff expires for body reads too");
    }

    #[test]
    fn the_provider_backoff_outranks_the_cadence_floor_in_the_refusal_it_names() {
        // Both conditions hold at once. The refusal must name the PROVIDER's backoff — the reason
        // the caller cannot fix by waiting the (shorter) local interval.
        let pacing = Pacing::default();
        let t0 = Instant::now();
        pacing.refresh_completed(t0);
        pacing.provider_asked_us_to_back_off(t0);
        match pacing.admit(&OperationKind::RefreshInbox, t0 + Duration::from_millis(1)) {
            Err(SurfaceError::ProviderBackoff { .. }) => {}
            other => panic!("the provider's own backoff is the truthful reason: {other:?}"),
        }
    }

    #[test]
    fn pacing_holds_timestamps_only_never_a_counter_or_a_quota_number() {
        // The tripwire, restated as a test: the ONLY state here is two instants. A hit counter, a
        // token bucket or a provider quota table would have to appear in this struct's fields, and
        // this assertion is where a reviewer looks for it.
        let pacing = Pacing::default();
        let t0 = Instant::now();
        for _ in 0..50 {
            let _ = pacing.admit(&OperationKind::RefreshInbox, t0);
        }
        pacing
            .admit(&OperationKind::RefreshInbox, t0)
            .expect("fifty refused attempts change nothing — there is nothing counting them");
    }
}
