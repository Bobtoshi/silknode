//! One local wallet worker with independent public-lifecycle driving. No proof
//! output channel, automatic offer, timer reset, retry or node-thread migration.
use super::{ProcessV1, QualifiedClockSample};
use silk_f04_relay::{Error as DriveError, Result as DriveResult};
use silk_f04_wallet::{
    Error as WalletError, Result as WalletResult,
    journal::intents::{IntentJournal, IntentReceipt, canonical::ReadyWalletView},
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::{thread, time::Duration};

/// Exactly one explicitly requested operation. Reservation and proving are
/// separate so the caller can independently retain the first receipt's pins.
pub enum WalletStepV1<'a> {
    /// Reserve a fresh payment with no earlier possibly exposed current intent.
    Reserve {
        /// Explicit full-domain recipient descriptor, not a network lookup.
        recipient: &'a str,
        /// Positive payment value; the existing one-unit fee is separate.
        value: u64,
    },
    /// Explicit new economic payment, retaining all old input exclusions.
    ReserveDistinct {
        /// Explicit full-domain recipient descriptor for the new payment.
        recipient: &'a str,
        /// Positive payment value; previous exposed inputs remain excluded.
        value: u64,
    },
    /// Prove the exact already-reserved payment, then durably latch exposure.
    Prove {
        /// Existing complete, authenticated Sapling parameters; never fetched here.
        parameters: &'a SaplingParameters,
    },
}

/// Neither result substitutes for the other. A failed client driver MUST NOT
/// hide a newly committed wallet pin or cause automatic proving/export again.
pub struct WalletStepReportV1 {
    /// New local pins, or failure leaving the existing wallet recovery rules intact.
    pub wallet: WalletResult<IntentReceipt>,
    /// First public-lifecycle/clock error. Driving stops, but the worker is joined.
    pub first_drive_error: Option<DriveError>,
}

/// Run one closed wallet operation on one scoped worker while the caller's
/// existing public lifecycle continues on the original process/node thread.
///
/// `drive` must obtain a FRESH qualified sample and service predetermined round
/// admission (with no ready offer), maintenance and outcome draining. This helper
/// then calls `ProcessV1::poll`. It creates no rounds, reconnect policy or clocks.
/// The callback must be bounded/nonblocking; native CPU/memory/thread containment
/// is still required externally. Sleep is fixed1ms, not payment-dependent pacing.
///
/// The journal's exclusive borrow prohibits export/overlapping jobs until return.
/// Only a receipt returns: retain both pins, then separately decide whether to
/// export/admit ONE offer to a future round. An already selected cover is never
/// replaced. Failure/panic never retries, cancels or unreserves this operation.
///
/// A driver error stops further network driving; the existing worker is allowed
/// to finish under its original external limits so its receipt is not discarded.
/// # Panics
/// A panic in the caller's drive callback unwinds the scope and joins its worker;
/// callers must treat lost receipts as uncertain and use explicit wallet recovery.
pub fn run_wallet_step_v1(
    process: &mut ProcessV1,
    journal: &mut IntentJournal<'_, '_>,
    view: ReadyWalletView<'_>,
    step: WalletStepV1<'_>,
    mut drive: impl FnMut(&mut ProcessV1) -> DriveResult<QualifiedClockSample>,
) -> WalletStepReportV1 {
    run_scoped(
        move || match step {
            WalletStepV1::Reserve { recipient, value } => {
                journal.reserve_from_view(&view, recipient, value)
            }
            WalletStepV1::ReserveDistinct { recipient, value } => {
                journal.reserve_distinct_from_view(&view, recipient, value)
            }
            WalletStepV1::Prove { parameters } => journal.prove_from_view(&view, parameters),
        },
        || drive(process).and_then(|sample| process.poll(&sample)),
    )
}

// Private closure seam permits bounded scheduling tests without generating
// proofs. Production callers can select only the closed operations above.
fn run_scoped(
    work: impl FnOnce() -> WalletResult<IntentReceipt> + Send,
    mut drive: impl FnMut() -> DriveResult<()>,
) -> WalletStepReportV1 {
    thread::scope(|scope| {
        let worker = match thread::Builder::new()
            .name("f04-wallet-step".into())
            .spawn_scoped(scope, work)
        {
            Ok(worker) => worker,
            Err(_) => {
                return WalletStepReportV1 {
                    wallet: Err(WalletError::Unavailable("wallet worker unavailable")),
                    first_drive_error: None,
                };
            }
        };
        let mut first_drive_error = None;
        while !worker.is_finished() {
            if first_drive_error.is_none() {
                first_drive_error = drive().err();
            }
            thread::sleep(Duration::from_millis(1));
        }
        WalletStepReportV1 {
            wallet: worker.join().unwrap_or(Err(WalletError::Unavailable(
                "wallet worker panicked; no automatic retry",
            ))),
            first_drive_error,
        }
    })
}

#[cfg(test)]
mod tests;
