//! Complete authenticated ancestry, streamed one record at a time. No peer authority.
use super::{
    AeadInOut, Digest, Error, InputRef, IntentStatus, Journal, KeyInit, MAX_RECORDS, RECORD_HEADER,
    Result, SEALED, State, XChaCha20Poly1305, XNonce, Zeroizing, context_bytes, decode,
    domain_hash, field, id, name, number, read,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

pub(super) struct Audit {
    pub sequence: u64,
    pub state: State,
    pub exposed: BTreeMap<Digest, InputRef>,
}
struct Record {
    version: u8,
    sequence: u64,
    previous: Digest,
    state: State,
}
fn record(journal: &Journal<'_>, expected: Digest) -> Result<Record> {
    let bytes = read(&journal.directory, &name(expected), SEALED)?;
    let version = match &bytes[..8] {
        b"SNF04PH1" => 1,
        b"SNF04PH2" => 2,
        _ => return Err(Error::Authentication),
    };
    if id(&bytes) != expected
        || bytes[8..40] != domain_hash("SilkNode-F04-local-wallet-store", &[&journal.header])
    {
        return Err(Error::Authentication);
    }
    let sequence = number(&bytes, 40);
    let previous = field(&bytes, 48);
    if sequence >= MAX_RECORDS || (sequence == 0) != (previous == [0; 32]) {
        return Err(Error::Authentication);
    }
    let nonce = field::<24>(&bytes, 80);
    let mut plain = Zeroizing::new(bytes[RECORD_HEADER..].to_vec());
    XChaCha20Poly1305::new_from_slice(journal.cipher_key.as_ref())
        .map_err(|_| Error::Authentication)?
        .decrypt_in_place(&XNonce::from(nonce), &bytes[..RECORD_HEADER], &mut *plain)
        .map_err(|_| Error::Authentication)?;
    let state = decode(&plain, journal.key)?;
    if (sequence == 0) != (state.status == IntentStatus::Empty) {
        return Err(Error::Authentication);
    }
    Ok(Record {
        version,
        sequence,
        previous,
        state,
    })
}

pub(super) fn transition(older: &State, newer: &State, newer_version: u8) -> Result<()> {
    let same_plan = match (&older.plan, &newer.plan) {
        (Some(a), Some(b)) => {
            a.id == b.id
                && a.inputs == b.inputs
                && context_bytes(a.context) == context_bytes(b.context)
                && a.recipient == b.recipient
                && a.value == b.value
                && a.change == b.change
                && a.change_value == b.change_value
        }
        _ => false,
    };
    let new_identity = newer
        .plan
        .as_ref()
        .is_some_and(|b| older.plan.as_ref().is_none_or(|a| a.id != b.id));
    let permitted = match (older.status, newer.status) {
        (IntentStatus::Empty | IntentStatus::CancelledBeforeRelease, IntentStatus::Reserved) => {
            new_identity
        }
        (
            IntentStatus::Reserved,
            IntentStatus::MayHaveEscaped | IntentStatus::CancelledBeforeRelease,
        ) => same_plan,
        (IntentStatus::MayHaveEscaped, IntentStatus::Reserved) => {
            newer_version == 2 && new_identity
        }
        _ => false,
    };
    if permitted {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

pub(super) fn audit(journal: &Journal<'_>, expected: Digest) -> Result<Audit> {
    let started = Instant::now();
    let mut current = record(journal, expected)?;
    let mut audited = Audit {
        sequence: current.sequence,
        state: current.state.clone(),
        exposed: BTreeMap::new(),
    };
    // Walking backward, any reservation already seen is LATER than this exposure.
    // Thus we can detect historical reuse without retaining every plaintext state
    // or quadratic scans. Sets are bounded by two inputs per fixed sequence slot.
    let mut newer_reservations = BTreeSet::new();
    loop {
        if started.elapsed() > Duration::from_secs(10) {
            return Err(Error::Unavailable(
                "complete payment history audit allowance",
            ));
        }
        if let Some(plan) = &current.state.plan {
            match current.state.status {
                IntentStatus::Reserved => {
                    newer_reservations.extend(plan.inputs.iter().map(|input| input.nf));
                }
                IntentStatus::MayHaveEscaped => {
                    for input in &plan.inputs {
                        if newer_reservations.contains(&input.nf)
                            || audited.exposed.insert(input.nf, input.clone()).is_some()
                        {
                            return Err(Error::Authentication);
                        }
                    }
                }
                _ => {}
            }
        }
        if current.sequence == 0 {
            break;
        }
        let older = record(journal, current.previous)?;
        if older.sequence.checked_add(1) != Some(current.sequence)
            || older.version > current.version
        {
            return Err(Error::Authentication);
        }
        transition(&older.state, &current.state, current.version)?;
        current = older;
    }
    // No partial cache can bypass missing ancestry, and a changed HEAD cannot be
    // adopted after validation. Hostile same-user filesystem mutation is not solved.
    if read(&journal.directory, "HEAD", 32)? != journal.head
        || read(&journal.directory, "INTENT_HEAD", 32)? != expected
    {
        return Err(Error::Unavailable(
            "payment continuity changed during audit",
        ));
    }
    Ok(audited)
}
