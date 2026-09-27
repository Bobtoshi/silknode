//! Exact independent Sapling verifications. No probabilistic batch acceptance.

use crate::{
    Error, Result,
    codec::{EFFECT_BYTES, ENVELOPE_BYTES, Envelope, EnvelopeView, domain_hash, field},
    parameters::{SaplingParameters, SaplingVerificationKeys},
};
use bellman::groth16::Proof;
use bls12_381::{Bls12, Scalar};
use ff::PrimeField;
use group::GroupEncoding;
use redjubjub::{Binding, Signature, SpendAuth, VerificationKey};
use sapling_crypto::{
    SaplingVerificationContext,
    circuit::{PreparedOutputVerifyingKey, PreparedSpendVerifyingKey},
    note::ExtractedNoteCommitment,
    value::ValueCommitment,
};

/// Real context-independent crypto validity. Only this module can construct it.
/// It does not establish work, canonical order, spentness, or anchor eligibility.
#[derive(Clone, Debug)]
pub struct VerifiedEnvelope {
    envelope: Envelope,
}

impl VerifiedEnvelope {
    /// Exact independently verified representation.
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }
}

/// Check all four Groth16 proofs, both spend authorizations and binding signature.
///
/// Call only after genuine work for peer carrier admission. Local wallet preparation
/// may call directly but gains no graph/economic authority.
///
/// # Errors
/// Returns `Encoding` for noncanonical curve/proof bytes, or `Crypto` for a failed check.
pub fn verify(envelope: Envelope, parameters: &SaplingParameters) -> Result<VerifiedEnvelope> {
    check_crypto(
        envelope.bytes(),
        envelope.anchor(),
        envelope.sighash(),
        &parameters.spend_vk,
        &parameters.output_vk,
    )?;
    Ok(VerifiedEnvelope { envelope })
}

/// Verify all exact proofs/authorizations without copying or owning the plaintext.
/// Relay verification gains no work, spentness or ledger acceptance authority.
/// # Errors
/// Identical encoding/cryptographic checks to `verify`; local budgets are external.
pub fn verify_borrowed(envelope: &EnvelopeView<'_>, keys: &SaplingVerificationKeys) -> Result<()> {
    check_crypto(
        envelope.bytes(),
        envelope.anchor(),
        domain_hash("SilkNode-F0-sign", &[&envelope.bytes()[..EFFECT_BYTES]]),
        &keys.spend_vk,
        &keys.output_vk,
    )
}

fn check_crypto(
    b: &[u8; ENVELOPE_BYTES],
    anchor: crate::Digest,
    sighash: crate::Digest,
    spend_vk: &PreparedSpendVerifyingKey,
    output_vk: &PreparedOutputVerifyingKey,
) -> Result<()> {
    let anchor = Option::<Scalar>::from(Scalar::from_repr(anchor))
        .ok_or(Error::Encoding("Sapling anchor"))?;
    let mut ctx = SaplingVerificationContext::new();
    for i in 0..2 {
        let at = 85 + 96 * i;
        let cv = cv(&field(&b[..], at))?;
        let rk = VerificationKey::<SpendAuth>::try_from(field::<32>(&b[..], at + 64))
            .map_err(|_| Error::Encoding("Sapling rk"))?;
        let proof = Proof::<Bls12>::read(&b[1830 + 192 * i..1830 + 192 * (i + 1)])
            .map_err(|_| Error::Encoding("Sapling spend proof"))?;
        let sig = Signature::from(field::<64>(&b[..], 2214 + 64 * i));
        if !ctx.check_spend(
            &cv,
            anchor,
            &field(&b[..], at + 32),
            rk,
            &sighash,
            sig,
            proof,
            spend_vk,
        ) {
            return Err(Error::Crypto("spend"));
        }
    }
    for i in 0..2 {
        let at = 278 + 756 * i;
        let cv = cv(&field(&b[..], at))?;
        let cmu = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(
            &field(&b[..], at + 32),
        ))
        .ok_or(Error::Encoding("Sapling cmu"))?;
        let epk = Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&field(
            &b[..],
            at + 64,
        )))
        .ok_or(Error::Encoding("Sapling epk"))?;
        let proof = Proof::<Bls12>::read(&b[2342 + 192 * i..2342 + 192 * (i + 1)])
            .map_err(|_| Error::Encoding("Sapling output proof"))?;
        if !ctx.check_output(&cv, cmu, epk, proof, output_vk) {
            return Err(Error::Crypto("output"));
        }
    }
    if !ctx.final_check(
        1_i64,
        &sighash,
        Signature::<Binding>::from(field::<64>(&b[..], 2726)),
    ) {
        return Err(Error::Crypto("binding signature"));
    }
    Ok(())
}

fn cv(bytes: &[u8; 32]) -> Result<ValueCommitment> {
    Option::<ValueCommitment>::from(ValueCommitment::from_bytes_not_small_order(bytes))
        .ok_or(Error::Encoding("Sapling value commitment"))
}

/// Verify one bounded batch using 1..=2 caller-scoped workers.
///
/// At most 32 inputs; every check is exact and results retain input order.
/// No partial success capability is returned. An operating node must serialize
/// outer batch admission and enforce its whole-job CPU/RSS/wall limits separately.
/// This bounds library work; it is not an OS CPU/RSS enforcement claim.
///
/// # Errors
/// Returns the first ordered validation error, or `Resource` for excess input/workers
/// or an unavailable/failed worker.
pub fn verify_many(
    envelopes: Vec<Envelope>,
    parameters: &SaplingParameters,
    workers: usize,
) -> Result<Vec<VerifiedEnvelope>> {
    if envelopes.len() > 32 || !(1..=2).contains(&workers) {
        return Err(Error::Resource("verification batch/workers"));
    }
    if workers == 1 || envelopes.len() < 2 {
        return envelopes
            .into_iter()
            .map(|e| verify(e, parameters))
            .collect();
    }
    let split = envelopes.len().div_ceil(2);
    let mut first = envelopes;
    let second = first.split_off(split);
    std::thread::scope(|scope| {
        let a = std::thread::Builder::new()
            .name("f04-exact-verify".into())
            .spawn_scoped(scope, move || {
                first
                    .into_iter()
                    .map(|e| verify(e, parameters))
                    .collect::<Result<Vec<_>>>()
            })
            .map_err(|_| Error::Resource("verification worker unavailable"))?;
        let b = second
            .into_iter()
            .map(|e| verify(e, parameters))
            .collect::<Result<Vec<_>>>();
        let mut a = a
            .join()
            .map_err(|_| Error::Resource("verification worker failed"))??;
        a.extend(b?);
        Ok(a)
    })
}
