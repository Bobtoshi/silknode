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

/// Compact, immutable IN-PROCESS capability for one exact verified representation.
///
/// Constructed only from `VerifiedEnvelope`; no deserialization/peer constructor.
/// The full representation hash includes proofs and signatures, not just effects.
/// It confers no work, graph, spentness, cut, settlement or genesis authority.
#[derive(Clone)]
pub struct LiveRepresentationBinding {
    domain: crate::Digest,
    representation: crate::Digest,
}

impl LiveRepresentationBinding {
    /// Reattach ONLY the same full immutable representation to its live capability.
    /// This is positive-capability reuse, not fresh proof verification. Cold node
    /// reopen must independently verify every original proof before creating it.
    /// # Errors
    /// Rejects a different context or any changed full-representation identifier.
    pub fn reattach(&self, envelope: Envelope) -> Result<VerifiedEnvelope> {
        if envelope.domain() != self.domain || envelope.envelope_id() != self.representation {
            return Err(Error::Encoding("live verified representation mismatch"));
        }
        Ok(VerifiedEnvelope { envelope })
    }
}

impl VerifiedEnvelope {
    /// Exact independently verified representation.
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }
    /// Retain a live exact-representation capability without retaining 2,790 bytes.
    /// This binding is never accepted from disk, a peer, a snapshot or a flag.
    #[must_use]
    pub fn live_representation_binding(&self) -> LiveRepresentationBinding {
        LiveRepresentationBinding {
            domain: self.envelope.domain(),
            representation: self.envelope.envelope_id(),
        }
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

#[cfg(test)]
mod live_binding_tests {
    use super::*;

    #[test]
    fn live_binding_compact_capability_refuses_every_changed_representation_class() {
        // Private test-only capability model, NOT a genuine cryptographic fixture.
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes[..12].copy_from_slice(b"SNPRV003\x03\0\0\0");
        bytes[12..44].fill(23);
        bytes[84] = 2;
        bytes[277] = 2;
        bytes[117] = 1;
        bytes[213] = 2;
        bytes[1790..1798].copy_from_slice(&1_i64.to_le_bytes());
        let envelope = Envelope::decode(&bytes, &[23; 32]).unwrap();
        let verified = VerifiedEnvelope {
            envelope: envelope.clone(),
        };
        let binding = verified.live_representation_binding();
        assert_eq!(std::mem::size_of::<LiveRepresentationBinding>(), 64);
        drop(verified);
        assert_eq!(
            binding
                .clone()
                .reattach(envelope)
                .unwrap()
                .envelope()
                .bytes(),
            &bytes
        );
        for position in [12, 44, 52, 117, 310, 1798, 1830, 2214, 2726] {
            let mut changed = bytes;
            changed[position] ^= 1;
            let domain = field(&changed, 12);
            let changed = Envelope::decode(&changed, &domain).unwrap();
            assert!(matches!(
                binding.reattach(changed),
                Err(Error::Encoding("live verified representation mismatch"))
            ));
        }
    }

    #[test]
    #[ignore = "requires one isolated authenticated retained encrypted proof representation and canonical parameters"]
    fn live_binding_retained_genuine_proof_reverifies_then_reattaches_only_exact_bytes() {
        use sha2::{Digest as _, Sha256};
        assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
        let bytes = hex::decode(std::env::var("SILK_F04_RETAINED_ENVELOPE_HEX").unwrap()).unwrap();
        assert_eq!(bytes.len(), ENVELOPE_BYTES);
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            std::env::var("SILK_F04_RETAINED_ENVELOPE_HASH").unwrap()
        );
        let domain = field(&bytes, 12);
        let envelope = Envelope::decode(&bytes, &domain).unwrap();
        let effect = envelope.effect_id();
        let parameter_dir =
            std::path::PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
        let parameters = SaplingParameters::load(
            &parameter_dir.join("sapling-spend.params"),
            &parameter_dir.join("sapling-output.params"),
        )
        .unwrap();
        let verified = verify(envelope.clone(), &parameters).unwrap();
        let binding = verified.live_representation_binding();
        drop(verified);
        let restored = binding.clone().reattach(envelope).unwrap();
        assert_eq!(restored.envelope().bytes().as_slice(), bytes);
        let mut changed = bytes.clone();
        changed[2214] ^= 1;
        let changed = Envelope::decode(&changed, &domain).unwrap();
        assert_eq!(changed.effect_id(), effect);
        assert!(binding.reattach(changed).is_err());
        let mut changed = bytes;
        changed[12] ^= 1;
        let foreign_domain = field(&changed, 12);
        assert!(
            binding
                .reattach(Envelope::decode(&changed, &foreign_domain).unwrap())
                .is_err()
        );
        println!(
            "fresh_full_crypto_verification=true; retained_representation_exact=true; compact_binding_bytes=64; full_body_dropped_before_reattach=true; same_effect_changed_authorization_refused=true; foreign_context_refused=true; new_proofs=0; graph_authority=false"
        );
    }
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
