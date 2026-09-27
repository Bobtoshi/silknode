//! Local-only Sapling proof/signature construction and ZIP-212 recovery.
//!
//! No PCZT, witness, key or plaintext is a transport object. This is not a
//! wallet database, mature-note selector, accepted genesis, or submission route.

use crate::{
    Digest, Error, Result,
    codec::{EFFECT_BYTES, ENVELOPE_BYTES, Envelope, RECOVERY_BYTES, domain_hash, field},
    crypto::{VerifiedEnvelope, verify},
    parameters::SaplingParameters,
};
use ff::{Field, PrimeField};
use incrementalmerkletree::Position;
use rand_core::{OsRng, RngCore};
use sapling_crypto::{
    Anchor, Bundle, MerklePath, Node, Note, PaymentAddress, Rseed,
    builder::{Builder, BundleType},
    bundle::{Authorization, OutputDescription},
    keys::{FullViewingKey, OutgoingViewingKey, PreparedIncomingViewingKey},
    note::ExtractedNoteCommitment,
    note_encryption::{
        SaplingDomain, Zip212Enforcement, try_sapling_note_decryption, try_sapling_output_recovery,
    },
    value::{NoteValue, ValueCommitment},
    zip32::ExtendedSpendingKey,
};
use zcash_note_encryption::{EphemeralKeyBytes, ShieldedOutput, try_output_recovery_with_ovk};

/// Maximum note value for local research construction (not a new circuit check).
pub const MAX_VALUE: u64 = 2_100_000_000_000_000;

/// Private local spending material. Intentionally has no Debug/serialization implementation.
pub struct SpendInput {
    /// Fresh research-only spending key; never import a production key.
    pub key: ExtendedSpendingKey,
    /// Actual decrypted note.
    pub note: Note,
    /// Witness at the caller's selected cut, including its note position.
    pub path: MerklePath,
}

/// Local output intent; never included as plaintext in an envelope.
pub struct PaymentOutput {
    /// Recipient's independently validated fresh diversified address.
    pub address: PaymentAddress,
    /// Local hidden value, zero allowed for standard padding.
    pub value: u64,
}

/// The public cut fields to authorize. A node/wallet layer must establish their
/// canonical lineage and eligibility; this primitive does not invent that authority.
#[derive(Clone, Copy)]
pub struct CutReference {
    /// Static network/genesis authorization domain.
    pub domain: Digest,
    /// Cut ordinal.
    pub index: u64,
    /// Full prefix-bound cut hash.
    pub id: Digest,
    /// Shared standard Sapling note root.
    pub root: Digest,
}

/// Construct a real 2+2 envelope with an exact one-unit burn.
///
/// One input is padded
/// with a fresh, normally proved/signed zero note. Standard builder shuffling is
/// retained. Both outputs are recovered with the sender OVK and checked against
/// intent before any spend signatures. This uses only the OS CSPRNG.
///
/// # Errors
/// Refuses invalid amounts, keys, positions, witnesses, output recovery or failed
/// proof/authorization checks. It never returns a partially authorized envelope.
#[allow(
    clippy::too_many_lines,
    reason = "Keep construction, intent checks and signing in one auditable sequential flow"
)]
#[allow(
    clippy::needless_pass_by_value,
    reason = "Local plaintext intent is owned for this construction operation"
)]
pub fn build_transfer(
    cut: CutReference,
    mut inputs: Vec<SpendInput>,
    outputs: [PaymentOutput; 2],
    parameters: &SaplingParameters,
) -> Result<VerifiedEnvelope> {
    if !(1..=2).contains(&inputs.len()) {
        return Err(Error::Wallet("requires one or two selected notes"));
    }
    let input_total = inputs
        .iter()
        .try_fold(0_u64, |n, i| n.checked_add(i.note.value().inner()))
        .ok_or(Error::Wallet("input overflow"))?;
    let output_total = outputs
        .iter()
        .try_fold(0_u64, |n, o| n.checked_add(o.value))
        .ok_or(Error::Wallet("output overflow"))?;
    if input_total > MAX_VALUE
        || input_total == 0
        || outputs.iter().any(|o| o.value > MAX_VALUE)
        || output_total.checked_add(1) != Some(input_total)
    {
        return Err(Error::Wallet("one-unit burn/research amount bound"));
    }
    let anchor = Option::<Anchor>::from(Anchor::from_bytes(cut.root))
        .ok_or(Error::Wallet("anchor encoding"))?;
    let mut rng = OsRng;
    if inputs.len() == 1 {
        inputs.push(dummy_input(&mut rng)?);
    }
    let ovk = inputs[0].key.to_diversifiable_full_viewing_key().fvk().ovk;
    let mut builder = Builder::new(
        Zip212Enforcement::On,
        BundleType::Transactional {
            bundle_required: true,
        },
        anchor,
    );
    for i in &inputs {
        if u64::from(i.path.position()) >= (1_u64 << sapling_crypto::NOTE_COMMITMENT_TREE_DEPTH) {
            return Err(Error::Wallet("note position exceeds depth-32 tree"));
        }
        let fvk = i.key.to_diversifiable_full_viewing_key().fvk().clone();
        if fvk.vk.to_payment_address(*i.note.recipient().diversifier()) != Some(i.note.recipient())
        {
            return Err(Error::Wallet("spending key does not own positioned note"));
        }
        if !matches!(i.note.rseed(), Rseed::AfterZip212(_)) {
            return Err(Error::Wallet("ZIP-212 required"));
        }
        if i.note.value().inner() != 0
            && i.path.root(Node::from_cmu(&i.note.cmu())).to_bytes() != cut.root
        {
            return Err(Error::Wallet("positive note witness does not match cut"));
        }
        builder
            .add_spend(fvk, i.note.clone(), i.path.clone())
            .map_err(|_| Error::Wallet("spend construction"))?;
    }
    let nfs: Vec<_> = inputs
        .iter()
        .map(|i| {
            i.note.nf(
                &i.key.to_diversifiable_full_viewing_key().fvk().vk.nk,
                u64::from(i.path.position()),
            )
        })
        .collect();
    if nfs[0] == nfs[1] {
        return Err(Error::Wallet("same positioned note selected twice"));
    }
    for o in &outputs {
        builder
            .add_output(Some(ovk), o.address, NoteValue::from_raw(o.value), [0; 512])
            .map_err(|_| Error::Wallet("output construction"))?;
    }
    let (mut pczt, metadata) = builder
        .build_for_pczt(&mut rng)
        .map_err(|_| Error::Wallet("bundle construction"))?;
    for (index, input) in inputs.iter().enumerate() {
        let slot = metadata
            .spend_index(index)
            .ok_or(Error::Wallet("spend metadata"))?;
        pczt.update_with(|mut u| {
            u.update_spend_with(slot, |mut s| {
                s.set_proof_generation_key(input.key.expsk.proof_generation_key())
            })
        })
        .map_err(|_| Error::Wallet("proving key association"))?;
        let spend = &pczt.spends()[slot];
        let expected = input.key.to_diversifiable_full_viewing_key();
        let vk = spend
            .proof_generation_key()
            .as_ref()
            .ok_or(Error::Wallet("missing proving key"))?
            .to_viewing_key();
        if vk.ak != expected.fvk().vk.ak || vk.nk != expected.fvk().vk.nk {
            return Err(Error::Wallet("proving key mismatch"));
        }
        spend
            .verify_cv()
            .map_err(|_| Error::Wallet("spend commitment"))?;
        spend
            .verify_nullifier(Some(expected.fvk()))
            .map_err(|_| Error::Wallet("spend nullifier"))?;
        spend
            .verify_rk(Some(expected.fvk()))
            .map_err(|_| Error::Wallet("spend randomized key"))?;
    }
    pczt.create_proofs(&parameters.spend, &parameters.output, rng)
        .map_err(|_| Error::Wallet("proof construction"))?;
    for (index, intended) in outputs.iter().enumerate() {
        let slot = metadata
            .output_index(index)
            .ok_or(Error::Wallet("output metadata"))?;
        let o = &pczt.outputs()[slot];
        o.verify_cv()
            .map_err(|_| Error::Wallet("output commitment"))?;
        o.verify_note_commitment()
            .map_err(|_| Error::Wallet("output note"))?;
        let output = OutputDescription::from_parts(
            o.cv().clone(),
            *o.cmu(),
            o.ephemeral_key().clone(),
            *o.enc_ciphertext(),
            *o.out_ciphertext(),
            o.zkproof().ok_or(Error::Wallet("missing output proof"))?,
        );
        let (note, address, memo) =
            try_sapling_output_recovery(&ovk, &output, Zip212Enforcement::On)
                .ok_or(Error::Wallet("outgoing recovery"))?;
        if note.value().inner() != intended.value || address != intended.address || memo != [0; 512]
        {
            return Err(Error::Wallet("encrypted output differs from intent"));
        }
        // When a corresponding incoming key is available, also validate recipient recovery.
        for input in &inputs {
            let fvk = input.key.to_diversifiable_full_viewing_key();
            if fvk
                .fvk()
                .vk
                .to_payment_address(*intended.address.diversifier())
                == Some(intended.address)
            {
                let ivk = PreparedIncomingViewingKey::new(&fvk.fvk().vk.ivk());
                let recovered = try_sapling_note_decryption(&ivk, &output, Zip212Enforcement::On)
                    .ok_or(Error::Wallet("incoming round trip"))?;
                if recovered.0 != note || recovered.1 != address || recovered.2 != memo {
                    return Err(Error::Wallet("incoming/outgoing mismatch"));
                }
            }
        }
    }
    let effects = pczt
        .extract_effects::<i64>()
        .map_err(|_| Error::Wallet("effect extraction"))?
        .ok_or(Error::Wallet("empty bundle"))?;
    let prefix = encode_effects(&effects, cut)?;
    let sighash = domain_hash("SilkNode-F0-sign", &[&prefix]);
    pczt.finalize_io(sighash, rng)
        .map_err(|_| Error::Wallet("binding key"))?;
    for (index, input) in inputs.iter().enumerate() {
        let slot = metadata
            .spend_index(index)
            .ok_or(Error::Wallet("spend metadata"))?;
        pczt.spends_mut()[slot]
            .sign(sighash, &input.key.expsk.ask, rng)
            .map_err(|_| Error::Wallet("spend signing"))?;
    }
    let bundle = pczt
        .extract::<i64>()
        .map_err(|_| Error::Wallet("authorized extraction"))?
        .ok_or(Error::Wallet("empty bundle"))?
        .apply_binding_signature(sighash, rng)
        .ok_or(Error::Wallet("binding signing"))?;
    if encode_effects(&bundle, cut)? != prefix {
        return Err(Error::Wallet("effects changed during signing"));
    }
    let mut bytes = [0; ENVELOPE_BYTES];
    bytes[..EFFECT_BYTES].copy_from_slice(&prefix);
    for (i, spend) in bundle.shielded_spends().iter().enumerate() {
        bytes[1830 + 192 * i..1830 + 192 * (i + 1)].copy_from_slice(spend.zkproof());
        bytes[2214 + 64 * i..2214 + 64 * (i + 1)]
            .copy_from_slice(&<[u8; 64]>::from(*spend.spend_auth_sig()));
    }
    for (i, output) in bundle.shielded_outputs().iter().enumerate() {
        bytes[2342 + 192 * i..2342 + 192 * (i + 1)].copy_from_slice(output.zkproof());
    }
    bytes[2726..].copy_from_slice(&<[u8; 64]>::from(bundle.authorization().binding_sig));
    verify(Envelope::decode(&bytes, &cut.domain)?, parameters)
}

fn dummy_input(rng: &mut OsRng) -> Result<SpendInput> {
    let mut seed = [0; 32];
    rng.fill_bytes(&mut seed);
    let key = ExtendedSpendingKey::master(&seed);
    let address = key.default_address().1;
    let mut rseed = [0; 32];
    rng.fill_bytes(&mut rseed);
    let note = Note::from_parts(address, NoteValue::ZERO, Rseed::AfterZip212(rseed));
    let siblings = (0..32)
        .map(|_| Node::from_scalar(bls12_381::Scalar::random(&mut *rng)))
        .collect();
    let path = MerklePath::from_parts(siblings, Position::from(0))
        .map_err(|()| Error::Wallet("dummy path"))?;
    Ok(SpendInput { key, note, path })
}

fn encode_effects<A: Authorization>(
    bundle: &Bundle<A, i64>,
    cut: CutReference,
) -> Result<[u8; EFFECT_BYTES]> {
    if bundle.shielded_spends().len() != 2
        || bundle.shielded_outputs().len() != 2
        || *bundle.value_balance() != 1
    {
        return Err(Error::Wallet("bundle shape/value balance"));
    }
    let mut b = [0; EFFECT_BYTES];
    b[..8].copy_from_slice(b"SNPRV003");
    b[8] = 3;
    b[12..44].copy_from_slice(&cut.domain);
    b[44..52].copy_from_slice(&cut.index.to_le_bytes());
    b[52..84].copy_from_slice(&cut.id);
    b[84] = 2;
    b[277] = 2;
    b[1790] = 1;
    b[1798..].copy_from_slice(&cut.root);
    for (i, s) in bundle.shielded_spends().iter().enumerate() {
        if s.anchor().to_repr() != cut.root {
            return Err(Error::Wallet("noncommon anchor"));
        }
        let at = 85 + 96 * i;
        b[at..at + 32].copy_from_slice(&s.cv().to_bytes());
        b[at + 32..at + 64].copy_from_slice(&s.nullifier().0);
        b[at + 64..at + 96].copy_from_slice(&<[u8; 32]>::from(*s.rk()));
    }
    for (i, o) in bundle.shielded_outputs().iter().enumerate() {
        let at = 278 + 756 * i;
        b[at..at + 32].copy_from_slice(&o.cv().to_bytes());
        b[at + 32..at + 64].copy_from_slice(&o.cmu().to_bytes());
        b[at + 64..at + 96].copy_from_slice(&o.ephemeral_key().0);
        b[at + 96..at + 676].copy_from_slice(o.enc_ciphertext());
        b[at + 676..at + 756].copy_from_slice(o.out_ciphertext());
    }
    Ok(b)
}

/// Canonical public recovery output. It carries no proof/work/state authority.
#[derive(Clone)]
pub struct RecoveryOutput {
    bytes: [u8; RECOVERY_BYTES],
}

impl RecoveryOutput {
    /// Check canonical commitment and ephemeral-key encodings without creating a
    /// fabricated OutputDescription/proof. Authentication belongs to the ledger stream.
    ///
    /// # Errors
    /// Returns `Encoding` for noncanonical commitment or ephemeral-key bytes.
    pub fn decode(bytes: [u8; RECOVERY_BYTES]) -> Result<Self> {
        use group::GroupEncoding;
        Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&field(
            &bytes, 0,
        )))
        .ok_or(Error::Encoding("recovery cmu"))?;
        Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&field(
            &bytes, 32,
        )))
        .ok_or(Error::Encoding("recovery epk"))?;
        Ok(Self { bytes })
    }
    /// Full ZIP-212 incoming recovery. `None` is not proof of unavailable history or
    /// an empty wallet; callers must separately authenticate stream completeness.
    #[must_use]
    pub fn decrypt(&self, fvk: &FullViewingKey) -> Option<(Note, PaymentAddress, [u8; 512])> {
        self.decrypt_ivk(&PreparedIncomingViewingKey::new(&fvk.vk.ivk()))
    }
    /// Receive-only local decryption. It grants no nullifier or spentness knowledge.
    #[must_use]
    pub fn decrypt_ivk(
        &self,
        ivk: &PreparedIncomingViewingKey,
    ) -> Option<(Note, PaymentAddress, [u8; 512])> {
        try_sapling_note_decryption(ivk, self, Zip212Enforcement::On)
    }
    /// Outgoing local recovery using the real value commitment from the accepted
    /// envelope. The724-byte recovery record alone cannot supply this linkage.
    /// This does not reveal the recipient's spentness or signing authority.
    /// # Errors
    /// Refuses malformed value commitments; `None` is ordinary failed decryption.
    pub fn recover_outgoing(
        &self,
        ovk: &OutgoingViewingKey,
        cv_bytes: &Digest,
    ) -> Result<Option<(Note, PaymentAddress, [u8; 512])>> {
        let cv =
            Option::<ValueCommitment>::from(ValueCommitment::from_bytes_not_small_order(cv_bytes))
                .ok_or(Error::Encoding("outgoing recovery value commitment"))?;
        Ok(try_output_recovery_with_ovk(
            &SaplingDomain::new(Zip212Enforcement::On),
            ovk,
            self,
            &cv,
            &field::<80>(&self.bytes, 644),
        ))
    }
    /// Exact retained output.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; RECOVERY_BYTES] {
        &self.bytes
    }
}

impl ShieldedOutput<sapling_crypto::note_encryption::SaplingDomain, 580> for RecoveryOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(field(&self.bytes, 32))
    }
    fn cmstar_bytes(&self) -> [u8; 32] {
        field(&self.bytes, 0)
    }
    fn enc_ciphertext(&self) -> &[u8; 580] {
        self.bytes[64..644]
            .try_into()
            .expect("fixed recovery layout")
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use sapling_crypto::{note_encryption::sapling_note_encryption, value::ValueCommitTrapdoor};
    use zcash_note_encryption::Domain;

    #[test]
    fn real_incoming_and_outgoing_recovery_requires_exact_cv_and_preserves_memo() {
        let mut seed = [0; 32];
        OsRng.fill_bytes(&mut seed);
        let key = ExtendedSpendingKey::master(&seed);
        let viewing = key.to_diversifiable_full_viewing_key();
        OsRng.fill_bytes(&mut seed);
        let note = key
            .default_address()
            .1
            .create_note(NoteValue::from_raw(7), Rseed::AfterZip212(seed));
        let cv = ValueCommitment::derive(note.value(), ValueCommitTrapdoor::random(OsRng));
        let encryption =
            sapling_note_encryption(Some(viewing.fvk().ovk), note.clone(), [23; 512], &mut OsRng);
        let mut bytes = [0; RECOVERY_BYTES];
        bytes[..32].copy_from_slice(&note.cmu().to_bytes());
        bytes[32..64].copy_from_slice(&SaplingDomain::epk_bytes(encryption.epk()).0);
        bytes[64..644].copy_from_slice(&encryption.encrypt_note_plaintext());
        bytes[644..].copy_from_slice(&encryption.encrypt_outgoing_plaintext(
            &cv,
            &note.cmu(),
            &mut OsRng,
        ));
        let output = RecoveryOutput::decode(bytes).unwrap();
        let incoming = output
            .decrypt_ivk(&PreparedIncomingViewingKey::new(&viewing.fvk().vk.ivk()))
            .unwrap();
        let outgoing = output
            .recover_outgoing(&viewing.fvk().ovk, &cv.to_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(incoming, outgoing);
        assert_eq!(outgoing.0, note);
        assert_eq!(outgoing.2, [23; 512]);
        let wrong =
            ValueCommitment::derive(NoteValue::from_raw(7), ValueCommitTrapdoor::random(OsRng));
        assert!(
            output
                .recover_outgoing(&viewing.fvk().ovk, &wrong.to_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            output
                .recover_outgoing(&OutgoingViewingKey([0; 32]), &cv.to_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            output
                .recover_outgoing(&viewing.fvk().ovk, &[255; 32])
                .is_err()
        );
        assert_eq!(output.bytes().len(), 724);
    }
}
