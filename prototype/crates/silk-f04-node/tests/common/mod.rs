//! Locally generated valueless fixture; test keys do NOT establish independent custodians.
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use sapling_crypto::{
    Note, Rseed,
    note_encryption::{SaplingDomain, sapling_note_encryption},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    zip32::ExtendedSpendingKey,
};
use silk_f04_node::{
    auth::sign_role,
    genesis::{Genesis, GenesisDerivation, parameter_bytes},
};
use silk_sapling_f04::{codec::RECOVERY_BYTES, wallet::RecoveryOutput};
use zcash_note_encryption::Domain;

#[allow(
    dead_code,
    reason = "The same fixture exposes material for codec tests and keys for genuine node tests"
)]
pub struct Fixture {
    pub genesis: Genesis,
    pub keys: Vec<ExtendedSpendingKey>,
    pub notes: Vec<Note>,
    pub descriptor: Vec<u8>,
    pub allocation: Vec<u8>,
    pub policy: Vec<u8>,
    pub receipt: Vec<u8>,
}
pub fn fixture(values: &[u64]) -> Fixture {
    fixture_inner(values, false)
}
#[allow(
    dead_code,
    reason = "Only the two-owned-input wallet fixture needs shared ownership"
)]
pub fn fixture_shared_key(values: &[u64]) -> Fixture {
    fixture_inner(values, true)
}
#[allow(
    clippy::too_many_lines,
    reason = "One test-only genesis ceremony keeps allocation and attestations together"
)]
fn fixture_inner(values: &[u64], shared: bool) -> Fixture {
    let mut keys: Vec<ExtendedSpendingKey> = Vec::new();
    let mut notes = Vec::new();
    let mut allocation = Vec::new();
    allocation.extend_from_slice(b"SNGEN002");
    allocation.extend_from_slice(&values.iter().sum::<u64>().to_le_bytes());
    allocation.extend_from_slice(&u32::try_from(values.len()).unwrap().to_le_bytes());
    for value in values {
        let mut seed = [0; 32];
        OsRng.fill_bytes(&mut seed);
        let key = if shared && !keys.is_empty() {
            keys[0].clone()
        } else {
            ExtendedSpendingKey::master(&seed)
        };
        let mut rseed = [0; 32];
        OsRng.fill_bytes(&mut rseed);
        let note = key
            .default_address()
            .1
            .create_note(NoteValue::from_raw(*value), Rseed::AfterZip212(rseed));
        let cv = ValueCommitment::derive(note.value(), ValueCommitTrapdoor::random(OsRng));
        let ne = sapling_note_encryption(
            Some(key.to_diversifiable_full_viewing_key().fvk().ovk),
            note.clone(),
            [0; 512],
            &mut OsRng,
        );
        let mut recovery = [0; RECOVERY_BYTES];
        recovery[..32].copy_from_slice(&note.cmu().to_bytes());
        recovery[32..64].copy_from_slice(&SaplingDomain::epk_bytes(ne.epk()).0);
        recovery[64..644].copy_from_slice(&ne.encrypt_note_plaintext());
        recovery[644..].copy_from_slice(&ne.encrypt_outgoing_plaintext(
            &cv,
            &note.cmu(),
            &mut OsRng,
        ));
        let recovered = RecoveryOutput::decode(recovery)
            .unwrap()
            .decrypt(key.to_diversifiable_full_viewing_key().fvk())
            .unwrap();
        assert_eq!(recovered.0, note);
        assert_eq!(recovered.1, key.default_address().1);
        allocation.extend_from_slice(&value.to_le_bytes());
        allocation.extend_from_slice(&recovery);
        keys.push(key);
        notes.push(note);
    }
    // Distinct PUBLIC TEST seeds; no pretense that these are independent operators.
    let signers: Vec<_> = (0..values.len() + 2)
        .map(|i| SigningKey::from_bytes(&[u8::try_from(i + 1).unwrap(); 32]))
        .collect();
    let mut policy = Vec::new();
    policy.extend_from_slice(b"SNAGP001\x01\0\0\0");
    policy.extend_from_slice(&u32::try_from(values.len()).unwrap().to_le_bytes());
    for key in &signers {
        policy.extend_from_slice(&key.verifying_key().to_bytes());
    }
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    // Explicit historical fixture genesis. Real ingress still checks current local time.
    let d = GenesisDerivation::derive(
        "f04-private-local-fixture",
        1_700_000_000,
        nonce,
        &allocation,
        &policy,
    )
    .unwrap();
    let mut receipt = Vec::new();
    receipt.extend_from_slice(b"SNAGR001\x01\0\0\0");
    receipt.extend_from_slice(&u32::try_from(values.len() + 2).unwrap().to_le_bytes());
    for (i, key) in signers.iter().enumerate() {
        let (role, index) = match i {
            0 => (0, u32::MAX),
            1 => (1, u32::MAX),
            _ => (2, u32::try_from(i - 2).unwrap()),
        };
        let body = d
            .attestation_body(&allocation, &policy, role, index)
            .unwrap();
        let label = b"SilkNode-F01-A_G-attestation";
        let mut m = vec![u8::try_from(label.len()).unwrap()];
        m.extend_from_slice(label);
        m.extend_from_slice(&body);
        let sig = sign_role(key, &m).unwrap();
        receipt.extend_from_slice(&body);
        receipt.extend_from_slice(&sig);
    }
    let genesis = Genesis::admit(
        &d.descriptor,
        &parameter_bytes(),
        &allocation,
        &policy,
        &receipt,
        true,
    )
    .unwrap();
    Fixture {
        genesis,
        keys,
        notes,
        descriptor: d.descriptor.to_vec(),
        allocation,
        policy,
        receipt,
    }
}
