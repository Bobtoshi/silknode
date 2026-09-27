//! Closed, zero-allocation PUBLIC VALUELESS testnet profile. No configurable
//! allocation or attestation bypass. The old F0.4 genesis admission is unchanged.
use super::*;

/// Network name; changing any profile byte creates a different network.
pub const NAME: &str = "silknode-public-zero-v1";
/// Independently byte-pinned full context domain.
pub const DOMAIN_HEX: &str = "3e156fe886be5b82188b5af94f48e4dac0017a8c061298ae7d136438c3bc987e";
/// SHA256 of the complete deterministic public genesis bundle.
pub const BUNDLE_SHA256: &str = "4e799358037512df91e2b97208ef38d21efd81c9d91006c48fe7269911166ef2";

/// Construct ONLY this pinned empty genesis. There are no allocated notes,
/// recipients, authority/auditor keys, custody premise, or premine. Mining credits
/// remain the existing NONTRANSFERABLE attribution; no new monetary rule exists.
pub fn genesis() -> Result<Genesis> {
    let mut allocation = vec![0; 20];
    allocation[..8].copy_from_slice(b"SNZERO01");
    let mut policy = vec![0; 16];
    policy[..8].copy_from_slice(b"SNZEROAP");
    policy[8] = 1;
    let mut receipt = vec![0; 16];
    receipt[..8].copy_from_slice(b"SNZEROAR");
    receipt[8] = 1;
    let ph = carriage_hash("SilkNode/F01-Parameters/v1", &[&parameter_bytes()]);
    let mut gd = [0; 244];
    gd[..8].copy_from_slice(b"SNGNP001");
    gd[8] = 1;
    gd[12] = NAME.len() as u8;
    gd[13..13 + NAME.len()].copy_from_slice(NAME.as_bytes());
    gd[76..84].copy_from_slice(&1_790_467_200_u64.to_le_bytes());
    gd[84..116].copy_from_slice(&raw_hash(b"SilkNode/public-zero-v1/no-premine/2026-09-27"));
    gd[116..148].copy_from_slice(&raw_hash(&allocation));
    gd[148..180].copy_from_slice(&RULES_ID);
    gd[180..212].copy_from_slice(&ph);
    gd[212..244].copy_from_slice(&domain_hash(
        "SilkNode-F01-genesis-audit-policy",
        &[&policy],
    ));
    let network = domain_hash(
        "SilkNode-F0-network-id",
        &[&[NAME.len() as u8], NAME.as_bytes()],
    );
    let chain = carriage_hash("SilkNode/F01-Chain/v1", &[&gd]);
    let profile = carriage_hash("SilkNode/F01-Profile/v1", &[&chain, &RULES_ID, &ph]);
    let id = carriage_hash("SilkNode/F01-GenesisId/v1", &[&gd, &chain, &profile]);
    let activation = carriage_hash(
        "SilkNode/F01-Activation/v1",
        &[&id, &profile, &0_u64.to_le_bytes(), &RULES_ID],
    );
    let mut x = [0; 256];
    x[..8].copy_from_slice(b"SNCTX003");
    x[8] = 3;
    for (at, value) in [
        (12, network),
        (44, chain),
        (76, profile),
        (108, id),
        (140, activation),
        (172, raw_hash(&allocation)),
        (220, RULES_ID),
    ] {
        x[at..at + 32].copy_from_slice(&value);
    }
    x[212..220].copy_from_slice(&[3, 0, 4, 0, 1, 0, 0, 0]);
    let g = Genesis {
        context: Context::decode(&x)?,
        descriptor: gd,
        allocation,
        policy,
        receipt,
        recoveries: Vec::new(),
        total: 0,
        tree: CommitmentTree::empty(),
    };
    if hex::encode(g.domain()) != DOMAIN_HEX
        || hex::encode(raw_hash(&g.local_bundle())) != BUNDLE_SHA256
    {
        return Err(Error::Unavailable("public testnet genesis byte pin"));
    }
    Ok(g)
}
