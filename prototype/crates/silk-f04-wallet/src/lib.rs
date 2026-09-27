//! Separate trusted local wallet/prover domain, never a node or relay endpoint.
//! Key restoration alone is not ledger recovery, spendability or anti-rollback.
pub mod backup;
pub mod journal;

use rand_core::{OsRng, RngCore};
use sapling_crypto::{PaymentAddress, zip32::ExtendedSpendingKey};
use silk_sapling_f04::Digest;
use zeroize::Zeroizing;
use zip32::DiversifierIndex;

/// Local wallet failures never classify a peer's proof as invalid.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Uniform password, corruption, framing or context authentication refusal.
    #[error("F04 wallet authentication failed")]
    Authentication,
    /// A new password does not meet the fixed local policy.
    #[error("F04 wallet password must contain at least 15 characters and at most 1024 UTF-8 bytes")]
    PasswordPolicy,
    /// Local entropy, memory, path or capacity is unavailable.
    #[error("F04 wallet unavailable: {0}")]
    Unavailable(&'static str),
    /// Local I/O failure; an encrypted partial stage may remain as evidence.
    #[error("F04 wallet I/O: {0}")]
    Io(#[from] std::io::Error),
}
/// Fallible local wallet operation.
pub type Result<T> = std::result::Result<T, Error>;

/// Fresh research-only key before the public genesis/context exists. There is
/// intentionally no raw-key/production-seed import or Debug implementation.
pub struct FreshKey(ExtendedSpendingKey);
impl FreshKey {
    /// Generate independent 256-bit OS entropy, then the standard Sapling key.
    /// # Errors
    /// Refuses unavailable OS entropy.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| Error::Unavailable("key entropy"))?;
        Ok(Self(ExtendedSpendingKey::master(seed.as_ref())))
    }
    /// Public initial address for constructing the subsequently accepted genesis.
    /// This is not an assertion that its allocation/ceremony has been accepted.
    #[must_use]
    pub fn initial_address(&self) -> PaymentAddress {
        self.0.default_address().1
    }
    /// Consume the fresh key into an independently accepted full F04 context.
    /// The caller must validate public genesis/X/N first; a key cannot accept it.
    #[must_use]
    pub const fn bind(self, accepted_domain: Digest) -> WalletKey {
        WalletKey {
            domain: accepted_domain,
            key: self.0,
            first_use: true,
        }
    }
}

/// Context-bound local spending authority.
///
/// Wrapper-owned serialized buffers are
/// wiped; upstream key objects do not provide a complete memory-erasure guarantee.
/// No Debug/Clone implementation, node interface, network access or secret log.
pub struct WalletKey {
    domain: Digest,
    key: ExtendedSpendingKey,
    // Never restored by a key backup. Consumed before attempting journal creation.
    first_use: bool,
}
/// Public address proposal.
///
/// The wallet journal must durably reserve `next`
/// (or exhaustion) BEFORE presenting this address. This object alone does not
/// issue it, and an old backup cannot establish the latest issuance cursor.
pub struct AddressCandidate {
    /// Full static context to encode in the exact sn3 descriptor.
    pub domain: Digest,
    /// Standard diversified public payment address.
    pub address: PaymentAddress,
    /// Successful 88-bit address index.
    pub index: [u8; 11],
    /// Next index; None means exhausted, never wrapped to zero.
    pub next: Option<[u8; 11]>,
}
impl WalletKey {
    /// Public context only, not a spending/viewing key.
    #[must_use]
    pub const fn domain(&self) -> Digest {
        self.domain
    }
    /// Propose a diversified address without pretending its cursor is durable.
    /// # Errors
    /// Refuses exhausted diversified address space.
    pub fn address_candidate(&self, start: [u8; 11]) -> Result<AddressCandidate> {
        let (index, address) = self
            .key
            .to_diversifiable_full_viewing_key()
            .find_address(DiversifierIndex::from(start))
            .ok_or(Error::Unavailable("address space exhausted"))?;
        let mut next = index;
        let following = if next.increment().is_ok() {
            Some(*next.as_bytes())
        } else {
            None
        };
        Ok(AddressCandidate {
            domain: self.domain,
            address,
            index: *index.as_bytes(),
            next: following,
        })
    }
}
