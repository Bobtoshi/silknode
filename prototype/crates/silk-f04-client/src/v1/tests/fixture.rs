//! Reuse admitted public genesis and TLS fixtures; no new proofs or mining.
use super::*;
use ed25519_dalek::SigningKey;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use silk_f04_node::{auth::sign_role, state::BranchState};
use silk_f04_relay::{
    frame::{HpkePrivate, generate_hpke_key},
    tls::{SetupStep, spki_pin},
};
use silk_sapling_f04::codec::domain_hash;
use std::net::{Ipv4Addr, TcpListener, TcpStream};

#[allow(dead_code)]
#[path = "../../../../silk-node/tests/support/private_relay_test_certificates.rs"]
mod certificates;
#[path = "../../../../silk-f04-node/tests/common/mod.rs"]
mod common;

pub struct Fixture {
    pub config: Rc<SignedConfig>,
    pub genesis: Rc<Genesis>,
    pub a: HpkePrivate,
    pub b: HpkePrivate,
    pub hashes: [Digest; 32],
    keys: [SigningKey; 5],
    listener: TcpListener,
    certs: tempfile::TempDir,
}
fn message(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(label.len()).unwrap()];
    for part in std::iter::once(label.as_bytes()).chain(parts.iter().copied()) {
        bytes.extend_from_slice(part);
    }
    bytes
}
impl Fixture {
    pub fn next_config(&self) -> (SignedConfig, [Digest; 32], [Digest; 2]) {
        let mut bytes = *self.config.bytes();
        let epoch = self.config.epoch() + 1;
        let first = u64::from(epoch) * 2880;
        bytes[44..48].copy_from_slice(&epoch.to_le_bytes());
        bytes[48..56].copy_from_slice(&first.to_le_bytes());
        bytes[56..64].copy_from_slice(&(first + 2880).to_le_bytes());
        let (_, a) = generate_hpke_key().unwrap();
        let (_, b) = generate_hpke_key().unwrap();
        bytes[128..160].copy_from_slice(&a);
        bytes[160..192].copy_from_slice(&b);
        let mut hashes = std::array::from_fn(|i| {
            domain_hash("SilkNode-F0-token", &[&[u8::try_from(i + 16).unwrap(); 32]])
        });
        hashes.sort_unstable();
        let flat: Vec<_> = hashes.iter().flatten().copied().collect();
        bytes[602..634].copy_from_slice(&domain_hash(
            "SilkNode-F0-roster",
            &[
                &self.config.domain(),
                &self.config.cohort().to_le_bytes(),
                &epoch.to_le_bytes(),
                &flat,
            ],
        ));
        let msg = message("SilkNode-F0-config-sign", &[&bytes[..642]]);
        bytes[642..706].copy_from_slice(&sign_role(&self.keys[0], &msg).unwrap());
        bytes[706..].copy_from_slice(&sign_role(&self.keys[1], &msg).unwrap());
        let roots = [
            self.keys[0].verifying_key().to_bytes(),
            self.keys[1].verifying_key().to_bytes(),
        ];
        (
            SignedConfig::verify(
                &bytes,
                self.config.domain(),
                self.config.cohort(),
                epoch,
                roots,
            )
            .unwrap(),
            hashes,
            roots,
        )
    }
    pub fn new() -> Self {
        let genesis = Rc::new(common::fixture(&[10]).genesis);
        let keys: [SigningKey; 5] =
            std::array::from_fn(|i| SigningKey::from_bytes(&[u8::try_from(i + 31).unwrap(); 32]));
        let (a, ap) = generate_hpke_key().unwrap();
        let (b, bp) = generate_hpke_key().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let certs = tempfile::tempdir().unwrap();
        let cert_path = certs.path().join("certs");
        certificates::generate(&cert_path, 1);
        let cert = CertificateDer::from(certificates::leaf_der(&cert_path, 0));
        let pin = spki_pin(&cert).unwrap();
        let mut bytes = [0; 770];
        bytes[..8].copy_from_slice(b"SNCFGF03");
        bytes[8..40].copy_from_slice(&genesis.domain());
        bytes[40..44].copy_from_slice(&3_u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&2_u32.to_le_bytes());
        bytes[48..56].copy_from_slice(&5760_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&8640_u64.to_le_bytes());
        for (i, key) in keys[..2].iter().enumerate() {
            bytes[64 + 32 * i..96 + 32 * i].copy_from_slice(&key.verifying_key().to_bytes());
        }
        bytes[128..160].copy_from_slice(&ap);
        bytes[160..192].copy_from_slice(&bp);
        for (i, key) in keys.iter().enumerate() {
            let at = 192 + 82 * i;
            bytes[at..at + 16].copy_from_slice(&Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
            bytes[at + 16..at + 18]
                .copy_from_slice(&listener.local_addr().unwrap().port().to_le_bytes());
            bytes[at + 18..at + 50].copy_from_slice(&key.verifying_key().to_bytes());
            bytes[at + 50..at + 82].copy_from_slice(&pin);
        }
        let mut hashes = std::array::from_fn(|i| {
            domain_hash("SilkNode-F0-token", &[&[u8::try_from(i).unwrap(); 32]])
        });
        hashes.sort_unstable();
        let flat: Vec<_> = hashes.iter().flatten().copied().collect();
        bytes[602..634].copy_from_slice(&domain_hash(
            "SilkNode-F0-roster",
            &[
                &genesis.domain(),
                &3_u32.to_le_bytes(),
                &2_u32.to_le_bytes(),
                &flat,
            ],
        ));
        bytes[634..638].copy_from_slice(&500_u32.to_le_bytes());
        bytes[638..640].copy_from_slice(&[8, 32]);
        let msg = message("SilkNode-F0-config-sign", &[&bytes[..642]]);
        bytes[642..706].copy_from_slice(&sign_role(&keys[0], &msg).unwrap());
        bytes[706..].copy_from_slice(&sign_role(&keys[1], &msg).unwrap());
        let config = Rc::new(
            SignedConfig::verify(
                &bytes,
                genesis.domain(),
                3,
                2,
                [
                    keys[0].verifying_key().to_bytes(),
                    keys[1].verifying_key().to_bytes(),
                ],
            )
            .unwrap(),
        );
        Self {
            config,
            genesis,
            a,
            b,
            hashes,
            keys,
            listener,
            certs,
        }
    }
    pub fn sign_manifest(&self, bytes: &mut [u8; 256]) {
        let msg = message("SilkNode-F0-round", &[&self.config.id(), &bytes[..128]]);
        bytes[128..192].copy_from_slice(&sign_role(&self.keys[0], &msg).unwrap());
        bytes[192..].copy_from_slice(&sign_role(&self.keys[1], &msg).unwrap());
    }
    pub fn manifest(&self) -> SignedManifest {
        let state = BranchState::genesis(&self.genesis).unwrap();
        let cut = &state.cuts()[0];
        let mut bytes = [0; 256];
        bytes[..8].copy_from_slice(b"SNRNDF03");
        bytes[8..40].copy_from_slice(&self.config.domain());
        bytes[40..44].copy_from_slice(&3_u32.to_le_bytes());
        bytes[44..52].copy_from_slice(&6000_u64.to_le_bytes());
        bytes[60..92].copy_from_slice(&cut.id);
        bytes[92..124].copy_from_slice(&cut.root);
        self.sign_manifest(&mut bytes);
        SignedManifest::verify(&bytes, &self.config, 6000).unwrap()
    }
    pub fn envelope(&self) -> [u8; ENVELOPE_BYTES] {
        let manifest = self.manifest();
        let mut bytes = [0; ENVELOPE_BYTES];
        bytes[..8].copy_from_slice(b"SNPRV003");
        bytes[8] = 3;
        bytes[12..44].copy_from_slice(&self.config.domain());
        bytes[52..84].copy_from_slice(&manifest.bytes()[60..92]);
        bytes[84] = 2;
        bytes[117] = 1;
        bytes[213] = 2;
        bytes[277] = 2;
        bytes[1790..1798].copy_from_slice(&1_i64.to_le_bytes());
        bytes[1798..1830].copy_from_slice(&manifest.bytes()[92..124]);
        EnvelopeView::decode(&bytes, &self.config.domain()).unwrap();
        bytes
    }
    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificates::root_der(
                &self.certs.path().join("certs"),
            )))
            .unwrap();
        roots
    }
    pub fn accept_setup(&self, deadline: Instant) -> silk_f04_relay::tls::Setup {
        let certs = self.certs.path().join("certs");
        let cert = CertificateDer::from(certificates::leaf_der(&certs, 0));
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificates::private_key_der(
            &certs, 0,
        )));
        Transport::server_setup(
            self.listener.accept().unwrap().0,
            self.config.endpoints()[0],
            vec![cert],
            key,
            deadline,
        )
        .unwrap()
    }
    pub fn pair(&self) -> (Transport, Transport) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let client = TcpStream::connect(self.listener.local_addr().unwrap()).unwrap();
        let mut pending = [
            Some(
                Transport::client_setup(client, self.config.endpoints()[0], self.roots(), deadline)
                    .unwrap(),
            ),
            Some(self.accept_setup(deadline)),
        ];
        let mut ready = [None, None];
        while ready.iter().any(Option::is_none) {
            assert!(Instant::now() < deadline);
            for i in 0..2 {
                if let Some(setup) = pending[i].take() {
                    match setup.poll().unwrap() {
                        SetupStep::Pending(setup) => pending[i] = Some(setup),
                        SetupStep::Established(link) => ready[i] = Some(link),
                    }
                }
            }
        }
        (ready[0].take().unwrap(), ready[1].take().unwrap())
    }
}
