use super::{Result, certificates, files};
use ed25519_dalek::SigningKey;
use hpke::Serializable;
use rand_core_06::{OsRng, RngCore};
use rustls::pki_types::CertificateDer;
use silk_f04_node::{auth::sign_role, genesis::Genesis};
use silk_f04_relay::{
    Digest,
    config::{Roster, SignedConfig},
    frame::generate_hpke_key,
    tls::spki_pin,
};
use silk_sapling_f04::codec::domain_hash;
use std::{
    net::Ipv4Addr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

pub const ROLES: [&str; 6] = ["a", "b", "p0", "p1", "p2", "clients"];

/// Provision ONE explicitly unqualified same-host fixture, not an admitted epoch.
pub fn prepare(wallet: &Path, root: &Path) -> Result<()> {
    let epoch = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400)?;
    prepare_epoch(wallet, root, epoch, 41000)
}

pub fn prepare_lifecycle(wallet: &Path, root: &Path) -> Result<()> {
    let epoch = u32::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86400)?;
    prepare_epoch(wallet, root, epoch, 41000)?;
    prepare_epoch(
        wallet,
        &root.join("next"),
        epoch.checked_add(1).ok_or("epoch overflow")?,
        41100,
    )
}

#[allow(clippy::too_many_lines)] // Keep the single fixed configuration layout auditable in order.
fn prepare_epoch(wallet: &Path, root: &Path, epoch: u32, port: u16) -> Result<()> {
    let genesis_bytes = files::read(&wallet.join("public-genesis"), 8 * 1024 * 1024)?;
    let wallet_pins = files::exact::<96>(&wallet.join("wallet-pins-before-export"))?;
    let domain: Digest = wallet_pins[..32].try_into()?;
    let genesis = Genesis::admit_local_bundle(&genesis_bytes, &domain, true)?;
    let payment = files::exact::<2790>(&wallet.join("payment-2790"))?;
    let _ = silk_sapling_f04::codec::Envelope::decode(payment.as_ref(), &domain)?;
    files::directory(root)?;
    let public = root.join("public");
    let secrets = root.join("secrets");
    files::directory(&public)?;
    files::directory(&secrets)?;
    for role in ROLES {
        files::directory(&secrets.join(role))?;
    }
    let tls = root.join("setup-only-tls");
    certificates::generate(&tls, 5);
    files::write_new(&public.join("ca.der"), &certificates::root_der(&tls))?;
    let signing: Vec<_> = (0..5)
        .map(|_| {
            let mut seed = Zeroizing::new([0; 32]);
            OsRng
                .try_fill_bytes(seed.as_mut())
                .map_err(|_| "OS entropy unavailable")?;
            Ok::<_, Box<dyn std::error::Error>>(SigningKey::from_bytes(&seed))
        })
        .collect::<Result<_>>()?;
    let (a_key, a_public) = generate_hpke_key()?;
    let (b_key, b_public) = generate_hpke_key()?;
    for (role, key) in [("a", a_key), ("b", b_key)] {
        let mut bytes = key.to_bytes();
        let written = files::write_new(&secrets.join(role).join("hpke"), bytes.as_slice());
        bytes.as_mut_slice().zeroize();
        written?;
    }
    let mut tokens = Zeroizing::new([[0; 32]; 32]);
    for token in tokens.iter_mut() {
        OsRng
            .try_fill_bytes(token)
            .map_err(|_| "OS entropy unavailable")?;
    }
    tokens.sort_by_key(|token| domain_hash("SilkNode-F0-token", &[token]));
    let hashes: [Digest; 32] =
        std::array::from_fn(|i| domain_hash("SilkNode-F0-token", &[&tokens[i]]));
    let flat: Vec<_> = hashes.iter().flatten().copied().collect();
    let cohort = 0_u32;
    let mut config = [0; 770];
    config[..8].copy_from_slice(b"SNCFGF03");
    config[8..40].copy_from_slice(&genesis.domain());
    config[40..44].copy_from_slice(&cohort.to_le_bytes());
    config[44..48].copy_from_slice(&epoch.to_le_bytes());
    config[48..56].copy_from_slice(&(u64::from(epoch) * 2880).to_le_bytes());
    config[56..64].copy_from_slice(&((u64::from(epoch) + 1) * 2880).to_le_bytes());
    config[64..96].copy_from_slice(&signing[0].verifying_key().to_bytes());
    config[96..128].copy_from_slice(&signing[1].verifying_key().to_bytes());
    config[128..160].copy_from_slice(&a_public);
    config[160..192].copy_from_slice(&b_public);
    for (i, identity) in signing.iter().enumerate() {
        let certificate = CertificateDer::from(certificates::leaf_der(&tls, i));
        let at = 192 + 82 * i;
        config[at..at + 16].copy_from_slice(&Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets());
        config[at + 16..at + 18].copy_from_slice(&(port + u16::try_from(i)?).to_le_bytes());
        config[at + 18..at + 50].copy_from_slice(&identity.verifying_key().to_bytes());
        config[at + 50..at + 82].copy_from_slice(&spki_pin(&certificate)?);
        let secret = secrets.join(ROLES[i]);
        files::write_new(
            &secret.join("signing"),
            Zeroizing::new(identity.to_bytes()).as_ref(),
        )?;
        files::write_new(
            &secret.join("tls.der"),
            Zeroizing::new(certificates::private_key_der(&tls, i)).as_ref(),
        )?;
        files::write_new(
            &public.join(format!("{}.der", ROLES[i])),
            certificate.as_ref(),
        )?;
    }
    config[602..634].copy_from_slice(&domain_hash(
        "SilkNode-F0-roster",
        &[&domain, &cohort.to_le_bytes(), &epoch.to_le_bytes(), &flat],
    ));
    config[634..638].copy_from_slice(&500_u32.to_le_bytes());
    config[638..640].copy_from_slice(&[8, 32]);
    let mut signed = vec![23];
    signed.extend_from_slice(b"SilkNode-F0-config-sign");
    // Exact domain framing uses the ASCII byte count, not a display label length.
    signed[0] = u8::try_from(b"SilkNode-F0-config-sign".len())?;
    signed.extend_from_slice(&config[..642]);
    config[642..706].copy_from_slice(&sign_role(&signing[0], &signed)?);
    config[706..770].copy_from_slice(&sign_role(&signing[1], &signed)?);
    let roots = [
        signing[0].verifying_key().to_bytes(),
        signing[1].verifying_key().to_bytes(),
    ];
    let accepted = SignedConfig::verify(&config, domain, cohort, epoch, roots)?;
    let _ = Roster::verify(hashes, &accepted)?;
    files::write_new(&public.join("config"), &config)?;
    files::write_new(&public.join("domain"), &domain)?;
    files::write_new(&public.join("roots"), &roots.concat())?;
    files::write_new(&public.join("genesis"), &genesis_bytes)?;
    files::write_new(&public.join("FUNCTIONAL_ONLY"), b"same-host fixture; epoch lifecycle and external UTC qualification absent; no privacy or independent custody acceptance\n")?;
    files::write_new(&secrets.join("a/roster"), &flat)?;
    let tokens_flat = Zeroizing::new(tokens.iter().flatten().copied().collect::<Vec<_>>());
    files::write_new(&secrets.join("clients/tokens"), &tokens_flat)?;
    files::write_new(&secrets.join("clients/payment-2790"), payment.as_ref())?;
    println!(
        "setup_complete=true epoch={epoch} functional_only=true independent_custody=false qualified_utc=false epoch_lifecycle=false"
    );
    Ok(())
}
