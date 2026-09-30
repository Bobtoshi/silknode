//! Explicit operator-pinned source set. No peer-supplied enrollment or trust.
use crate::{
    Result,
    config::{Config, digest, read_file},
    fail,
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub const MAX_SOURCES: usize = 8;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerPin {
    endpoint: SocketAddr,
    ca_der_hex: PathBuf,
    certificate_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerFile {
    schema: String,
    peers: Vec<PeerPin>,
}

/// Keep the configured primary first; additional sources have separate TLS pins.
/// Only the caller's networking fields change. Store, retained pin and parameters
/// are always the original operator's, never supplied by a discovery response.
pub fn load(primary: &Config, path: &Path) -> Result<Vec<Config>> {
    if !path.is_absolute() {
        return fail("peer manifest path must be absolute");
    }
    let file: PeerFile = serde_json::from_slice(&read_file(path, 16384)?)?;
    from_file(primary, file)
}

fn from_file(primary: &Config, file: PeerFile) -> Result<Vec<Config>> {
    if file.schema != "silknode-public-peers-v1"
        || file.peers.is_empty()
        || file.peers.len() >= MAX_SOURCES
    {
        return fail("explicit peer schema and 1..7 additional sources required");
    }
    let mut endpoints = BTreeSet::from([primary.seed]);
    let mut sources = vec![primary.clone()];
    for pin in file.peers {
        if pin.endpoint.port() == 0
            || pin.endpoint.ip().is_unspecified()
            || pin.endpoint.ip().is_multicast()
            || !pin.ca_der_hex.is_absolute()
            || !endpoints.insert(pin.endpoint)
        {
            return fail("peer endpoint/path/duplicate bound");
        }
        digest(&pin.certificate_sha256)?;
        let mut source = primary.clone();
        source.seed = pin.endpoint;
        source.ca_der_hex = pin.ca_der_hex;
        source.seed_certificate_sha256 = pin.certificate_sha256;
        sources.push(source);
    }
    Ok(sources)
}

#[cfg(test)]
pub(crate) fn fixture_config(endpoint: SocketAddr) -> Config {
    Config {
        schema: "silknode-public-testnet-config-v1".into(),
        accept_public_zero_value: true,
        domain: silk_f04_node::genesis::public_testnet_v1::DOMAIN_HEX.into(),
        store: "/synthetic/store".into(),
        retained_head: "/synthetic/pins/head".into(),
        host_margin: "/synthetic".into(),
        spend_parameters: "/synthetic/spend".into(),
        output_parameters: "/synthetic/output".into(),
        seed: endpoint,
        ca_der_hex: "/synthetic/ca.hex".into(),
        seed_certificate_sha256: "1".repeat(64),
        reward_owner: "2".repeat(64),
        listen: None,
        server_certificate_der: None,
        server_key_pkcs8_der: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pin(endpoint: &str) -> PeerPin {
        PeerPin {
            endpoint: endpoint.parse().unwrap(),
            ca_der_hex: "/other/ca.hex".into(),
            certificate_sha256: "3".repeat(64),
        }
    }
    fn file(peers: Vec<PeerPin>) -> PeerFile {
        PeerFile {
            schema: "silknode-public-peers-v1".into(),
            peers,
        }
    }
    #[test]
    fn pinned_sources_do_not_replace_operator_authority_or_primary_defaults() {
        let primary = fixture_config("127.0.0.1:10001".parse().unwrap());
        let sources = from_file(&primary, file(vec![pin("127.0.0.1:10002")])).unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].seed, primary.seed);
        assert_eq!(sources[1].seed_certificate_sha256, "3".repeat(64));
        assert_eq!(sources[1].ca_der_hex, PathBuf::from("/other/ca.hex"));
        for source in &sources {
            assert_eq!(source.store, primary.store);
            assert_eq!(source.retained_head, primary.retained_head);
            assert_eq!(source.spend_parameters, primary.spend_parameters);
            assert_eq!(source.output_parameters, primary.output_parameters);
            assert_eq!(source.reward_owner, primary.reward_owner);
            assert_eq!(source.domain, primary.domain);
        }
    }
    #[test]
    fn malformed_unpinned_duplicate_or_excessive_sources_refuse() {
        let primary = fixture_config("127.0.0.1:10001".parse().unwrap());
        for pins in [
            vec![],
            vec![pin("127.0.0.1:10001")],
            vec![pin("127.0.0.1:10002"), pin("127.0.0.1:10002")],
            vec![pin("0.0.0.0:10002")],
            vec![pin("127.0.0.1:0")],
            vec![pin("224.0.0.1:10002")],
            (10002..10010)
                .map(|p| pin(&format!("127.0.0.1:{p}")))
                .collect(),
        ] {
            assert!(from_file(&primary, file(pins)).is_err());
        }
        let mut bad = pin("127.0.0.1:10002");
        bad.ca_der_hex = "relative.hex".into();
        assert!(from_file(&primary, file(vec![bad])).is_err());
        let mut bad = pin("127.0.0.1:10002");
        bad.certificate_sha256 = "F".repeat(64);
        assert!(from_file(&primary, file(vec![bad])).is_err());
        let mut bad = file(vec![pin("127.0.0.1:10002")]);
        bad.schema.push('2');
        assert!(from_file(&primary, bad).is_err());
        assert!(
            serde_json::from_str::<PeerFile>(
                r#"{"schema":"silknode-public-peers-v1","peers":[],"trust_remote_head":true}"#
            )
            .is_err()
        );
    }
}
