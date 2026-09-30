//! Driver/transport components only. MemoryReceiver grants no node authority.
use super::*;
use crate::{config::sha256, peers::fixture_config};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    sync::Arc,
    thread,
};

#[path = "tests/live.rs"]
mod live;

fn status(peer: &Config, total: usize) -> Info {
    Info {
        schema: "silknode-public-status-v1".into(),
        seed: peer.seed.to_string(),
        domain: public_testnet_v1::DOMAIN_HEX.into(),
        vertices: total,
        checkpoint_index: 0,
        checkpoint: "4".repeat(64),
        state: "5".repeat(64),
        executed: total,
        initial_allocation: 0,
    }
}
#[derive(Default)]
struct MemoryReceiver {
    values: BTreeSet<Vec<u8>>,
    calls: usize,
    fail_local: bool,
}
impl Receiver for MemoryReceiver {
    fn ingest(&mut self, bytes: &[u8]) -> Result<()> {
        self.calls += 1;
        if self.fail_local {
            return fail("synthetic local clock/storage/resource refusal");
        }
        self.values.insert(bytes.to_vec());
        Ok(())
    }
    fn snapshot(&self) -> Result<Info> {
        Ok(status(
            &fixture_config("127.0.0.1:10001".parse().unwrap()),
            self.values.len(),
        ))
    }
}
fn frame(values: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(values.len()).unwrap()];
    for value in values {
        bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(value);
    }
    bytes
}
fn offset(request: &[u8]) -> usize {
    assert_eq!(request.len(), 5);
    assert_eq!(request[0], 1);
    u32::from_be_bytes(request[1..].try_into().unwrap()) as usize
}
fn sources() -> Vec<Config> {
    vec![
        fixture_config("127.0.0.1:10001".parse().unwrap()),
        fixture_config("127.0.0.1:10002".parse().unwrap()),
    ]
}

#[test]
fn disconnect_keeps_accepted_prefix_and_restarts_new_source_at_zero() {
    let sources = sources();
    let mut receiver = MemoryReceiver::default();
    let mut ranges = Vec::new();
    let target = run_sources(&mut receiver, &sources, |peer, request, _| {
        if request == [0] {
            return Ok(serde_json::to_vec(&status(peer, 4))?);
        }
        let start = offset(request);
        ranges.push((peer.seed, start));
        if peer.seed == sources[0].seed {
            if start == 0 {
                return Ok(frame(&[b"a", b"b"]));
            }
            return fail("synthetic peer disconnect");
        }
        // Same graph, different source order: do not reuse A's cursor at B.
        assert_eq!(start, 0);
        Ok(frame(&[b"b", b"a", b"c", b"d"]))
    })
    .unwrap();
    assert_eq!(target.seed, sources[1].seed.to_string());
    assert_eq!(receiver.values.len(), 4);
    assert_eq!(receiver.calls, 6); // Exact duplicates still reach ordinary ingress.
    assert_eq!(
        ranges,
        [
            (sources[0].seed, 0),
            (sources[0].seed, 2),
            (sources[1].seed, 0)
        ]
    );
}

#[test]
fn malformed_range_and_forged_discovery_do_not_ingest_a_prefix() {
    let sources = sources();
    for forged_discovery in [false, true] {
        let mut receiver = MemoryReceiver::default();
        run_sources(&mut receiver, &sources, |peer, request, _| {
            if request == [0] {
                let mut info = status(peer, 1);
                if peer.seed == sources[0].seed && forged_discovery {
                    info.domain = "0".repeat(64);
                }
                return Ok(serde_json::to_vec(&info)?);
            }
            assert_eq!(offset(request), 0);
            if peer.seed == sources[0].seed {
                let mut malformed = frame(&[b"must-not-ingest"]);
                malformed.push(99);
                return Ok(malformed);
            }
            Ok(frame(&[b"valid-framing-only"]))
        })
        .unwrap();
        assert_eq!(receiver.calls, 1);
        assert_eq!(
            receiver.values,
            BTreeSet::from([b"valid-framing-only".to_vec()])
        );
    }
}

#[test]
fn local_failure_stops_without_trying_another_peer_or_renewing_a_job() {
    let sources = sources();
    let mut receiver = MemoryReceiver {
        fail_local: true,
        ..MemoryReceiver::default()
    };
    let mut calls = 0;
    let error = run_sources(&mut receiver, &sources, |peer, request, _| {
        calls += 1;
        assert_eq!(peer.seed, sources[0].seed);
        if request == [0] {
            Ok(serde_json::to_vec(&status(peer, 1))?)
        } else {
            Ok(frame(&[b"one-attempt-only"]))
        }
    })
    .unwrap_err();
    assert!(error.to_string().contains("local clock/storage/resource"));
    assert_eq!(calls, 2);
    assert_eq!(receiver.calls, 1);
    assert!(receiver.values.is_empty());
}

#[test]
fn peer_state_claims_do_not_replace_locally_derived_state() {
    let sources = sources();
    let mut receiver = MemoryReceiver::default();
    let mut endpoints = Vec::new();
    run_sources(&mut receiver, &sources, |peer, request, _| {
        endpoints.push(peer.seed);
        assert_eq!(request, [0]);
        let mut info = status(peer, 0);
        if peer.seed == sources[0].seed {
            info.state = "6".repeat(64);
        }
        Ok(serde_json::to_vec(&info)?)
    })
    .unwrap();
    assert_eq!(endpoints, [sources[0].seed, sources[1].seed]);
    assert_eq!(receiver.snapshot().unwrap().state, "5".repeat(64));
    assert_eq!(receiver.calls, 0);
}

#[test]
fn exhaustion_is_bounded_and_accepted_state_is_not_erased() {
    let sources = sources();
    let mut receiver = MemoryReceiver::default();
    receiver.values.insert(b"retained".to_vec());
    let mut attempts = Vec::new();
    assert!(
        run_sources(&mut receiver, &sources, |peer, _, _| {
            attempts.push(peer.seed);
            fail("synthetic unavailable peer")
        })
        .is_err()
    );
    assert_eq!(attempts, [sources[0].seed, sources[1].seed]);
    assert_eq!(receiver.values, BTreeSet::from([b"retained".to_vec()]));
    for bad in [Vec::new(), vec![sources[0].clone(); MAX_SOURCES + 1]] {
        assert!(
            run_sources(&mut receiver, &bad, |_, _, _| panic!(
                "invalid source bound connected"
            ))
            .is_err()
        );
    }
}

#[test]
fn cumulative_deadline_is_identical_across_sources_and_expiry_never_connects() {
    let sources = sources();
    let mut receiver = MemoryReceiver::default();
    let until = Some(Instant::now() + Duration::from_secs(10));
    let mut calls = 0;
    assert!(
        run_until(
            &mut receiver,
            &sources,
            |_, _, actual| {
                assert_eq!(actual, until);
                calls += 1;
                fail("synthetic disconnect; do not renew the allowance")
            },
            until
        )
        .is_err()
    );
    assert_eq!(calls, 2);
    assert!(
        run_until(
            &mut receiver,
            &sources,
            |_, _, _| panic!("expired invocation connected"),
            Some(Instant::now() - Duration::from_secs(1))
        )
        .is_err()
    );
    assert_eq!(receiver.calls, 0);
}

struct TlsFixture {
    dir: std::path::PathBuf,
    config: Arc<ServerConfig>,
    ca: std::path::PathBuf,
    pin: String,
}
impl TlsFixture {
    fn new() -> Self {
        let nonce: u64 = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        let dir =
            std::env::temp_dir().join(format!("silknode-sync-tls-{}-{nonce}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let cert = dir.join("cert.der");
        let key = dir.join("key.pem");
        let der = dir.join("key.der");
        let generate = Command::new("openssl")
            .args([
                "req",
                "-config",
                "/dev/null",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=sync-component-test",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth",
                "-outform",
                "DER",
                "-out",
                cert.to_str().unwrap(),
                "-keyout",
                key.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            generate.status.success(),
            "{}",
            String::from_utf8_lossy(&generate.stderr)
        );
        assert!(
            Command::new("openssl")
                .args([
                    "pkcs8",
                    "-topk8",
                    "-nocrypt",
                    "-in",
                    key.to_str().unwrap(),
                    "-outform",
                    "DER",
                    "-out",
                    der.to_str().unwrap()
                ])
                .output()
                .unwrap()
                .status
                .success()
        );
        let bytes = fs::read(&cert).unwrap();
        let ca = dir.join("ca.hex");
        fs::write(&ca, hex::encode(&bytes)).unwrap();
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(bytes.clone())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fs::read(der).unwrap())),
                )
                .unwrap();
        config.send_tls13_tickets = 0;
        config.alpn_protocols = vec![b"silknode-zero/1".to_vec()];
        Self {
            dir,
            config: Arc::new(config),
            ca,
            pin: sha256(&bytes),
        }
    }
    fn source(&self, correct_pin: bool) -> (Config, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = fixture_config(listener.local_addr().unwrap());
        peer.ca_der_hex = self.ca.clone();
        peer.seed_certificate_sha256 = if correct_pin {
            self.pin.clone()
        } else {
            "0".repeat(64)
        };
        let reply = serde_json::to_vec(&status(&peer, 0)).unwrap();
        let config = self.config.clone();
        listener.set_nonblocking(true).unwrap();
        let worker = thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(3);
            let (socket, _) = loop {
                match listener.accept() {
                    Ok(value) => break value,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < until =>
                    {
                        thread::sleep(Duration::from_millis(1))
                    }
                    other => panic!("bounded fixture accept failed: {other:?}"),
                }
            };
            // macOS can inherit the listener's nonblocking mode on accept.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut stream = StreamOwned::new(ServerConnection::new(config).unwrap(), socket);
            let mut hello = [0; 140];
            if !correct_pin {
                // Trusted CA + valid IP still cannot override the explicit leaf pin.
                assert!(stream.read_exact(&mut hello).is_err());
                return;
            }
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(
                hello,
                wire::hello(&public_testnet_v1::genesis().unwrap()).unwrap()
            );
            stream.write_all(&[0]).unwrap();
            stream.flush().unwrap();
            assert_eq!(
                wire::read_frame(&mut stream, wire::MAX_REQUEST).unwrap(),
                [0]
            );
            let mut response = vec![0];
            response.extend(reply);
            wire::write_frame(&mut stream, &response).unwrap();
        });
        (peer, worker)
    }
}
impl Drop for TlsFixture {
    fn drop(&mut self) {
        for name in ["cert.der", "key.pem", "key.der", "ca.hex"] {
            fs::remove_file(self.dir.join(name)).unwrap();
        }
        fs::remove_dir(&self.dir).unwrap();
    }
}

#[test]
fn actual_tls_wrong_pin_fails_over_to_separately_pinned_loopback_peer() {
    let fixture = TlsFixture::new();
    let (wrong, wrong_worker) = fixture.source(false);
    let (right, right_worker) = fixture.source(true);
    let sources = [wrong, right];
    let genesis = public_testnet_v1::genesis().unwrap();
    let mut receiver = MemoryReceiver::default();
    let result = run_sources(&mut receiver, &sources, |peer, request, until| {
        wire::request_until(
            peer,
            &genesis,
            request,
            until.expect("shared multi-source deadline"),
        )
    });
    wrong_worker.join().unwrap();
    right_worker.join().unwrap();
    let target = result.unwrap();
    assert_eq!(target.seed, sources[1].seed.to_string());
    assert_eq!(receiver.calls, 0);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut expired = sources[1].clone();
    expired.seed = listener.local_addr().unwrap();
    assert!(
        wire::request_until(
            &expired,
            &genesis,
            &[0],
            Instant::now() - Duration::from_secs(1)
        )
        .is_err()
    );
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
