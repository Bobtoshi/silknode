//! Functional loopback TLS check; not fixed-slot/kernel-trace privacy acceptance.
#[allow(dead_code)]
#[path = "../../silk-node/tests/support/private_relay_test_certificates.rs"]
mod certificates;

use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use silk_f04_relay::{
    config::Endpoint,
    tls::{RecordSize, Transport, spki_pin},
};
use std::{
    net::{Ipv4Addr, TcpListener, TcpStream},
    time::{Duration, Instant},
};

#[test]
fn exact_live_tls_records_and_wrong_spki_refusal() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("tls");
    certificates::generate(&root, 1);
    let cert = CertificateDer::from(certificates::leaf_der(&root, 0));
    for valid in [true, false] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = Endpoint {
            address: Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets(),
            port: address.port(),
            signing: [0; 32],
            spki: spki_pin(&cert).unwrap(),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificates::private_key_der(
            &root, 0,
        )));
        let cert = cert.clone();
        let receiver = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let result = Transport::server(socket, endpoint, vec![cert], key, deadline);
            if !valid {
                assert!(result.is_err());
                return;
            }
            let mut transport = result.unwrap();
            for (i, size) in [
                RecordSize::Join,
                RecordSize::Manifest,
                RecordSize::Control,
                RecordSize::Cell,
            ]
            .into_iter()
            .enumerate()
            {
                transport.expect(size, deadline).unwrap();
                let plaintext = loop {
                    if let Some(data) = transport.read_step().unwrap() {
                        break data;
                    }
                    std::thread::yield_now();
                };
                assert_eq!(
                    plaintext.as_slice(),
                    vec![u8::try_from(i).unwrap(); size.bytes()]
                );
            }
        });
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificates::root_der(&root)))
            .unwrap();
        let mut expected = endpoint;
        if !valid {
            expected.spki[0] ^= 1;
        }
        let result = Transport::client(
            TcpStream::connect(address).unwrap(),
            expected,
            roots,
            deadline,
        );
        if valid {
            let mut transport = result.unwrap();
            // Join immediately follows local Finished, without a server-ready barrier.
            for (i, size) in [
                RecordSize::Join,
                RecordSize::Manifest,
                RecordSize::Control,
                RecordSize::Cell,
            ]
            .into_iter()
            .enumerate()
            {
                transport
                    .queue(
                        size,
                        &vec![u8::try_from(i).unwrap(); size.bytes()],
                        deadline,
                    )
                    .unwrap();
                while !transport.write_step().unwrap() {
                    std::thread::yield_now();
                }
            }
        } else {
            assert!(result.is_err());
        }
        receiver.join().unwrap();
    }
}
