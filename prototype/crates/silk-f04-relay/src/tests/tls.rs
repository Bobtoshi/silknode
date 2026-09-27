//! Reusable local TLS pair, no application role/clock/custody authority.
use super::certificates;
use crate::{
    config::Endpoint,
    tls::{SetupStep, Transport, spki_pin},
};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::{
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::Path,
    time::{Duration, Instant},
};

pub fn pair(certs: &Path) -> (Transport, Transport) {
    let cert = CertificateDer::from(certificates::leaf_der(certs, 0));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificates::private_key_der(
        certs, 0,
    )));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificates::root_der(certs)))
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let endpoint = Endpoint {
        address: Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets(),
        port: listener.local_addr().unwrap().port(),
        signing: [0; 32],
        spki: spki_pin(&cert).unwrap(),
    };
    assert_ne!(endpoint.spki, certificates::leaf_pin(certs, 0));
    let deadline = Instant::now() + Duration::from_secs(3);
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    let mut pending = [
        Some(Transport::client_setup(client, endpoint, roots, deadline).unwrap()),
        Some(Transport::server_setup(server, endpoint, vec![cert], key, deadline).unwrap()),
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
        std::thread::sleep(Duration::from_micros(100));
    }
    (ready[0].take().unwrap(), ready[1].take().unwrap())
}
