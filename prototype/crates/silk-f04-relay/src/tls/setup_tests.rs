//! Focused local incremental-handshake checks, not clock/epoch admission.
use super::*;
use crate::tls::{ConnectStep, Connecting, RecordSize, spki_pin};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use std::net::{Ipv4Addr, TcpListener};

use crate::tests::certificates;

#[test]
fn incremental_handshake_preserves_queued_join_and_original_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let certs = temp.path().join("tls");
    certificates::generate(&certs, 1);
    let certificate = CertificateDer::from(certificates::leaf_der(&certs, 0));
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificates::private_key_der(
        &certs, 0,
    )));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificates::root_der(&certs)))
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let endpoint = Endpoint {
        address: Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets(),
        port: listener.local_addr().unwrap().port(),
        signing: [0; 32],
        spki: spki_pin(&certificate).unwrap(),
    };
    assert_ne!(endpoint.spki, certificates::leaf_pin(&certs, 0)); // Exact SPKI, not whole leaf DER.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut connecting = Connecting::new(endpoint, roots.clone(), deadline).unwrap();
    let mut client = Some(loop {
        match connecting.poll().unwrap() {
            ConnectStep::Pending(pending) => connecting = pending,
            ConnectStep::Handshaking(handshake) => break handshake,
        }
        std::thread::sleep(Duration::from_micros(100));
    });
    let server_socket = listener.accept().unwrap().0;
    let mut server = Some(
        Transport::server_setup(server_socket, endpoint, vec![certificate], key, deadline).unwrap(),
    );
    let mut client_ready = None;
    let mut server_ready = None;
    let mut hold_server = false;
    let join = [42; 128];
    let mut join_queued = false;
    let mut join_written = false;
    while server_ready.is_none() || !join_written {
        assert!(
            Instant::now() < deadline,
            "bounded handshake did not finish"
        );
        if let Some(pending) = client.take() {
            match pending.poll().unwrap() {
                SetupStep::Pending(pending) => {
                    let Connection::Client(connection) = &pending.connection else {
                        panic!("client type");
                    };
                    // Server Finished has been processed. Stop the server until
                    // client Finished AND Join are queued, ensuring its next
                    // reads cannot rely on absence of following application data.
                    hold_server |= !connection.is_handshaking();
                    client = Some(pending);
                }
                SetupStep::Established(transport) => client_ready = Some(transport),
            }
        }
        if let Some(transport) = &mut client_ready {
            if !join_queued {
                transport.queue(RecordSize::Join, &join, deadline).unwrap();
                join_queued = true;
            }
            if !join_written {
                join_written = transport.write_step().unwrap();
            }
        }
        if (!hold_server || join_written)
            && let Some(pending) = server.take()
        {
            match pending.poll().unwrap() {
                SetupStep::Pending(pending) => server = Some(pending),
                SetupStep::Established(transport) => server_ready = Some(transport),
            }
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    assert!(hold_server && client_ready.is_some());
    let mut server = server_ready.unwrap();
    server.expect(RecordSize::Join, deadline).unwrap();
    loop {
        if let Some(bytes) = server.read_step().unwrap() {
            assert_eq!(bytes.as_slice(), join);
            break;
        }
        std::thread::sleep(Duration::from_micros(100));
    }
    // A silent socket cannot refresh the attempt's deadline across polls.
    let silent_client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let _silent_server = listener.accept().unwrap().0;
    let short = Instant::now() + Duration::from_millis(20);
    let pending = Transport::client_setup(silent_client, endpoint, roots, short).unwrap();
    let SetupStep::Pending(pending) = pending.poll().unwrap() else {
        panic!("no server handshake");
    };
    std::thread::sleep(Duration::from_millis(25));
    assert!(pending.poll().is_err());
}
