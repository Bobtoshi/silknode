//! Socket workers never hold or mutate the node. Its owner alone handles requests.
use crate::{
    Result,
    limits::{Limits, MAX_CONNECTIONS},
    wire,
};
use rustls::ServerConfig;
use std::{
    io,
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        Arc,
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::Instant,
};

struct Ready {
    request: Vec<u8>,
    until: Instant,
    reply: SyncSender<Vec<u8>>,
}
struct Worker {
    cancel: TcpStream,
    thread: JoinHandle<()>,
}
pub struct Server {
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    expected: [u8; 140],
    limits: Limits,
    send: SyncSender<Ready>,
    ready: Option<Receiver<Ready>>,
    workers: Vec<Worker>,
}
impl Server {
    pub fn new(listener: TcpListener, tls: Arc<ServerConfig>, expected: [u8; 140]) -> Result<Self> {
        listener.set_nonblocking(true)?;
        let (send, ready) = mpsc::sync_channel(MAX_CONNECTIONS);
        Ok(Self {
            listener,
            tls,
            expected,
            limits: Limits::new(),
            send,
            ready: Some(ready),
            workers: Vec::with_capacity(MAX_CONNECTIONS),
        })
    }
    // At most one queued request and one accept per tick, including refusals.
    pub fn tick(&mut self, mut handle: impl FnMut(&[u8]) -> Result<Vec<u8>>) -> Result<bool> {
        let mut i = 0;
        while i < self.workers.len() {
            if self.workers[i].thread.is_finished() {
                self.workers
                    .swap_remove(i)
                    .thread
                    .join()
                    .map_err(|_| "seed worker failed")?;
            } else {
                i += 1;
            }
        }
        if let Ok(work) = self.ready.as_ref().ok_or("seed stopped")?.try_recv() {
            if Instant::now() < work.until {
                // A reply lost after admission never authorizes state reset/retry.
                let _ = work.reply.try_send(handle(&work.request)?);
            }
        }
        let accepted = match self.listener.accept() {
            Ok((socket, peer)) => {
                if self.workers.len() < MAX_CONNECTIONS {
                    if let Some(permit) = self.limits.admit(peer.ip(), Instant::now()) {
                        let cancel = socket.try_clone()?;
                        let tls = self.tls.clone();
                        let expected = self.expected;
                        let send = self.send.clone();
                        let worker =
                            thread::Builder::new()
                                .name("seed-socket".into())
                                .spawn(move || {
                                    // A peer error closes only this socket and releases its permit.
                                    let _ = (|| -> Result<()> {
                                        if let Some(mut stream) =
                                            wire::accept(socket, tls, &expected, permit)?
                                        {
                                            let request =
                                                wire::read_frame(&mut stream, wire::MAX_REQUEST)?;
                                            let (reply, receive) = mpsc::sync_channel(1);
                                            let until = stream.sock.until();
                                            send.try_send(Ready {
                                                request,
                                                until,
                                                reply,
                                            })?;
                                            let bytes =
                                                receive.recv_timeout(stream.sock.remaining()?)?;
                                            wire::write_frame(&mut stream, &bytes)?;
                                        }
                                        Ok(())
                                    })();
                                })?;
                        self.workers.push(Worker {
                            cancel,
                            thread: worker,
                        });
                    }
                }
                true
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                false
            }
            Err(e) => return Err(e.into()),
        };
        Ok(accepted)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        // Disconnect queued replies and interrupt blocked socket I/O before joining.
        self.ready.take();
        for worker in &self.workers {
            let _ = worker.cancel.shutdown(Shutdown::Both);
        }
        for worker in self.workers.drain(..) {
            let _ = worker.thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    };
    use std::{
        fs,
        io::{Read, Write},
        path::PathBuf,
        process::Command,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    struct Fixture {
        dir: PathBuf,
        server: Arc<ServerConfig>,
        client: Arc<ClientConfig>,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "silknode-seed-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&dir).unwrap();
            let generate = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
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
                    dir.join("cert.der").to_str().unwrap(),
                    "-keyout",
                    dir.join("key.pem").to_str().unwrap(),
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
                        dir.join("key.pem").to_str().unwrap(),
                        "-outform",
                        "DER",
                        "-out",
                        dir.join("key.der").to_str().unwrap(),
                    ])
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            let certificate = CertificateDer::from(fs::read(dir.join("cert.der")).unwrap());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut server = ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        fs::read(dir.join("key.der")).unwrap(),
                    )),
                )
                .unwrap();
            server.send_tls13_tickets = 0;
            server.alpn_protocols = vec![b"silknode-zero/1".to_vec()];
            let mut roots = RootCertStore::empty();
            roots.add(certificate).unwrap();
            let mut client = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client.alpn_protocols = vec![b"silknode-zero/1".to_vec()];
            Self {
                dir,
                server: Arc::new(server),
                client: Arc::new(client),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for name in ["key.pem", "key.der", "cert.der"] {
                fs::remove_file(self.dir.join(name)).unwrap();
            }
            fs::remove_dir(&self.dir).unwrap();
        }
    }
    fn client(
        config: Arc<ClientConfig>,
        address: std::net::SocketAddr,
    ) -> StreamOwned<ClientConnection, TcpStream> {
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let connection =
            ClientConnection::new(config, ServerName::IpAddress(address.ip().into())).unwrap();
        StreamOwned::new(connection, socket)
    }

    #[test]
    fn stalled_tls_and_hello_do_not_block_discovery_and_caps_clean_up() {
        let fixture = Fixture::new();
        for complete_tls in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            // A mock application identity/status isolates transport scheduling;
            // no node store, history, proof or work generation is involved.
            let expected = [23; 140];
            let mut server = Server::new(listener, fixture.server.clone(), expected).unwrap();
            let mut idle = client(fixture.client.clone(), address);
            accept_next(&mut server);
            if complete_tls {
                while idle.conn.is_handshaking() {
                    idle.conn.complete_io(&mut idle.sock).unwrap();
                }
            }
            let config = fixture.client.clone();
            let legitimate = thread::spawn(move || {
                let mut stream = client(config, address);
                stream.write_all(&expected).unwrap();
                stream.flush().unwrap();
                let mut ack = [255];
                stream.read_exact(&mut ack).unwrap();
                assert_eq!(ack, [0]);
                wire::write_frame(&mut stream, &[0]).unwrap();
                wire::read_frame(&mut stream, wire::MAX_RESPONSE).unwrap()
            });
            let began = Instant::now();
            let discovery = b"\0{\"schema\":\"silknode-public-status-v1\"}";
            while !legitimate.is_finished() && began.elapsed() < Duration::from_secs(1) {
                server
                    .tick(|request| {
                        assert_eq!(request, [0]);
                        Ok(discovery.to_vec())
                    })
                    .unwrap();
                thread::sleep(Duration::from_millis(1));
            }
            assert!(
                legitimate.is_finished(),
                "discovery waited behind the stalled peer"
            );
            assert_eq!(legitimate.join().unwrap(), discovery);
            assert!(began.elapsed() < wire::HANDSHAKE_WINDOW);
            let reap = Instant::now();
            while server.workers.len() != 1 && reap.elapsed() < Duration::from_millis(250) {
                server.tick(|_| panic!("unexpected request")).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(
                server.workers.len(),
                1,
                "idle handshake must still be occupying a slot"
            );
            let _second_idle = TcpStream::connect(address).unwrap();
            let admitted = Instant::now();
            while server.workers.len() != 2 && admitted.elapsed() < Duration::from_millis(250) {
                server.tick(|_| panic!("unexpected request")).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(server.workers.len(), 2);
            let mut refused = TcpStream::connect(address).unwrap();
            refused
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            accept_next(&mut server);
            match refused.read(&mut [0]) {
                Ok(0) => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                other => panic!("per-IP cap did not close the excess connection: {other:?}"),
            }
            let wait = Instant::now();
            while !server.workers.is_empty()
                && wait.elapsed() < wire::HANDSHAKE_WINDOW + Duration::from_secs(1)
            {
                server
                    .tick(|_| panic!("idle peer reached application"))
                    .unwrap();
                thread::sleep(Duration::from_millis(5));
            }
            assert!(
                server.workers.is_empty(),
                "handshake deadline did not release workers"
            );
            let mut cancelled = TcpStream::connect(address).unwrap();
            cancelled
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            accept_next(&mut server);
            let cleanup = Instant::now();
            drop(server);
            assert!(cleanup.elapsed() < Duration::from_secs(1));
            match cancelled.read(&mut [0]) {
                Ok(0) => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                other => panic!("shutdown did not close the worker socket: {other:?}"),
            }
        }
    }
    fn accept_next(server: &mut Server) {
        let began = Instant::now();
        while !server.tick(|_| panic!("unexpected request")).unwrap() {
            assert!(
                began.elapsed() < Duration::from_millis(250),
                "loopback accept was not ready"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }
}
