//! One bounded request per TLS1.3 connection. This is full work-bearing vertex
//! gossip, not a wallet envelope ingress or a replacement for the private relay.
use crate::{
    Result,
    config::{Config, read_file, sha256},
    fail,
    limits::Permit,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::NoServerSessionStorage,
};
use silk_f04_node::genesis::Genesis;
use silk_sapling_f04::codec::carriage_hash;
use std::{
    io::{self, Read, Write},
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

pub const MAGIC: &[u8; 8] = b"SNZNET01";
pub const PROTOCOL_HEX: &str = "9f0c99bc6d025ee6d0716dce183ab4d564a651c1ca30a042f588773a26e666a3";
pub const MAX_RESPONSE: usize = 32 * (90_000 + 4) + 4096;
pub const MAX_REQUEST: usize = 90_001;
const WINDOW: Duration = Duration::from_secs(45);
pub const HANDSHAKE_WINDOW: Duration = Duration::from_secs(3);
// Linux can coalesce a long SO_RCVTIMEO/SO_SNDTIMEO past its nominal end.
// Short waits recheck the original Instant; progress never renews the window.
const IO_SLICE: Duration = Duration::from_millis(100);
pub fn hello(g: &Genesis) -> Result<[u8; 140]> {
    let protocol = carriage_hash(
        "SilkNode/PublicZeroWire/v1",
        &[MAGIC, &[1], g.context().bytes()],
    );
    if hex::encode(protocol) != PROTOCOL_HEX {
        return fail("wire protocol byte pin");
    }
    let mut b = [0; 140];
    b[..8].copy_from_slice(MAGIC);
    b[8] = 1;
    b[12..44].copy_from_slice(&g.context().bytes()[12..44]);
    b[44..76].copy_from_slice(&g.context().bytes()[44..76]);
    b[76..108].copy_from_slice(&g.domain());
    b[108..].copy_from_slice(&protocol);
    Ok(b)
}
// Every underlying I/O operation uses the remaining ORIGINAL exchange window.
// Partial reads/TLS progress cannot renew a slow peer's occupancy indefinitely.
pub struct DeadlineSocket {
    socket: TcpStream,
    until: Instant,
    budget: Option<Permit>,
}
impl DeadlineSocket {
    fn new(socket: TcpStream) -> Result<Self> {
        // Accepted sockets can inherit the nonblocking listener mode on macOS.
        // Worker I/O is blocking, with the remaining deadline applied below.
        socket.set_nonblocking(false)?;
        socket.set_nodelay(true)?;
        Ok(Self {
            socket,
            until: Instant::now() + WINDOW,
            budget: None,
        })
    }
    pub fn remaining(&self) -> io::Result<Duration> {
        self.until
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "exchange deadline"))
    }
    pub fn until(&self) -> Instant {
        self.until
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        loop {
            self.socket
                .set_read_timeout(Some(self.remaining()?.min(IO_SLICE)))?;
            match self.socket.read(b) {
                Ok(n) => {
                    self.remaining()?;
                    return Ok(n);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        loop {
            self.socket
                .set_write_timeout(Some(self.remaining()?.min(IO_SLICE)))?;
            if let Some(budget) = &mut self.budget {
                // Each actual TCP attempt, including retries, remains charged.
                budget.charge(b.len(), Instant::now())?;
            }
            self.remaining()?;
            match self.socket.write(b) {
                Ok(n) => {
                    self.remaining()?;
                    return Ok(n);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}
pub fn server_config(c: &Config) -> Result<Arc<ServerConfig>> {
    let cert = read_file(
        c.server_certificate_der
            .as_deref()
            .ok_or("server certificate")?,
        8192,
    )?;
    if sha256(&cert) != c.seed_certificate_sha256 {
        return fail("own seed certificate pin");
    }
    let key = read_file(c.server_key_pkcs8_der.as_deref().ok_or("server key")?, 8192)?;
    let mut out =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            )?;
    out.session_storage = Arc::new(NoServerSessionStorage {});
    out.send_tls13_tickets = 0;
    out.max_early_data_size = 0;
    out.alpn_protocols = vec![b"silknode-zero/1".to_vec()];
    Ok(Arc::new(out))
}
pub fn accept(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    expected: &[u8; 140],
    permit: Permit,
) -> Result<Option<StreamOwned<ServerConnection, DeadlineSocket>>> {
    let mut conn = ServerConnection::new(config)?;
    conn.set_buffer_limit(Some(128 * 1024));
    let mut socket = DeadlineSocket::new(socket)?;
    socket.until = permit.began + HANDSHAKE_WINDOW;
    socket.budget = Some(permit);
    let mut stream = StreamOwned::new(conn, socket);
    let mut h = [0; 140];
    stream.read_exact(&mut h)?;
    if &h != expected {
        stream.write_all(&[1])?;
        stream.flush()?;
        return Ok(None);
    }
    stream.write_all(&[0])?;
    stream.flush()?;
    // The payload window starts once, only after TLS and the exact hello succeed.
    stream.sock.remaining()?;
    stream.sock.until = Instant::now() + WINDOW;
    Ok(Some(stream))
}
pub fn connect(c: &Config) -> Result<StreamOwned<ClientConnection, DeadlineSocket>> {
    let ca_text = read_file(&c.ca_der_hex, 16384)?;
    let ca = hex::decode(std::str::from_utf8(&ca_text)?.trim())?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca))?;
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_sni = false;
    config.alpn_protocols = vec![b"silknode-zero/1".to_vec()];
    let mut conn =
        ClientConnection::new(Arc::new(config), ServerName::IpAddress(c.seed.ip().into()))?;
    conn.set_buffer_limit(Some(128 * 1024));
    let socket = TcpStream::connect_timeout(&c.seed, Duration::from_secs(5))?;
    let mut socket = DeadlineSocket::new(socket)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut socket)?;
    }
    if conn
        .peer_certificates()
        .and_then(|p| p.first())
        .map(|p| sha256(p.as_ref()))
        != Some(c.seed_certificate_sha256.clone())
    {
        return fail("seed certificate pin");
    }
    Ok(StreamOwned::new(conn, socket))
}
pub fn request(c: &Config, g: &Genesis, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut stream = connect(c)?;
    stream.write_all(&hello(g)?)?;
    stream.flush()?;
    let mut ack = [0];
    stream.read_exact(&mut ack)?;
    if ack != [0] {
        return fail("seed refused network identity");
    }
    write_frame(&mut stream, bytes)?;
    let response = read_frame(&mut stream, MAX_RESPONSE)?;
    if response.first() != Some(&0) {
        return fail("seed refused request");
    }
    Ok(response[1..].to_vec())
}
pub fn wrong_network(c: &Config, g: &Genesis) -> Result<()> {
    let mut stream = connect(c)?;
    let mut h = hello(g)?;
    h[12] ^= 1;
    stream.write_all(&h)?;
    stream.flush()?;
    let mut ack = [0];
    stream.read_exact(&mut ack)?;
    if ack != [1] {
        return fail("wrong network was not explicitly refused");
    }
    println!("wrong_network=REFUSED;tls_certificate=VERIFIED;before_vertex_admission=true");
    Ok(())
}
pub fn read_frame(stream: &mut impl Read, limit: usize) -> Result<Vec<u8>> {
    let mut size = [0; 4];
    stream.read_exact(&mut size)?;
    let n = u32::from_be_bytes(size) as usize;
    if n == 0 || n > limit {
        return fail("wire frame limit");
    }
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
pub fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_RESPONSE {
        return fail("outgoing frame limit");
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn short_io_slices_keep_original_deadline_and_refuse_late_io() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let mut stream = DeadlineSocket::new(socket).unwrap();
        let began = Instant::now();
        stream.until = began + Duration::from_millis(250);
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(began.elapsed() >= Duration::from_millis(250));
        assert!(began.elapsed() < Duration::from_millis(500));
        peer.write_all(&[7]).unwrap();
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            stream.write(&[8]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
