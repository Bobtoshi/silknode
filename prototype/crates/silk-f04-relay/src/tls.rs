//! Pinned TLS1.3 single-record transport, not a schedule/custody admission.
//!
//! Setup and established I/O have bounded incremental owners. Blocking helpers
//! remain explicit conveniences for setup-only functional fixtures.
//! rustls retains internal allocated plaintext; no whole-process erasure claim.
use crate::{Digest, Error, Result, config::Endpoint};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    client::{
        Resumption, UnbufferedClientConnection, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{CryptoProvider, ring},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    server::{NoServerSessionStorage, ParsedCertificate, UnbufferedServerConnection},
    unbuffered::{ConnectionState, UnbufferedStatus},
};
use sha2::{Digest as _, Sha256};
use std::{
    io::{Read, Write},
    net::{IpAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
mod connect;
mod cleanup;
mod profile;
mod setup;
pub use connect::{ConnectStep, Connecting};
pub use cleanup::CleanupOnly;
pub use profile::{ClientProfile, Listener, ServerProfile};
pub use setup::{Setup, SetupStep};

const HANDSHAKE_CAP: usize = 64 * 1024;
const WIRE_CAP: usize = 8192 + 22;
const SOCKET_CAP: usize = 256 * 1024;
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

/// Fixed application record class. Join is setup-only and must never be used as
/// an in-round substitute for a scheduled manifest/control/cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordSize {
    /// Once-per-epoch connection admission.
    Join,
    /// Co-signed round manifest.
    Manifest,
    /// Fixed signed control.
    Control,
    /// Fixed ciphertext data cell.
    Cell,
}
/// Local read progress only; no peer-arrival timestamp or completed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveProgress {
    /// No selected read.
    Idle,
    /// Selected read with no consumed wire byte.
    WaitingZeroBytes,
    /// Partial TLS record; never discard and reuse its TLS sequence.
    Partial {
        /// Already consumed ciphertext bytes.
        consumed: usize,
        /// Exact selected wire length.
        expected: usize,
    },
    /// Connection is poisoned and cannot be resumed.
    Failed,
}
impl RecordSize {
    /// Exact plaintext content length (TLS adds22 bytes).
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::Join => 128,
            Self::Manifest => 256,
            Self::Control => 512,
            Self::Cell => 8192,
        }
    }
}
fn provider() -> Arc<CryptoProvider> {
    let mut provider = ring::default_provider();
    provider.cipher_suites = vec![ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
    provider.kx_groups = vec![ring::kx_group::X25519];
    Arc::new(provider)
}
/// Compute the exact public SPKI pin used by the immutable endpoint record.
/// # Errors
/// Refuses malformed DER; this alone does not verify a handshake or certificate.
pub fn spki_pin(certificate: &CertificateDer<'_>) -> Result<Digest> {
    let parsed = ParsedCertificate::try_from(certificate)
        .map_err(|_| Error::Invalid("TLS certificate DER"))?;
    Ok(Sha256::digest(parsed.subject_public_key_info().as_ref()).into())
}
#[derive(Debug)]
struct PinnedServer {
    standard: Arc<WebPkiServerVerifier>,
    pin: Digest,
}
impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let verified = self
            .standard
            .verify_server_cert(leaf, intermediates, name, ocsp, now)?;
        if spki_pin(leaf).ok() != Some(self.pin) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls12_signature(msg, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.standard.verify_tls13_signature(msg, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.standard.supported_verify_schemes()
    }
}
enum Connection {
    Client(UnbufferedClientConnection),
    Server(UnbufferedServerConnection),
}
struct Pending {
    bytes: Box<[u8; WIRE_CAP]>,
    used: usize,
    offset: usize,
    deadline: Instant,
}
struct Incoming {
    wire: Pending,
    size: RecordSize,
}

/// Observation around an actual nonblocking socket step. The interval bounds
/// the local syscall/validation; it is not a packet timestamp or UTC qualification.
#[cfg(feature = "aip2-preparation")]
pub struct WireObservation {
    /// Original established connection identity.
    pub connection: u64,
    /// Monotonic time immediately before the step.
    pub started: Instant,
    /// Monotonic time immediately after the step.
    pub completed: Instant,
    /// Actual wire bytes transferred, including progress before a later failure.
    pub bytes: usize,
    /// Whole selected record completed locally.
    pub record_complete: bool,
    /// Step failed, including EOF, deadline or authentication failure.
    pub failed: bool,
}

/// One established pinned connection, one pending transmit and one pending read.
///
/// No source queues, reconnection, retries, TLS resumption or post-handshake
/// control emission. Driver owns fixed slot selection, aggregate role bounds,
/// clock health, lifecycle and all control/HPKE/proof barriers.
pub struct Transport {
    connection: Connection,
    socket: TcpStream,
    transmit: Option<Pending>,
    receive: Option<Incoming>,
    failed: bool,
    id: u64,
    endpoint: Endpoint,
    client: bool,
    // Descriptor and rustls buffers drop before releasing their socket capacity.
    quota: Option<crate::resources::SocketPermit>,
    setup_quota: Option<crate::resources::SetupPermit>,
}
impl Transport {
    // Deterministic partial-TCP fixture hook, absent from production builds.
    #[cfg(test)]
    pub(crate) fn write_prefix_for_test(&mut self, limit: usize) -> Result<usize> {
        self.ready()?;
        let pending = self
            .transmit
            .as_mut()
            .ok_or(Error::Unavailable("fixture no selected record"))?;
        remaining(pending.deadline)?;
        let end = pending.offset.saturating_add(limit).min(pending.used);
        let n = self.socket.write(&pending.bytes[pending.offset..end])?;
        pending.offset += n;
        Ok(n)
    }
    /// Complete setup with CA/IP/time AND exact endpoint SPKI authentication.
    /// Wallet clients never send client certificates. Application role signatures
    /// and token admission remain required; this is not client identity evidence.
    /// # Errors
    /// Refuses a wrong socket endpoint, trust failure, suite or setup deadline.
    pub fn client(
        socket: TcpStream,
        endpoint: Endpoint,
        roots: RootCertStore,
        deadline: Instant,
    ) -> Result<Self> {
        Self::client_setup(socket, endpoint, roots, deadline)?.complete_blocking()
    }
    /// Start an incremental authenticated TLS handshake on an already connected
    /// exact endpoint. The caller owns fixed setup-window and socket admission.
    /// # Errors
    /// Refuses a foreign socket, trust/profile setup or expired original deadline.
    pub fn client_setup(
        socket: TcpStream,
        endpoint: Endpoint,
        roots: RootCertStore,
        deadline: Instant,
    ) -> Result<Setup> {
        ClientProfile::new(endpoint, roots)?.start(socket, deadline)
    }
    /// Complete setup for this endpoint. The certificate/key must match its SPKI.
    /// No client wallet certificate is requested; roles/tokens are checked above TLS.
    /// # Errors
    /// Refuses missing/wrong certificate, suite or fixed setup deadline.
    pub fn server(
        socket: TcpStream,
        endpoint: Endpoint,
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        deadline: Instant,
    ) -> Result<Self> {
        Self::server_setup(socket, endpoint, certificates, key, deadline)?.complete_blocking()
    }
    /// Start an incremental server handshake without reading past client Finished
    /// into a coalesced Join. This alone grants no role/token admission.
    /// # Errors
    /// Refuses a foreign listener endpoint, key/profile or setup deadline.
    pub fn server_setup(
        socket: TcpStream,
        endpoint: Endpoint,
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        deadline: Instant,
    ) -> Result<Setup> {
        ServerProfile::new(endpoint, certificates, key)?.start(socket, deadline)
    }
    fn finish_setup(
        connection: Connection,
        socket: TcpStream,
        deadline: Instant,
        endpoint: Endpoint,
        client: bool,
    ) -> Result<Self> {
        remaining(deadline)?;
        let common: &rustls::CommonState = match &connection {
            Connection::Client(c) => c,
            Connection::Server(c) => c,
        };
        if common.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || common.negotiated_cipher_suite().map(|s| s.suite())
                != Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
            || common
                .negotiated_key_exchange_group()
                .map(rustls::crypto::SupportedKxGroup::name)
                != Some(rustls::NamedGroup::X25519)
            || common.alpn_protocol().is_some()
        {
            return Err(Error::Unavailable("TLS negotiated profile"));
        }
        socket.set_read_timeout(None)?;
        socket.set_write_timeout(None)?;
        socket.set_nonblocking(true)?;
        remaining(deadline)?;
        Ok(Self {
            connection,
            socket,
            transmit: None,
            receive: None,
            failed: false,
            id: NEXT_CONNECTION
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .map_err(|_| Error::Unavailable("TLS connection identity exhausted"))?,
            endpoint,
            client,
            quota: None,
            setup_quota: None,
        })
    }
    pub(crate) fn resources(&self) -> Option<crate::resources::RoleResources> {
        self.quota.as_ref().map(|p| p.resources().clone())
    }
    pub(crate) fn enrollment_complete(&mut self) {
        self.setup_quota = None;
    }
    pub(crate) fn account(&mut self, resources: &crate::resources::RoleResources) -> Result<()> {
        if let Some(permit) = &self.quota {
            if !permit.resources().same(resources) {
                return Err(Error::Unavailable("TLS foreign resource root"));
            }
        } else {
            self.quota = Some(resources.socket()?);
        }
        Ok(())
    }
    pub(crate) const fn id(&self) -> u64 {
        self.id
    }
    /// Check an established connection's original pinned endpoint and direction.
    /// This authenticates neither application enrollment nor clock qualification.
    /// # Errors
    /// Refuses a different endpoint/direction or a quarantined connection.
    pub fn check_endpoint(&self, endpoint: Endpoint, client: bool) -> Result<()> {
        if self.endpoint != endpoint || self.client != client {
            return Err(Error::Unavailable("TLS role endpoint binding"));
        }
        self.ready()
    }
    /// Encrypt exactly once into one immutable TLS record for a fixed write slot.
    /// No socket write occurs here; subsequent steps resume these exact bytes.
    /// # Errors
    /// Refuses pending work, wrong sizes, expiry or any extra TLS control record.
    pub fn queue(&mut self, size: RecordSize, plaintext: &[u8], deadline: Instant) -> Result<()> {
        self.ready()?;
        if self.transmit.is_some() || plaintext.len() != size.bytes() {
            return Err(Error::Unavailable("TLS transmit slot/length"));
        }
        remaining(deadline)?;
        self.failed = true;
        let mut bytes = Box::new([0; WIRE_CAP]);
        let used = match &mut self.connection {
            Connection::Client(c) => encrypt(
                c.process_tls_records(&mut []),
                plaintext,
                &mut bytes[..size.bytes() + 22],
            )?,
            Connection::Server(c) => encrypt(
                c.process_tls_records(&mut []),
                plaintext,
                &mut bytes[..size.bytes() + 22],
            )?,
        };
        check_record(&bytes[..used], size)?;
        self.transmit = Some(Pending {
            bytes,
            used,
            offset: 0,
            deadline,
        });
        self.failed = false;
        Ok(())
    }
    /// One nonblocking socket write; true only after every selected byte was sent.
    /// The deadline is original and immutable across calls, including partial writes.
    /// # Errors
    /// Any failure poisons this connection. Some bytes may already have escaped.
    pub fn write_step(&mut self) -> Result<bool> {
        self.ready()?;
        let pending = self
            .transmit
            .as_mut()
            .ok_or(Error::Unavailable("TLS no selected write"))?;
        self.failed = true;
        remaining(pending.deadline)?;
        match self
            .socket
            .write(&pending.bytes[pending.offset..pending.used])
        {
            Ok(0) => return Err(Error::Unavailable("TLS write EOF")),
            Ok(written) => pending.offset += written,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e.into()),
        }
        remaining(pending.deadline)?;
        let complete = pending.offset == pending.used;
        if complete {
            self.transmit = None;
        }
        self.failed = false;
        Ok(complete)
    }
    /// Observe socket progress, including partial writes and failures. Queueing
    /// never produces this observation and is not represented as transmission.
    #[cfg(feature = "aip2-preparation")]
    pub fn write_step_observed(&mut self) -> (Result<bool>, WireObservation) {
        let started = Instant::now();
        let before = self.transmit.as_ref().map(|p| (p.offset, p.used));
        let result = self.write_step();
        let bytes = before.map_or(0, |(old, used)| {
            self.transmit
                .as_ref()
                .map_or(used - old, |p| p.offset.saturating_sub(old))
        });
        let observation = WireObservation {
            connection: self.id,
            started,
            completed: Instant::now(),
            bytes,
            record_complete: matches!(result, Ok(true)),
            failed: result.is_err(),
        };
        (result, observation)
    }
    /// Observe actual reads and their completion/authentication outcome. A read
    /// may transfer bytes and still fail; both facts remain in this observation.
    #[cfg(feature = "aip2-preparation")]
    pub fn read_step_observed(&mut self) -> (Result<Option<Zeroizing<Vec<u8>>>>, WireObservation) {
        let started = Instant::now();
        let before = self.receive.as_ref().map(|r| (r.wire.offset, r.wire.used));
        let result = self.read_step();
        let bytes = before.map_or(0, |(old, used)| {
            self.receive
                .as_ref()
                .map_or(used - old, |r| r.wire.offset.saturating_sub(old))
        });
        let observation = WireObservation {
            connection: self.id,
            started,
            completed: Instant::now(),
            bytes,
            record_complete: matches!(result, Ok(Some(_))),
            failed: result.is_err(),
        };
        (result, observation)
    }
    /// Select one expected record for this scheduled slot, before reading its bytes.
    /// # Errors
    /// Refuses overlapping reads or an already expired deadline.
    pub fn expect(&mut self, size: RecordSize, deadline: Instant) -> Result<()> {
        self.ready()?;
        if self.receive.is_some() {
            return Err(Error::Unavailable("TLS overlapping receive"));
        }
        remaining(deadline)?;
        self.receive = Some(Incoming {
            size,
            wire: Pending {
                bytes: Box::new([0; WIRE_CAP]),
                used: size.bytes() + 22,
                offset: 0,
                deadline,
            },
        });
        Ok(())
    }
    /// Read at most the remaining fixed record; return only authenticated exact data.
    /// Outer scheduling must reject/discard bytes outside their allocated phase.
    /// # Errors
    /// Rejects wrong wire length, padding, interleaved TLS controls, EOF and expiry.
    pub fn read_step(&mut self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.ready()?;
        let incoming = self
            .receive
            .as_mut()
            .ok_or(Error::Unavailable("TLS no expected read"))?;
        self.failed = true;
        let pending = &mut incoming.wire;
        remaining(pending.deadline)?;
        let end = if pending.offset < 5 { 5 } else { pending.used };
        match self.socket.read(&mut pending.bytes[pending.offset..end]) {
            Ok(0) => return Err(Error::Unavailable("TLS read EOF")),
            Ok(read) => pending.offset += read,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e.into()),
        }
        if pending.offset >= 5 {
            check_header(&pending.bytes[..5], incoming.size)?;
        }
        remaining(pending.deadline)?;
        if pending.offset < pending.used {
            self.failed = false;
            return Ok(None);
        }
        let size = incoming.size;
        let used = pending.used;
        let data = match &mut self.connection {
            Connection::Client(c) => decrypt(
                c.process_tls_records(&mut pending.bytes[..used]),
                size,
                used,
            )?,
            Connection::Server(c) => decrypt(
                c.process_tls_records(&mut pending.bytes[..used]),
                size,
                used,
            )?,
        };
        remaining(pending.deadline)?;
        self.receive = None;
        self.failed = false;
        Ok(Some(data))
    }
    /// Read-only detection for the coordinator's between-slot extra-record barrier.
    /// A closed input phase may discard late data; this does not reopen that phase.
    /// # Errors
    /// Reports EOF/I/O failure; does not silently establish quietness.
    pub fn has_extra_bytes(&self) -> Result<bool> {
        self.ready()?;
        match self.socket.peek(&mut [0]) {
            Ok(0) => Err(Error::Unavailable("TLS peer closed")),
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    /// Read progress for the coordinator's input cutoff. Does not peek/read TCP.
    #[must_use]
    pub const fn receive_progress(&self) -> ReceiveProgress {
        if self.failed {
            return ReceiveProgress::Failed;
        }
        match &self.receive {
            None => ReceiveProgress::Idle,
            Some(incoming) if incoming.wire.offset == 0 => ReceiveProgress::WaitingZeroBytes,
            Some(incoming) => ReceiveProgress::Partial {
                consumed: incoming.wire.offset,
                expected: incoming.wire.used,
            },
        }
    }
    /// Framing hint at an untouched boundary only. This consumes no bytes and
    /// establishes no TLS/application authenticity or round identity.
    pub(crate) fn peek_record_size(&self) -> Result<Option<RecordSize>> {
        self.ready()?;
        if !matches!(
            self.receive_progress(),
            ReceiveProgress::Idle | ReceiveProgress::WaitingZeroBytes
        ) {
            return Err(Error::Unavailable("TLS classify consumed record"));
        }
        let mut header = [0; 5];
        match self.socket.peek(&mut header) {
            Ok(0) => Err(Error::Unavailable("TLS peer closed")),
            Ok(5) => record_size(header).map(Some),
            Ok(_) => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    pub(crate) fn selected_read(&self) -> Option<(RecordSize, Instant)> {
        self.receive.as_ref().map(|r| (r.size, r.wire.deadline))
    }
    /// Retire only an untouched cell selection at a closed input barrier.
    /// Does not reset failure, extend a read, consume ciphertext or grant reuse
    /// when late bytes appear; the coordinator must quarantine such connections.
    /// # Errors
    /// Partial, failed, absent and non-cell reads cannot be retired.
    pub fn retire_empty_cell(&mut self) -> Result<()> {
        self.retire_empty(RecordSize::Cell)
    }
    pub(crate) fn retire_expired_control(&mut self) -> Result<()> {
        if self
            .receive
            .as_ref()
            .is_none_or(|r| Instant::now() < r.wire.deadline)
        {
            return Err(Error::Unavailable("TLS old control deadline still open"));
        }
        self.retire_empty(RecordSize::Control)
    }
    pub(crate) fn retire_expired_read(&mut self) -> Result<()> {
        let read = self
            .receive
            .as_ref()
            .ok_or(Error::Unavailable("TLS old read absent"))?;
        if Instant::now() < read.wire.deadline {
            return Err(Error::Unavailable("TLS old read deadline still open"));
        }
        self.retire_empty(read.size)
    }
    pub(crate) fn retire_empty(&mut self, size: RecordSize) -> Result<()> {
        self.ready()?;
        if !self
            .receive
            .as_ref()
            .is_some_and(|r| r.size == size && r.wire.offset == 0)
        {
            return Err(Error::Unavailable("TLS cannot retire consumed receive"));
        }
        self.receive = None;
        Ok(())
    }
    /// Permanently close this connection; never discard partial TLS bytes and reuse it.
    /// The role coordinator may establish a later connection only in maintenance.
    /// # Errors
    /// Reports shutdown failure while retaining the local poisoned state.
    pub fn quarantine(&mut self) -> Result<()> {
        self.failed = true;
        self.socket.shutdown(std::net::Shutdown::Both)?;
        Ok(())
    }
    const fn ready(&self) -> Result<()> {
        if self.failed {
            Err(Error::Unavailable("failed TLS connection"))
        } else {
            Ok(())
        }
    }
}
const fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_canonical(),
        other @ IpAddr::V4(_) => other,
    }
}
fn record_size(header: [u8; 5]) -> Result<RecordSize> {
    for size in [
        RecordSize::Join,
        RecordSize::Manifest,
        RecordSize::Control,
        RecordSize::Cell,
    ] {
        if check_header(&header, size).is_ok() {
            return Ok(size);
        }
    }
    Err(Error::Invalid("TLS unsupported fixed record header"))
}
fn remaining(deadline: Instant) -> Result<Duration> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Unavailable("TLS fixed deadline"))?;
    if left > Duration::from_secs(30) {
        return Err(Error::Unavailable("TLS deadline exceeds round"));
    }
    Ok(left)
}
fn configure_socket(socket: &TcpStream) -> Result<()> {
    socket.set_nonblocking(true)?;
    socket.set_nodelay(true)?;
    socket.set_read_timeout(None)?;
    socket.set_write_timeout(None)?;
    // Linux doubles SO_*BUF requests; the actual value, not the request, is bounded.
    rustix::net::sockopt::set_socket_recv_buffer_size(socket, SOCKET_CAP / 2)
        .map_err(std::io::Error::from)?;
    rustix::net::sockopt::set_socket_send_buffer_size(socket, SOCKET_CAP / 2)
        .map_err(std::io::Error::from)?;
    if rustix::net::sockopt::socket_recv_buffer_size(socket).map_err(std::io::Error::from)?
        > SOCKET_CAP
        || rustix::net::sockopt::socket_send_buffer_size(socket).map_err(std::io::Error::from)?
            > SOCKET_CAP
    {
        return Err(Error::Unavailable("TLS socket buffer cap"));
    }
    Ok(())
}
fn encrypt<Data>(
    status: UnbufferedStatus<'_, '_, Data>,
    plaintext: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    if status.discard != 0 {
        return Err(Error::Unavailable("TLS unexpected transmit discard"));
    }
    match status
        .state
        .map_err(|_| Error::Invalid("TLS established state"))?
    {
        ConnectionState::WriteTraffic(mut data) => data
            .encrypt(plaintext, output)
            .map_err(|_| Error::Unavailable("TLS exact single-record encoding")),
        _ => Err(Error::Invalid("TLS unsolicited post-handshake control")),
    }
}
fn decrypt<Data>(
    status: UnbufferedStatus<'_, '_, Data>,
    size: RecordSize,
    used: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut discard = status.discard;
    match status
        .state
        .map_err(|_| Error::Invalid("TLS record authentication"))?
    {
        ConnectionState::ReadTraffic(mut traffic) => {
            let record = traffic
                .next_record()
                .ok_or(Error::Invalid("TLS absent app record"))?
                .map_err(|_| Error::Invalid("TLS app authentication"))?;
            discard += record.discard;
            if record.payload.len() != size.bytes() || discard != used {
                return Err(Error::Invalid("TLS padded/split/extra record"));
            }
            let output = Zeroizing::new(record.payload.to_vec());
            if traffic.next_record().is_some() {
                return Err(Error::Invalid("TLS multiple app records"));
            }
            Ok(output)
        }
        _ => Err(Error::Invalid("TLS unsolicited post-handshake control")),
    }
}
fn check_record(bytes: &[u8], size: RecordSize) -> Result<()> {
    if bytes.len() != size.bytes() + 22 {
        return Err(Error::Unavailable("TLS one-record wire size"));
    }
    check_header(&bytes[..5], size)
}
fn check_header(bytes: &[u8], size: RecordSize) -> Result<()> {
    if bytes[..3] != [23, 3, 3]
        || usize::from(u16::from_be_bytes([bytes[3], bytes[4]])) != size.bytes() + 17
    {
        return Err(Error::Invalid("TLS record type/length/padding"));
    }
    Ok(())
}
