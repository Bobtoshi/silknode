//! One incremental TLS handshake with original deadline and bounded flights.
use super::{
    Connection, Endpoint, Error, HANDSHAKE_CAP, Result, Transport, configure_socket, remaining,
};
use rustls::unbuffered::{ConnectionState, UnbufferedStatus};
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};
#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;

struct ReadRecord {
    start: usize,
    offset: usize,
    end: usize,
}
enum Action {
    Again,
    Read,
    Flush,
    Ready,
}

/// A single setup attempt. Failure/drop consumes the socket; no reset or retry
/// method exists. A role owner must bound simultaneous attempts and their window.
pub struct Setup {
    connection: Connection,
    socket: TcpStream,
    endpoint: Endpoint,
    client: bool,
    deadline: Instant,
    incoming: Box<[u8]>,
    filled: usize,
    reading: Option<ReadRecord>,
    outgoing: Vec<u8>,
    sent: usize,
    flushing: bool,
    pub(super) quota: Option<crate::resources::SocketPermit>,
    pub(super) pending_quota: Option<crate::resources::SetupPermit>,
}
/// Consuming transition: only a complete pinned handshake returns a transport.
pub enum SetupStep {
    /// Same socket, TLS state, offsets and immutable deadline.
    Pending(Setup),
    /// Complete exact negotiated profile; application role/Join still required.
    Established(Transport),
}
impl Setup {
    pub(super) fn new(
        connection: Connection,
        socket: TcpStream,
        deadline: Instant,
        endpoint: Endpoint,
        client: bool,
    ) -> Result<Self> {
        remaining(deadline)?;
        configure_socket(&socket)?;
        Ok(Self {
            connection,
            socket,
            endpoint,
            client,
            deadline,
            incoming: vec![0; HANDSHAKE_CAP].into_boxed_slice(),
            filled: 0,
            reading: None,
            outgoing: Vec::with_capacity(HANDSHAKE_CAP),
            sent: 0,
            flushing: false,
            quota: None,
            pending_quota: None,
        })
    }
    /// Advance at most one nonblocking socket operation OR one rustls state
    /// transition. No helper thread, blocking socket call or loop until ready.
    /// # Errors
    /// Deadline, authentication, framing/cap or socket failure destroys this attempt.
    pub fn poll(mut self) -> Result<SetupStep> {
        remaining(self.deadline)?;
        if self.advance()? {
            let mut transport = Transport::finish_setup(
                self.connection,
                self.socket,
                self.deadline,
                self.endpoint,
                self.client,
            )?;
            transport.quota = self.quota;
            // A's incoming baseline setup includes the subsequent actual Join.
            // Other hop setups end here; lifecycle attempts carry their own permit.
            if !transport.client
                && transport
                    .quota
                    .as_ref()
                    .is_some_and(|p| p.resources().role() == crate::control::Role::A)
            {
                transport.setup_quota = self.pending_quota;
            }
            return Ok(SetupStep::Established(transport));
        }
        remaining(self.deadline)?;
        Ok(SetupStep::Pending(self))
    }
    pub(super) fn complete_blocking(mut self) -> Result<Transport> {
        loop {
            match self.poll()? {
                SetupStep::Established(transport) => return Ok(transport),
                SetupStep::Pending(pending) => self = pending,
            }
            std::thread::sleep(Duration::from_micros(500));
        }
    }
    fn advance(&mut self) -> Result<bool> {
        if self.flushing {
            match self.socket.write(&self.outgoing[self.sent..]) {
                Ok(0) => return Err(Error::Unavailable("TLS handshake write EOF")),
                Ok(written) => self.sent += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(error) => return Err(error.into()),
            }
            if self.sent == self.outgoing.len() {
                self.flushing = false;
            }
            return Ok(false);
        }
        if let Some(read) = &mut self.reading {
            match self.socket.read(&mut self.incoming[read.offset..read.end]) {
                Ok(0) => return Err(Error::Unavailable("TLS handshake read EOF")),
                Ok(got) => read.offset += got,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(error) => return Err(error.into()),
            }
            if read.offset == read.start + 5 && read.end == read.start + 5 {
                let body = usize::from(u16::from_be_bytes([
                    self.incoming[read.start + 3],
                    self.incoming[read.start + 4],
                ]));
                read.end = read
                    .end
                    .checked_add(body)
                    .filter(|end| *end <= HANDSHAKE_CAP)
                    .ok_or(Error::Unavailable("TLS handshake capacity"))?;
            }
            if read.offset == read.end {
                self.filled = read.end;
                self.reading = None;
            }
            return Ok(false);
        }
        let (discard, action) = match &mut self.connection {
            Connection::Client(connection) => step(
                connection.process_tls_records(&mut self.incoming[..self.filled]),
                &mut self.outgoing,
                &mut self.sent,
            )?,
            Connection::Server(connection) => step(
                connection.process_tls_records(&mut self.incoming[..self.filled]),
                &mut self.outgoing,
                &mut self.sent,
            )?,
        };
        if discard > self.filled {
            return Err(Error::Unavailable("TLS handshake discard"));
        }
        self.incoming.copy_within(discard..self.filled, 0);
        self.filled -= discard;
        match action {
            Action::Again => (),
            Action::Flush => self.flushing = true,
            Action::Read => {
                let end = self
                    .filled
                    .checked_add(5)
                    .filter(|end| *end <= HANDSHAKE_CAP)
                    .ok_or(Error::Unavailable("TLS handshake header capacity"))?;
                self.reading = Some(ReadRecord {
                    start: self.filled,
                    offset: self.filled,
                    end,
                });
            }
            Action::Ready => {
                if self.filled != 0 || !self.outgoing.is_empty() {
                    return Err(Error::Invalid("TLS unsolicited handshake tail"));
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn step<Data>(
    status: UnbufferedStatus<'_, '_, Data>,
    outgoing: &mut Vec<u8>,
    sent: &mut usize,
) -> Result<(usize, Action)> {
    let action = match status
        .state
        .map_err(|_| Error::Invalid("TLS handshake authentication/state"))?
    {
        ConnectionState::EncodeTlsData(mut data) => {
            // This token owns a popped rustls chunk: encode it before yielding.
            // Merely dropping the token would silently lose the flight bytes.
            let start = outgoing.len();
            outgoing.resize(HANDSHAKE_CAP, 0);
            let written = data
                .encode(&mut outgoing[start..])
                .map_err(|_| Error::Unavailable("TLS handshake output cap"))?;
            outgoing.truncate(start + written);
            Action::Again
        }
        ConnectionState::TransmitTlsData(data) => {
            if *sent == outgoing.len() {
                // Partial writes have finished on the same socket. Until now
                // the token was dropped WITHOUT done, retaining wants_write.
                data.done();
                outgoing.clear();
                *sent = 0;
                Action::Again
            } else {
                Action::Flush
            }
        }
        ConnectionState::BlockedHandshake => Action::Read,
        ConnectionState::WriteTraffic(_) => Action::Ready,
        _ => return Err(Error::Invalid("TLS unexpected setup record")),
    };
    Ok((status.discard, action))
}
