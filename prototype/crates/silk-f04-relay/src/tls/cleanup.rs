//! Irreversible socket retention after application authority is destroyed.
use super::*;
use zeroize::Zeroize;

/// Original socket with no TLS state, record buffers or application write API.
/// Retains its existing resource permits until the fixed boundary or peer close.
/// Dropping this owner closes the socket; the enclosing driver must drive it.
pub struct CleanupOnly {
    socket: TcpStream,
    deadline: Instant,
    complete: bool,
    _quota: Option<crate::resources::SocketPermit>,
    _setup_quota: Option<crate::resources::SetupPermit>,
}
impl Transport {
    /// Consume all TLS/read/write authority without closing the original socket.
    /// The client supplies its original public cleanup deadline. A hard sixty
    /// second retention cap also bounds misuse; no poll can renew either bound.
    pub fn into_cleanup(self, deadline: Instant) -> CleanupOnly {
        let Self {
            socket,
            connection,
            transmit,
            receive,
            quota,
            setup_quota,
            ..
        } = self;
        if let Some(mut pending) = transmit {
            pending.bytes.zeroize();
        }
        if let Some(mut incoming) = receive {
            incoming.wire.bytes.zeroize();
        }
        drop(connection);
        CleanupOnly {
            socket,
            deadline: deadline.min(Instant::now() + Duration::from_secs(60)),
            complete: false,
            _quota: quota,
            _setup_quota: setup_quota,
        }
    }
}
impl CleanupOnly {
    /// One nonblocking closure check, with no application reads or writes.
    /// Unexpected inbound bytes and nonterminal I/O errors cannot grant reuse
    /// or shorten retention. Peer closure behind unread data may be detected
    /// only at the fixed deadline.
    pub fn poll(&mut self) -> bool {
        if self.complete {
            return true;
        }
        let closed = match self.socket.peek(&mut [0]) {
            Ok(0) => true,
            Err(error) => matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::NotConnected
            ),
            Ok(_) => false,
        };
        if closed || Instant::now() >= self.deadline {
            let _ = self.socket.shutdown(std::net::Shutdown::Both);
            self.complete = true;
        }
        self.complete
    }
    /// Drive cleanup on the existing enclosing thread, with bounded sleeps and
    /// no new worker, task, proof or connection. Returns by the original bound
    /// subject to the same host scheduling availability as every socket driver.
    pub fn finish(&mut self) {
        while !self.poll() {
            std::thread::sleep(
                Duration::from_millis(5)
                    .min(self.deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}
impl Drop for CleanupOnly {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}
