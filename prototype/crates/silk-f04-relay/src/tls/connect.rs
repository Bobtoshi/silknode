//! One nonblocking TCP attempt followed by the same original TLS setup deadline.
use super::{
    ClientProfile, Endpoint, Error, Result, RootCertStore, Setup, configure_socket, remaining,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{AddressFamily, SocketFlags, SocketType, ipproto},
};
use std::{
    net::{Ipv6Addr, SocketAddr, TcpStream},
    time::Instant,
};

/// Pending fixed-endpoint TCP connection. The lifecycle owner must reserve its
/// single setup/maintenance attempt BEFORE constructing this object.
pub struct Connecting {
    socket: TcpStream,
    profile: ClientProfile,
    deadline: Instant,
    quota: Option<crate::resources::SocketPermit>,
    setup_quota: Option<crate::resources::SetupPermit>,
}
/// Only a genuinely connected configured socket can progress to TLS.
#[allow(clippy::large_enum_variant)] // One bounded ~1.3KiB setup state; flights are heap-capped.
pub enum ConnectStep {
    /// Same socket and original deadline; no further connect call is made.
    Pending(Connecting),
    /// Incremental TLS authentication, not application/Join admission.
    Handshaking(Setup),
}
impl Connecting {
    /// Make exactly one nonblocking TCP connection attempt. This API is not
    /// permission to retry or an epoch/maintenance admission by itself.
    /// # Errors
    /// Rejects expired/overlong deadline, socket cap or immediate connect failure.
    pub fn new(endpoint: Endpoint, roots: RootCertStore, deadline: Instant) -> Result<Self> {
        Self::with_profile(ClientProfile::new(endpoint, roots)?, deadline)
    }
    /// Reuse an immutable endpoint policy for one separately admitted attempt.
    /// # Errors
    /// Refuses the original deadline, socket limits or immediate connect failure.
    pub fn with_profile(profile: ClientProfile, deadline: Instant) -> Result<Self> {
        Self::start(profile, deadline, None)
    }
    /// Reserve shared socket AND pending-setup capacity before a baseline attempt.
    /// This is resource admission only, not a fixed lifecycle-window permit.
    /// # Errors
    /// Refuses either cap, the original deadline or the one TCP attempt.
    pub fn with_resources(
        profile: ClientProfile,
        deadline: Instant,
        resources: &crate::resources::RoleResources,
    ) -> Result<Self> {
        let setup = resources.setup()?;
        let socket = resources.socket()?;
        let mut connecting = Self::start(profile, deadline, Some(socket))?;
        connecting.setup_quota = Some(setup);
        Ok(connecting)
    }
    pub(crate) fn bounded(
        profile: ClientProfile,
        deadline: Instant,
        quota: crate::resources::SocketPermit,
    ) -> Result<Self> {
        Self::start(profile, deadline, Some(quota))
    }
    fn start(
        profile: ClientProfile,
        deadline: Instant,
        quota: Option<crate::resources::SocketPermit>,
    ) -> Result<Self> {
        remaining(deadline)?;
        let endpoint = profile.endpoint();
        let address = SocketAddr::new(
            Ipv6Addr::from(endpoint.address).to_canonical(),
            endpoint.port,
        );
        let domain = if address.is_ipv4() {
            AddressFamily::INET
        } else {
            AddressFamily::INET6
        };
        #[cfg(target_os = "linux")]
        let flags = SocketFlags::NONBLOCK | SocketFlags::CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = SocketFlags::empty();
        let fd = rustix::net::socket_with(domain, SocketType::STREAM, flags, Some(ipproto::TCP))
            .map_err(std::io::Error::from)?;
        // Darwin has no atomic socket flags. This single-coordinator API does
        // not spawn/fork; set close-on-exec before exposing or connecting fd.
        #[cfg(not(target_os = "linux"))]
        rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC).map_err(std::io::Error::from)?;
        let socket = TcpStream::from(fd);
        configure_socket(&socket)?;
        match rustix::net::connect(&socket, &address) {
            Ok(()) | Err(rustix::io::Errno::INPROGRESS) => (),
            Err(error) => return Err(std::io::Error::from(error).into()),
        }
        remaining(deadline)?;
        Ok(Self {
            socket,
            profile,
            deadline,
            quota,
            setup_quota: None,
        })
    }
    /// Check readiness with a zero-timeout OS poll; `SO_ERROR` alone is not proof
    /// of connection completion. TLS rechecks the actual peer endpoint.
    /// # Errors
    /// Socket/poll/auth setup errors or original expiry consume this attempt.
    pub fn poll(self) -> Result<ConnectStep> {
        remaining(self.deadline)?;
        let mut fds = [PollFd::new(&self.socket, PollFlags::OUT)];
        let ready = match poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        ) {
            Ok(ready) => ready,
            Err(rustix::io::Errno::INTR) => {
                remaining(self.deadline)?;
                return Ok(ConnectStep::Pending(self));
            }
            Err(error) => return Err(std::io::Error::from(error).into()),
        };
        remaining(self.deadline)?;
        if ready == 0 {
            return Ok(ConnectStep::Pending(self));
        }
        if fds[0]
            .revents()
            .intersects(PollFlags::NVAL | PollFlags::HUP)
        {
            return Err(Error::Unavailable("TCP setup descriptor/hangup"));
        }
        rustix::net::sockopt::socket_error(&self.socket)
            .map_err(std::io::Error::from)?
            .map_err(std::io::Error::from)?;
        if !fds[0].revents().contains(PollFlags::OUT) {
            return Err(Error::Unavailable("TCP setup not writable"));
        }
        let mut setup = self.profile.start(self.socket, self.deadline)?;
        setup.quota = self.quota;
        setup.pending_quota = self.setup_quota;
        Ok(ConnectStep::Handshaking(setup))
    }
}
