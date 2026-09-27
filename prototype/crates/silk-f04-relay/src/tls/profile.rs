//! Reusable immutable exact-endpoint profiles. These are not lifecycle permits.
use super::{
    ClientConfig, Connection, Endpoint, Error, NoServerSessionStorage, PinnedServer, Result,
    Resumption, RootCertStore, ServerConfig, ServerName, Setup, UnbufferedClientConnection,
    UnbufferedServerConnection, WebPkiServerVerifier, canonical, provider, remaining, spki_pin,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{
    io::ErrorKind,
    net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::Instant,
};

/// CA/IP/time and exact-SPKI client policy, built once per configured endpoint.
/// Clones share the immutable rustls policy, not connections or retry authority.
#[derive(Clone)]
pub struct ClientProfile {
    endpoint: Endpoint,
    config: Arc<ClientConfig>,
}
impl ClientProfile {
    /// Build the fixed TLS1.3/X25519/ChaCha policy with no resumption/early data.
    /// # Errors
    /// Refuses unavailable trust roots or an unsupported TLS policy.
    pub fn new(endpoint: Endpoint, roots: RootCertStore) -> Result<Self> {
        let provider = provider();
        let standard =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(|_| Error::Unavailable("TLS trust roots"))?;
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::Unavailable("TLS version"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServer {
                standard,
                pin: endpoint.spki,
            }))
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        config.enable_sni = false;
        config.max_fragment_size = Some(8197);
        Ok(Self {
            endpoint,
            config: Arc::new(config),
        })
    }
    /// Immutable configured destination. No DNS or peer-supplied replacement.
    #[must_use]
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// Start on one connected socket using the caller's already-reserved window.
    /// # Errors
    /// Rejects another peer, an expired deadline or TLS allocation failure.
    pub fn start(&self, socket: TcpStream, deadline: Instant) -> Result<Setup> {
        remaining(deadline)?;
        let expected_ip = Ipv6Addr::from(self.endpoint.address).to_canonical();
        let peer = socket.peer_addr()?;
        if canonical(peer.ip()) != expected_ip || peer.port() != self.endpoint.port {
            return Err(Error::Unavailable("TLS configured endpoint"));
        }
        let connection = UnbufferedClientConnection::new(
            Arc::clone(&self.config),
            ServerName::IpAddress(expected_ip.into()),
        )
        .map_err(|_| Error::Unavailable("TLS client setup"))?;
        Setup::new(
            Connection::Client(connection),
            socket,
            deadline,
            self.endpoint,
            true,
        )
    }
}

/// Fixed local certificate/key and TLS policy. It does not authenticate a client
/// role: signed controls or A's actual roster Join remain separately required.
#[derive(Clone)]
pub struct ServerProfile {
    endpoint: Endpoint,
    config: Arc<ServerConfig>,
}
impl ServerProfile {
    /// Verify the own SPKI pin and build the no-ticket/no-client-certificate policy.
    /// # Errors
    /// Refuses a foreign certificate, unusable key or unsupported TLS policy.
    pub fn new(
        endpoint: Endpoint,
        certificates: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        if certificates.first().map(spki_pin).transpose()? != Some(endpoint.spki) {
            return Err(Error::Unavailable("TLS own endpoint SPKI"));
        }
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::Unavailable("TLS version"))?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|_| Error::Unavailable("TLS server key/cert"))?;
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.send_half_rtt_data = false;
        config.max_fragment_size = Some(8197);
        Ok(Self {
            endpoint,
            config: Arc::new(config),
        })
    }
    /// Configured listener endpoint; this is not a remote client identity.
    #[must_use]
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// Begin one accepted handshake with its unchanged setup deadline.
    /// # Errors
    /// Refuses a foreign listener, expiry or TLS setup failure.
    pub fn start(&self, socket: TcpStream, deadline: Instant) -> Result<Setup> {
        remaining(deadline)?;
        let local = socket.local_addr()?;
        if canonical(local.ip()) != Ipv6Addr::from(self.endpoint.address).to_canonical()
            || local.port() != self.endpoint.port
        {
            return Err(Error::Unavailable("TLS configured local endpoint"));
        }
        let connection = UnbufferedServerConnection::new(Arc::clone(&self.config))
            .map_err(|_| Error::Unavailable("TLS server setup"))?;
        Setup::new(
            Connection::Server(connection),
            socket,
            deadline,
            self.endpoint,
            false,
        )
    }
}

/// One nonblocking fixed-endpoint listener. Its owner must reserve both a socket
/// and one of its two role-wide pending-attempt slots BEFORE calling `accept`.
pub struct Listener {
    socket: TcpListener,
    profile: ServerProfile,
    quota: Option<crate::resources::SocketPermit>,
}
impl Listener {
    /// Bind once to the configured numeric address/port. Never picks another port.
    /// # Errors
    /// Rejects wildcard/ephemeral endpoints, bind failure or nonblocking failure.
    pub fn bind(profile: ServerProfile) -> Result<Self> {
        Self::bind_with_quota(profile, None)
    }
    /// Reserve from the role's shared socket cap BEFORE binding this listener.
    /// # Errors
    /// Refuses resource exhaustion, an invalid endpoint or bind failure.
    pub fn bounded(
        profile: ServerProfile,
        resources: &crate::resources::RoleResources,
    ) -> Result<Self> {
        Self::bind_with_quota(profile, Some(resources.socket()?))
    }
    fn bind_with_quota(
        profile: ServerProfile,
        quota: Option<crate::resources::SocketPermit>,
    ) -> Result<Self> {
        let ip = Ipv6Addr::from(profile.endpoint.address).to_canonical();
        if ip.is_unspecified() || profile.endpoint.port == 0 {
            return Err(Error::Unavailable("TLS exact listener endpoint"));
        }
        let socket = TcpListener::bind(SocketAddr::new(ip, profile.endpoint.port))?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            profile,
            quota,
        })
    }
    /// The local endpoint bound to this listener's immutable server profile.
    #[must_use]
    pub const fn endpoint(&self) -> Endpoint {
        self.profile.endpoint
    }

    /// At most one nonblocking accept. An accepted socket consumes an attempt even
    /// if subsequent setup fails. None means no accepted socket, never a retry.
    /// # Errors
    /// Refuses expiry, socket failure or failed TLS setup without retaining a socket.
    pub fn accept(&self, deadline: Instant) -> Result<Option<Setup>> {
        let setup_quota = self
            .quota
            .as_ref()
            .map(|p| p.resources().setup())
            .transpose()?;
        let quota = self
            .quota
            .as_ref()
            .map(|p| p.resources().socket())
            .transpose()?;
        let mut setup = self.accept_with_quota(deadline, quota)?;
        if let Some(accepted) = &mut setup {
            accepted.pending_quota = setup_quota;
        }
        Ok(setup)
    }
    pub(crate) fn resources(&self) -> Option<crate::resources::RoleResources> {
        self.quota.as_ref().map(|p| p.resources().clone())
    }
    pub(crate) fn accept_bounded(
        &self,
        deadline: Instant,
        quota: crate::resources::SocketPermit,
    ) -> Result<Option<Setup>> {
        if self
            .quota
            .as_ref()
            .is_none_or(|p| !p.resources().same(quota.resources()))
        {
            return Err(Error::Unavailable("TLS listener resource root"));
        }
        self.accept_with_quota(deadline, Some(quota))
    }
    fn accept_with_quota(
        &self,
        deadline: Instant,
        quota: Option<crate::resources::SocketPermit>,
    ) -> Result<Option<Setup>> {
        remaining(deadline)?;
        match self.socket.accept() {
            Ok((socket, _)) => {
                let mut setup = self.profile.start(socket, deadline)?;
                setup.quota = quota;
                Ok(Some(setup))
            }
            Err(error)
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) =>
            {
                remaining(deadline)?;
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        tests::certificates,
        tls::{ConnectStep, Connecting, SetupStep},
    };
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use std::{net::Ipv4Addr, time::Duration};

    #[test]
    #[allow(clippy::too_many_lines)] // One end-to-end permit lifetime, including actual Join.
    fn lifecycle_baseline_permits_follow_tls_join_and_quarantined_socket() {
        use crate::{
            config::Roster,
            control::Role,
            input::{Enrolling, Enrollment},
            resources::RoleResources,
            tls::RecordSize,
        };
        let root = tempfile::tempdir().unwrap();
        let certs = root.path().join("tls");
        certificates::generate(&certs, 1);
        let certificate = CertificateDer::from(certificates::leaf_der(&certs, 0));
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint = Endpoint {
            address: Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets(),
            port: reserved.local_addr().unwrap().port(),
            signing: [0; 32],
            spki: spki_pin(&certificate).unwrap(),
        };
        drop(reserved);
        let profile = ServerProfile::new(
            endpoint,
            vec![certificate],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificates::private_key_der(
                &certs, 0,
            ))),
        )
        .unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificates::root_der(&certs)))
            .unwrap();
        let resources = RoleResources::new(Role::A).unwrap();
        let listener = Listener::bounded(profile, &resources).unwrap();
        assert_eq!(resources.sockets(), 1);
        let deadline = Instant::now() + Duration::from_secs(3);
        assert!(listener.accept(deadline).unwrap().is_none());
        assert_eq!(resources.sockets(), 1);
        assert_eq!(resources.pending_setups(), 0);
        let mut connecting = Some(
            Connecting::with_resources(
                ClientProfile::new(endpoint, roots).unwrap(),
                deadline,
                &resources,
            )
            .unwrap(),
        );
        let mut outbound = None;
        let mut inbound = None;
        let mut client = None;
        let mut server = None;
        while client.is_none() || server.is_none() {
            assert!(Instant::now() < deadline);
            if let Some(pending) = connecting.take() {
                match pending.poll().unwrap() {
                    ConnectStep::Pending(pending) => connecting = Some(pending),
                    ConnectStep::Handshaking(pending) => outbound = Some(pending),
                }
            }
            if inbound.is_none() && server.is_none() {
                inbound = listener.accept(deadline).unwrap();
            }
            for (setup, transport) in [(&mut outbound, &mut client), (&mut inbound, &mut server)] {
                if let Some(pending) = setup.take() {
                    match pending.poll().unwrap() {
                        SetupStep::Pending(pending) => *setup = Some(pending),
                        SetupStep::Established(ready) => *transport = Some(ready),
                    }
                }
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        assert_eq!(resources.sockets(), 3);
        assert_eq!(resources.pending_setups(), 1); // Server A still awaits actual Join.
        let config = crate::tests::relay_test_config();
        let mut hashes = std::array::from_fn(|i| {
            silk_sapling_f04::codec::domain_hash(
                "SilkNode-F0-token",
                &[&[u8::try_from(i).unwrap(); 32]],
            )
        });
        hashes.sort_unstable();
        let roster = Roster::verify(hashes, &config).unwrap();
        let mut join = [0; 128];
        join[..8].copy_from_slice(b"SNJOIN03");
        join[8..40].copy_from_slice(&config.domain());
        join[40..44].copy_from_slice(&config.cohort().to_le_bytes());
        join[44..48].copy_from_slice(&config.epoch().to_le_bytes());
        let mut client = client.unwrap();
        client.queue(RecordSize::Join, &join, deadline).unwrap();
        while !client.write_step().unwrap() {
            std::thread::sleep(Duration::from_micros(100));
        }
        let mut enrolling = Enrolling::new(server.unwrap(), deadline).unwrap();
        let admitted = loop {
            match enrolling.poll(&config, &roster).unwrap() {
                Enrollment::Pending(pending) => enrolling = pending,
                Enrollment::Admitted(session) => break session,
            }
            std::thread::sleep(Duration::from_micros(100));
        };
        assert_eq!(resources.pending_setups(), 0);
        client.quarantine().unwrap();
        assert_eq!(resources.sockets(), 3); // Quarantine does not free the held descriptor.
        drop(admitted);
        drop(client);
        drop(listener);
        assert_eq!(resources.sockets(), 0);
    }

    #[test]
    fn shared_profiles_accept_incrementally_without_resumption_or_deadline_renewal() {
        let root = tempfile::tempdir().unwrap();
        let certs = root.path().join("tls");
        certificates::generate(&certs, 1);
        let certificate = CertificateDer::from(certificates::leaf_der(&certs, 0));
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let endpoint = Endpoint {
            address: Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets(),
            port: reserved.local_addr().unwrap().port(),
            signing: [0; 32],
            spki: spki_pin(&certificate).unwrap(),
        };
        drop(reserved);
        let profile = ServerProfile::new(
            endpoint,
            vec![certificate],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificates::private_key_der(
                &certs, 0,
            ))),
        )
        .unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificates::root_der(&certs)))
            .unwrap();
        let client = ClientProfile::new(endpoint, roots).unwrap();
        assert!(Arc::ptr_eq(&client.config, &client.clone().config));
        assert!(Arc::ptr_eq(&profile.config, &profile.clone().config));
        assert_eq!(profile.config.send_tls13_tickets, 0);
        assert_eq!(profile.config.max_early_data_size, 0);
        let listener = Listener::bind(profile).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        assert!(listener.accept(deadline).unwrap().is_none());
        let mut identities = Vec::new();
        for _ in 0..2 {
            let mut connecting = Some(Connecting::with_profile(client.clone(), deadline).unwrap());
            let mut outbound = None;
            let mut inbound = None;
            let mut ready_out = None;
            let mut ready_in = None;
            while ready_out.is_none() || ready_in.is_none() {
                assert!(Instant::now() < deadline);
                if let Some(pending) = connecting.take() {
                    match pending.poll().unwrap() {
                        ConnectStep::Pending(pending) => connecting = Some(pending),
                        ConnectStep::Handshaking(pending) => outbound = Some(pending),
                    }
                }
                if inbound.is_none() && ready_in.is_none() {
                    inbound = listener.accept(deadline).unwrap();
                }
                for (setup, transport) in [
                    (&mut outbound, &mut ready_out),
                    (&mut inbound, &mut ready_in),
                ] {
                    if let Some(pending) = setup.take() {
                        match pending.poll().unwrap() {
                            SetupStep::Pending(pending) => *setup = Some(pending),
                            SetupStep::Established(ready) => *transport = Some(ready),
                        }
                    }
                }
                std::thread::sleep(Duration::from_micros(100));
            }
            identities.push(ready_out.unwrap().id());
            identities.push(ready_in.unwrap().id());
        }
        identities.sort_unstable();
        identities.dedup();
        assert_eq!(identities.len(), 4);
        assert!(listener.accept(Instant::now()).is_err());
        assert!(Connecting::with_profile(client, Instant::now()).is_err());
    }
}
