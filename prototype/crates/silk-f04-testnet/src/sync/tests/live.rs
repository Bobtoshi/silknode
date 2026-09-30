//! Opt-in genuine admission and ordinary CLI receiver process lifetimes.
//! Sources serve freshly verified node snapshots, not the production seed loop.
use super::*;
use crate::config::read_file;
use silk_f04_node::node::NodeStatus;
use std::{os::unix::fs::PermissionsExt, path::PathBuf, process::Child};

fn save(path: &std::path::Path, bytes: &[u8]) {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn configure(
    root: &std::path::Path,
    a: &Config,
    b: &Config,
    parameters: &std::path::Path,
) -> Config {
    let config = serde_json::json!({
        "schema": "silknode-public-testnet-config-v1", "accept_public_zero_value": true,
        "domain": public_testnet_v1::DOMAIN_HEX,
        "store": root.join("receiver"), "retained_head": root.join("pins/head"),
        "host_margin": "/work", "spend_parameters": parameters.join("sapling-spend.params"),
        "output_parameters": parameters.join("sapling-output.params"),
        "seed": a.seed, "ca_der_hex": a.ca_der_hex,
        "seed_certificate_sha256": a.seed_certificate_sha256, "reward_owner": "2".repeat(64)
    });
    let peers = serde_json::json!({"schema":"silknode-public-peers-v1", "peers":[{
        "endpoint": b.seed, "ca_der_hex": b.ca_der_hex,
        "certificate_sha256": b.seed_certificate_sha256
    }]});
    save(
        &root.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    );
    save(
        &root.join("peers.json"),
        &serde_json::to_vec(&peers).unwrap(),
    );
    Config::load(&root.join("config.json")).unwrap()
}

fn peer(fixture: &TlsFixture, endpoint: std::net::SocketAddr) -> Config {
    let mut c = fixture_config(endpoint);
    c.ca_der_hex = fixture.ca.clone();
    c.seed_certificate_sha256 = fixture.pin.clone();
    c
}

// Kill/reap only our exact child on every failure/panic. No automatic retry.
struct OwnedChild(Child);
impl OwnedChild {
    fn start(root: &std::path::Path, command: &str) -> Self {
        let binary = PathBuf::from(std::env::var_os("SILK_F04_SYNC_BINARY").unwrap());
        assert!(binary.is_absolute());
        let mut child = Command::new(binary);
        child
            .arg(command)
            .arg("--config")
            .arg(root.join("config.json"));
        if command == "sync" {
            child.arg("--peers").arg(root.join("peers.json"));
        }
        let process = child.spawn().unwrap();
        println!("owned_receiver_pid={};command={command}", process.id());
        Self(process)
    }
    fn finish(&mut self, expected: i32) {
        let end = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert_eq!(status.code(), Some(expected), "unexpected CLI exit");
                return;
            }
            assert!(
                Instant::now() < end,
                "CLI phase exceeded 120 seconds; no retry"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

// Synchronous fixture serving: harness2 + CLI1 + core worker1 fit TasksMax=4.
// No extra socket thread and no alternate receiver implementation.
fn source(
    listener: TcpListener,
    fixture: &TlsFixture,
    mut status: Info,
    carriers: &[Vec<u8>],
    lose: bool,
) {
    status.seed = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    for exchange in 0..3 {
        let end = Instant::now() + Duration::from_secs(30);
        let (socket, _) = loop {
            match listener.accept() {
                Ok(value) => break value,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => {
                    thread::sleep(Duration::from_millis(2))
                }
                other => panic!("bounded live source accept: {other:?}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut stream = StreamOwned::new(
            ServerConnection::new(fixture.config.clone()).unwrap(),
            socket,
        );
        let mut hello = [0; 140];
        stream.read_exact(&mut hello).unwrap();
        assert_eq!(
            hello,
            wire::hello(&public_testnet_v1::genesis().unwrap()).unwrap()
        );
        stream.write_all(&[0]).unwrap();
        stream.flush().unwrap();
        let request = wire::read_frame(&mut stream, wire::MAX_REQUEST).unwrap();
        if lose && exchange == 2 {
            assert_eq!(offset(&request), 4);
            return; // Real TLS/socket loss after accepted prefix.
        }
        let payload = if request == [0] {
            serde_json::to_vec(&status).unwrap()
        } else {
            let start = offset(&request);
            assert_eq!(start, 0); // Both sources must start at their own zero.
            let values: Vec<&[u8]> = carriers
                .iter()
                .skip(start)
                .take(if lose { 4 } else { 8 })
                .map(Vec::as_slice)
                .collect();
            frame(&values)
        };
        let mut reply = vec![0];
        reply.extend(payload);
        wire::write_frame(&mut stream, &reply).unwrap();
        if !lose && exchange == 1 {
            return;
        }
    }
}

fn retained(c: &Config, p: &SaplingParameters) -> Node {
    let node = Node::open_retained_pinned(
        &c.store,
        &c.host_margin,
        public_testnet_v1::genesis().unwrap(),
        p,
        c.load_pin().unwrap(),
    )
    .unwrap();
    assert_eq!(node.status().unwrap(), NodeStatus::Ready);
    assert_eq!(node.local_head().unwrap(), c.load_pin().unwrap());
    node
}

#[test]
#[ignore = "requires explicit qualified Linux lab, ordinary CLI and eight unverified previously mined zero-value carriers"]
fn genuine_pinned_catchup_peer_loss_and_process_restart() {
    if !cfg!(target_os = "linux") {
        panic!("native Linux deadlines required");
    }
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("SILK_F04_SYNC_LAB").unwrap());
    assert!(root.is_absolute());
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(root.join("pins")).unwrap();
    fs::set_permissions(root.join("pins"), fs::Permissions::from_mode(0o700)).unwrap();
    let bytes = read_file(
        &PathBuf::from(std::env::var_os("SILK_F04_SYNC_CARRIERS").unwrap()),
        720_041,
    )
    .unwrap();
    let batch = RangeBatchV1::decode(&bytes, 0, 8).unwrap();
    assert_eq!(batch.carriers().len(), 8);
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let p = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let a_tls = TlsFixture::new();
    let b_tls = TlsFixture::new();
    let a_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let b_reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = peer(&a_tls, a_listener.local_addr().unwrap());
    let b = peer(&b_tls, b_reservation.local_addr().unwrap());
    drop(b_reservation); // Backup is unavailable during first invocation.
    let c = configure(&root, &a, &b, &parameter_dir);
    let mut source_node = Node::create(
        &root.join("source"),
        &PathBuf::from("/work"),
        public_testnet_v1::genesis().unwrap(),
    )
    .unwrap();
    let mut operator = a.clone();
    operator.store = root.join("source");
    operator.retained_head = root.join("pins/source-head");
    for bytes in batch.carriers() {
        assert_eq!(source_node.ingest(bytes, &p).unwrap(), Ingress::Admitted);
        settle(&mut source_node, &operator).unwrap();
    }
    let target = info(&source_node, &operator).unwrap();
    assert_eq!(target.vertices, 8);
    assert_eq!(target.checkpoint_index, 1);
    let carriers = source_node.export_range(0, 8).unwrap();
    save(
        &root.join("target.json"),
        &serde_json::to_vec(&target).unwrap(),
    );
    drop(source_node);
    OwnedChild::start(&root, "init").finish(0);
    let mut partial = OwnedChild::start(&root, "sync");
    source(a_listener, &a_tls, target.clone(), &carriers, true);
    partial.finish(78); // Source exhausted, not a node validity/ownership failure.
    let node = retained(&c, &p);
    assert_eq!(node.vertex_count(), 4);
    let partial_head = node.local_head().unwrap();
    save(
        &root.join("partial.json"),
        &serde_json::to_vec(&info(&node, &c).unwrap()).unwrap(),
    );
    save(
        &root.join("partial-head"),
        hex::encode(partial_head).as_bytes(),
    );
    drop(node);
    for phase in ["resume", "repeat"] {
        let listener = TcpListener::bind(b.seed).unwrap();
        let mut receiver = OwnedChild::start(&root, "sync");
        source(listener, &b_tls, target.clone(), &carriers, false);
        receiver.finish(0);
        let node = retained(&c, &p);
        same_state(&info(&node, &c).unwrap(), &target).unwrap();
        assert_eq!(node.export_range(0, 8).unwrap(), carriers);
        println!(
            "receiver_phase={phase};pid={};vertices=8;checkpoint=1;head={};state={}",
            receiver.0.id(),
            hex::encode(node.local_head().unwrap()),
            info(&node, &c).unwrap().state
        );
        save(
            &root.join(format!("{phase}.json")),
            &serde_json::to_vec(&info(&node, &c).unwrap()).unwrap(),
        );
        // The ordinary CLI explicitly writes its local-clock record at clean
        // shutdown. Compare state/checkpoint/carriers and each OWN pin, not heads
        // across distinct process lifetimes or independently owned stores.
    }
    let mut negative = Node::create(
        &root.join("negative"),
        &PathBuf::from("/work"),
        public_testnet_v1::genesis().unwrap(),
    )
    .unwrap();
    let before = negative.local_head().unwrap();
    let mut invalid = carriers[0].clone();
    invalid[511] ^= 1; // Candidate frame56 + header required-work last byte455.
    assert!(negative.ingest(&invalid, &p).is_err());
    assert_eq!(negative.vertex_count(), 0);
    assert_eq!(negative.local_head().unwrap(), before);
    println!(
        "live_sync_complete=true;vertices=8;checkpoint=1;receiver_sync_lifetimes=3;peer_loss=true;local_invalid_work_refused=true;fixture={}",
        root.display()
    );
}
