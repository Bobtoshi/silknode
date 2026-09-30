//! Explicit, Linux-only, zero-value public testnet seed and connecting miner.
//! No mainnet activation, wallet submission, DNS, telemetry or valuable rewards.
mod config;
mod limits;
mod server;
mod wire;
use config::{Config, digest};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use silk_f04_node::{
    carriage::{Body, Candidate},
    genesis::{Genesis, public_testnet_v1 as profile},
    node::{Node, NodeStatus},
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::{
    net::TcpListener,
    path::Path,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn fail<T>(message: &'static str) -> Result<T> {
    Err(message.into())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Info {
    schema: String,
    seed: String,
    domain: String,
    vertices: usize,
    checkpoint_index: u64,
    checkpoint: String,
    state: String,
    executed: usize,
    initial_allocation: u64,
}
fn info(node: &Node, c: &Config) -> Result<Info> {
    let state = node.state()?;
    Ok(Info {
        schema: "silknode-public-status-v1".into(),
        seed: c.seed.to_string(),
        domain: hex::encode(node.genesis().domain()),
        vertices: node.vertex_count(),
        checkpoint_index: state.checkpoint_index(),
        checkpoint: hex::encode(state.checkpoint_id()),
        state: hex::encode(state.digest()),
        executed: state.executed().len(),
        initial_allocation: 0,
    })
}
fn report(node: &Node, c: &Config) -> Result<()> {
    println!("{}", serde_json::to_string(&info(node, c)?)?);
    eprintln!(
        "retained_local_head={};accounted_bytes={}",
        hex::encode(node.local_head()?),
        node.accounted_bytes()
    );
    Ok(())
}
fn settle(node: &mut Node, c: &Config) -> Result<()> {
    c.save_pin(node)?;
    for _ in 0..1024 {
        if node.status()? == NodeStatus::Ready {
            return Ok(());
        }
        node.advance()?;
        c.save_pin(node)?;
    }
    fail("bounded reconciliation incomplete; no new admission")
}
fn peer_info(c: &Config, g: &Genesis) -> Result<Info> {
    let value: Info = serde_json::from_slice(&wire::request(c, g, &[0])?)?;
    if value.schema != "silknode-public-status-v1"
        || value.domain != profile::DOMAIN_HEX
        || value.seed != c.seed.to_string()
        || value.vertices > 4096
        || value.initial_allocation != 0
    {
        return fail("peer discovery identity/bounds");
    }
    Ok(value)
}
fn same_state(local: &Info, remote: &Info) -> Result<()> {
    if local.vertices != remote.vertices
        || local.checkpoint_index != remote.checkpoint_index
        || local.checkpoint != remote.checkpoint
        || local.state != remote.state
        || local.executed != remote.executed
    {
        return fail("peer state differs from independently verified local history; sync again");
    }
    Ok(())
}
fn synchronize(node: &mut Node, c: &Config, parameters: &SaplingParameters) -> Result<()> {
    let target = peer_info(c, node.genesis())?;
    let mut start = 0_usize;
    while start < target.vertices {
        let mut request = vec![1];
        request.extend_from_slice(&(start as u32).to_be_bytes());
        let response = wire::request(c, node.genesis(), &request)?;
        let count = usize::from(*response.first().ok_or("range count")?);
        if count == 0 || count > 32 || start + count > target.vertices {
            return fail("range count/bounds changed");
        }
        let mut at = 1;
        for _ in 0..count {
            let size: [u8; 4] = response.get(at..at + 4).ok_or("range length")?.try_into()?;
            at += 4;
            let size = u32::from_be_bytes(size) as usize;
            if size > 90_000 {
                return fail("range vertex size");
            }
            let bytes = response.get(at..at + size).ok_or("range truncated")?;
            // No checkpoint, clock or peer work claim is trusted by this receiver.
            node.ingest(bytes, parameters)?;
            settle(node, c)?;
            at += size;
        }
        if at != response.len() {
            return fail("range trailing bytes");
        }
        start += count;
    }
    same_state(&info(node, c)?, &target)?;
    println!(
        "peer_discovered={};tls=verified;history=locally_verified",
        target.seed
    );
    Ok(())
}
fn response(
    node: &mut Node,
    c: &Config,
    parameters: &SaplingParameters,
    request: &[u8],
    publication_incomplete: &mut bool,
) -> Result<Vec<u8>> {
    match request {
        [0] => Ok(serde_json::to_vec(&info(node, c)?)?),
        [1, a, b, d, e] => {
            let start = u32::from_be_bytes([*a, *b, *d, *e]) as usize;
            let values = node.export_range(start, 32)?;
            let mut bytes = vec![values.len() as u8];
            for v in values {
                bytes.extend_from_slice(&(v.len() as u32).to_be_bytes());
                bytes.extend(v);
            }
            Ok(bytes)
        }
        [2, bytes @ ..] if !bytes.is_empty() => {
            // Only full work-bearing carriers. No raw-envelope submission route.
            node.ingest(bytes, parameters)?;
            *publication_incomplete = true;
            settle(node, c)?;
            report(node, c)?;
            *publication_incomplete = false;
            Ok(serde_json::to_vec(&info(node, c)?)?)
        }
        _ => fail("unknown request/version/length"),
    }
}
fn seed(mut node: Node, c: &Config, parameters: &SaplingParameters) -> Result<()> {
    let tls = wire::server_config(c)?;
    let expected = wire::hello(node.genesis())?;
    let listener = TcpListener::bind(c.listen.ok_or("explicit seed listen address")?)?;
    report(&node, c)?;
    println!(
        "seed_listening={};value=ZERO;privacy=NOT_CLAIMED",
        listener.local_addr()?
    );
    let mut server = server::Server::new(listener, tls, expected)?;
    loop {
        server.tick(|request| {
            let mut publication_incomplete = false;
            let payload = response(
                &mut node,
                c,
                parameters,
                request,
                &mut publication_incomplete,
            );
            let bytes = match payload {
                Ok(payload) => {
                    let mut out = vec![0];
                    out.extend(payload);
                    out
                }
                Err(_) => vec![1],
            };
            // Ordinary peer rejection is not a restart. A faulted writer STOPS; a
            // service restart cannot adopt another head or clear an unfinished job.
            if publication_incomplete
                || node.status()? != NodeStatus::Ready
                || c.load_pin()? != node.local_head()?
            {
                return fail(
                    "seed stopped after incomplete reconciliation or retained-pin publication",
                );
            }
            Ok(bytes)
        })?;
        // Bound accept/refusal work too; a busy backlog cannot starve queued requests.
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn mine(mut node: Node, c: &Config, parameters: &SaplingParameters, count: usize) -> Result<()> {
    let owner = digest(&c.reward_owner)?;
    if owner == [0; 32] {
        return fail("nonzero public reward attribution tag required");
    }
    for i in 0..count {
        let began = Instant::now();
        synchronize(&mut node, c, parameters)?;
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "mining entropy")?;
        let body = Body::new(&node.genesis().domain(), &[])?;
        let candidate: Candidate = node.mine_current(body, owner, nonce, None)?;
        let bytes = candidate.encode();
        let mut request = vec![2];
        request.extend_from_slice(&bytes);
        // Submit first: after a lost acknowledgement the next sync learns the
        // accepted bytes, without inventing credit or rewriting local history.
        let ack: Info = serde_json::from_slice(&wire::request(c, node.genesis(), &request)?)?;
        node.ingest(&bytes, parameters)?;
        settle(&mut node, c)?;
        same_state(&info(&node, c)?, &ack)?;
        println!(
            "mined_vertex={};required_work={};timestamp={};seed_accepted=true;local_work_reverified=true",
            hex::encode(candidate.id),
            candidate.header.work,
            candidate.header.timestamp
        );
        report(&node, c)?;
        // Real wall-time pacing only. The original parent-local DAA is unchanged;
        // there is no claimed-work override or historical timestamp option.
        if i + 1 < count {
            if let Some(left) = Duration::from_secs(40).checked_sub(began.elapsed()) {
                std::thread::sleep(left);
            }
        }
    }
    node.flush_clock()?;
    c.save_pin(&node)?;
    report(&node, c)
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let g = profile::genesis()?;
    wire::hello(&g)?;
    if args.as_slice() == ["identity"] {
        println!(
            "name={};network={};chain={};genesis={};domain={};bundle_sha256={};magic={};protocol={};initial_allocation=0;initial_work=1",
            profile::NAME,
            hex::encode(&g.context().bytes()[12..44]),
            hex::encode(&g.context().bytes()[44..76]),
            hex::encode(&g.context().bytes()[108..140]),
            profile::DOMAIN_HEX,
            profile::BUNDLE_SHA256,
            hex::encode(wire::MAGIC),
            wire::PROTOCOL_HEX
        );
        return Ok(());
    }
    if args.len() < 3
        || args[1] != "--config"
        || !matches!(
            args[0].as_str(),
            "init" | "seed" | "mine" | "sync" | "probe" | "wrong-network"
        )
    {
        return fail(
            "usage: silk-f04-testnet identity | init|seed|sync|probe|wrong-network --config ABS.json | mine --config ABS.json --count 1..32",
        );
    }
    let command = &args[0];
    let count = if command == "mine" {
        if args.len() != 5 || args[3] != "--count" {
            return fail("mine requires --count 1..32");
        }
        let n: usize = args[4].parse()?;
        if !(1..=32).contains(&n) {
            return fail("mine count 1..32");
        }
        n
    } else {
        if args.len() != 3 {
            return fail("unexpected options");
        }
        0
    };
    let c = Config::load(Path::new(&args[2]))?;
    if command == "probe" {
        println!("{}", serde_json::to_string(&peer_info(&c, &g)?)?);
        return Ok(());
    }
    if command == "wrong-network" {
        return wire::wrong_network(&c, &g);
    }
    if !cfg!(target_os = "linux") {
        return fail("node/miner requires Linux native deadline enforcement");
    }
    c.pin_parent()?;
    if command == "init" {
        if c.retained_head.try_exists()? {
            return fail("refuse existing independently retained head");
        }
        let node = Node::create(&c.store, &c.host_margin, g)?;
        c.save_pin(&node)?;
        return report(&node, &c);
    }
    let parameters = SaplingParameters::load(&c.spend_parameters, &c.output_parameters)?;
    let mut node =
        Node::open_retained_pinned(&c.store, &c.host_margin, g, &parameters, c.load_pin()?)?;
    settle(&mut node, &c)?;
    match command.as_str() {
        "seed" => seed(node, &c, &parameters),
        "mine" => mine(node, &c, &parameters, count),
        "sync" => {
            synchronize(&mut node, &c, &parameters)?;
            node.flush_clock()?;
            c.save_pin(&node)?;
            report(&node, &c)
        }
        _ => fail("unsupported command"),
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("STOP: {e}");
        // No automatic retry of an uncertain durable operation by systemd.
        std::process::exit(78);
    }
}
