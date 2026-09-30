//! Bounded multi-source catch-up. Transport failures never become node validity.
use crate::{
    Info, Result, config::Config, decode_peer_info, fail, info, peers::MAX_SOURCES, same_state,
    settle, wire,
};
use silk_f04_node::{
    genesis::public_testnet_v1,
    node::{Ingress, Node},
    sync::RangeBatchV1,
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::time::{Duration, Instant};

const MULTI_SOURCE_WINDOW: Duration = Duration::from_secs(1800);

fn check_deadline(until: Option<Instant>) -> Result<()> {
    if until.is_some_and(|end| Instant::now() >= end) {
        return fail("cumulative multi-source sync allowance exhausted; accepted prefix retained");
    }
    Ok(())
}

enum Failure {
    Peer(Box<dyn std::error::Error>),
    Local(Box<dyn std::error::Error>),
}

trait Receiver {
    fn ingest(&mut self, bytes: &[u8]) -> Result<()>;
    fn snapshot(&self) -> Result<Info>;
}

struct LiveReceiver<'a> {
    node: &'a mut Node,
    operator: &'a Config,
    parameters: &'a SaplingParameters,
}
impl Receiver for LiveReceiver<'_> {
    fn ingest(&mut self, bytes: &[u8]) -> Result<()> {
        // Exact duplicates are still compared by the receiver. No positional
        // prefix, remote checkpoint or asserted work skips ordinary ingress.
        if self.node.ingest(bytes, self.parameters)? != Ingress::AlreadyKnown {
            settle(self.node, self.operator)?;
        }
        Ok(())
    }
    fn snapshot(&self) -> Result<Info> {
        info(self.node, self.operator)
    }
}

fn attempt(
    receiver: &mut impl Receiver,
    peer: &Config,
    request: &mut impl FnMut(&Config, &[u8], Option<Instant>) -> Result<Vec<u8>>,
    until: Option<Instant>,
) -> std::result::Result<Info, Failure> {
    check_deadline(until).map_err(Failure::Local)?;
    let bytes = request(peer, &[0], until).map_err(Failure::Peer)?;
    let target = decode_peer_info(peer, &bytes).map_err(Failure::Peer)?;
    // Offsets belong to this source's admission order. Restart at zero when
    // switching source; equal graph sizes do not establish equal prefixes.
    let mut start = 0_usize;
    while start < target.vertices {
        let mut range = vec![1];
        range.extend_from_slice(
            &u32::try_from(start)
                .expect("bounded sync index")
                .to_be_bytes(),
        );
        check_deadline(until).map_err(Failure::Local)?;
        let response = request(peer, &range, until).map_err(Failure::Peer)?;
        let batch = RangeBatchV1::decode(&response, start, target.vertices)
            .map_err(|e| Failure::Peer(e.into()))?;
        for bytes in batch.carriers() {
            check_deadline(until).map_err(Failure::Local)?;
            // A local work/proof/resource/storage/clock error STOPS the whole
            // invocation. Failover must not renew an uncertain job's allowance.
            receiver.ingest(bytes).map_err(Failure::Local)?;
        }
        start += batch.carriers().len();
    }
    check_deadline(until).map_err(Failure::Local)?;
    let local = receiver.snapshot().map_err(Failure::Local)?;
    same_state(&local, &target).map_err(Failure::Peer)?;
    Ok(target)
}

fn run_sources(
    receiver: &mut impl Receiver,
    sources: &[Config],
    request: impl FnMut(&Config, &[u8], Option<Instant>) -> Result<Vec<u8>>,
) -> Result<Info> {
    // Existing single-source commands retain their timing policy. Only explicit
    // multi-source operation adds one shared cooperative allowance.
    let until = (sources.len() > 1).then(|| Instant::now() + MULTI_SOURCE_WINDOW);
    run_until(receiver, sources, request, until)
}

fn run_until(
    receiver: &mut impl Receiver,
    sources: &[Config],
    mut request: impl FnMut(&Config, &[u8], Option<Instant>) -> Result<Vec<u8>>,
    until: Option<Instant>,
) -> Result<Info> {
    if sources.is_empty() || sources.len() > MAX_SOURCES {
        return fail("sync source bound");
    }
    for source in sources {
        check_deadline(until)?;
        match attempt(receiver, source, &mut request, until) {
            Ok(target) => return Ok(target),
            Err(Failure::Local(error)) => return Err(error),
            Err(Failure::Peer(_error)) => {
                // Do not print arbitrary peer-controlled error text. Each
                // explicitly pinned source is tried once, without auto-enrollment.
                eprintln!(
                    "sync_peer_unavailable={};accepted_prefix_retained=true",
                    source.seed
                );
            }
        }
    }
    fail("all explicitly pinned sync sources failed; accepted history retained")
}

pub fn synchronize(
    node: &mut Node,
    operator: &Config,
    sources: &[Config],
    parameters: &SaplingParameters,
) -> Result<()> {
    let genesis = public_testnet_v1::genesis()?;
    let mut receiver = LiveReceiver {
        node,
        operator,
        parameters,
    };
    let target = run_sources(&mut receiver, sources, |source, bytes, until| {
        if let Some(until) = until {
            wire::request_until(source, &genesis, bytes, until)
        } else {
            wire::request(source, &genesis, bytes)
        }
    })?;
    println!(
        "peer_discovered={};tls=verified;history=locally_verified",
        target.seed
    );
    Ok(())
}

#[cfg(test)]
mod tests;
