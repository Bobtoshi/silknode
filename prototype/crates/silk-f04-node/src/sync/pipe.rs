//! Opt-in full-duplex private byte pipes. Transport authentication and hard
//! aggregate containment belong to the operator; these bytes grant no validity.
use super::{RANGE_LIMIT_V1, RangeBatchV1};
use crate::{
    Error, Result,
    carriage::MAX_VERTEX_BYTES,
    node::{Ingress, Node, NodeStatus},
    wire::raw_hash,
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::io::{Read, Write};

const HELLO: &[u8; 8] = b"SNF04PS1";
const MAX_RESPONSE: usize = 1 + RANGE_LIMIT_V1 * (4 + MAX_VERTEX_BYTES);

/// Completed ordinary receiving operations, NOT peer validity, convergence,
/// an accepted snapshot, a durable cursor or permission to retry a failed job.
#[derive(Debug, PartialEq, Eq)]
pub struct PipeReceiveV1 {
    pub source_positions: usize,
    pub admitted: usize,
    pub already_known: usize,
}

fn write_frame(output: &mut impl Write, bytes: &[u8]) -> Result<()> {
    output.write_all(
        &u32::try_from(bytes.len())
            .map_err(|_| Error::Invalid("pipe frame length"))?
            .to_be_bytes(),
    )?;
    output.write_all(bytes)?;
    output.flush()?;
    Ok(())
}
fn read_frame(input: &mut impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err(Error::Invalid("pipe frame bounds"));
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn source_count(hello: &[u8], domain: &[u8; 32], bundle: &[u8; 32], limit: usize) -> Result<usize> {
    if hello.len() != 76
        || &hello[..8] != HELLO
        || hello[8..40] != *domain
        || hello[40..72] != *bundle
    {
        return Err(Error::Invalid("pipe source version/genesis"));
    }
    let total = u32::from_be_bytes(hello[72..76].try_into().unwrap()) as usize;
    if total > limit {
        return Err(Error::Unavailable("pipe receiver resource profile"));
    }
    Ok(total)
}

/// Serve a single fixed, locally verified admission-order inventory through a
/// private authenticated pipe. No listener, submission endpoint or store export.
/// The caller must impose a hard whole-process timer; idle pipe reads can block.
/// Mandatory cold opening is still ordinary full retained replay, not snapshot
/// adoption. This reader never changes the source clock or local HEAD.
pub fn serve_pipe_v1(node: &Node, input: &mut impl Read, output: &mut impl Write) -> Result<()> {
    if node.status()? != NodeStatus::Ready {
        return Err(Error::Paused("pipe source needs reconciliation"));
    }
    let total = node.vertex_count();
    if read_frame(input, 1)? != [0] {
        return Err(Error::Invalid("pipe initial request"));
    }
    let mut hello = Vec::from(HELLO.as_slice());
    hello.extend_from_slice(&node.genesis().domain());
    hello.extend_from_slice(&raw_hash(&node.genesis().local_bundle()));
    hello.extend_from_slice(&(total as u32).to_be_bytes());
    write_frame(output, &hello)?;
    let mut start = 0;
    // Cursor exists only inside this one process. Never accepts a caller offset,
    // never skips exact duplicate receiver checks, and never renews native jobs.
    while start < total {
        let request = read_frame(input, 5)?;
        if request.len() != 5
            || request[0] != 1
            || u32::from_be_bytes(request[1..5].try_into().unwrap()) as usize != start
        {
            return Err(Error::Invalid("pipe request sequence"));
        }
        let carriers = node.export_range(start, RANGE_LIMIT_V1)?;
        if carriers.is_empty() || carriers.len() > (total - start).min(RANGE_LIMIT_V1) {
            return Err(Error::Unavailable("pipe source range"));
        }
        let mut bytes = vec![carriers.len() as u8];
        for carrier in &carriers {
            bytes.extend_from_slice(&(carrier.len() as u32).to_be_bytes());
            bytes.extend_from_slice(carrier);
        }
        write_frame(output, &bytes)?;
        start += carriers.len();
    }
    Ok(())
}

/// Automatically request every source position once, from zero, and use the
/// ordinary live native admission/reconciliation route. A received count never
/// selects the local profile or asserts matching prefixes/checkpoints/state.
/// Whole bounded response framing completes before its first admission.
/// A later native failure may retain earlier admissions; this is NOT atomic.
/// On transport loss preserve the accepted prefix and externally retain its
/// healthy own HEAD. Never reopen/retry an interrupted native owner.
/// Caller supplies authenticated transport and hard process/aggregate limits.
pub fn receive_pipe_v1(
    node: &mut Node,
    parameters: &SaplingParameters,
    input: &mut impl Read,
    output: &mut impl Write,
    max_steps: usize,
) -> Result<PipeReceiveV1> {
    if !(1..=512).contains(&max_steps) {
        return Err(Error::Invalid("pipe reconciliation bound"));
    }
    if node.status()? != NodeStatus::Ready {
        return Err(Error::Paused("pipe receiver needs reconciliation"));
    }
    write_frame(output, &[0])?;
    let hello = read_frame(input, 76)?;
    let total = source_count(
        &hello,
        &node.genesis().domain(),
        &raw_hash(&node.genesis().local_bundle()),
        node.history_limits().vertices(),
    )?;
    let mut receipt = PipeReceiveV1 {
        source_positions: total,
        admitted: 0,
        already_known: 0,
    };
    let mut start = 0;
    while start < total {
        let mut request = vec![1];
        request.extend_from_slice(&(start as u32).to_be_bytes());
        write_frame(output, &request)?;
        let response = read_frame(input, MAX_RESPONSE)?;
        let batch =
            RangeBatchV1::decode_with_limits(&response, start, total, node.history_limits())?;
        for carrier in batch.carriers() {
            match node.ingest(carrier, parameters)? {
                Ingress::AlreadyKnown => receipt.already_known += 1,
                Ingress::Admitted => receipt.admitted += 1,
                Ingress::Pending => return Err(Error::Unavailable("pipe unfinished ingress")),
            }
            for _ in 0..max_steps {
                if node.status()? == NodeStatus::Ready {
                    break;
                }
                node.advance()?;
            }
            if node.status()? != NodeStatus::Ready {
                return Err(Error::Paused("pipe receiver needs reconciliation"));
            }
        }
        start += batch.carriers().len();
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pipe_framing_refuses_partial_overlong_and_zero_before_exposure() {
        let mut complete = Vec::new();
        write_frame(&mut complete, b"complete unverified bytes").unwrap();
        for cut in 0..complete.len() {
            assert!(read_frame(&mut &complete[..cut], 32).is_err());
        }
        assert_eq!(
            read_frame(&mut complete.as_slice(), 32).unwrap(),
            b"complete unverified bytes"
        );
        assert!(read_frame(&mut complete.as_slice(), 8).is_err());
        assert!(read_frame(&mut &[0, 0, 0, 0][..], 32).is_err());
        assert!(read_frame(&mut u32::MAX.to_be_bytes().as_slice(), MAX_RESPONSE).is_err());
    }
    #[test]
    fn pipe_source_identity_and_count_never_enlarge_receiver_profile() {
        let mut hello = Vec::from(HELLO.as_slice());
        hello.extend_from_slice(&[1; 32]);
        hello.extend_from_slice(&[2; 32]);
        hello.extend_from_slice(&4104_u32.to_be_bytes());
        assert!(source_count(&hello, &[1; 32], &[2; 32], 4096).is_err());
        assert_eq!(
            source_count(&hello, &[1; 32], &[2; 32], 8192).unwrap(),
            4104
        );
        assert!(source_count(&hello, &[3; 32], &[2; 32], 8192).is_err());
        assert!(source_count(&hello, &[1; 32], &[3; 32], 8192).is_err());
        for cut in 0..hello.len() {
            assert!(source_count(&hello[..cut], &[1; 32], &[2; 32], 8192).is_err());
        }
        hello[0] ^= 1;
        assert!(source_count(&hello, &[1; 32], &[2; 32], 8192).is_err());
    }
}
