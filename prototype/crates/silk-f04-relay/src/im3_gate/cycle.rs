//! Private fixed-stream helpers, shared by the separate IM3 timed owners.
use super::*;
use crate::tls::WireObservation;

#[derive(Default)]
pub(super) struct ReadState {
    pub armed: bool,
    pub selected_any: bool,
}
#[derive(Default)]
pub(super) struct WriteState {
    pub queued: bool,
}
pub(super) type Observation = Option<(u8, WireObservation)>;
pub(super) fn close(link: &mut Transport) {
    let _ = link.quarantine();
}
pub(super) fn read(
    link: &mut Transport,
    state: &mut ReadState,
    size: RecordSize,
    early: Instant,
    end: Instant,
    lane: u8,
    observation: &mut Observation,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    before(end)?;
    if !state.armed {
        // Bind the stream's first record before its earliest receive envelope.
        // Later exact records retain this same original stream cutoff; no
        // replacement connection or deadline renewal is accepted.
        if !state.selected_any {
            before(early)?;
            if link.has_extra_bytes()? {
                return Err(Error::Invalid("IM3 premature original stream"));
            }
            if end
                .checked_duration_since(Instant::now())
                .is_some_and(|d| d > std::time::Duration::from_secs(30))
            {
                return Ok(None);
            }
        }
        link.expect(size, end)?;
        state.armed = true;
        state.selected_any = true;
    }
    if Instant::now() < early {
        if link.has_extra_bytes()? {
            return Err(Error::Invalid("IM3 early original record"));
        }
        return Ok(None);
    }
    let (result, o) = link.read_step_observed();
    *observation = Some((lane, o));
    let bytes = result?;
    before(end)?;
    if bytes.is_some() {
        state.armed = false;
    }
    Ok(bytes)
}
pub(super) fn write(
    link: &mut Transport,
    state: &mut WriteState,
    size: RecordSize,
    bytes: &[u8],
    start: Instant,
    end: Instant,
    lane: u8,
    observation: &mut Observation,
) -> Result<bool> {
    if Instant::now() < start {
        return Ok(false);
    }
    before(end)?;
    if !state.queued {
        link.queue(size, bytes, end)?;
        state.queued = true;
    }
    let (result, o) = link.write_step_observed();
    *observation = Some((lane, o));
    let done = result?;
    before(end)?;
    if done {
        state.queued = false;
    }
    Ok(done)
}
pub(super) fn quiet(link: &Transport) -> Result<()> {
    if link.has_extra_bytes()? {
        Err(Error::Invalid("IM3 extra closed-stream bytes"))
    } else {
        Ok(())
    }
}
pub(super) fn copy_ready(c: &MiddleContext<'_>, ready: &Im3ReadyChain) -> Result<Im3ReadyChain> {
    Im3ReadyChain::verify(
        c,
        Im3Control::verify(ready.a.bytes(), c)?,
        Im3Control::verify(ready.c.bytes(), c)?,
        Im3Control::verify(ready.b.bytes(), c)?,
    )
}
pub(super) fn copy_acks(c: &MiddleContext<'_>, chain: &Im3AckChain) -> Result<Im3AckChain> {
    let acks = chain
        .acks
        .iter()
        .map(|a| Im3Control::verify(a.bytes(), c))
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| Error::Invalid("IM3 copied ACK count"))?;
    Im3AckChain::verify(c, copy_ready(c, &chain.ready)?, acks)
}
pub(super) fn terminal_fields(chain: &Im3AckChain, previous: Digest) -> [Digest; 7] {
    let b = &chain.ready.b;
    [
        b.field(116),
        b.field(148),
        b.field(180),
        previous,
        b.field(244),
        [0; 32],
        chain.evidence_digest(),
    ]
}
pub(super) fn authorization_choice(c: &MiddleContext<'_>, chain: &Im3AckChain) -> Digest {
    domain_hash(
        "SilkNode-IM3-authorization-decision",
        &[
            &c.q.id(),
            &c.r2.round.manifest.id(),
            &c.r2.round.manifest.round().to_le_bytes(),
            &chain.ready.b.id(),
            &chain.evidence_digest(),
        ],
    )
}
pub(super) fn release_choice(c: &MiddleContext<'_>, auth: &Im3Authorization) -> Digest {
    domain_hash(
        "SilkNode-IM3-release-decision",
        &[
            &c.q.id(),
            &c.r2.round.manifest.id(),
            &c.r2.round.manifest.round().to_le_bytes(),
            &auth.control.id(),
            &auth.chain.ready.b.id(),
            &auth.chain.evidence_digest(),
        ],
    )
}
pub(super) fn take_controls(v: &mut Vec<Im3Control>) -> Result<[Im3Control; 3]> {
    std::mem::take(v)
        .try_into()
        .map_err(|_| Error::Invalid("IM3 exact three controls"))
}
