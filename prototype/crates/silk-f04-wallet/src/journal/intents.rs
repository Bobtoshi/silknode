//! Bounded local reservation/exposure journal. Not canonical-history authority.
//! One current intent; historical exposed inputs are never released or reset.
use super::{
    AeadInOut, Digest, Error, Journal, KeyInit, MAX_FILES, MAX_RECORDS, Path, RECORD_HEADER,
    RESERVATION, Result, WalletKey, XChaCha20Poly1305, XNonce, Zeroizing, binding, capacity,
    domain_hash, entropy, inventory, publish, read,
};
use sapling_crypto::{MerklePath, Node, Note, PaymentAddress, Rseed};
use silk_sapling_f04::{
    codec::{ENVELOPE_BYTES, Envelope},
    parameters::SaplingParameters,
    wallet::{CutReference, MAX_VALUE, PaymentOutput, SpendInput, build_transfer},
};

const PLAIN: usize = 4096;
const SEALED: usize = RECORD_HEADER + PLAIN + 16;
mod history;

/// One explicit export of already durably exposed bytes for a local client.
///
/// No Clone/Debug, inputs, witnesses, keys or writable bytes are exposed. Consuming
/// this value cannot undo exposure or authorize an automatic later-round retry.
pub struct SavedOfferV1(Zeroizing<[u8; ENVELOPE_BYTES]>);
impl SavedOfferV1 {
    /// Consume the export into a wiping transport-side buffer. This is not a
    /// ledger acceptance, delivery receipt or permission to retry.
    #[must_use]
    pub fn into_bytes(self) -> Zeroizing<[u8; ENVELOPE_BYTES]> {
        self.0
    }
}

/// Opt-in adapter over one locally verified ready node, inside the trusted wallet.
///
#[cfg(feature = "local-node")]
pub mod canonical;

/// Local state, not a ledger confirmation or a transport-delivery receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentStatus {
    /// Fresh explicitly initialized journal, not a missing journal.
    Empty,
    /// Inputs reserved locally; no signed bytes have left this API.
    Reserved,
    /// Exact signed bytes committed before possible export. Never reset on failure.
    MayHaveEscaped,
    /// Explicitly cancelled before any signed-envelope export was possible.
    CancelledBeforeRelease,
}
impl IntentStatus {
    const fn byte(self) -> u8 {
        match self {
            Self::Empty => 0,
            Self::Reserved => 1,
            Self::MayHaveEscaped => 2,
            Self::CancelledBeforeRelease => 3,
        }
    }
}

/// Caller-supplied binding from a COMPLETE locally verified canonical snapshot.
///
/// This component checks consistency, ownership and witnesses, NOT the history's
/// work, lineage, spentness or authenticity. The node adapter must establish those
/// before reservation and again before proving. No peer snapshot is authority.
#[derive(Clone, Copy)]
pub struct SpendContext {
    /// Completed canonical checkpoint ordinal.
    pub checkpoint_index: u64,
    /// Exact checkpoint identifier.
    pub checkpoint: Digest,
    /// Canonical full-state digest at that checkpoint.
    pub state: Digest,
    /// Current canonical checkpoint-prefix commitment.
    pub prefix: Digest,
    /// Exact eligible cut, including full static domain.
    pub cut: CutReference,
    /// Complete number of leaves in that cut.
    pub cut_leaves: u64,
}
/// Private positioned input and witness; never sent to a submission component.
pub struct SelectedInput {
    /// Locally decrypted positive note.
    pub note: Note,
    /// Reconstructed witness at the chosen complete canonical cut.
    pub path: MerklePath,
}
#[derive(Clone, PartialEq, Eq)]
struct InputRef {
    position: u64,
    cmu: Digest,
    nf: Digest,
    value: u64,
}
#[derive(Clone)]
struct Plan {
    id: Digest,
    context: SpendContext,
    inputs: Vec<InputRef>,
    recipient: PaymentAddress,
    value: u64,
    change: PaymentAddress,
    change_value: u64,
}
#[derive(Clone)]
struct State {
    status: IntentStatus,
    plan: Option<Plan>,
    signed: Option<Envelope>,
}

/// Save BOTH pins independently; neither a key backup nor directory HEAD is a
/// substitute. No plaintext amount, note, key or envelope is returned here.
pub struct IntentReceipt {
    /// Latest address cursor pin (reservation allocates a fresh change address).
    pub address_head: Digest,
    /// Exact encrypted payment-state pin.
    pub intent_head: Digest,
    /// Local lifecycle status, not canonical acceptance.
    pub status: IntentStatus,
}

/// Borrows the address journal and SAME exclusive wallet lock. There cannot be a
/// concurrent address/payment writer through this API. No Debug/Clone or reset.
pub struct IntentJournal<'journal, 'key> {
    journal: &'journal mut Journal<'key>,
    head: Digest,
    sequence: u64,
    state: State,
    exposed: std::collections::BTreeMap<Digest, InputRef>,
}
impl<'key> Journal<'key> {
    /// Create a new address AND empty payment journal before returning either pin.
    /// Existing address-only wallets need a separately designed migration; opening
    /// a missing payment journal never silently creates an empty one.
    /// # Errors
    /// Same refusals as `create`, plus payment initialization/publication failures.
    pub fn create_with_intents(
        path: &Path,
        margin: &Path,
        key: &'key mut WalletKey,
        password: &str,
    ) -> Result<(Self, Digest)> {
        let mut journal = Self::create(path, margin, key, password)?;
        let mut intents = IntentJournal {
            journal: &mut journal,
            head: [0; 32],
            sequence: 0,
            exposed: std::collections::BTreeMap::new(),
            state: State {
                status: IntentStatus::Empty,
                plan: None,
                signed: None,
            },
        };
        let empty = intents.state.clone();
        intents.write_state(empty, true)?;
        let pin = intents.head;
        Ok((journal, pin))
    }
    /// Open payment continuity using its independently saved pin, under this lock.
    /// # Errors
    /// Refuses missing/stale/malformed state; never promotes an orphan or resets.
    pub fn intents(&mut self, expected: Digest) -> Result<IntentJournal<'_, 'key>> {
        self.head()?;
        if read(&self.directory, "HEAD", 32)? != self.head
            || read(&self.directory, "INTENT_HEAD", 32)? != expected
        {
            self.poisoned = true;
            return Err(Error::Unavailable("payment continuity pin mismatch"));
        }
        let audited = history::audit(self, expected)?;
        self.used = inventory(&self.directory)?;
        capacity(&self.directory, &self.margin, self.used.bytes, 0)?;
        Ok(IntentJournal {
            journal: self,
            head: expected,
            sequence: audited.sequence,
            state: audited.state,
            exposed: audited.exposed,
        })
    }
}

impl IntentJournal<'_, '_> {
    /// Current local receipt; callers must retain it outside received input.
    /// # Errors
    /// Refuses an uncertain publication handle.
    pub fn receipt(&self) -> Result<IntentReceipt> {
        Ok(IntentReceipt {
            address_head: self.journal.head()?,
            intent_head: self.head,
            status: self.state.status,
        })
    }
    fn current(&mut self) -> Result<()> {
        self.journal.head()?;
        if read(&self.journal.directory, "HEAD", 32)? != self.journal.head
            || read(&self.journal.directory, "INTENT_HEAD", 32)? != self.head
        {
            self.journal.poisoned = true;
            return Err(Error::Unavailable("payment continuity changed"));
        }
        Ok(())
    }
    /// Reserve one/two caller-verified unspent notes BEFORE proving. This checks
    /// ownership/witness/value consistency, not canonical history or spentness.
    /// A fresh change address is durably allocated first and is never rewound.
    /// # Errors
    /// Refuses another outstanding intent, invalid descriptor/context/selection,
    /// insufficient value, storage limits or uncertain publication.
    pub fn reserve(
        &mut self,
        context: SpendContext,
        inputs: &[SelectedInput],
        recipient: &str,
        value: u64,
    ) -> Result<IntentReceipt> {
        self.reserve_inner(context, inputs, recipient, value, false)
    }
    /// Explicitly begin a DISTINCT subsequent payment, never a retry/reset of the
    /// previous one. Its exposed inputs remain excluded permanently, even after
    /// conflict or reorg. Caller-supplied history still needs independent validation.
    /// # Errors
    /// Refuses no prior exposure, any historically exposed input, or `reserve` errors.
    pub fn reserve_distinct(
        &mut self,
        context: SpendContext,
        inputs: &[SelectedInput],
        recipient: &str,
        value: u64,
    ) -> Result<IntentReceipt> {
        self.reserve_inner(context, inputs, recipient, value, true)
    }
    fn reserve_inner(
        &mut self,
        context: SpendContext,
        inputs: &[SelectedInput],
        recipient: &str,
        value: u64,
        distinct: bool,
    ) -> Result<IntentReceipt> {
        self.current()?;
        let permitted = if distinct {
            self.state.status == IntentStatus::MayHaveEscaped
        } else {
            matches!(
                self.state.status,
                IntentStatus::Empty | IntentStatus::CancelledBeforeRelease
            )
        };
        if !permitted {
            return Err(Error::Unavailable("payment already reserved or exposed"));
        }
        let recipient = silk_sapling_f04::address::decode(recipient, &self.journal.key.domain)
            .map_err(|_| Error::Unavailable("recipient descriptor"))?;
        let refs = selected(self.journal.key, context, inputs)?;
        if refs
            .iter()
            .any(|input| self.exposed.contains_key(&input.nf))
        {
            return Err(Error::Unavailable(
                "historically exposed input remains reserved",
            ));
        }
        let total = refs
            .iter()
            .try_fold(0_u64, |sum, input| sum.checked_add(input.value))
            .ok_or(Error::Unavailable("payment value overflow"))?;
        let change_value = total
            .checked_sub(value)
            .and_then(|v| v.checked_sub(1))
            .filter(|_| value > 0 && value <= MAX_VALUE && total <= MAX_VALUE)
            .ok_or(Error::Unavailable("payment value and one-unit fee"))?;
        // Leave a sequence slot for exposure OR explicit pre-release cancellation.
        if self
            .sequence
            .checked_add(2)
            .is_none_or(|n| n >= MAX_RECORDS)
            || self
                .journal
                .sequence
                .checked_add(1)
                .is_none_or(|n| n >= MAX_RECORDS)
        {
            return Err(Error::Unavailable("wallet journal horizon"));
        }
        self.journal.used = inventory(&self.journal.directory)?;
        if self
            .journal
            .used
            .files
            .checked_add(4)
            .is_none_or(|n| n > MAX_FILES)
        {
            return Err(Error::Unavailable("combined payment entry reservation"));
        }
        capacity(
            &self.journal.directory,
            &self.journal.margin,
            self.journal.used.bytes,
            2 * RESERVATION,
        )?;
        let change = self.journal.issue_address()?.address.address;
        let plan = Plan {
            id: entropy::<32>()?,
            context,
            inputs: refs,
            recipient,
            value,
            change,
            change_value,
        };
        self.write_state(
            State {
                status: IntentStatus::Reserved,
                plan: Some(plan),
                signed: None,
            },
            false,
        )?;
        self.receipt()
    }
    /// Build internally, then durably latch `MAY_HAVE_ESCAPED` with exact signed
    /// bytes BEFORE returning even a receipt. No envelope escapes this call.
    /// The caller must freshly verify canonical context/spentness; supplying this
    /// same context is NOT that verification. Failures keep the reservation.
    /// # Errors
    /// Refuses changed selection/context, construction or uncertain publication.
    pub fn prove_reserved(
        &mut self,
        context: SpendContext,
        inputs: Vec<SelectedInput>,
        parameters: &SaplingParameters,
    ) -> Result<IntentReceipt> {
        self.current()?;
        if self.state.status != IntentStatus::Reserved {
            return Err(Error::Unavailable("no unexposed reserved payment"));
        }
        let plan = self
            .state
            .plan
            .as_ref()
            .ok_or(Error::Authentication)?
            .clone();
        if context_bytes(context) != context_bytes(plan.context)
            || selected(self.journal.key, context, &inputs)? != plan.inputs
            || plan
                .inputs
                .iter()
                .any(|input| self.exposed.contains_key(&input.nf))
        {
            return Err(Error::Unavailable(
                "reserved payment inputs/context changed",
            ));
        }
        // Do not run the expensive prover when publication is already known to
        // be impossible. The actual write repeats these checks after proving.
        self.sequence
            .checked_add(1)
            .filter(|n| *n < MAX_RECORDS)
            .ok_or(Error::Unavailable("payment journal horizon"))?;
        self.journal.used = inventory(&self.journal.directory)?;
        self.journal.used.reserve()?;
        capacity(
            &self.journal.directory,
            &self.journal.margin,
            self.journal.used.bytes,
            RESERVATION,
        )?;
        let inputs = inputs
            .into_iter()
            .map(|input| SpendInput {
                key: self.journal.key.key.clone(),
                note: input.note,
                path: input.path,
            })
            .collect();
        let verified = build_transfer(
            context.cut,
            inputs,
            [
                PaymentOutput {
                    address: plan.recipient,
                    value: plan.value,
                },
                PaymentOutput {
                    address: plan.change,
                    value: plan.change_value,
                },
            ],
            parameters,
        )
        .map_err(|_| Error::Unavailable("reserved payment construction failed"))?;
        // The only production path into exposure owns construction and its intent
        // round-trip checks. Accepting caller-visible VerifiedEnvelope is forbidden.
        let signed = verified.envelope().clone();
        check_envelope(&plan, &signed)?;
        self.write_state(
            State {
                status: IntentStatus::MayHaveEscaped,
                plan: Some(plan),
                signed: Some(signed),
            },
            false,
        )?;
        self.receipt()
    }
    /// Explicitly export ONLY the saved exact bytes, after the caller retained
    /// both receipt pins. This grants no inclusion, retry or transport authority.
    /// # Errors
    /// Refuses stale receipts, uncertain storage or an unprepared intent.
    pub fn release_saved_envelope(
        &mut self,
        retained_intent_pin: Digest,
    ) -> Result<[u8; ENVELOPE_BYTES]> {
        self.current()?;
        if retained_intent_pin != self.head || self.state.status != IntentStatus::MayHaveEscaped {
            return Err(Error::Unavailable("no pinned exposed payment"));
        }
        Ok(*self
            .state
            .signed
            .as_ref()
            .ok_or(Error::Authentication)?
            .bytes())
    }
    /// Explicit one-use modular client export, after independent pin retention.
    /// A second invocation is a separate caller decision, never a timeout policy.
    /// # Errors
    /// Applies the same current-pin, durable-exposure and exact-byte checks as
    /// `release_saved_envelope`; failure leaves reservation/exposure unchanged.
    pub fn offer_saved(&mut self, retained_intent_pin: Digest) -> Result<SavedOfferV1> {
        self.current()?;
        if retained_intent_pin != self.head || self.state.status != IntentStatus::MayHaveEscaped {
            return Err(Error::Unavailable("no pinned exposed payment"));
        }
        let mut bytes = Zeroizing::new([0; ENVELOPE_BYTES]);
        bytes.copy_from_slice(
            self.state
                .signed
                .as_ref()
                .ok_or(Error::Authentication)?
                .bytes(),
        );
        Ok(SavedOfferV1(bytes))
    }
    /// Cancellation is permitted only before signed bytes could be released.
    /// Failure/timeout/reorg after exposure cannot recall bytes or free inputs.
    /// # Errors
    /// Refuses exposed/missing intent or any uncertain durable transition.
    pub fn cancel_before_release(&mut self) -> Result<IntentReceipt> {
        self.current()?;
        if self.state.status != IntentStatus::Reserved {
            return Err(Error::Unavailable("cannot cancel possibly exposed payment"));
        }
        let mut state = self.state.clone();
        state.status = IntentStatus::CancelledBeforeRelease;
        self.write_state(state, false)?;
        self.receipt()
    }
    fn write_state(&mut self, state: State, initial: bool) -> Result<()> {
        self.journal.head()?;
        if !initial {
            self.current()?;
            history::transition(&self.state, &state, 2)?;
        }
        let sequence = if initial {
            0
        } else {
            self.sequence
                .checked_add(1)
                .filter(|n| *n < MAX_RECORDS)
                .ok_or(Error::Unavailable("payment journal horizon"))?
        };
        self.journal.used = inventory(&self.journal.directory)?;
        self.journal.used.reserve()?;
        capacity(
            &self.journal.directory,
            &self.journal.margin,
            self.journal.used.bytes,
            RESERVATION,
        )?;
        let nonce = entropy::<24>()?;
        let mut header = [0; RECORD_HEADER];
        // New local format fence: older snapshot-only readers must fail closed.
        header[..8].copy_from_slice(b"SNF04PH2");
        header[8..40].copy_from_slice(&domain_hash(
            "SilkNode-F04-local-wallet-store",
            &[&self.journal.header],
        ));
        header[40..48].copy_from_slice(&sequence.to_le_bytes());
        header[48..80].copy_from_slice(&self.head);
        header[80..].copy_from_slice(&nonce);
        let mut plain = encode(&state, self.journal.key)?;
        XChaCha20Poly1305::new_from_slice(self.journal.cipher_key.as_ref())
            .map_err(|_| Error::Authentication)?
            .encrypt_in_place(&XNonce::from(nonce), &header, &mut *plain)
            .map_err(|_| Error::Authentication)?;
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(&plain);
        let head = id(&bytes);
        self.journal.poisoned = true;
        publish(
            &self.journal.directory,
            &name(head),
            &bytes,
            false,
            &self.journal.faults,
        )?;
        publish(
            &self.journal.directory,
            "INTENT_HEAD",
            &head,
            !initial,
            &self.journal.faults,
        )?;
        self.journal.used = inventory(&self.journal.directory)?;
        capacity(
            &self.journal.directory,
            &self.journal.margin,
            self.journal.used.bytes,
            0,
        )?;
        self.head = head;
        self.sequence = sequence;
        if state.status == IntentStatus::MayHaveEscaped {
            for input in &state.plan.as_ref().ok_or(Error::Authentication)?.inputs {
                self.exposed.insert(input.nf, input.clone());
            }
        }
        self.state = state;
        self.journal.poisoned = false;
        Ok(())
    }
}

fn selected(
    key: &WalletKey,
    context: SpendContext,
    inputs: &[SelectedInput],
) -> Result<Vec<InputRef>> {
    check_context(context, key.domain)?;
    if !(1..=2).contains(&inputs.len()) {
        return Err(Error::Unavailable("one or two real inputs required"));
    }
    let fvk = key.key.to_diversifiable_full_viewing_key();
    let mut refs = Vec::new();
    for input in inputs {
        let position = u64::from(input.path.position());
        if position >= context.cut_leaves
            || input.note.value().inner() == 0
            || input.note.value().inner() > MAX_VALUE
            || !matches!(input.note.rseed(), Rseed::AfterZip212(_))
            || fvk
                .fvk()
                .vk
                .to_payment_address(*input.note.recipient().diversifier())
                != Some(input.note.recipient())
            || input
                .path
                .root(Node::from_cmu(&input.note.cmu()))
                .to_bytes()
                != context.cut.root
        {
            return Err(Error::Unavailable("selected note ownership/witness/value"));
        }
        refs.push(InputRef {
            position,
            cmu: input.note.cmu().to_bytes(),
            nf: input.note.nf(&fvk.fvk().vk.nk, position).0,
            value: input.note.value().inner(),
        });
    }
    if refs.len() == 2 && (refs[0].position == refs[1].position || refs[0].nf == refs[1].nf) {
        return Err(Error::Unavailable("same positioned input selected twice"));
    }
    Ok(refs)
}
fn check_context(context: SpendContext, domain: Digest) -> Result<()> {
    let j = context
        .checkpoint_index
        .checked_add(1)
        .ok_or(Error::Unavailable("checkpoint overflow"))?;
    if context.cut.domain != domain
        || context.cut.index > ((j - 1) / 128).saturating_sub(2)
        || context.cut_leaves == 0
        || context.cut_leaves > (1_u64 << 32)
    {
        return Err(Error::Unavailable("payment context/cut bounds"));
    }
    Ok(())
}
fn check_envelope(plan: &Plan, signed: &Envelope) -> Result<()> {
    if signed.domain() != plan.context.cut.domain
        || signed.cut_index() != plan.context.cut.index
        || signed.cut_id() != plan.context.cut.id
        || signed.anchor() != plan.context.cut.root
        || plan
            .inputs
            .iter()
            .any(|input| !signed.nullifiers().contains(&input.nf))
    {
        return Err(Error::Authentication);
    }
    Ok(())
}
fn context_bytes(context: SpendContext) -> [u8; 184] {
    let mut b = [0; 184];
    b[..8].copy_from_slice(&context.checkpoint_index.to_le_bytes());
    b[8..40].copy_from_slice(&context.checkpoint);
    b[40..72].copy_from_slice(&context.state);
    b[72..104].copy_from_slice(&context.prefix);
    b[104..112].copy_from_slice(&context.cut.index.to_le_bytes());
    b[112..144].copy_from_slice(&context.cut.id);
    b[144..176].copy_from_slice(&context.cut.root);
    b[176..184].copy_from_slice(&context.cut_leaves.to_le_bytes());
    b
}
fn encode(state: &State, key: &WalletKey) -> Result<Zeroizing<Vec<u8>>> {
    let mut b = Zeroizing::new(vec![0; PLAIN]);
    b[..8].copy_from_slice(b"SNF04PI1");
    b[8..40].copy_from_slice(binding(key).as_ref());
    b[40] = state.status.byte();
    if let Some(plan) = &state.plan {
        b[41] = u8::try_from(plan.inputs.len()).map_err(|_| Error::Authentication)?;
        b[48..80].copy_from_slice(&plan.id);
        b[80..264].copy_from_slice(&context_bytes(plan.context));
        for (index, input) in plan.inputs.iter().enumerate() {
            let at = 264 + 80 * index;
            b[at..at + 8].copy_from_slice(&input.position.to_le_bytes());
            b[at + 8..at + 40].copy_from_slice(&input.cmu);
            b[at + 40..at + 72].copy_from_slice(&input.nf);
            b[at + 72..at + 80].copy_from_slice(&input.value.to_le_bytes());
        }
        b[424..467].copy_from_slice(&plan.recipient.to_bytes());
        b[467..475].copy_from_slice(&plan.value.to_le_bytes());
        b[475..518].copy_from_slice(&plan.change.to_bytes());
        b[518..526].copy_from_slice(&plan.change_value.to_le_bytes());
    }
    if let Some(signed) = &state.signed {
        b[526..558].copy_from_slice(&signed.effect_id());
        b[558..590].copy_from_slice(&signed.envelope_id());
        b[590..3380].copy_from_slice(signed.bytes());
    }
    Ok(b)
}
fn decode(b: &[u8], key: &WalletKey) -> Result<State> {
    if b.len() != PLAIN
        || &b[..8] != b"SNF04PI1"
        || b[8..40] != *binding(key)
        || b[42..48] != [0; 6]
        || b[3380..].iter().any(|v| *v != 0)
    {
        return Err(Error::Authentication);
    }
    let status = match b[40] {
        0 => IntentStatus::Empty,
        1 => IntentStatus::Reserved,
        2 => IntentStatus::MayHaveEscaped,
        3 => IntentStatus::CancelledBeforeRelease,
        _ => return Err(Error::Authentication),
    };
    if status == IntentStatus::Empty {
        if b[41..].iter().any(|v| *v != 0) {
            return Err(Error::Authentication);
        }
        return Ok(State {
            status,
            plan: None,
            signed: None,
        });
    }
    let count = usize::from(b[41]);
    if !(1..=2).contains(&count) || (count == 1 && b[344..424] != [0; 80]) {
        return Err(Error::Authentication);
    }
    let context = SpendContext {
        checkpoint_index: number(b, 80),
        checkpoint: field(b, 88),
        state: field(b, 120),
        prefix: field(b, 152),
        cut: CutReference {
            domain: key.domain,
            index: number(b, 184),
            id: field(b, 192),
            root: field(b, 224),
        },
        cut_leaves: number(b, 256),
    };
    check_context(context, key.domain).map_err(|_| Error::Authentication)?;
    let mut inputs = Vec::new();
    for index in 0..count {
        let at = 264 + 80 * index;
        let input = InputRef {
            position: number(b, at),
            cmu: field(b, at + 8),
            nf: field(b, at + 40),
            value: number(b, at + 72),
        };
        if input.position >= context.cut_leaves || input.value == 0 || input.value > MAX_VALUE {
            return Err(Error::Authentication);
        }
        inputs.push(input);
    }
    if count == 2 && (inputs[0].position == inputs[1].position || inputs[0].nf == inputs[1].nf) {
        return Err(Error::Authentication);
    }
    let plan = Plan {
        id: field(b, 48),
        context,
        inputs,
        recipient: PaymentAddress::from_bytes(&field(b, 424)).ok_or(Error::Authentication)?,
        value: number(b, 467),
        change: PaymentAddress::from_bytes(&field(b, 475)).ok_or(Error::Authentication)?,
        change_value: number(b, 518),
    };
    let total = plan
        .inputs
        .iter()
        .try_fold(0_u64, |n, i| n.checked_add(i.value))
        .ok_or(Error::Authentication)?;
    let vk = key.key.to_diversifiable_full_viewing_key();
    if plan.value == 0
        || total > MAX_VALUE
        || plan
            .value
            .checked_add(plan.change_value)
            .and_then(|v| v.checked_add(1))
            != Some(total)
        || vk.fvk().vk.to_payment_address(*plan.change.diversifier()) != Some(plan.change)
    {
        return Err(Error::Authentication);
    }
    let signed = decode_signed(b, key, status, &plan)?;
    Ok(State {
        status,
        plan: Some(plan),
        signed,
    })
}
fn decode_signed(
    b: &[u8],
    key: &WalletKey,
    status: IntentStatus,
    plan: &Plan,
) -> Result<Option<Envelope>> {
    if status == IntentStatus::MayHaveEscaped {
        let signed =
            Envelope::decode(&b[590..3380], &key.domain).map_err(|_| Error::Authentication)?;
        if signed.effect_id() != field::<32>(b, 526) || signed.envelope_id() != field::<32>(b, 558)
        {
            return Err(Error::Authentication);
        }
        check_envelope(plan, &signed)?;
        Ok(Some(signed))
    } else {
        if b[526..3380].iter().any(|v| *v != 0) {
            return Err(Error::Authentication);
        }
        Ok(None)
    }
}
fn id(b: &[u8]) -> Digest {
    domain_hash("SilkNode-F04-local-intent-record", &[b])
}
fn name(id: Digest) -> String {
    format!("intent-{}", hex::encode(id))
}
fn field<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    b[at..at + N]
        .try_into()
        .expect("fixed checked intent layout")
}
fn number(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(field(b, at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FreshKey, backup, journal::Boundary};
    use sapling_crypto::{CommitmentTree, IncrementalWitness, value::NoteValue};
    use std::{fs::File, io::Write};
    const PASSWORD: &str = "PUBLIC INTENT TEST PASSWORD";
    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    // Genuine owned note/witness, but deliberately caller-asserted toy snapshot:
    // this is NOT accepted genesis, canonicality or spentness evidence.
    fn input(key: &WalletKey) -> (SpendContext, SelectedInput) {
        let note = key
            .key
            .default_address()
            .1
            .create_note(NoteValue::from_raw(10), Rseed::AfterZip212([31; 32]));
        let mut tree = CommitmentTree::empty();
        tree.append(Node::from_cmu(&note.cmu())).unwrap();
        let root = tree.root().to_bytes();
        let path = IncrementalWitness::from_tree(tree).unwrap().path().unwrap();
        (
            SpendContext {
                checkpoint_index: 0,
                checkpoint: [41; 32],
                state: [42; 32],
                prefix: [43; 32],
                cut: CutReference {
                    domain: key.domain,
                    index: 0,
                    id: [44; 32],
                    root,
                },
                cut_leaves: 1,
            },
            SelectedInput { note, path },
        )
    }
    fn three_inputs(key: &WalletKey) -> (SpendContext, Vec<SelectedInput>) {
        let mut tree = CommitmentTree::empty();
        let mut witnesses: Vec<IncrementalWitness> = Vec::new();
        let mut notes = Vec::new();
        for seed in [31, 32, 33] {
            let note = key
                .key
                .default_address()
                .1
                .create_note(NoteValue::from_raw(10), Rseed::AfterZip212([seed; 32]));
            let commitment = Node::from_cmu(&note.cmu());
            tree.append(commitment).unwrap();
            for witness in &mut witnesses {
                witness.append(commitment).unwrap();
            }
            witnesses.push(IncrementalWitness::from_tree(tree.clone()).unwrap());
            notes.push(note);
        }
        let (mut context, _) = input(key);
        context.cut.root = tree.root().to_bytes();
        context.cut_leaves = 3;
        (
            context,
            notes
                .into_iter()
                .zip(witnesses)
                .map(|(note, witness)| SelectedInput {
                    note,
                    path: witness.path().unwrap(),
                })
                .collect(),
        )
    }
    fn expose_unverified_journal_fixture(intents: &mut IntentJournal<'_, '_>) -> IntentReceipt {
        let plan = intents.state.plan.as_ref().unwrap().clone();
        let signed = unverified_framing_only(&plan);
        intents
            .write_state(
                State {
                    status: IntentStatus::MayHaveEscaped,
                    plan: Some(plan),
                    signed: Some(signed),
                },
                false,
            )
            .unwrap();
        intents.receipt().unwrap()
    }
    fn copy_input(input: &SelectedInput) -> SelectedInput {
        SelectedInput {
            note: input.note.clone(),
            path: input.path.clone(),
        }
    }
    fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
        let mut rows = std::fs::read_dir(root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.file_name().into_string().unwrap(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        rows.sort();
        rows
    }
    fn recipient(key: &WalletKey) -> String {
        silk_sapling_f04::address::encode(&key.domain, &key.key.default_address().1)
    }
    fn unverified_framing_only(plan: &Plan) -> Envelope {
        // Tests journal publication only, NEVER cryptographic acceptance. This
        // helper is absent from non-test builds and cannot call prove_reserved.
        let mut b = [0; ENVELOPE_BYTES];
        b[..8].copy_from_slice(b"SNPRV003");
        b[8] = 3;
        b[12..44].copy_from_slice(&plan.context.cut.domain);
        b[44..52].copy_from_slice(&plan.context.cut.index.to_le_bytes());
        b[52..84].copy_from_slice(&plan.context.cut.id);
        b[84] = 2;
        b[277] = 2;
        b[1790] = 1;
        b[1798..1830].copy_from_slice(&plan.context.cut.root);
        b[117..149].copy_from_slice(&plan.inputs[0].nf);
        let mut other = plan.inputs[0].nf;
        other[0] ^= 1;
        b[213..245].copy_from_slice(&other);
        Envelope::decode(&b, &plan.context.cut.domain).unwrap()
    }
    #[test]
    fn reservation_cancel_continuity_and_strict_input_binding() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let mut key = FreshKey::generate().unwrap().bind([61; 32]);
        let (context, selected) = input(&key);
        let recipient = recipient(&key);
        let (mut journal, first) =
            Journal::create_with_intents(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let address_first = journal.head().unwrap();
        let mut intents = journal.intents(first).unwrap();
        let before = snapshot(&path);
        let mut wrong = context;
        wrong.cut.domain = [62; 32];
        assert!(
            intents
                .reserve(wrong, &[copy_input(&selected)], &recipient, 4)
                .is_err()
        );
        wrong = context;
        wrong.cut.index = 1;
        assert!(
            intents
                .reserve(wrong, &[copy_input(&selected)], &recipient, 4)
                .is_err()
        );
        assert!(
            intents
                .reserve(
                    context,
                    &[copy_input(&selected), copy_input(&selected)],
                    &recipient,
                    4
                )
                .is_err()
        );
        assert!(
            intents
                .reserve(
                    context,
                    &[copy_input(&selected)],
                    &recipient.to_uppercase(),
                    4
                )
                .is_err()
        );
        assert!(
            intents
                .reserve(context, &[copy_input(&selected)], &recipient, 10)
                .is_err()
        );
        assert_eq!(snapshot(&path), before);
        let reserved = intents
            .reserve(context, &[copy_input(&selected)], &recipient, 4)
            .unwrap();
        assert_eq!(reserved.status, IntentStatus::Reserved);
        assert_ne!(reserved.address_head, address_first);
        assert_ne!(reserved.intent_head, first);
        assert!(
            intents
                .release_saved_envelope(reserved.intent_head)
                .is_err()
        );
        assert!(
            intents
                .reserve(context, &[copy_input(&selected)], &recipient, 4)
                .is_err()
        );
        let change = intents.state.plan.as_ref().unwrap().change;
        let cancelled = intents.cancel_before_release().unwrap();
        assert_eq!(cancelled.status, IntentStatus::CancelledBeforeRelease);
        assert!(
            intents
                .release_saved_envelope(cancelled.intent_head)
                .is_err()
        );
        let second = intents
            .reserve(context, &[selected], &recipient, 4)
            .unwrap();
        assert_ne!(intents.state.plan.as_ref().unwrap().change, change);
        drop(intents);
        drop(journal);
        let mut journal =
            Journal::open(&path, dir.path(), &key, PASSWORD, second.address_head).unwrap();
        assert!(journal.intents(first).is_err());
        drop(journal);
        let mut journal =
            Journal::open(&path, dir.path(), &key, PASSWORD, second.address_head).unwrap();
        let intents = journal.intents(second.intent_head).unwrap();
        assert_eq!(intents.receipt().unwrap().status, IntentStatus::Reserved);
        assert_eq!(intents.state.plan.as_ref().unwrap().inputs.len(), 1);
    }
    #[test]
    fn missing_payment_state_is_not_empty_and_horizon_leaves_resolution_room() {
        let dir = private_dir();
        let mut key = FreshKey::generate().unwrap().bind([63; 32]);
        let path = dir.path().join("address-only");
        let mut address_only = Journal::create(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let before = snapshot(&path);
        assert!(address_only.intents([0; 32]).is_err());
        assert_eq!(snapshot(&path), before);
        let mut fresh = FreshKey::generate().unwrap().bind([64; 32]);
        let (context, selected) = input(&fresh);
        let recipient = recipient(&fresh);
        let path = dir.path().join("with-intents");
        let (mut journal, pin) =
            Journal::create_with_intents(&path, dir.path(), &mut fresh, PASSWORD).unwrap();
        let mut intents = journal.intents(pin).unwrap();
        let before = snapshot(&path);
        let cursor = intents.journal.next;
        // Arithmetic boundary fixture, not an actual65534-transition execution.
        intents.sequence = MAX_RECORDS - 2;
        assert!(
            intents
                .reserve(context, &[copy_input(&selected)], &recipient, 4)
                .is_err()
        );
        assert_eq!(snapshot(&path), before);
        assert_eq!(intents.journal.next, cursor);
        intents.sequence = MAX_RECORDS - 3;
        intents
            .reserve(context, &[selected], &recipient, 4)
            .unwrap();
        intents.cancel_before_release().unwrap();
        assert_eq!(intents.sequence, MAX_RECORDS - 1);
    }
    #[test]
    fn exposure_publication_faults_withhold_output_and_preserve_old_pins_only() {
        for is_head in [false, true] {
            for boundary in [
                Boundary::Created,
                Boundary::Written,
                Boundary::Synced,
                Boundary::Renamed,
                Boundary::Durable,
            ] {
                let dir = private_dir();
                let path = dir.path().join("wallet");
                let mut key = FreshKey::generate().unwrap().bind([65; 32]);
                let (context, selected) = input(&key);
                let recipient = recipient(&key);
                let (mut journal, pin) =
                    Journal::create_with_intents(&path, dir.path(), &mut key, PASSWORD).unwrap();
                let mut intents = journal.intents(pin).unwrap();
                let prior = intents
                    .reserve(context, &[selected], &recipient, 4)
                    .unwrap();
                let plan = intents.state.plan.as_ref().unwrap().clone();
                let fake = unverified_framing_only(&plan);
                let before = inventory(&intents.journal.directory).unwrap().bytes;
                intents.journal.faults.at = Some((is_head, boundary));
                assert!(
                    intents
                        .write_state(
                            State {
                                status: IntentStatus::MayHaveEscaped,
                                plan: Some(plan),
                                signed: Some(fake)
                            },
                            false
                        )
                        .is_err()
                );
                assert!(intents.release_saved_envelope(prior.intent_head).is_err());
                assert!(intents.receipt().is_err());
                assert!(inventory(&intents.journal.directory).unwrap().bytes > before);
                let now = read(&intents.journal.directory, "INTENT_HEAD", 32).unwrap();
                drop(intents);
                drop(journal);
                let mut journal =
                    Journal::open(&path, dir.path(), &key, PASSWORD, prior.address_head).unwrap();
                let opened = journal.intents(prior.intent_head);
                if now == prior.intent_head {
                    assert_eq!(
                        opened.unwrap().receipt().unwrap().status,
                        IntentStatus::Reserved
                    );
                } else {
                    assert!(opened.is_err());
                    assert!(is_head && matches!(boundary, Boundary::Renamed | Boundary::Durable));
                }
            }
        }
    }
    #[test]
    fn saved_offer_is_exact_pin_gated_and_consumption_never_unreserves() {
        let dir = private_dir();
        let mut key = FreshKey::generate().unwrap().bind([66; 32]);
        let (context, selected) = input(&key);
        let recipient = recipient(&key);
        let (mut journal, pin) = Journal::create_with_intents(
            &dir.path().join("wallet"),
            dir.path(),
            &mut key,
            PASSWORD,
        )
        .unwrap();
        let mut intents = journal.intents(pin).unwrap();
        assert!(intents.offer_saved(pin).is_err());
        let reserved = intents
            .reserve(context, &[copy_input(&selected)], &recipient, 4)
            .unwrap();
        assert!(intents.offer_saved(reserved.intent_head).is_err());
        // Framing-only journal fixture: no proof-generation or acceptance claim.
        let receipt = expose_unverified_journal_fixture(&mut intents);
        let expected = *intents.state.signed.as_ref().unwrap().bytes();
        assert!(intents.offer_saved(reserved.intent_head).is_err());
        let bytes = intents
            .offer_saved(receipt.intent_head)
            .unwrap()
            .into_bytes();
        assert_eq!(*bytes, expected);
        drop(bytes);
        assert_eq!(
            intents.receipt().unwrap().status,
            IntentStatus::MayHaveEscaped
        );
        assert!(intents.cancel_before_release().is_err());
        assert!(
            intents
                .reserve(context, &[selected], &recipient, 4)
                .is_err()
        );
    }

    #[test]
    fn authenticated_exposure_reopens_exactly_but_cannot_cancel_or_reset() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let mut key = FreshKey::generate().unwrap().bind([66; 32]);
        let backup = backup::seal(&key, PASSWORD).unwrap();
        let (context, selected) = input(&key);
        let recipient = recipient(&key);
        let (mut journal, pin) =
            Journal::create_with_intents(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let mut intents = journal.intents(pin).unwrap();
        let prior = intents
            .reserve(context, &[copy_input(&selected)], &recipient, 4)
            .unwrap();
        let plan = intents.state.plan.as_ref().unwrap().clone();
        let fake = unverified_framing_only(&plan);
        let expected = *fake.bytes();
        let exposed = State {
            status: IntentStatus::MayHaveEscaped,
            plan: Some(plan),
            signed: Some(fake),
        };
        let mut encoded = encode(&exposed, intents.journal.key).unwrap();
        assert_eq!(
            encode(
                &decode(&encoded, intents.journal.key).unwrap(),
                intents.journal.key
            )
            .unwrap()
            .as_slice(),
            encoded.as_slice()
        );
        for at in [42, 344, 526, 558, 3380, 4095] {
            encoded[at] ^= 1;
            assert!(decode(&encoded, intents.journal.key).is_err());
            encoded[at] ^= 1;
        }
        intents.write_state(exposed, false).unwrap();
        let receipt = intents.receipt().unwrap();
        assert!(intents.release_saved_envelope(prior.intent_head).is_err());
        assert_eq!(
            intents.release_saved_envelope(receipt.intent_head).unwrap(),
            expected
        );
        assert!(intents.cancel_before_release().is_err());
        assert!(
            intents
                .reserve(context, &[selected], &recipient, 4)
                .is_err()
        );
        drop(intents);
        drop(journal);
        let mut restored = backup::open(&backup, key.domain(), PASSWORD).unwrap();
        assert!(
            Journal::create_with_intents(
                &dir.path().join("reset"),
                dir.path(),
                &mut restored,
                PASSWORD
            )
            .is_err()
        );
        let mut journal =
            Journal::open(&path, dir.path(), &restored, PASSWORD, receipt.address_head).unwrap();
        let mut intents = journal.intents(receipt.intent_head).unwrap();
        assert_eq!(
            intents.release_saved_envelope(receipt.intent_head).unwrap(),
            expected
        );
        assert!(intents.cancel_before_release().is_err());
    }

    #[test]
    fn sequential_history_keeps_old_exposures_after_new_cancellation_and_reopen() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let mut key = FreshKey::generate().unwrap().bind([68; 32]);
        let (context, inputs) = three_inputs(&key);
        let recipient = recipient(&key);
        let (mut journal, first) =
            Journal::create_with_intents(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let mut intents = journal.intents(first).unwrap();
        assert!(
            intents
                .reserve_distinct(context, &[copy_input(&inputs[0])], &recipient, 4)
                .is_err()
        );
        intents
            .reserve(context, &[copy_input(&inputs[0])], &recipient, 4)
            .unwrap();
        expose_unverified_journal_fixture(&mut intents);
        let before = snapshot(&path);
        assert!(
            intents
                .reserve_distinct(context, &[copy_input(&inputs[0])], &recipient, 4)
                .is_err()
        );
        assert_eq!(snapshot(&path), before);
        intents
            .reserve_distinct(context, &[copy_input(&inputs[1])], &recipient, 4)
            .unwrap();
        let second = expose_unverified_journal_fixture(&mut intents);
        intents
            .reserve_distinct(context, &[copy_input(&inputs[2])], &recipient, 4)
            .unwrap();
        let cancelled = intents.cancel_before_release().unwrap();
        assert_eq!(intents.exposed.len(), 2);
        drop(intents);
        drop(journal);
        let mut journal =
            Journal::open(&path, dir.path(), &key, PASSWORD, cancelled.address_head).unwrap();
        let mut intents = journal.intents(cancelled.intent_head).unwrap();
        assert_eq!(intents.exposed.len(), 2);
        let before = snapshot(&path);
        for selected in &inputs[..2] {
            assert!(
                intents
                    .reserve(context, &[copy_input(selected)], &recipient, 4)
                    .is_err()
            );
        }
        assert!(intents.release_saved_envelope(second.intent_head).is_err());
        assert_eq!(snapshot(&path), before);
        // The latest cancellation cannot hide a missing oldest exposure ancestor.
        drop(intents);
        let oldest = path.join(name(first));
        let retained = path.join("retained-oldest-for-test");
        std::fs::rename(&oldest, &retained).unwrap();
        assert!(journal.intents(cancelled.intent_head).is_err());
        std::fs::rename(&retained, &oldest).unwrap();
        let mut intents = journal.intents(cancelled.intent_head).unwrap();
        intents
            .reserve(context, &[copy_input(&inputs[2])], &recipient, 4)
            .unwrap();
        let current = read(&intents.journal.directory, &name(intents.head), SEALED).unwrap();
        assert_eq!(&current[..8], b"SNF04PH2");
        assert_ne!(&current[..8], b"SNF04PH1"); // Original reader's explicit refusal.
    }

    #[test]
    fn authenticated_history_transition_checks_are_strict() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let mut key = FreshKey::generate().unwrap().bind([69; 32]);
        let (context, inputs) = three_inputs(&key);
        let recipient = recipient(&key);
        let (mut journal, first) =
            Journal::create_with_intents(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let mut intents = journal.intents(first).unwrap();
        let empty = intents.state.clone();
        intents
            .reserve(context, &[copy_input(&inputs[0])], &recipient, 4)
            .unwrap();
        let reserved = intents.state.clone();
        expose_unverified_journal_fixture(&mut intents);
        let exposed = intents.state.clone();
        intents
            .reserve_distinct(context, &[copy_input(&inputs[1])], &recipient, 4)
            .unwrap();
        let successor = intents.state.clone();
        assert!(history::transition(&exposed, &successor, 2).is_ok());
        assert!(history::transition(&exposed, &successor, 1).is_err());
        assert!(history::transition(&exposed, &empty, 2).is_err());
        assert!(history::transition(&reserved, &successor, 2).is_err());
        let mut changed = exposed;
        changed.plan.as_mut().unwrap().context.prefix[0] ^= 1;
        assert!(history::transition(&reserved, &changed, 2).is_err());
        let receipt = intents.receipt().unwrap();
        let bytes = read(&intents.journal.directory, &name(first), SEALED).unwrap();
        drop(intents);
        // A valid latest snapshot cannot bypass an altered ancestor's digest/tag.
        let mut changed = bytes.clone();
        changed[RECORD_HEADER] ^= 1;
        std::fs::write(path.join(name(first)), changed).unwrap();
        assert!(journal.intents(receipt.intent_head).is_err());
        std::fs::write(path.join(name(first)), bytes).unwrap();
        assert!(journal.intents(receipt.intent_head).is_ok());
    }

    #[test]
    fn audit_allows_unexposed_reuse_but_refuses_exposed_reuse_hidden_by_cancellation() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let mut key = FreshKey::generate().unwrap().bind([70; 32]);
        let (context, selected) = input(&key);
        let recipient = recipient(&key);
        let (mut journal, first) =
            Journal::create_with_intents(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let mut intents = journal.intents(first).unwrap();
        intents
            .reserve(context, &[copy_input(&selected)], &recipient, 4)
            .unwrap();
        intents.cancel_before_release().unwrap();
        intents
            .reserve(context, &[selected], &recipient, 4)
            .unwrap();
        let exposed = expose_unverified_journal_fixture(&mut intents);
        drop(intents);
        let mut intents = journal.intents(exposed.intent_head).unwrap();
        assert_eq!(intents.exposed.len(), 1);
        // Test-only authenticated bad-history construction, bypassing BOTH public
        // reservation entry points. A latest-snapshot-only reader would miss it.
        let mut plan = intents.state.plan.as_ref().unwrap().clone();
        plan.id[0] ^= 1;
        intents
            .write_state(
                State {
                    status: IntentStatus::Reserved,
                    plan: Some(plan),
                    signed: None,
                },
                false,
            )
            .unwrap();
        let cancelled = intents.cancel_before_release().unwrap();
        drop(intents);
        assert!(matches!(
            journal.intents(cancelled.intent_head),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn legacy_initial_ancestry_is_authenticated_but_new_heads_fence_old_readers() {
        let dir = private_dir();
        let path = dir.path().join("wallet");
        let mut key = FreshKey::generate().unwrap().bind([71; 32]);
        let (context, selected) = input(&key);
        let recipient = recipient(&key);
        let (mut journal, first) =
            Journal::create_with_intents(&path, dir.path(), &mut key, PASSWORD).unwrap();
        let mut bytes = read(&journal.directory, &name(first), SEALED).unwrap();
        bytes.truncate(RECORD_HEADER);
        bytes[..8].copy_from_slice(b"SNF04PH1");
        let nonce = entropy::<24>().unwrap();
        bytes[80..].copy_from_slice(&nonce);
        let mut payload = encode(
            &State {
                status: IntentStatus::Empty,
                plan: None,
                signed: None,
            },
            journal.key,
        )
        .unwrap();
        XChaCha20Poly1305::new_from_slice(journal.cipher_key.as_ref())
            .unwrap()
            .encrypt_in_place(&XNonce::from(nonce), &bytes, &mut *payload)
            .unwrap();
        bytes.extend_from_slice(&payload);
        let legacy = id(&bytes);
        publish(
            &journal.directory,
            &name(legacy),
            &bytes,
            false,
            &journal.faults,
        )
        .unwrap();
        publish(
            &journal.directory,
            "INTENT_HEAD",
            &legacy,
            true,
            &journal.faults,
        )
        .unwrap();
        let mut intents = journal.intents(legacy).unwrap();
        let reserved = intents
            .reserve(context, &[selected], &recipient, 4)
            .unwrap();
        let header = read(
            &intents.journal.directory,
            &name(reserved.intent_head),
            SEALED,
        )
        .unwrap();
        assert_eq!(&header[..8], b"SNF04PH2");
        drop(intents);
        assert!(journal.intents(reserved.intent_head).is_ok());
    }

    pub(super) fn qualified_paths() -> (std::path::PathBuf, std::path::PathBuf, SaplingParameters) {
        assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
        let store = std::path::PathBuf::from(std::env::var_os("SILK_F04_LAB_STORE").unwrap());
        let margin = std::path::PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
        let parameters =
            std::path::PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
        let parameters = SaplingParameters::load(
            &parameters.join("sapling-spend.params"),
            &parameters.join("sapling-output.params"),
        )
        .unwrap();
        (store, margin, parameters)
    }
    pub(super) fn save_public_fixture(lab: &Path, name: &str, bytes: &[u8]) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(lab.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        File::open(lab).unwrap().sync_all().unwrap();
    }

    #[test]
    #[ignore = "requires canonical parameters and the isolated 1GiB/two-task wallet runtime"]
    fn genuine_private_proof_durable_exposure() {
        use std::os::unix::fs::PermissionsExt;
        let started = std::time::Instant::now();
        let (store, margin, parameters) = qualified_paths();
        let lab = tempfile::Builder::new()
            .prefix("f04-wallet-intent-")
            .tempdir_in(store)
            .unwrap()
            .keep();
        std::fs::set_permissions(&lab, std::fs::Permissions::from_mode(0o700)).unwrap();
        println!(
            "retained_lab={}; caller_context=toy-not-canonical; fixture_only=true",
            lab.display()
        );
        let mut key = FreshKey::generate().unwrap().bind([67; 32]);
        // Public fixture password, fresh valueless key. No production seed input.
        backup::save_new(&lab.join("encrypted-key"), &key, PASSWORD).unwrap();
        let (context, selected) = input(&key);
        let recipient = recipient(&key);
        let (mut journal, pin) =
            Journal::create_with_intents(&lab.join("wallet"), &margin, &mut key, PASSWORD).unwrap();
        let mut intents = journal.intents(pin).unwrap();
        let reserved = intents
            .reserve(context, &[copy_input(&selected)], &recipient, 4)
            .unwrap();
        assert!(
            intents
                .release_saved_envelope(reserved.intent_head)
                .is_err()
        );
        let before = snapshot(&lab.join("wallet"));
        let mut changed = context;
        changed.state[0] ^= 1;
        assert!(
            intents
                .prove_reserved(changed, vec![copy_input(&selected)], &parameters)
                .is_err()
        );
        assert_eq!(snapshot(&lab.join("wallet")), before);
        let proving = std::time::Instant::now();
        let exposed = intents
            .prove_reserved(context, vec![selected], &parameters)
            .unwrap();
        let proving_ms = proving.elapsed().as_millis();
        assert_eq!(exposed.status, IntentStatus::MayHaveEscaped);
        assert_ne!(exposed.intent_head, reserved.intent_head);
        assert!(
            intents
                .release_saved_envelope(reserved.intent_head)
                .is_err()
        );
        // Independently retain both public pins BEFORE requesting any signed bytes.
        // This fixture file is outside the journal but not independent custody.
        let mut receipt = Vec::from(intents.journal.key.domain());
        receipt.extend_from_slice(&exposed.address_head);
        receipt.extend_from_slice(&exposed.intent_head);
        save_public_fixture(&lab, "public-pins", &receipt);
        let bytes = intents.release_saved_envelope(exposed.intent_head).unwrap();
        let envelope = Envelope::decode(&bytes, &intents.journal.key.domain()).unwrap();
        silk_sapling_f04::crypto::verify(envelope.clone(), &parameters).unwrap();
        let mut outputs = envelope
            .recovery()
            .into_iter()
            .map(|bytes| {
                silk_sapling_f04::wallet::RecoveryOutput::decode(bytes)
                    .unwrap()
                    .decrypt(
                        intents
                            .journal
                            .key
                            .key
                            .to_diversifiable_full_viewing_key()
                            .fvk(),
                    )
                    .unwrap()
                    .0
                    .value()
                    .inner()
            })
            .collect::<Vec<_>>();
        outputs.sort_unstable();
        assert_eq!(outputs, [4, 5]);
        save_public_fixture(&lab, "public-envelope-id", &envelope.envelope_id());
        assert!(intents.cancel_before_release().is_err());
        assert!(
            intents
                .prove_reserved(context, vec![], &parameters)
                .is_err()
        );
        println!(
            "genuine_exposure_ms={};proof_ms={proving_ms};signed_bytes={};durable_before_export=true;canonical_wallet_recovery=false",
            started.elapsed().as_millis(),
            bytes.len()
        );
    }

    #[test]
    #[ignore = "separate cold process after genuine_private_proof_durable_exposure"]
    fn cold_restore_genuine_saved_exposure() {
        let (_store, margin, parameters) = qualified_paths();
        let lab = std::path::PathBuf::from(std::env::var_os("SILK_F04_WALLET_FIXTURE").unwrap());
        let pins = std::fs::read(lab.join("public-pins")).unwrap();
        assert_eq!(pins.len(), 96);
        let domain = field(&pins, 0);
        let key = backup::load(&lab.join("encrypted-key"), domain, PASSWORD).unwrap();
        let before = snapshot(&lab.join("wallet"));
        let mut journal = Journal::open(
            &lab.join("wallet"),
            &margin,
            &key,
            PASSWORD,
            field(&pins, 32),
        )
        .unwrap();
        let mut intents = journal.intents(field(&pins, 64)).unwrap();
        assert_eq!(
            intents.receipt().unwrap().status,
            IntentStatus::MayHaveEscaped
        );
        let bytes = intents.release_saved_envelope(field(&pins, 64)).unwrap();
        let envelope = Envelope::decode(&bytes, &domain).unwrap();
        assert_eq!(
            envelope.envelope_id().as_slice(),
            std::fs::read(lab.join("public-envelope-id")).unwrap()
        );
        silk_sapling_f04::crypto::verify(envelope, &parameters).unwrap();
        assert!(intents.cancel_before_release().is_err());
        let (context, selected) = input(&key);
        assert!(
            intents
                .reserve(context, &[selected], &recipient(&key), 4)
                .is_err()
        );
        assert_eq!(snapshot(&lab.join("wallet")), before);
        println!(
            "cold_pid={};exact_saved_envelope=true;no_reproof_or_reset=true;canonical_wallet_recovery=false",
            std::process::id()
        );
    }
}
