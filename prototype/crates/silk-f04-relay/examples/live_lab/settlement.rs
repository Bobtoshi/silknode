//! Explicit same-operator, valueless vertical fixture. No public/default endpoint.
//! The controller must contain each process and retain owner/job pins separately.
use super::{Result, files};
use silk_f04_node::{
    Digest,
    carriage::{Body, MiningTemplate, WorkEngine},
    genesis::Genesis,
    node::{Ingress, Node, NodeStatus},
    offer::v1::{LocalOfferV1, PreparedV1},
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::{path::Path, sync::Arc};

fn digest(value: &str) -> Result<Digest> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected canonical32-byte lowercase pin/domain".into());
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)?;
    }
    Ok(bytes)
}
fn hex(value: Digest) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(64);
    for byte in value {
        write!(result, "{byte:02x}").expect("String formatting");
    }
    result
}
fn genesis(root: &Path, domain: Digest) -> Result<Genesis> {
    Ok(Genesis::admit_local_bundle(
        &files::read(&root.join("public-genesis"), 8 * 1024 * 1024)?,
        &domain,
        true,
    )?)
}
fn parameters() -> Result<SaplingParameters> {
    Ok(SaplingParameters::load(
        Path::new("/work/parameters/sapling-spend.params"),
        Path::new("/work/parameters/sapling-output.params"),
    )?)
}
fn owner(root: &Path, domain: Digest, pin: Digest, slot: u32) -> Result<Node> {
    if slot >= 8 {
        return Err("at most8 work records; no automatic retry".into());
    }
    let node = Node::open_retained_pinned(
        &root.join("node"),
        Path::new("/work/margin"),
        genesis(root, domain)?,
        &parameters()?,
        pin,
    )?;
    if node.status()? != NodeStatus::Ready || node.vertex_count() != slot as usize {
        return Err("owner is not at the independently selected ready prefix".into());
    }
    Ok(node)
}

pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(String::as_str) {
        // im3-replay-delivered NEW_ROOT DOMAIN. Explicit functional lab only.
        // The controller supplies the actual IM3 producer offers and immutable
        // historical candidates. No mining, proof generation or settled-state
        // copy substitutes for fresh ordinary receiver admission here.
        Some("im3-replay-delivered") if args.len() == 3 => {
            use silk_f04_node::carriage::Candidate;
            let root = Path::new(&args[1]);
            let domain = digest(&args[2])?;
            let delivered = files::read(
                Path::new("/work/delivery/producer-0-local-offer.bin"),
                89_300,
            )?;
            let body = Body::decode(&delivered, &domain)?;
            let [payment] = body.representations() else {
                return Err("exactly one actual producer payment required".into());
            };
            if payment.as_slice() != files::read(&root.join("payment-2790"), 2790)?.as_slice() {
                return Err("IM3 delivery changed original wallet payment".into());
            }
            for i in 1..3 {
                if files::read(
                    &Path::new("/work/delivery").join(format!("producer-{i}-local-offer.bin")),
                    89_300,
                )?
                .as_slice()
                    != delivered.as_slice()
                {
                    return Err("IM3 producer offers differ".into());
                }
            }
            // Ordinary adapter framing is checked without manufacturing relay
            // authority: custody is the actual prior original-stream receipt.
            if LocalOfferV1::decode_local(&delivered, domain)?.encode_local()?
                != delivered.as_slice()
            {
                return Err("ordinary IM3 offer bytes changed".into());
            }
            let genesis = genesis(root, domain)?;
            let parameters = parameters()?;
            let mut node = Node::create(&root.join("node"), Path::new("/work/margin"), genesis)?;
            if node.vertex_count() != 0 || node.state()?.checkpoint_index() != 0 {
                return Err("IM3 replay node not genuinely fresh".into());
            }
            for slot in 0..8 {
                let bytes = files::read(
                    &Path::new("/work/candidates").join(format!("candidate-{slot}")),
                    90_000,
                )?;
                let candidate = Candidate::decode(&bytes, node.genesis())?;
                if slot == 0 {
                    if candidate.body.bytes() != delivered.as_slice() {
                        return Err(
                            "retained work public body differs from actual IM3 delivery".into()
                        );
                    }
                } else if !candidate.body.representations().is_empty() {
                    return Err("unexpected second payment in retained work".into());
                }
                let mut ingress = node.ingest(&bytes, &parameters)?;
                for _ in 0..512 {
                    if ingress != Ingress::Pending {
                        break;
                    }
                    ingress = node.resume_ingest(&parameters)?;
                }
                if ingress != Ingress::Admitted || node.vertex_count() != slot + 1 {
                    return Err("ordinary retained work admission incomplete".into());
                }
                for _ in 0..512 {
                    if node.status()? == NodeStatus::Ready {
                        break;
                    }
                    node.advance()?;
                }
                if node.status()? != NodeStatus::Ready
                    || node.ingest(&bytes, &parameters)? != Ingress::AlreadyKnown
                {
                    return Err("IM3 replay reconciliation/duplicate refusal".into());
                }
            }
            if node.state()?.checkpoint_index() != 1 {
                return Err("IM3 delivery did not reach first seal".into());
            }
            files::write_new(&root.join("im3-node-head"), &node.local_head()?)?;
            println!(
                "im3_actual_three_producer_offer_admitted=true;fresh_node=true;vertices=8;checkpoint=1;retained_exact_work=8;new_work=0;new_payment_proofs=0;node_head={}",
                hex(node.local_head()?)
            );
            Ok(())
        }
        Some("journal-cap-check") if args.len() == 2 => {
            use silk_f04_relay::{control::Role, journal::Journal};
            let root = Path::new(&args[1]);
            let legacy = root.join("legacy-refusal");
            files::directory(&legacy)?;
            if !matches!(
                Journal::create(&legacy, [1; 32], 0, Role::A, 100),
                Err(silk_f04_relay::Error::Unavailable("journal host margin"))
            ) {
                return Err("legacy4GiB guard must still refuse the1GiB store".into());
            }
            let same = root.join("same-filesystem-refusal");
            files::directory(&same)?;
            if !matches!(
                Journal::create_with_host_margin(&same, root, [1; 32], 0, Role::A, 100),
                Err(silk_f04_relay::Error::Unavailable(
                    "journal margin must be a separate filesystem"
                ))
            ) || same.join("LOCK").exists()
            {
                return Err("same-filesystem margin must refuse before mutation".into());
            }
            let symlink = root.join("symlink-margin");
            std::os::unix::fs::symlink("/work/margin", &symlink)?;
            if Journal::create_with_host_margin(&same, &symlink, [1; 32], 0, Role::A, 100).is_ok() {
                return Err("symlink margin must refuse".into());
            }
            let correct = root.join("capped");
            files::directory(&correct)?;
            let journal = Journal::create_with_host_margin(
                &correct,
                Path::new("/work/margin"),
                [1; 32],
                0,
                Role::A,
                100,
            )?;
            let pin = journal.pin();
            drop(journal);
            let bytes = files::read(&correct.join("CURRENT"), 4096)?;
            if bytes.len() != 4096 || &bytes[..8] != b"SNJRLF04" {
                return Err("journal bytes changed".into());
            }
            if Journal::open_with_host_margin(
                &correct,
                Path::new("/work/margin"),
                [1; 32],
                0,
                Role::A,
                [0; 32],
                100,
            )
            .is_ok()
            {
                return Err("wrong continuity pin must refuse".into());
            }
            if files::read(&correct.join("CURRENT"), 4096)? != bytes {
                return Err("wrong-pin refusal must not mutate retained bytes".into());
            }
            let journal = Journal::open_with_host_margin(
                &correct,
                Path::new("/work/margin"),
                [1; 32],
                0,
                Role::A,
                pin,
                100,
            )?;
            if journal.earliest_round() != 103 {
                return Err("cold high-water floor changed".into());
            }
            println!(
                "capped_journal_create_and_pinned_reopen=true;legacy4GiB_guard_retained=true;same_filesystem_and_symlink_refused=true;new_work=0;new_payment_proofs=0"
            );
            Ok(())
        }
        // prepare ROOT NEW_JOB SLOT OWNER_PIN DOMAIN
        Some("prepare") if args.len() == 6 => {
            let root = Path::new(&args[1]);
            let slot: u32 = args[3].parse()?;
            let pin = digest(&args[4])?;
            let domain = digest(&args[5])?;
            let mut node = owner(root, domain, pin, slot)?;
            let template = if slot == 0 {
                let bytes = files::read(Path::new("/work/delivery/p0-offer.local"), 89_300)?;
                for name in ["p1-offer.local", "p2-offer.local"] {
                    if files::read(&Path::new("/work/delivery").join(name), 89_300)? != bytes {
                        return Err("three producers did not deliver the same exact body".into());
                    }
                }
                let body = Body::decode(&bytes, &domain)?;
                let [payment] = body.representations() else {
                    return Err("expected one payment bundle, not another proof".into());
                };
                if payment.as_slice() != files::read(&root.join("payment-2790"), 2790)?.as_slice() {
                    return Err(
                        "delivered payment differs from durably exposed wallet payment".into(),
                    );
                }
                let PreparedV1::Template(template) = LocalOfferV1::decode_local(&bytes, domain)?
                    .prepare_current(&mut node, [7; 32], [8; 32])?
                else {
                    return Err("actual payment must prepare one job".into());
                };
                template
            } else {
                node.prepare_mining_current(Body::new(&domain, &[])?, [7; 32], [8; 32], None)?
            };
            if root.join("node/ACTIVE_JOB").exists()
                || node.local_head()? != pin
                || node.vertex_count() != slot as usize
            {
                return Err("preparation changed the ledger or left a durable job".into());
            }
            let (bytes, job_pin) = template.encode_local();
            files::write_new(Path::new(&args[2]), &bytes)?;
            println!(
                "prepared_slot={slot};job_pin={};node_head={};new_work=0;ordinary_current_time=true",
                hex(job_pin),
                hex(pin)
            );
            Ok(())
        }
        // mine PUBLIC_ROOT JOB JOB_PIN DOMAIN NEW_CANDIDATE
        Some("mine") if args.len() == 6 => {
            if Path::new("/work/wallet").exists()
                || Path::new("/work/parameters").exists()
                || Path::new("/home/silknode").exists()
            {
                return Err("miner must have no wallet/node store/proving parameter access".into());
            }
            let genesis = Arc::new(genesis(Path::new(&args[1]), digest(&args[4])?)?);
            let bytes = files::read(Path::new(&args[2]), 89_912)?;
            let template = MiningTemplate::decode_local(&bytes, genesis, digest(&args[3])?)?;
            let mut work = WorkEngine::default();
            for nonce in 0..64 {
                if let Some(candidate) = work.evaluate_nonce(&template, nonce)? {
                    files::write_new(Path::new(&args[5]), &candidate.encode())?;
                    println!(
                        "mined_nonce={nonce};new_work=1;node_store_access=false;new_payment_proofs=0;unadmitted=true"
                    );
                    return Ok(());
                }
            }
            Err("bounded64 nonce attempts exhausted; no retry".into())
        }
        // admit ROOT CANDIDATE SLOT OWNER_PIN DOMAIN
        Some("admit") if args.len() == 6 => {
            let root = Path::new(&args[1]);
            let slot: u32 = args[3].parse()?;
            let mut node = owner(root, digest(&args[5])?, digest(&args[4])?, slot)?;
            let candidate = files::read(Path::new(&args[2]), 90_000)?;
            let parameters = parameters()?;
            let mut ingress = node.ingest(&candidate, &parameters)?;
            for _ in 0..512 {
                if ingress != Ingress::Pending {
                    break;
                }
                ingress = node.resume_ingest(&parameters)?;
            }
            if ingress != Ingress::Admitted || node.vertex_count() != slot as usize + 1 {
                return Err("ordinary admission did not complete; no retry".into());
            }
            for _ in 0..512 {
                if node.status()? == NodeStatus::Ready {
                    break;
                }
                node.advance()?;
            }
            if node.status()? != NodeStatus::Ready
                || node.ingest(&candidate, &parameters)? != Ingress::AlreadyKnown
            {
                return Err("reconciliation or duplicate refusal did not complete".into());
            }
            if slot == 7 && node.state()?.checkpoint_index() != 1 {
                return Err("eight vertices did not produce the first checkpoint".into());
            }
            println!(
                "admitted_slot={slot};node_head={};vertices={};checkpoint={};duplicate_no_new_credit=true",
                hex(node.local_head()?),
                node.vertex_count(),
                node.state()?.checkpoint_index()
            );
            Ok(())
        }
        _ => Err("expected explicit settlement prepare/mine/admit arguments".into()),
    }
}
