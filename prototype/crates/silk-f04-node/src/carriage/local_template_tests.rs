//! Two native phases: node reopen verifies existing work; importer allocates no VM.
use super::*;
use crate::{
    node::{Node, NodeStatus},
    offer::v1::{LocalOfferV1, PreparedV1},
    wire::raw_hash,
};
use std::{fs, path::PathBuf};

fn fixture() -> (PathBuf, Arc<Genesis>) {
    assert_eq!(
        std::env::var("SILK_F04_LOCAL_TEMPLATE_GATE").as_deref(),
        Ok("1")
    );
    let root = PathBuf::from(std::env::var_os("SILK_F04_TEMPLATE_WORK").unwrap());
    let domain: Digest = hex::decode(std::env::var("SILK_F04_NONEMPTY_DOMAIN").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let source: Digest = hex::decode(std::env::var("SILK_F04_NONEMPTY_GENESIS_HASH").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let bytes = fs::read(root.join("genesis.public")).unwrap();
    assert_eq!(raw_hash(&bytes), source);
    (
        root,
        Arc::new(Genesis::admit_local_bundle(&bytes, &domain, true).unwrap()),
    )
}

#[test]
#[ignore = "fresh public15 owner; export only, no nonce search or proof generation"]
fn prepare_local_jobs_in_node_process() {
    use std::io::Write;
    let (root, genesis) = fixture();
    let store = root.join("node");
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameters = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let parameters = silk_sapling_f04::parameters::SaplingParameters::load(
        &parameters.join("sapling-spend.params"),
        &parameters.join("sapling-output.params"),
    )
    .unwrap();
    let pin: Digest = hex::decode(std::env::var("SILK_F04_TEMPLATE_NODE_PIN").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut node =
        Node::open_retained_pinned(&store, &margin, (*genesis).clone(), &parameters, pin).unwrap();
    assert_eq!(node.status().unwrap(), NodeStatus::Ready);
    assert_eq!(node.vertex_count(), 15);
    let state = node.state().unwrap().manifest();
    let carriers = node.export_range(0, 15).unwrap();
    let saved: Vec<_> = carriers
        .iter()
        .flat_map(|bytes| {
            Candidate::decode(bytes, &genesis)
                .unwrap()
                .body
                .representations()
                .to_vec()
        })
        .collect();
    assert!(!saved.is_empty());
    for count in [0, 1, 32] {
        let template = if count == 0 {
            // An explicit empty mining-template preparation, not a cover offer.
            node.prepare_mining_current(
                Body::new(&genesis.domain(), &[]).unwrap(),
                [7; 32],
                [8; 32],
                None,
            )
            .unwrap()
        } else {
            let selected = (0..count).map(|i| saved[i % saved.len()]).collect();
            let PreparedV1::Template(template) =
                LocalOfferV1::from_local_payloads(genesis.domain(), selected)
                    .unwrap()
                    .prepare_current(&mut node, [7; 32], [8; 32])
                    .unwrap()
            else {
                panic!("real template");
            };
            template
        };
        for nonce in [0, 7, u64::MAX] {
            let input = work_input(template.header(), &genesis, template.key, nonce).unwrap();
            let path = root.join(format!("reference-{count}-{nonce}.input"));
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            output.write_all(&input).unwrap();
            output.sync_all().unwrap();
        }
        let (bytes, input_pin) = template.encode_local();
        assert_eq!(bytes.len(), 632 + count * ENVELOPE_BYTES);
        assert_eq!(raw_hash(&bytes), input_pin);
        let path = root.join(format!("job-{count}.local"));
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output.write_all(&bytes).unwrap();
        output.sync_all().unwrap();
        println!(
            "local_job_count={count}; bytes={}; input_pin={}",
            bytes.len(),
            hex::encode(input_pin)
        );
        assert!(!store.join("ACTIVE_JOB").exists());
        assert_eq!(node.local_head().unwrap(), pin);
        assert_eq!(node.state().unwrap().manifest(), state);
        assert_eq!(node.vertex_count(), 15);
    }
    println!("node_process_exported=true; new_work=0; new_proofs=0; new_wallet_keys=0");
}

#[test]
#[ignore = "second native process, no node store access or Sapling parameters; imports independently supplied job pins only"]
fn import_local_jobs_in_separate_miner_process() {
    let (root, genesis) = fixture();
    assert!(
        !root.join("node").exists(),
        "miner namespace must not contain node store"
    );
    for name in [
        "SILK_F04_FORBIDDEN_NODE_STORE",
        "SILK_F04_FORBIDDEN_PARAMETERS",
    ] {
        assert!(
            !PathBuf::from(std::env::var_os(name).unwrap()).exists(),
            "host path must be hidden from miner"
        );
    }
    let pin_values = std::env::var("SILK_F04_TEMPLATE_PINS").unwrap();
    let pins: Vec<Digest> = pin_values
        .split(',')
        .map(|s| hex::decode(s).unwrap().try_into().unwrap())
        .collect();
    assert_eq!(pins.len(), 3);
    for (count, pin) in [0, 1, 32].into_iter().zip(pins) {
        let bytes = fs::read(root.join(format!("job-{count}.local"))).unwrap();
        let template = MiningTemplate::decode_local(&bytes, genesis.clone(), pin).unwrap();
        assert_eq!(template.body().representations().len(), count);
        for nonce in [0, 7, u64::MAX] {
            assert_eq!(
                work_input(template.header(), &genesis, template.key, nonce).unwrap(),
                fs::read(root.join(format!("reference-{count}-{nonce}.input"))).unwrap()
            );
        }
        let (encoded, encoded_pin) = template.encode_local();
        assert_eq!(encoded, bytes);
        assert_eq!(encoded_pin, pin);
        assert!(MiningTemplate::decode_local(&bytes, genesis.clone(), [0; 32]).is_err());
        for at in [0, 8, 12, 16, 20, 196, 580, 612] {
            let mut changed = bytes.clone();
            changed[at] ^= 1;
            assert!(
                MiningTemplate::decode_local(&changed, genesis.clone(), raw_hash(&changed))
                    .is_err(),
                "framing/context/binding mutation at {at}"
            );
        }
        let truncated = &bytes[..bytes.len() - 1];
        assert!(
            MiningTemplate::decode_local(truncated, genesis.clone(), raw_hash(truncated)).is_err()
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(MiningTemplate::decode_local(&extra, genesis.clone(), raw_hash(&extra)).is_err());
        // Correct pins do not upgrade arbitrary statically framed parent claims.
        let mut changed = bytes.clone();
        changed[20 + 416] ^= 1;
        let forged =
            MiningTemplate::decode_local(&changed, genesis.clone(), raw_hash(&changed)).unwrap();
        assert_ne!(forged.header().daa, field::<32>(&bytes, 20 + 416).unwrap());
    }
    assert!(MiningTemplate::decode_local(&vec![0; 89_913], genesis.clone(), [0; 32]).is_err());
    println!(
        "separate_miner_process_import=true; node_store_access=false; parameter_access=false; exact_original_work_inputs=true; new_vm=0; new_work=0; new_proofs=0; validity_or_relay_authority=false; fresh_settlement=false"
    );
}
