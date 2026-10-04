//! Synthetic framing/storage checks only; no fake work is ever admitted.
use super::*;
use crate::{
    budget::JobBudget,
    carriage::{Body, Header},
    sync::RangeBatchV1,
};
use std::fs;
#[path = "../../tests/common/mod.rs"]
mod common;

fn fixture(count: usize) -> (tempfile::TempDir, Arc<Genesis>, Vec<u8>, Vec<Vec<u8>>) {
    let temp = std::env::var_os("SILK_F04_ANCESTRY_TEST_PARENT").map_or_else(
        || tempfile::tempdir().unwrap(),
        |path| tempfile::tempdir_in(path).unwrap(),
    );
    let genesis = Arc::new(common::fixture(&[10]).genesis);
    let body = Body::new(&genesis.domain(), &[]).unwrap();
    let facts = crate::parent::PrefixCache::new(&genesis)
        .unwrap()
        .derive(
            &crate::graph::DurableGraph::default(),
            &silk_order::sg0_v1::Sg0ParentSetV1::Anchor,
            &genesis,
            &JobBudget::vertex().unwrap(),
        )
        .unwrap();
    let header = Header::new(
        &genesis,
        silk_order::sg0_v1::Sg0ParentSetV1::Anchor,
        &body,
        [0; 32],
        [7; 32],
        genesis.timestamp() + 10,
        &facts,
    )
    .unwrap();
    let mut proof = [0; 52];
    proof[..8].copy_from_slice(b"SLKDPOW4");
    proof[9] = 4;
    let base = Candidate {
        id: [0; 32],
        header,
        body,
        proof,
    }
    .encode();
    let mut manifest = Vec::from(b"SNF04HF1".as_slice());
    manifest.extend_from_slice(&genesis.domain());
    manifest.extend_from_slice(&raw_hash(&genesis.local_bundle()));
    for claim in [1, 2, 3] {
        manifest.extend_from_slice(&[claim; 32]);
    }
    manifest.extend_from_slice(&u32::try_from(count).unwrap().to_le_bytes());
    manifest.extend_from_slice(&[0; 4]);
    let mut carriers = Vec::new();
    for ordinal in 0..count {
        let mut bytes = base.clone();
        bytes[36..44].copy_from_slice(&(ordinal as u64 + 1).to_be_bytes());
        let hash = raw_hash(&bytes);
        manifest.extend_from_slice(&bytes[12..44]);
        manifest.extend_from_slice(&hash);
        manifest.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        fs::write(
            temp.path().join(format!("{}.vertex", hex::encode(hash))),
            &bytes,
        )
        .unwrap();
        carriers.push(bytes);
    }
    fs::write(temp.path().join("history.manifest"), &manifest).unwrap();
    (temp, genesis, manifest, carriers)
}

fn open(root: &Path, genesis: Arc<Genesis>, manifest: &[u8]) -> Result<PublicHistoryV1> {
    fs::write(root.join("history.manifest"), manifest).unwrap();
    PublicHistoryV1::open(root, raw_hash(manifest), genesis)
}

#[test]
fn public_history_ranges_match_existing_wire_and_never_assert_work_validity() {
    let (temp, genesis, manifest, carriers) = fixture(35);
    let source = open(temp.path(), genesis, &manifest).unwrap();
    assert_eq!(source.len(), 35);
    assert!(!source.is_empty());
    assert_eq!(source.source_head(), [1; 32]);
    assert_eq!(source.claimed_checkpoint(), [2; 32]);
    assert_eq!(source.claimed_state(), [3; 32]);
    for start in [0, 32, 34] {
        let bytes = source.read_range(start, 32).unwrap();
        let decoded = RangeBatchV1::decode(&bytes, start, source.len()).unwrap();
        assert_eq!(
            decoded.carriers(),
            carriers[start..(start + 32).min(35)]
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>()
        );
    }
    // The proof bytes and ID claims are synthetic and NOT valid work. Returning
    // them as unverified full bytes cannot confer graph credit or crypto validity.
}

fn received_batch(carriers: &[&[u8]]) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(carriers.len()).unwrap()];
    for carrier in carriers {
        bytes.extend_from_slice(&u32::try_from(carrier.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(carrier);
    }
    bytes
}

#[test]
fn received_history_ranges_bind_exact_windows_without_work_authority() {
    let (temp, genesis, manifest, carriers) = fixture(35);
    let source = open(temp.path(), genesis, &manifest).unwrap();
    for start in [0, 32, 34] {
        let bytes = source.read_range(start, 32).unwrap();
        for _ in 0..2 {
            let received = source.decode_range(&bytes, start, 32).unwrap();
            assert_eq!(
                received.carriers(),
                carriers[start..(start + 32).min(35)]
                    .iter()
                    .map(Vec::as_slice)
                    .collect::<Vec<_>>()
            );
            assert_eq!(received.carriers()[0].as_ptr(), bytes[5..].as_ptr());
        }
    }
    // Static identity only: these synthetic proofs/ID claims are not valid work.
    // Repeating a transport decode neither admits a carrier nor advances a node.
}

#[test]
fn received_history_ranges_refuse_partial_reordered_replayed_and_foreign_bytes() {
    let (temp, genesis, manifest, carriers) = fixture(3);
    let source = open(temp.path(), genesis.clone(), &manifest).unwrap();
    let good = source.read_range(0, 3).unwrap();
    for cut in [0, 1, 4, 5, 5 + carriers[0].len(), good.len() - 1] {
        assert!(source.decode_range(&good[..cut], 0, 3).is_err());
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(source.decode_range(&trailing, 0, 3).is_err());
    let short = source.read_range(0, 2).unwrap();
    assert!(RangeBatchV1::decode(&short, 0, 3).is_ok());
    assert!(source.decode_range(&short, 0, 3).is_err());
    let replayed = source.read_range(1, 2).unwrap();
    assert!(source.decode_range(&replayed, 0, 2).is_err());
    let reordered = received_batch(&[&carriers[1], &carriers[0], &carriers[2]]);
    assert!(RangeBatchV1::decode(&reordered, 0, 3).is_ok());
    assert!(source.decode_range(&reordered, 0, 3).is_err());
    let duplicated = received_batch(&[&carriers[0], &carriers[0], &carriers[2]]);
    assert!(source.decode_range(&duplicated, 0, 3).is_err());

    // A different independently framed source can supply a different final row.
    // The original immutable pin must refuse the entire mixed response.
    let mut foreign = carriers[2].clone();
    foreign[36..44].copy_from_slice(&99_u64.to_be_bytes());
    let mut other_manifest = manifest.clone();
    let row = HEADER + 2 * ROW;
    other_manifest[row..row + 32].copy_from_slice(&foreign[12..44]);
    other_manifest[row + 32..row + 64].copy_from_slice(&raw_hash(&foreign));
    fs::write(
        temp.path()
            .join(format!("{}.vertex", hex::encode(raw_hash(&foreign)))),
        &foreign,
    )
    .unwrap();
    let other = open(temp.path(), genesis, &other_manifest).unwrap();
    let mixed = other.read_range(0, 3).unwrap();
    assert!(other.decode_range(&mixed, 0, 3).is_ok());
    assert!(source.decode_range(&mixed, 0, 3).is_err());
    assert!(source.decode_range(&good, 0, 3).is_ok());
}

#[test]
fn received_history_ranges_refuse_bad_requests_and_pinned_static_id_claims() {
    let (temp, genesis, manifest, _) = fixture(1);
    let source = open(temp.path(), genesis.clone(), &manifest).unwrap();
    let bytes = source.read_range(0, 1).unwrap();
    for (start, count) in [(0, 0), (0, 33), (1, 1), (usize::MAX, 1)] {
        assert!(source.decode_range(&bytes, start, count).is_err());
    }
    let mut wrong = manifest.clone();
    wrong[HEADER] ^= 1;
    let wrong_source = open(temp.path(), genesis.clone(), &wrong).unwrap();
    assert!(wrong_source.decode_range(&bytes, 0, 1).is_err());
    let mut empty = manifest[..HEADER].to_vec();
    empty[168..172].copy_from_slice(&0_u32.to_le_bytes());
    let empty_source = open(temp.path(), genesis, &empty).unwrap();
    assert!(empty_source.decode_range(&bytes, 0, 1).is_err());
}

#[test]
fn received_history_prefix_queries_refuse_context_fences_and_expired_scope() {
    let (temp, genesis, manifest, _) = fixture(1);
    let source = open(temp.path(), genesis.clone(), &manifest).unwrap();
    let margin = std::env::var_os("SILK_F04_HOST_MARGIN")
        .map_or_else(|| std::path::PathBuf::from("/"), std::path::PathBuf::from);
    let root = temp.path().join("receiver");
    let node = Node::create(&root, &margin, (*genesis).clone()).unwrap();
    let head = node.local_head().unwrap();
    assert_eq!(source.admitted_prefix(&node).unwrap(), 0);
    let mut empty_manifest = manifest[..HEADER].to_vec();
    empty_manifest[168..172].copy_from_slice(&0_u32.to_le_bytes());
    let empty = open(temp.path(), genesis.clone(), &empty_manifest).unwrap();
    assert_eq!(empty.admitted_prefix(&node).unwrap(), 0);
    let expired = JobBudget::testing(std::time::Duration::ZERO).unwrap();
    assert!(source.admitted_prefix_budget(&node, &expired).is_err());
    assert!(empty.admitted_prefix_budget(&node, &expired).is_err());
    for marker in ["ACTIVE_JOB", "ACTIVE_REPLAY"] {
        // Synthetic pointer to the existing genesis record, NOT a native attempt.
        fs::write(root.join(marker), fs::read(root.join("HEAD")).unwrap()).unwrap();
        assert!(matches!(
            source.admitted_prefix(&node),
            Err(Error::Paused(_))
        ));
        assert!(matches!(
            empty.admitted_prefix(&node),
            Err(Error::Paused(_))
        ));
        fs::remove_file(root.join(marker)).unwrap();
    }
    assert_eq!(source.admitted_prefix(&node).unwrap(), 0);
    assert_eq!(node.local_head().unwrap(), head);
    let other = Node::create(
        &temp.path().join("other-receiver"),
        &margin,
        crate::genesis::public_testnet_v1::genesis().unwrap(),
    )
    .unwrap();
    assert_ne!(other.genesis().domain(), source.genesis.domain());
    assert!(matches!(
        source.admitted_prefix(&other),
        Err(Error::Invalid(_))
    ));
}

#[test]
fn public_history_manifest_hash_context_shapes_duplicates_and_horizon_refuse() {
    let (temp, genesis, manifest, _) = fixture(2);
    assert!(PublicHistoryV1::open(temp.path(), [0; 32], genesis.clone()).is_err());
    for offset in [0, 8, 40, 172] {
        let mut changed = manifest.clone();
        changed[offset] ^= 1;
        assert!(open(temp.path(), genesis.clone(), &changed).is_err());
    }
    let mut duplicate = manifest.clone();
    duplicate[HEADER + ROW..HEADER + ROW + 32].copy_from_slice(&manifest[HEADER..HEADER + 32]);
    assert!(open(temp.path(), genesis.clone(), &duplicate).is_err());
    let mut duplicate = manifest.clone();
    duplicate[HEADER + ROW + 32..HEADER + ROW + 64]
        .copy_from_slice(&manifest[HEADER + 32..HEADER + 64]);
    assert!(open(temp.path(), genesis.clone(), &duplicate).is_err());
    for size in [0, 719, MAX_VERTEX_BYTES + 1] {
        let mut changed = manifest.clone();
        changed[HEADER + 64..HEADER + 68]
            .copy_from_slice(&u32::try_from(size).unwrap().to_be_bytes());
        assert!(open(temp.path(), genesis.clone(), &changed).is_err());
    }
    for count in [1, HISTORY_LIMIT_V1 + 1, u32::MAX as usize] {
        let mut changed = manifest.clone();
        changed[168..172].copy_from_slice(&u32::try_from(count).unwrap().to_le_bytes());
        assert!(open(temp.path(), genesis.clone(), &changed).is_err());
    }
    for cut in [0, 8, HEADER - 1, manifest.len() - 1] {
        assert!(open(temp.path(), genesis.clone(), &manifest[..cut]).is_err());
    }
    let mut extra = manifest.clone();
    extra.push(0);
    assert!(open(temp.path(), genesis, &extra).is_err());
}

#[test]
fn public_history_later_damage_refuses_whole_range_and_reads_are_fresh() {
    let (temp, genesis, manifest, carriers) = fixture(2);
    let source = open(temp.path(), genesis, &manifest).unwrap();
    let path = temp
        .path()
        .join(format!("{}.vertex", hex::encode(raw_hash(&carriers[1]))));
    assert!(source.read_range(0, 2).is_ok());
    fs::write(&path, b"changed").unwrap();
    assert!(source.read_range(0, 2).is_err());
    fs::write(&path, &carriers[1]).unwrap();
    assert!(source.read_range(0, 2).is_ok());
    fs::remove_file(&path).unwrap();
    assert!(source.read_range(0, 2).is_err());
    let other = temp.path().join("other");
    fs::write(&other, &carriers[1]).unwrap();
    std::os::unix::fs::symlink(&other, &path).unwrap();
    assert!(source.read_range(0, 2).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&other, &path).unwrap();
    assert!(source.read_range(0, 2).is_err());
}

#[test]
fn public_history_closed_rows_cannot_change_claimed_id_and_directory_is_held() {
    let (temp, genesis, manifest, _) = fixture(1);
    let mut wrong = manifest.clone();
    wrong[HEADER] ^= 1;
    let source = open(temp.path(), genesis.clone(), &wrong).unwrap();
    assert!(source.read_range(0, 1).is_err());
    let source = open(temp.path(), genesis, &manifest).unwrap();
    let moved = temp.path().with_extension("held-public-history");
    fs::rename(temp.path(), &moved).unwrap();
    fs::create_dir(temp.path()).unwrap();
    assert!(source.read_range(0, 1).is_ok());
    // Move back solely so TempDir removes its own synthetic fixtures normally.
    fs::remove_dir(temp.path()).unwrap();
    fs::rename(moved, temp.path()).unwrap();
}

#[test]
fn public_history_maximum_inventory_remains_one_bounded_range() {
    let (temp, genesis, manifest, carriers) = fixture(HISTORY_LIMIT_V1);
    let source = open(temp.path(), genesis, &manifest).unwrap();
    let bytes = source
        .read_range(HISTORY_LIMIT_V1 - 1, RANGE_LIMIT_V1)
        .unwrap();
    let range = RangeBatchV1::decode(&bytes, HISTORY_LIMIT_V1 - 1, HISTORY_LIMIT_V1).unwrap();
    assert_eq!(range.carriers(), &[carriers.last().unwrap().as_slice()]);
    assert_eq!(bytes.len(), 1 + 4 + carriers.last().unwrap().len());
    for (start, count) in [
        (0, 0),
        (0, RANGE_LIMIT_V1 + 1),
        (HISTORY_LIMIT_V1, 1),
        (usize::MAX, 1),
    ] {
        assert!(source.read_range(start, count).is_err());
    }
}

#[test]
#[ignore = "named task-owned public historical export only; static codec/range compatibility, NO PoW/proof/ledger replay"]
fn historical_public_carrier_codec_and_range_compatibility() {
    assert_eq!(
        std::env::var("SILK_F04_PUBLIC_HISTORY_INSPECTION").as_deref(),
        Ok("1")
    );
    let root = std::path::PathBuf::from(std::env::var_os("SILK_F04_PUBLIC_HISTORY_ROOT").unwrap());
    let digest = |name: &str| -> Digest {
        hex::decode(std::env::var(name).unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let bytes = fs::read(root.join("genesis.bundle")).unwrap();
    assert!(bytes.len() <= 8 * 1024 * 1024);
    assert_eq!(raw_hash(&bytes), digest("SILK_F04_PUBLIC_HISTORY_GENESIS"));
    let genesis = Arc::new(
        Genesis::admit_local_bundle(&bytes, &digest("SILK_F04_PUBLIC_HISTORY_DOMAIN"), true)
            .unwrap(),
    );
    let source =
        PublicHistoryV1::open(&root, digest("SILK_F04_PUBLIC_HISTORY_MANIFEST"), genesis).unwrap();
    assert_eq!(source.len(), 3080);
    assert_eq!(
        source.source_head(),
        digest("SILK_F04_PUBLIC_HISTORY_SOURCE")
    );
    assert_eq!(
        source.claimed_checkpoint(),
        digest("SILK_F04_PUBLIC_HISTORY_CHECKPOINT")
    );
    assert_eq!(
        source.claimed_state(),
        digest("SILK_F04_PUBLIC_HISTORY_STATE")
    );
    let mut count = 0;
    let mut ranges = 0;
    for start in (0..source.len()).step_by(RANGE_LIMIT_V1) {
        let bytes = source.read_range(start, RANGE_LIMIT_V1).unwrap();
        let decoded = source.decode_range(&bytes, start, RANGE_LIMIT_V1).unwrap();
        count += decoded.carriers().len();
        ranges += 1;
    }
    assert_eq!(count, 3080);
    assert_eq!(ranges, 97);
    println!(
        "public_carriers=3080; ranges=97; current_genesis_and_static_codec_bound=true; native_work_evaluations=0; payment_proofs_verified=0; node_opens=0; wallet_or_private_git_imports=0"
    );
}
