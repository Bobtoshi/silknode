//! Completion-only public replay/sync using the separately retained genuine archive.
//! Does not rerun construction/mining or claim recovery of its unretained private keys.
use sha2::{Digest as _, Sha256};
use silk_f04_node::{
    Digest,
    genesis::Genesis,
    node::{Node, NodeStatus},
};
use silk_sapling_f04::parameters::SaplingParameters;
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Instant,
};

// Independently recorded after the original aggregate timeout; never read from HEAD.
const RETAINED_HEAD: &str = "76e462bd2ba8e7d412f3f4d69d79d055f29b1779c62e6f440f78b318c79e0560";
const CHECKPOINT: &str = "efbd7a79bdc8b07eb7ebfe67a1af5dd9a592114314c76e09f91c6e1603efd2da";
const DOMAIN: &str = "8c0325387abf1c5ae3bbc8a02e91fc87fedfbde653e94343ea79152287d1b466";
fn object(root: &Path, id: Digest) -> Vec<u8> {
    let path = root.join(format!("{}.obj", hex::encode(id)));
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= 8 * 1024 * 1024);
    let mut bytes = Vec::new();
    fs::File::open(path)
        .unwrap()
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, metadata.len());
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), id);
    bytes
}
fn admitted_genesis(root: &Path, head: Digest) -> Genesis {
    let pinned = object(root, head);
    assert_eq!(pinned.len(), 232);
    let domain: Digest = pinned[56..88].try_into().unwrap();
    assert_eq!(hex::encode(domain), DOMAIN);
    let mut cursor = head;
    for _ in 0..20_000 {
        let record = object(root, cursor);
        assert_eq!(record.len(), 232);
        assert_eq!(&record[..12], b"SNF04HD1\x01\0\0\0");
        assert_eq!(record[56..88], domain);
        let previous: Digest = record[24..56].try_into().unwrap();
        if previous == [0; 32] {
            assert_eq!(record[12], 0);
            let data = object(root, record[96..128].try_into().unwrap());
            // The independently retained head authenticates this exact local
            // ancestry/N. This is NOT permission to adopt an arbitrary remote head.
            return Genesis::admit_local_bundle(&data, &domain, true).unwrap();
        }
        cursor = previous;
    }
    panic!("retained ancestry exceeds fixed horizon");
}
fn copy_local(source: &Path, destination: &Path) {
    let source_meta = fs::symlink_metadata(source).unwrap();
    assert!(source_meta.is_dir() && source_meta.mode() & 0o777 == 0o700);
    fs::create_dir(destination).unwrap();
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(source_meta.dev(), destination.metadata().unwrap().dev());
    let mut total = 0_u64;
    for (i, entry) in fs::read_dir(source).unwrap().enumerate() {
        assert!(i < 100_000);
        let entry = entry.unwrap();
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        assert!(metadata.is_file() && metadata.nlink() == 1 && metadata.uid() == source_meta.uid());
        total = total.checked_add(metadata.len()).unwrap();
        assert!(total <= 512 * 1024 * 1024);
        assert!(fs2::available_space(destination).unwrap() >= 4 * 1024 * 1024 * 1024);
        fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
    }
}

#[test]
#[ignore = "one authorized completion-only isolated replay/sync; real RandomX and Sapling remain mandatory"]
fn retained_mature_history_replays_then_fully_syncs() {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    let source = PathBuf::from(std::env::var_os("SILK_F04_MATURE_SOURCE").unwrap());
    let store = PathBuf::from(std::env::var_os("SILK_F04_LAB_STORE").unwrap());
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    assert_eq!(
        fs::read_to_string(source.join("HEAD")).unwrap().trim(),
        RETAINED_HEAD
    );
    assert!(fs2::available_space(&margin).unwrap() >= 4 * 1024 * 1024 * 1024);
    let head = hex::decode(RETAINED_HEAD).unwrap().try_into().unwrap();
    let genesis = admitted_genesis(&source, head);
    let parameters = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    let lab = tempfile::Builder::new()
        .prefix("f04-mature-completion-")
        .tempdir_in(store)
        .unwrap()
        .keep();
    println!(
        "retained_lab={}; source_head={RETAINED_HEAD}; domain={}; public_completion_only=true",
        lab.display(),
        hex::encode(genesis.domain())
    );
    let copy = lab.join("replay-copy");
    copy_local(&source, &copy);
    let started = Instant::now();
    let mut replayed =
        Node::open_retained_pinned(&copy, &margin, genesis.clone(), &parameters, head).unwrap();
    assert!(!replayed.recovered_previous());
    assert_eq!(replayed.vertex_count(), 3080);
    let state = replayed.state().unwrap();
    assert_eq!(state.executed().len(), 3080);
    assert_eq!(state.checkpoint_index(), 385);
    assert_eq!(hex::encode(state.checkpoint_id()), CHECKPOINT);
    assert_eq!(state.eligible_cut().index, 1);
    assert_eq!(state.leaves(), 6);
    assert_eq!(state.private_counters(), (298, 2));
    println!(
        "retained_replay_ms={}; beginning_live_full_sync",
        started.elapsed().as_millis()
    );
    let sync = Instant::now();
    let mut peer = Node::create(&lab.join("fresh-peer"), &margin, genesis).unwrap();
    for start in (0..3080).step_by(32) {
        for bytes in replayed.export_range(start, 32).unwrap() {
            peer.ingest(&bytes, &parameters).unwrap();
            while peer.status().unwrap() != NodeStatus::Ready {
                peer.advance().unwrap();
            }
        }
        if start % 128 == 0 {
            println!(
                "peer_vertices={}; sync_ms={}",
                peer.vertex_count(),
                sync.elapsed().as_millis()
            );
        }
    }
    let expected = replayed.state().unwrap();
    let actual = peer.state().unwrap();
    assert_eq!(peer.vertex_count(), 3080);
    assert_eq!(actual.checkpoint_bytes(), expected.checkpoint_bytes());
    assert_eq!(actual.digest(), expected.digest());
    assert_eq!(actual.cuts(), expected.cuts());
    assert_eq!(actual.recovery(), expected.recovery());
    assert_eq!(actual.accepted_outputs(), expected.accepted_outputs());
    peer.flush_clock().unwrap();
    replayed.flush_clock().unwrap();
    assert_eq!(
        fs::read_to_string(source.join("HEAD")).unwrap().trim(),
        RETAINED_HEAD
    );
    println!(
        "completion_ms={}; sync_ms={}; vertices=3080; checkpoint=385; source_unchanged=true; full_crypto_replay=true; live_ingress_full_sync=true; private_key_rescan=false; replay_head={}; peer_head={}",
        started.elapsed().as_millis(),
        sync.elapsed().as_millis(),
        hex::encode(replayed.local_head().unwrap()),
        hex::encode(peer.local_head().unwrap())
    );
}
