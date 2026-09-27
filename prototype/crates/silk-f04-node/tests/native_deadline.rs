//! Actual isolated-process expiry and cold refusal, not proof/work or power-loss evidence.
#![cfg(target_os = "linux")]
mod common;
use sha2::{Digest as _, Sha256};
use silk_f04_node::{
    Error,
    carriage::{Body, Candidate, Header, ParentFacts},
    genesis::Genesis,
    node::{Ingress, Node},
};
use silk_order::sg0_v1::Sg0ParentSetV1;
use silk_sapling_f04::parameters::SaplingParameters;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

fn lab() -> PathBuf {
    assert_eq!(std::env::var("SILK_F04_ISOLATED_LAB").as_deref(), Ok("1"));
    PathBuf::from(std::env::var_os("SILK_F04_DEADLINE_LAB").unwrap())
}
fn public_evidence(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}
fn snapshot(root: &Path) -> Vec<(String, [u8; 32])> {
    let mut records = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                Sha256::digest(std::fs::read(entry.path()).unwrap()).into(),
            )
        })
        .collect::<Vec<_>>();
    records.sort();
    records
}

#[test]
#[ignore = "expected SIGKILL after five seconds; isolated child only"]
fn parked_admission_child() {
    let lab = lab();
    assert_eq!(std::fs::read_dir(&lab).unwrap().count(), 0);
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let f = common::fixture(&[10]);
    let mut node = Node::create(&lab.join("node"), &margin, f.genesis.clone()).unwrap();
    public_evidence(
        &lab.join("independent-head-pin"),
        &node.local_head().unwrap(),
    );
    public_evidence(&lab.join("domain"), &f.genesis.domain());
    public_evidence(&lab.join("genesis"), &f.genesis.local_bundle());
    let body = Body::new(&f.genesis.domain(), &[]).unwrap();
    let facts = ParentFacts {
        source_record: [0; 184],
        epoch: 1,
        daa: [0; 32],
        work: 1,
        minimum_time: f.genesis.timestamp() + 1,
        source_index: 0,
        source_checkpoint: [0; 32],
        source_j: [0; 32],
        seed: [0; 32],
        key_material: [0; 32],
    };
    let header = Header::new(
        &f.genesis,
        Sg0ParentSetV1::Anchor,
        &body,
        [0; 32],
        [0; 32],
        f.genesis.timestamp() + 1,
        &facts,
    )
    .unwrap();
    let mut proof = [0; 52];
    proof[..8].copy_from_slice(b"SLKDPOW4");
    proof[9] = 4;
    // Deliberately unverified framing: no worker quantum is granted, hence no
    // genuine work/proof or graph-validity assertion is made for this candidate.
    let bytes = Candidate {
        id: [1; 32],
        header,
        body,
        proof,
    }
    .encode();
    assert_eq!(node.begin_ingest(&bytes).unwrap(), Ingress::Pending);
    assert_eq!(node.vertex_count(), 0);
    assert!(matches!(node.state(), Err(Error::Paused(_))));
    println!("parked_native_attempt=true; vertices=0; expected_signal=SIGKILL; wall_cap_seconds=5");
    std::thread::sleep(Duration::from_secs(10));
    panic!("parked native deadline did not terminate");
}

#[test]
#[ignore = "runs only after the isolated parked child actually died"]
fn cold_refusal_after_native_expiry() {
    let lab = lab();
    let root = lab.join("node");
    let margin = PathBuf::from(std::env::var_os("SILK_F04_HOST_MARGIN").unwrap());
    let domain: [u8; 32] = std::fs::read(lab.join("domain"))
        .unwrap()
        .try_into()
        .unwrap();
    let pin: [u8; 32] = std::fs::read(lab.join("independent-head-pin"))
        .unwrap()
        .try_into()
        .unwrap();
    let g =
        Genesis::admit_local_bundle(&std::fs::read(lab.join("genesis")).unwrap(), &domain, true)
            .unwrap();
    let parameter_dir = PathBuf::from(std::env::var_os("SILK_F04_PARAMETER_DIR").unwrap());
    let p = SaplingParameters::load(
        &parameter_dir.join("sapling-spend.params"),
        &parameter_dir.join("sapling-output.params"),
    )
    .unwrap();
    assert_eq!(
        std::fs::read(root.join("HEAD")).unwrap(),
        hex::encode(pin).as_bytes()
    );
    assert_eq!(std::fs::read(root.join("ACTIVE_JOB")).unwrap().len(), 64);
    assert!(!root.join("ACTIVE_REPLAY").exists());
    let before = snapshot(&root);
    for _ in 0..2 {
        assert!(matches!(
            Node::open_retained_pinned(&root, &margin, g.clone(), &p, pin),
            Err(Error::Paused(
                "uncommitted local job requires explicit bounded authority"
            ))
        ));
        assert_eq!(snapshot(&root), before);
    }
    println!(
        "actual_native_expiry_cold_refusal=true; byte_unchanged_reopens=2; renewed_allowance=false"
    );
}
