//! Small valueless local example; no network, mining or transfer-proof generation.

#[path = "../tests/common/mod.rs"]
mod common;

use silk_f04_node::{
    node::{Node, NodeStatus},
    scanner::{NoteStatus, scan, witness_at_cut},
    state::BranchState,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = common::fixture(&[10, 20]);
    let state = BranchState::genesis(&fixture.genesis)?;
    assert_eq!(state.checkpoint_index(), 0);
    assert_eq!(state.checkpoint_bytes().len(), 136);
    assert_eq!(state.private_counters(), (30, 0));
    assert_eq!(state.leaves(), 2);
    assert_eq!(state.eligible_cut().index, 0);

    for (index, value) in [10_u64, 20].into_iter().enumerate() {
        let viewing = fixture.keys[index].to_diversifiable_full_viewing_key();
        let found = scan(&state, viewing.fvk())?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].position, index as u64);
        assert_eq!(found[0].note, fixture.notes[index]);
        assert_eq!(found[0].note.value().inner(), value);
        assert_eq!(found[0].status, NoteStatus::SpendableAtCut);
        let path = witness_at_cut(&state, state.eligible_cut(), index as u64)?;
        assert_eq!(
            path.root(sapling_crypto::Node::from_cmu(&found[0].note.cmu()))
                .to_bytes(),
            state.root()
        );
    }

    // Ordinary resource refusals remain active. This is not a runtime sandbox.
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("node");
    let node = Node::create(&root, directory.path(), fixture.genesis.clone())?;
    assert_eq!(node.status()?, NodeStatus::Ready);
    assert_eq!(node.vertex_count(), 0);
    assert_eq!(node.state()?.digest(), state.digest());
    assert_eq!(node.state()?.cuts(), state.cuts());
    assert_eq!(
        std::fs::read(root.join("HEAD"))?,
        hex::encode(node.local_head()?).into_bytes()
    );
    drop(node);
    directory.close()?;

    println!("local-smoke: PASS (valueless genesis, recipient scans, witnesses, empty node store)");
    Ok(())
}
