use super::*;
use crate::{node::storage_integrity_failure, wire::raw_hash};
use std::fs;

const DOMAIN: Digest = [7; 32];

fn store() -> (tempfile::TempDir, Store) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::create(&temp.path().join("node"), temp.path()).unwrap();
    store
        .begin_replay(b"synthetic directory-only fence")
        .unwrap();
    (temp, store)
}
fn address(ordinal: u64) -> Digest {
    raw_hash(&ordinal.to_le_bytes())
}
fn build(store: &mut Store, leaves: u64) -> Directory {
    let mut builder = Builder::new(DOMAIN, leaves * 64).unwrap();
    for ordinal in (0..leaves).rev() {
        builder.push(store, ordinal, address(ordinal)).unwrap();
        assert!(builder.pending.iter().all(|pending| {
            pending
                .as_ref()
                .is_none_or(|pending| pending.children.len() < FANOUT)
        }));
    }
    builder.finish().unwrap()
}

#[test]
fn generation_directory_crosses_each_physical_level_with_bounded_groups() {
    let (_temp, mut store) = store();
    // Unverified digests only; this tests address geometry, not a large chain.
    for leaves in [1, 64, 65, 4096, 4097, MAX_GENERATIONS_V1 / 64] {
        let directory = build(&mut store, leaves);
        for ordinal in [0, leaves / 2, leaves - 1] {
            assert_eq!(directory.leaf(&store, ordinal).unwrap(), address(ordinal));
        }
        assert!(directory.leaf(&store, leaves).is_err());
        assert_eq!(
            directory.level,
            if leaves <= 64 {
                0
            } else if leaves <= 4096 {
                1
            } else {
                2
            }
        );
    }
    assert!(Builder::new(DOMAIN, 0).is_err());
    assert!(Builder::new(DOMAIN, MAX_GENERATIONS_V1 + 1).is_err());
    assert_eq!(HEADER + FANOUT * 32, 2104);
    assert_eq!(LEVELS * FANOUT * 32, 6144);
}

#[test]
fn generation_directory_rejects_out_of_order_incomplete_or_zero_source() {
    let (_temp, mut store) = store();
    let mut builder = Builder::new(DOMAIN, 65).unwrap();
    assert!(builder.push(&mut store, 0, address(0)).is_err());
    assert!(builder.push(&mut store, 1, [0; 32]).is_err());
    builder.push(&mut store, 1, address(1)).unwrap();
    assert!(builder.finish().is_err());
    let mut builder = Builder::new(DOMAIN, 1).unwrap();
    builder.push(&mut store, 0, address(0)).unwrap();
    assert!(builder.push(&mut store, 0, address(0)).is_err());
    assert!(store.active_replay().unwrap().is_some());
    assert_eq!(store.head(), None);
}

#[test]
fn generation_directory_encoding_context_coverage_and_source_labels_are_closed() {
    let (_temp, mut store) = store();
    let mut directory = build(&mut store, 2);
    let original = store.object(directory.root).unwrap();
    assert_eq!(Page::decode(&original).unwrap().encode(), original);
    for cut in 0..original.len() {
        assert!(Page::decode(&original[..cut]).is_err());
    }
    let mut extra = original.clone();
    extra.push(0);
    assert!(Page::decode(&extra).is_err());
    for offset in [48, 49, 50] {
        let mut bytes = original.clone();
        bytes[offset] = 255;
        assert!(Page::decode(&bytes).is_err());
    }
    let mut zero = original.clone();
    zero[HEADER..HEADER + 32].fill(0);
    assert!(Page::decode(&zero).is_err());
    for mutation in 0..4 {
        let mut page = Page::decode(&original).unwrap();
        match mutation {
            0 => page.domain = [9; 32],
            1 => page.base = 64,
            2 => page.level = 1,
            _ => {
                page.children.pop();
            }
        }
        directory.root = store.retain_replay_page(&page.encode()).unwrap();
        assert!(matches!(
            directory.leaf(&store, 0),
            Err(Error::Unavailable(
                "retained replay directory binding/coverage"
            ))
        ));
    }
}

#[test]
fn generation_directory_missing_or_changed_page_stops_without_fallback() {
    let (temp, mut store) = store();
    let directory = build(&mut store, 65);
    let root = Page::decode(&store.object(directory.root).unwrap()).unwrap();
    let path = temp
        .path()
        .join("node")
        .join(format!("{}.obj", hex::encode(root.children[0])));
    fs::write(&path, b"changed auxiliary directory").unwrap();
    for remove in [false, true] {
        if remove {
            fs::remove_file(&path).unwrap();
        }
        let error = directory.leaf(&store, 0).err().unwrap();
        assert!(matches!(
            error,
            Error::Unavailable("retained replay directory load failed")
        ));
        assert!(!storage_integrity_failure(&error));
        assert_eq!(store.head(), None);
        assert!(store.active_replay().unwrap().is_some());
    }
}

#[test]
fn generation_directory_failed_write_returns_no_root_and_retains_stop() {
    let (temp, mut store) = store();
    let bytes = Page {
        domain: DOMAIN,
        base: 0,
        level: 0,
        children: vec![address(0)],
    }
    .encode();
    let path = temp
        .path()
        .join("node")
        .join(format!("{}.obj", hex::encode(raw_hash(&bytes))));
    fs::write(path, b"occupied new directory address").unwrap();
    let mut builder = Builder::new(DOMAIN, 1).unwrap();
    let error = builder.push(&mut store, 0, address(0)).err().unwrap();
    assert!(!storage_integrity_failure(&error));
    assert!(builder.root.is_none());
    assert!(builder.finish().is_err());
    assert!(store.active_replay().unwrap().is_some());
    assert_eq!(store.head(), None);
    assert!(store.commit(&[], b"no renewed publication").is_err());
}
