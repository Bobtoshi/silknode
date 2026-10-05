//! Synthetic physical-storage checks only: no work, crypto or graph acceptance.
use super::super::{PAUSE_BYTES, ancestry_test_store};
use super::*;
use std::{collections::HashSet, fs, time::Duration};

fn budget() -> JobBudget {
    JobBudget::testing(Duration::from_secs(60)).unwrap()
}
fn order(n: usize) -> Vec<u8> {
    let mut bytes = Vec::from(b"SNF04OR1".as_slice());
    bytes.extend_from_slice(&raw_hash(&n.to_le_bytes()));
    bytes.extend_from_slice(&[2; 32]);
    bytes.extend_from_slice(&u32::try_from(n).unwrap().to_le_bytes());
    for i in 0..n {
        bytes.extend_from_slice(&raw_hash(&i.to_le_bytes()));
    }
    bytes
}
fn object_path(root: &std::path::Path, id: Digest) -> std::path::PathBuf {
    root.join(format!("{}.obj", hex::encode(id)))
}
fn descriptor_path(root: &std::path::Path, id: Digest) -> std::path::PathBuf {
    root.join(format!("{}.ord", hex::encode(id)))
}
fn names(root: &std::path::Path) -> HashSet<std::ffi::OsString> {
    fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect()
}

#[test]
fn streaming_order_exact_pages_hash_tail_and_original_budget() {
    let (temp, mut store) = ancestry_test_store();
    let root = temp.path().join("store");
    store.begin_job(b"synthetic streaming order").unwrap();
    for n in [0, 64, 65, 513, LIMIT] {
        let original = order(n);
        store
            .commit_ordered(&[], &original, &n.to_le_bytes(), &budget())
            .unwrap();
        let reader = store.object_reader().unwrap();
        let mut observed = Vec::new();
        let header = reader
            .visit_order(
                raw_hash(&original),
                original.len(),
                &budget(),
                &mut |rows| {
                    assert!(rows.len() <= ROWS * 32);
                    observed.extend_from_slice(rows);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(header, original[..HEADER]);
        assert_eq!(observed, original[HEADER..]);
        assert_eq!(
            reader
                .order(raw_hash(&original), original.len(), &budget())
                .unwrap(),
            original
        );
    }
    let original = order(LIMIT);
    let id = raw_hash(&original);
    let reader = store.object_reader().unwrap();
    let leaf = Tree::derive(&original, &budget()).unwrap().pages[63].id;
    let path = object_path(&root, leaf);
    let held = path.with_extension("held");
    fs::rename(&path, &held).unwrap();
    let mut calls = 0;
    assert!(
        reader
            .visit_order(id, original.len(), &budget(), &mut |_| {
                calls += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(calls, 63); // No successful result from a usable-looking prefix.
    fs::rename(&held, &path).unwrap();
    let descriptor = descriptor_path(&root, id);
    let bytes = fs::read(&descriptor).unwrap();
    let mut wrong = bytes.clone();
    wrong[16] ^= 1; // Valid tree, wrong canonical header hash.
    fs::write(&descriptor, wrong).unwrap();
    assert!(
        reader
            .visit_order(id, original.len(), &budget(), &mut |_| Ok(()))
            .is_err()
    );
    fs::write(&descriptor, bytes).unwrap();
    let expired = JobBudget::testing(Duration::ZERO).unwrap();
    assert!(
        reader
            .visit_order(id, original.len(), &expired, &mut |_| panic!(
                "expired visitor"
            ))
            .is_err()
    );
    assert!(
        reader
            .visit_order(id, original.len() - 1, &budget(), &mut |_| panic!(
                "oversize visitor"
            ))
            .is_err()
    );
}

#[test]
fn streaming_publication_preserves_every_reference_page_descriptor_and_charge() {
    let b = budget();
    for n in [65, 66, 511, 512, 513, 4095, LIMIT] {
        let original = order(n);
        let reference = Tree::derive(&original, &b).unwrap();
        let expected: BTreeMap<_, _> = reference
            .pages
            .into_iter()
            .map(|page| (page.id, page.bytes))
            .collect();
        let mut observed = BTreeMap::new();
        let descriptor = visit_tree(&original, &b, &mut |page| {
            assert!(page.bytes.len() <= PAGE_LIMIT);
            assert!(observed.insert(page.id, page.bytes).is_none());
            Ok(())
        })
        .unwrap();
        assert_eq!(descriptor, reference.descriptor);
        assert_eq!(observed, expected);
    }
    let (temp, mut store) = ancestry_test_store();
    let root = temp.path().join("store");
    let marker = store.begin_job(b"synthetic streamed publication").unwrap();
    for n in [65, 66, 513, 514] {
        let original = order(n);
        let Plan::Shared {
            descriptor,
            missing,
        } = store.plan_order(&original, &b).unwrap()
        else {
            panic!("new synthetic order must be shared");
        };
        let reference = Tree::derive(&original, &b).unwrap();
        let expected: BTreeMap<_, _> = reference
            .pages
            .into_iter()
            .filter(|page| !object_path(&root, page.id).exists())
            .map(|page| (page.id, page.bytes.len()))
            .collect();
        assert_eq!(missing, expected);
        assert_eq!(descriptor, reference.descriptor);
        let prior = store.accounted_bytes();
        let head = n.to_le_bytes();
        let expected_charge = 4 * 4096
            + charge(head.len() as u64)
            + charge(DESCRIPTOR as u64)
            + missing
                .values()
                .map(|size| charge(*size as u64))
                .sum::<u64>();
        store.commit_ordered(&[], &original, &head, &b).unwrap();
        assert_eq!(store.accounted_bytes() - prior, expected_charge);
        assert_eq!(
            store.order_object(raw_hash(&original), &b).unwrap(),
            original
        );
        assert!(matches!(
            store.plan_order(&original, &b).unwrap(),
            Plan::Existing
        ));
    }
    store.finish_job(marker, true).unwrap();
    drop(store);
    let margin = std::env::var_os("SILK_F04_HOST_MARGIN")
        .map_or_else(|| temp.path().to_owned(), std::path::PathBuf::from);
    let reopened = Store::open(&root, &margin).unwrap();
    assert_eq!(
        reopened.order_object(raw_hash(&order(514)), &b).unwrap(),
        order(514)
    );
    let before = names(&root);
    let expired = JobBudget::testing(Duration::ZERO).unwrap();
    assert!(
        visit_tree(&order(515), &expired, &mut |_| panic!(
            "expired publication visitor"
        ))
        .is_err()
    );
    assert_eq!(names(&root), before);
}

#[test]
fn shared_order_codec_boundaries_and_closed_shapes() {
    let (temp, mut store) = ancestry_test_store();
    let root = temp.path().join("store");
    store
        .begin_job(b"synthetic ordering storage codec")
        .unwrap();
    for n in [0, 1, 64, 65, 511, 512, 513, 4095, 4096] {
        let bytes = order(n);
        let b = budget();
        store
            .commit_ordered(&[], &bytes, &n.to_le_bytes(), &b)
            .unwrap();
        let id = raw_hash(&bytes);
        assert_eq!(store.order_object(id, &budget()).unwrap(), bytes);
        assert_eq!(object_path(&root, id).exists(), n <= ROWS);
        assert_eq!(descriptor_path(&root, id).exists(), n > ROWS);
        assert!(
            store
                .object_reader()
                .unwrap()
                .order(id, bytes.len() - 1, &budget())
                .is_err()
        );
    }
    for mut bytes in [order(65), order(65), order(65), order(4097)] {
        if bytes.len() == HEADER + 65 * 32 {
            bytes.push(0);
        }
        assert!(count(&bytes).is_err());
    }
    let mut wrong_magic = order(65);
    wrong_magic[0] ^= 1;
    assert!(count(&wrong_magic).is_err());
    assert!(count(&order(65)[..75]).is_err());
    assert!(Tree::derive(&order(64), &budget()).is_err());
}

#[test]
fn shared_order_all_prefixes_add_at_most_three_pages_at_fixed_horizon() {
    // In-memory content-address model, NOT 4,096 filesystem publications.
    let b = budget();
    let mut seen = HashSet::new();
    let mut packed_charge = 0_u64;
    let mut legacy_charge = 0_u64;
    for n in 65..=LIMIT {
        let bytes = order(n);
        let tree = Tree::derive(&bytes, &b).unwrap();
        assert!(tree.pages.len() <= 73);
        let mut new_pages = 0;
        for page in tree.pages {
            if seen.insert(page.id) {
                new_pages += 1;
                packed_charge += charge(u64::try_from(page.bytes.len()).unwrap());
            }
        }
        // First shared representation seeds the existing two leaves and branches.
        assert!(new_pages <= if n == 65 { 4 } else { 3 });
        packed_charge += charge(DESCRIPTOR as u64);
        legacy_charge += charge(u64::try_from(bytes.len()).unwrap());
    }
    assert!(packed_charge < legacy_charge / 2);
    assert_eq!(order(3080).len(), 98_636);
}

#[test]
fn shared_order_disk_prefix_sharing_cold_reads_and_legacy_compatibility() {
    let (temp, mut store) = ancestry_test_store();
    let root = temp.path().join("store");
    let marker = store.begin_job(b"synthetic physical prefix test").unwrap();
    let mut ids = Vec::new();
    for n in 64..=256 {
        let bytes = order(n);
        store
            .commit_ordered(&[], &bytes, &n.to_le_bytes(), &budget())
            .unwrap();
        ids.push(raw_hash(&bytes));
    }
    let head = store.head();
    let used = store.accounted_bytes();
    let before = names(&root);
    store
        .commit_ordered(&[], &order(256), b"synthetic clock-only head", &budget())
        .unwrap();
    assert_eq!(names(&root).len(), before.len() + 1);
    assert_eq!(store.accounted_bytes() - used, 4 * 4096 + charge(25));
    store.finish_job(marker, true).unwrap();
    drop(store);
    let margin = std::env::var_os("SILK_F04_HOST_MARGIN")
        .map_or_else(|| temp.path().to_owned(), std::path::PathBuf::from);
    let reopened = Store::open(&root, &margin).unwrap();
    assert_ne!(reopened.head(), head);
    for (offset, id) in ids.iter().enumerate() {
        assert_eq!(
            reopened.order_object(*id, &budget()).unwrap(),
            order(64 + offset)
        );
    }
    drop(reopened);
    // Existing large raw objects stay byte-identical and never migrate/prune.
    let mut reopened = Store::open(&root, &margin).unwrap();
    let legacy = order(513);
    reopened
        .commit(&[&legacy], b"synthetic legacy head")
        .unwrap();
    let id = raw_hash(&legacy);
    reopened
        .commit_ordered(&[], &legacy, b"synthetic legacy clock", &budget())
        .unwrap();
    assert_eq!(fs::read(object_path(&root, id)).unwrap(), legacy);
    assert!(!descriptor_path(&root, id).exists());
}

#[test]
fn shared_order_fence_quota_and_expired_budget_refuse_before_writes() {
    let (temp, mut store) = ancestry_test_store();
    let root = temp.path().join("store");
    store.commit(&[], b"prior synthetic head").unwrap();
    let head = store.head();
    let before = names(&root);
    assert!(
        store
            .commit_ordered(&[], &order(65), b"must not publish", &budget())
            .is_err()
    );
    assert_eq!(store.head(), head);
    assert_eq!(names(&root), before);
    assert!(store.poisoned);
    drop(store);
    let margin = std::env::var_os("SILK_F04_HOST_MARGIN")
        .map_or_else(|| temp.path().to_owned(), std::path::PathBuf::from);
    let mut store = Store::open(&root, &margin).unwrap();
    store.begin_job(b"synthetic ordering quota").unwrap();
    let before = names(&root);
    store.used = PAUSE_BYTES - 1;
    assert!(matches!(
        store.commit_ordered(&[], &order(65), b"quota", &budget()),
        Err(Error::Paused("persistent quota reservation"))
    ));
    assert_eq!(names(&root), before);
    assert_eq!(store.head(), head);
    let expired = JobBudget::testing(Duration::ZERO).unwrap();
    assert!(
        store
            .commit_ordered(&[], &order(65), b"expired", &expired)
            .is_err()
    );
    assert_eq!(names(&root), before);
    assert_eq!(store.head(), head);
}

#[test]
fn shared_order_damage_is_fresh_stop_without_previous_head_adoption() {
    let (temp, mut store) = ancestry_test_store();
    let root = temp.path().join("store");
    store.commit(&[], b"previous synthetic head").unwrap();
    store.begin_job(b"synthetic corruption fence").unwrap();
    let bytes = order(129);
    let id = raw_hash(&bytes);
    store
        .commit_ordered(&[], &bytes, b"current synthetic head", &budget())
        .unwrap();
    let head = store.head();
    let previous = fs::read(root.join("PREVIOUS")).unwrap();
    let reader = store.object_reader().unwrap();
    let tree = Tree::derive(&bytes, &budget()).unwrap();
    let last_leaf = tree.pages[2].id;
    let leaf_path = object_path(&root, last_leaf);
    let original = fs::read(&leaf_path).unwrap();
    assert_eq!(reader.order(id, bytes.len(), &budget()).unwrap(), bytes);
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    fs::write(&leaf_path, corrupt).unwrap();
    let error = reader.order(id, bytes.len(), &budget()).unwrap_err();
    assert!(matches!(error, Error::Unavailable(DAMAGED)));
    assert!(!crate::node::storage_integrity_failure(&error));
    fs::remove_file(&leaf_path).unwrap();
    let error = reader.order(id, bytes.len(), &budget()).unwrap_err();
    assert!(!crate::node::storage_integrity_failure(&error));
    assert!(
        store
            .commit_ordered(&[], &bytes, b"must not repair", &budget())
            .is_err()
    );
    assert!(store.poisoned);
    assert!(!leaf_path.exists());
    assert_eq!(store.head(), head);
    assert_eq!(fs::read(root.join("PREVIOUS")).unwrap(), previous);
    assert!(store.active_job().unwrap().is_some());
    // Only the test fixture restores its deliberately damaged synthetic bytes.
    fs::write(&leaf_path, &original).unwrap();
    let extra = root.join("synthetic-hardlink");
    fs::hard_link(&leaf_path, &extra).unwrap();
    assert!(reader.order(id, bytes.len(), &budget()).is_err());
    fs::remove_file(&extra).unwrap();
    fs::remove_file(&leaf_path).unwrap();
    let target = temp.path().join("synthetic-target");
    fs::write(&target, &original).unwrap();
    std::os::unix::fs::symlink(&target, &leaf_path).unwrap();
    assert!(reader.order(id, bytes.len(), &budget()).is_err());
}

#[test]
fn shared_order_rejects_hashed_wrong_positions_depth_shape_and_canonical_id() {
    let (temp, mut store) = ancestry_test_store();
    let root = temp.path().join("store");
    store.begin_job(b"synthetic malformed tree").unwrap();
    let bytes = order(65);
    let id = raw_hash(&bytes);
    store
        .commit_ordered(&[], &bytes, b"synthetic shape head", &budget())
        .unwrap();
    let tree = Tree::derive(&bytes, &budget()).unwrap();
    let descriptor = descriptor_path(&root, id);
    let reader = store.object_reader().unwrap();
    // Hash-valid but structurally wrong root pages remain untrusted bytes.
    let good_root = &tree.pages.last().unwrap().bytes;
    for (at, value) in [(8, 1), (9, 2), (10, 1)] {
        let mut bad_root = good_root.clone();
        bad_root[at] = value;
        let bad_id = store.put(&bad_root).unwrap();
        let mut bad_descriptor = tree.descriptor.clone();
        bad_descriptor[8 + HEADER..].copy_from_slice(&bad_id);
        fs::write(&descriptor, bad_descriptor).unwrap();
        assert!(reader.order(id, bytes.len(), &budget()).is_err());
    }
    let mut bad = tree.descriptor.clone();
    bad[16] ^= 1; // graph context differs while framing is still valid
    fs::write(&descriptor, bad).unwrap();
    assert!(reader.order(id, bytes.len(), &budget()).is_err());
    let mut bad = tree.descriptor.clone();
    bad.push(0);
    fs::write(&descriptor, bad).unwrap();
    assert!(reader.order(id, bytes.len(), &budget()).is_err());
    fs::write(&descriptor, &tree.descriptor).unwrap();
    // Raw-name damage must not fall through to a valid descriptor.
    fs::write(object_path(&root, id), b"synthetic damaged legacy object").unwrap();
    assert!(reader.order(id, bytes.len(), &budget()).is_err());
    fs::remove_file(object_path(&root, id)).unwrap();
    assert_eq!(reader.order(id, bytes.len(), &budget()).unwrap(), bytes);
    fs::rename(&root, temp.path().join("original")).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(descriptor_path(&root, id), b"replacement directory").unwrap();
    assert_eq!(reader.order(id, bytes.len(), &budget()).unwrap(), bytes);
}

#[test]
fn shared_order_failed_descriptor_stage_is_retained_and_never_overwrites() {
    let (temp, store) = ancestry_test_store();
    let root = temp.path().join("store");
    let tree = Tree::derive(&order(65), &budget()).unwrap();
    let id = raw_hash(&order(65));
    let path = descriptor_path(&root, id);
    fs::write(&path, b"existing synthetic destination").unwrap();
    assert!(store.put_order_descriptor(id, &tree.descriptor).is_err());
    assert_eq!(fs::read(path).unwrap(), b"existing synthetic destination");
    assert!(
        names(&root)
            .iter()
            .any(|name| name.to_string_lossy().starts_with("order-stage-"))
    );
    assert!(store.head().is_none());
}
