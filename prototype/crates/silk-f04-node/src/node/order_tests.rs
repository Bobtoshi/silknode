//! New creation-path order binding; no work, crypto proof or networking.
use super::*;

#[test]
fn admission_diagnostic_is_readable_after_stop_without_health_or_retry_authority() {
    let (temp, store) = crate::store::ancestry_test_store();
    drop(store);
    let margin = std::env::var_os("SILK_F04_HOST_MARGIN")
        .map_or_else(|| temp.path().to_path_buf(), std::path::PathBuf::from);
    let mut node = Node::create(
        &temp.path().join("diagnostic"),
        &margin,
        crate::genesis::public_testnet_v1::genesis().unwrap(),
    )
    .unwrap();
    assert_eq!(node.admission_budget_failure(), None);
    let head = node.local_head().unwrap();
    let mut budget = JobBudget::new(
        std::time::Duration::from_secs(60),
        std::time::Duration::ZERO,
    )
    .unwrap();
    node.admission_trace = Some(budget.track_admission());
    budget.phase(crate::budget::AdmissionPhase::CoreDecode);
    assert!(budget.check().is_err());
    node.faulted = true; // synthetic STOP integration, no native ingress was run
    let diagnostic = node.admission_budget_failure().unwrap();
    assert_eq!(diagnostic.phase, crate::budget::AdmissionPhase::CoreDecode);
    assert_eq!(diagnostic.cpu_expired, Some(true));
    assert!(node.begin_ingest(&[]).is_err());
    assert!(node.flush_clock().is_err());
    assert_eq!(node.store.head(), Some(head));
    assert_eq!(node.admission_budget_failure(), Some(diagnostic));
}

#[test]
fn disk_order_created_node_reuses_original_empty_order_and_refuses_before_clock_write() {
    let (temp, store) = crate::store::ancestry_test_store();
    drop(store);
    let root = temp.path().join("created");
    let margin = std::env::var_os("SILK_F04_HOST_MARGIN")
        .map_or_else(|| temp.path().to_path_buf(), std::path::PathBuf::from);
    let mut node = Node::create(
        &root,
        &margin,
        crate::genesis::public_testnet_v1::genesis().unwrap(),
    )
    .unwrap();
    let budget = JobBudget::checkpoint().unwrap();
    let id = node
        .core
        .order
        .retained_id()
        .expect("creation must discard snapshot");
    let original = node.core.order.bytes(&budget).unwrap();
    assert_eq!(original.len(), 76);
    assert!(node.core.order.eligible(&budget).unwrap().is_empty());
    assert_eq!(
        node.core.selected_parent(&budget).unwrap(),
        Sg0ParentSetV1::Anchor
    );
    let path = root.join(format!("{}.obj", hex::encode(id)));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let held = path.with_extension("held");
    let head = node.local_head().unwrap();
    std::fs::rename(&path, &held).unwrap();
    assert!(matches!(node.flush_clock(), Err(Error::Io(_))));
    assert!(node.core.selected_parent(&budget).is_err());
    assert_eq!(node.local_head().unwrap(), head);
    assert!(!root.join("ACTIVE_JOB").exists());
    std::fs::rename(&held, &path).unwrap();
    node.flush_clock().unwrap();
    assert_eq!(node.core.order.retained_id(), Some(id));
    assert_eq!(node.core.order.bytes(&budget).unwrap(), original);
}
