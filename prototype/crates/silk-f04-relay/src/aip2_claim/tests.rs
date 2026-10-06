//! Native checks of the exact core scope component. No new proof generation.
use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "aip2-scope-{}-{}-{label}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn binding() -> PreparedClaimBinding {
    PreparedClaimBinding {
        role: ClaimRole::Client,
        domain: [1; 32],
        config: [2; 32],
        profile: [3; 32],
        vk_hash: [4; 32],
        epoch: 0,
    }
}
#[derive(Clone, Default)]
struct Pins(Arc<Mutex<(Vec<[u8; 32]>, bool)>>);
impl ClaimPinRetention for Pins {
    fn retain_claim_pin(&mut self, pin: [u8; 32]) -> ClaimResult<()> {
        let mut state = self.0.lock().unwrap();
        if state.1 {
            return Err(ClaimError::Unavailable("test retention failure"));
        }
        state.0.push(pin);
        Ok(())
    }
}
#[test]
fn claim_is_durable_before_receipt_and_never_reopens_under_changed_manifest() {
    let path = directory("claim");
    let pins = Pins::default();
    let mut owner = PreparedScopeStore::create(&path, binding(), pins.clone()).unwrap();
    let previous = owner.pin();
    let receipt = owner.consume(5, [5; 32], [6; 32]).unwrap();
    assert_eq!(receipt.round(), 5);
    assert_eq!(receipt.manifest(), [5; 32]);
    assert_eq!(receipt.message(), [6; 32]);
    drop(receipt);
    let bytes = fs::read(path.join("CURRENT")).unwrap();
    assert_eq!(bytes.len(), 512);
    assert_eq!(&bytes[160..192], &[5; 32]);
    assert_eq!(&bytes[192..224], &[6; 32]);
    assert_eq!(&bytes[224..256], &previous);
    assert_eq!(pins.0.lock().unwrap().0.last().copied(), Some(owner.pin()));
    assert!(owner.consume(5, [7; 32], [8; 32]).is_err());
    assert!(owner.consume(4, [5; 32], [6; 32]).is_err());
    assert!(owner.consume(6, [5; 32], [6; 32]).is_ok());
}
#[test]
fn cold_reopen_has_no_old_permit_and_rejects_stale_pin() {
    let path = directory("reopen");
    let mut owner = PreparedScopeStore::create(&path, binding(), Pins::default()).unwrap();
    let old = owner.pin();
    drop(owner.consume(5, [5; 32], [6; 32]).unwrap());
    let latest = owner.pin();
    drop(owner);
    assert!(PreparedScopeStore::open(&path, binding(), old, 0, Pins::default()).is_err());
    let mut reopened =
        PreparedScopeStore::open(&path, binding(), latest, 0, Pins::default()).unwrap();
    assert_eq!(reopened.earliest_round(), 6);
    assert!(reopened.consume(5, [7; 32], [8; 32]).is_err());
    assert!(reopened.consume(6, [7; 32], [8; 32]).is_ok());
}
#[test]
fn restarted_current_round_and_overflow_are_unavailable() {
    let path = directory("floor");
    let owner = PreparedScopeStore::create(&path, binding(), Pins::default()).unwrap();
    let pin = owner.pin();
    drop(owner);
    let mut reopened =
        PreparedScopeStore::open(&path, binding(), pin, 10, Pins::default()).unwrap();
    assert_eq!(reopened.earliest_round(), 13);
    assert!(reopened.consume(12, [5; 32], [6; 32]).is_err());
    drop(reopened);
    assert!(PreparedScopeStore::open(&path, binding(), pin, u64::MAX, Pins::default()).is_err());
}
#[test]
fn external_pin_failure_poisoned_before_any_receipt() {
    let path = directory("pins");
    let pins = Pins::default();
    let mut owner = PreparedScopeStore::create(&path, binding(), pins.clone()).unwrap();
    pins.0.lock().unwrap().1 = true;
    assert!(owner.consume(5, [5; 32], [6; 32]).is_err());
    pins.0.lock().unwrap().1 = false;
    assert!(owner.consume(6, [5; 32], [6; 32]).is_err());
    assert_eq!(
        u64::from_le_bytes(
            fs::read(path.join("CURRENT")).unwrap()[152..160]
                .try_into()
                .unwrap()
        ),
        5
    );
}
#[test]
fn exclusive_owner_and_binding_substitution_refused() {
    let path = directory("exclusive");
    let owner = PreparedScopeStore::create(&path, binding(), Pins::default()).unwrap();
    let pin = owner.pin();
    assert!(PreparedScopeStore::open(&path, binding(), pin, 0, Pins::default()).is_err());
    drop(owner);
    for which in 0..6 {
        let mut changed = binding();
        match which {
            0 => changed.role = ClaimRole::Exit,
            1 => changed.domain = [9; 32],
            2 => changed.config = [9; 32],
            3 => changed.profile = [9; 32],
            4 => changed.vk_hash = [9; 32],
            _ => changed.epoch = 1,
        };
        assert!(PreparedScopeStore::open(&path, changed, pin, 0, Pins::default()).is_err());
    }
}
#[test]
fn incomplete_stage_is_preserved_and_never_adopted() {
    let path = directory("stage");
    let owner = PreparedScopeStore::create(&path, binding(), Pins::default()).unwrap();
    let pin = owner.pin();
    drop(owner);
    fs::write(path.join("STAGE"), [0; 17]).unwrap();
    assert!(PreparedScopeStore::open(&path, binding(), pin, 0, Pins::default()).is_err());
    assert_eq!(fs::read(path.join("STAGE")).unwrap(), [0; 17]);
    assert!(PreparedScopeStore::create(&path, binding(), Pins::default()).is_err());
}
#[test]
fn corrupted_or_linked_snapshot_and_directory_alias_refused() {
    let path = directory("corrupt");
    let owner = PreparedScopeStore::create(&path, binding(), Pins::default()).unwrap();
    let pin = owner.pin();
    drop(owner);
    let mut bytes = fs::read(path.join("CURRENT")).unwrap();
    bytes[300] = 1;
    fs::write(path.join("CURRENT"), &bytes).unwrap();
    assert!(PreparedScopeStore::open(&path, binding(), pin, 0, Pins::default()).is_err());
    fs::hard_link(path.join("CURRENT"), path.join("ALIAS")).unwrap();
    assert!(PreparedScopeStore::open(&path, binding(), pin, 0, Pins::default()).is_err());
    let parent = directory("alias");
    symlink(&path, parent.join("store")).unwrap();
    assert!(
        PreparedScopeStore::open(&parent.join("store"), binding(), pin, 0, Pins::default())
            .is_err()
    );
}
#[test]
fn modified_live_storage_stops_owner_permanently() {
    let path = directory("live");
    let mut owner = PreparedScopeStore::create(&path, binding(), Pins::default()).unwrap();
    let mut bytes = fs::read(path.join("CURRENT")).unwrap();
    bytes[17] ^= 1;
    fs::write(path.join("CURRENT"), bytes).unwrap();
    assert!(owner.consume(5, [5; 32], [6; 32]).is_err());
    assert!(owner.consume(6, [5; 32], [6; 32]).is_err());
}
#[test]
fn epoch_and_unknown_zero_vk_refused_without_creating_files() {
    for which in 0..5 {
        let path = directory("unknown");
        let mut value = binding();
        match which {
            0 => value.domain = [0; 32],
            1 => value.config = [0; 32],
            2 => value.profile = [0; 32],
            3 => value.vk_hash = [0; 32],
            _ => value.vk_hash = super::OLD_VK,
        };
        assert!(PreparedScopeStore::create(&path, value, Pins::default()).is_err());
        assert_eq!(fs::read_dir(path).unwrap().count(), 0);
    }
    let path = directory("epoch");
    let mut value = binding();
    value.epoch = 1;
    let mut owner = PreparedScopeStore::create(&path, value, Pins::default()).unwrap();
    assert!(owner.consume(2879, [5; 32], [6; 32]).is_err());
    assert!(owner.consume(5760, [5; 32], [6; 32]).is_err());
    assert!(owner.consume(2880, [5; 32], [6; 32]).is_ok());
}
