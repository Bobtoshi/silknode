//! Live receiver-derived recovery pages; never decoded as persisted validity.
#[cfg(test)]
use crate::budget::JobBudget;
use crate::{Digest, Error, Result, store::Store};
use silk_sapling_f04::codec::RECOVERY_BYTES;
use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(count: usize) -> RecoveryHistory {
        // Synthetic encrypted-row storage model ONLY, not real admitted notes.
        let mut rows = RecoveryHistory::new(256);
        for position in 0..count {
            let mut row = [0; RECOVERY_BYTES];
            row[..8].copy_from_slice(&(position as u64).to_le_bytes());
            rows.push(Arc::new(row)).unwrap();
        }
        rows
    }
    #[test]
    fn disk_recovery_unfenced_or_uncertain_write_stops_without_directory_or_head_credit() {
        use std::os::unix::fs::PermissionsExt;
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        let rows = fixture(1);
        let accounted = store.accounted_bytes();
        assert!(rows.retain(&mut store, [19; 32], &budget).is_err());
        assert_eq!(store.accounted_bytes(), accounted);
        assert_eq!(store.head(), None);
        store
            .begin_replay(b"synthetic recovery write refusal")
            .unwrap();
        let root = temp.path().join("store");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(
            rows.retain(&mut store, [19; 32], &budget),
            Err(Error::Unavailable(
                "retained recovery page publication failed"
            ))
        ));
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(store.head(), None);
        assert!(matches!(
            store.check_external_write(1),
            Err(Error::Unavailable(
                "store requires reopen after failed write"
            ))
        ));
        assert_eq!(rows.len(), 1);
    }
    #[test]
    fn disk_recovery_detaches_rows_and_preserves_exact_positions_and_held_directory() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic recovery page fixture")
            .unwrap();
        let rows = fixture(129);
        let weak = Arc::downgrade(rows.get(64).unwrap());
        let retained = rows.retain(&mut store, [19; 32], &budget).unwrap();
        let head = store.head();
        assert_eq!(retained.retained_ids().len(), 3);
        assert_eq!(retained.cache_charge(), rows.cache_charge());
        let expected = rows.iter().map(|row| **row).collect::<Vec<_>>();
        drop(rows);
        assert!(weak.upgrade().is_none());
        let restored = retained.materialize(Some(&budget)).unwrap();
        assert_eq!(
            restored.iter().map(|row| **row).collect::<Vec<_>>(),
            expected
        );
        assert!(restored.get(129).is_none());
        assert!(restored.get(usize::MAX).is_none());
        assert_eq!(store.head(), head);
        drop(store);
        assert_eq!(
            retained
                .materialize(Some(&budget))
                .unwrap()
                .iter()
                .map(|row| **row)
                .collect::<Vec<_>>(),
            expected
        );
    }
    #[test]
    fn disk_recovery_missing_tampered_or_hardlinked_page_refuses_complete_materialization() {
        let (temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store
            .begin_replay(b"synthetic recovery refusal fixture")
            .unwrap();
        let rows = fixture(129);
        let retained = rows.retain(&mut store, [19; 32], &budget).unwrap();
        let ids = retained.retained_ids();
        let path = temp
            .path()
            .join("store")
            .join(format!("{}.obj", hex::encode(ids[2])));
        let held = path.with_extension("held");
        let bytes = std::fs::read(&path).unwrap();
        let head = store.head();
        std::fs::rename(&path, &held).unwrap();
        assert!(matches!(
            retained.materialize(Some(&budget)),
            Err(Error::Io(_))
        ));
        assert_eq!(retained.retained_ids(), ids);
        assert_eq!(retained.len(), 129);
        assert_eq!(store.head(), head);
        std::fs::rename(&held, &path).unwrap();
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(retained.materialize(Some(&budget)).is_err());
        std::fs::write(&path, &bytes).unwrap();
        std::fs::hard_link(&path, &held).unwrap();
        assert!(retained.materialize(Some(&budget)).is_err());
        std::fs::remove_file(&held).unwrap();
        assert_eq!(
            retained.materialize(Some(&budget)).unwrap().as_slice(),
            rows.as_slice()
        );
        assert_eq!(store.head(), head);
    }
    #[test]
    fn disk_recovery_fork_reuses_full_pages_and_keeps_distinct_tails_and_context() {
        let (_temp, mut store) = crate::store::ancestry_test_store();
        let budget = JobBudget::checkpoint().unwrap();
        store.begin_replay(b"synthetic recovery forks").unwrap();
        let base = fixture(129).retain(&mut store, [19; 32], &budget).unwrap();
        let mut left = base.materialize(Some(&budget)).unwrap();
        let mut right = base.materialize(Some(&budget)).unwrap();
        left.push(Arc::new([1; RECOVERY_BYTES])).unwrap();
        right.push(Arc::new([2; RECOVERY_BYTES])).unwrap();
        let left = left.retain(&mut store, [19; 32], &budget).unwrap();
        let right = right.retain(&mut store, [19; 32], &budget).unwrap();
        assert_eq!(&base.retained_ids()[..2], &left.retained_ids()[..2]);
        assert_eq!(&base.retained_ids()[..2], &right.retained_ids()[..2]);
        assert_ne!(left.retained_ids()[2], right.retained_ids()[2]);
        assert_ne!(base.retained_ids()[2], left.retained_ids()[2]);
        assert_eq!(base.len(), 129);
        let accounted = store.accounted_bytes();
        assert!(left.retain(&mut store, [20; 32], &budget).is_err());
        assert_eq!(store.accounted_bytes(), accounted);
        assert_eq!(
            left.materialize(Some(&budget))
                .unwrap()
                .get(129)
                .unwrap()
                .as_slice(),
            &[1; RECOVERY_BYTES]
        );
        assert_eq!(
            right
                .materialize(Some(&budget))
                .unwrap()
                .get(129)
                .unwrap()
                .as_slice(),
            &[2; RECOVERY_BYTES]
        );
    }
}
pub(super) type RecoveryHistory = super::history::LedgerHistory<Arc<[u8; RECOVERY_BYTES]>>;

impl super::history::Item for Arc<[u8; RECOVERY_BYTES]> {
    const MAGIC: [u8; 8] = *b"SNF04RP1";
    const WIDTH: usize = RECOVERY_BYTES;
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(self.as_slice());
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(Arc::new(bytes.try_into().map_err(|_| {
            Error::Unavailable("retained recovery row")
        })?))
    }
    fn validate_encoded(bytes: &[u8]) -> Result<()> {
        if bytes.len() != RECOVERY_BYTES {
            return Err(Error::Unavailable("retained recovery row"));
        }
        Ok(())
    }
    fn retain_page(store: &mut Store, bytes: &[u8]) -> Result<Digest> {
        store.retain_recovery_page(bytes)
    }
}
