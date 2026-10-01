//! Third-party-style checks use the public compiled library, not private source.
#[cfg(test)]
mod sync {
    use silk_f04_node::{
        carriage::MAX_VERTEX_BYTES,
        sync::{RANGE_LIMIT_V1, RangeBatchV1},
    };

    fn frame(values: &[&[u8]]) -> Vec<u8> {
        let mut bytes = vec![u8::try_from(values.len()).unwrap()];
        for value in values {
            bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(value);
        }
        bytes
    }

    #[test]
    fn public_adapter_preserves_unverified_bytes_and_existing_limits() {
        let bytes = frame(&[b"unverified", b"still not a valid carrier"]);
        let range = RangeBatchV1::decode(&bytes, 4094, 4096).unwrap();
        assert_eq!(
            range.carriers(),
            &[
                b"unverified".as_slice(),
                b"still not a valid carrier".as_slice()
            ]
        );
        let maximum = vec![7; MAX_VERTEX_BYTES];
        let bytes = frame(&vec![maximum.as_slice(); RANGE_LIMIT_V1]);
        assert_eq!(
            RangeBatchV1::decode(&bytes, 4064, 4096)
                .unwrap()
                .carriers()
                .len(),
            32
        );
    }

    #[test]
    fn public_adapter_refuses_incomplete_excessive_or_trailing_frames() {
        let good = frame(&[b"first", b"second"]);
        for cut in 0..good.len() {
            assert!(RangeBatchV1::decode(&good[..cut], 0, 2).is_err());
        }
        let mut extra = good.clone();
        extra.push(0);
        assert!(RangeBatchV1::decode(&extra, 0, 2).is_err());
        for (bytes, start, total) in [
            (&[0][..], 0, 1),
            (&[33][..], 0, 4096),
            (good.as_slice(), 0, 1),
            (good.as_slice(), usize::MAX, 4096),
            (good.as_slice(), 0, 4097),
            (good.as_slice(), 2, 2),
        ] {
            assert!(RangeBatchV1::decode(bytes, start, total).is_err());
        }
        assert!(RangeBatchV1::decode(&frame(&[b""]), 0, 1).is_err());
        let mut oversized = vec![1];
        oversized.extend_from_slice(&u32::try_from(MAX_VERTEX_BYTES + 1).unwrap().to_be_bytes());
        assert!(RangeBatchV1::decode(&oversized, 0, 1).is_err());
    }
}

#[cfg(test)]
mod capacity {
    use silk_f04_node::{
        Error,
        capacity::{GENERATION_LIMIT_V1, HistoryCapacityV1},
        genesis::public_testnet_v1,
        node::Node,
        sync::HISTORY_LIMIT_V1,
    };

    #[test]
    fn capacity_preflight_reserves_admission_rollback_and_complete_reconciliation() {
        // No prior executed state needs rollback; vertex eight can complete one interval.
        let cap = HistoryCapacityV1::for_counts(GENERATION_LIMIT_V1 - 2, 7, 0).unwrap();
        assert_eq!(cap.admission_generations, 2);
        cap.check_admission().unwrap();
        assert!(matches!(
            HistoryCapacityV1::for_counts(GENERATION_LIMIT_V1 - 1, 7, 0)
                .unwrap()
                .check_admission(),
            Err(Error::Paused("generation reference horizon"))
        ));
        // A preferred-history change can require one rollback and rebuilding every interval.
        let cap =
            HistoryCapacityV1::for_counts(GENERATION_LIMIT_V1 - 514, 4095, 4095 / 8 * 8).unwrap();
        assert_eq!(cap.admission_generations, 514);
        cap.check_admission().unwrap();
        assert!(
            HistoryCapacityV1::for_counts(GENERATION_LIMIT_V1 - 513, 4095, 4088)
                .unwrap()
                .check_admission()
                .is_err()
        );
        // A final non-checkpoint admission is safe, but no later generation is promised.
        let cap = HistoryCapacityV1::for_counts(GENERATION_LIMIT_V1 - 1, 0, 0).unwrap();
        assert_eq!(cap.admission_generations, 1);
        cap.check_admission().unwrap();
        assert!(cap.check_generations(2).is_err());
    }

    #[test]
    fn capacity_preflight_keeps_reference_horizons_and_rejects_inconsistent_counts() {
        let cap = HistoryCapacityV1::for_counts(1, HISTORY_LIMIT_V1, HISTORY_LIMIT_V1).unwrap();
        assert!(matches!(
            cap.check_admission(),
            Err(Error::Paused("admitted-vertex reference horizon"))
        ));
        let cap = HistoryCapacityV1::for_counts(GENERATION_LIMIT_V1, 0, 0).unwrap();
        assert!(cap.check_generations(1).is_err());
        cap.check_generations(0).unwrap();
        for (sequence, vertices, executed) in [
            (GENERATION_LIMIT_V1 + 1, 0, 0),
            (0, HISTORY_LIMIT_V1 + 1, 0),
            (0, 7, 8),
            (0, 7, 1),
            (u64::MAX, usize::MAX, usize::MAX),
        ] {
            assert!(HistoryCapacityV1::for_counts(sequence, vertices, executed).is_err());
        }
    }

    #[test]
    fn capacity_preflight_reconciliation_preserves_clock_headroom_and_handles_forks() {
        for (executed, common, eligible, expected) in [
            (0, 0, 7, 0),
            (0, 0, 8, 1),
            (8, 8, 15, 0),
            (8, 8, 16, 1),
            (16, 8, 8, 2),
            (4096, 0, 4096, 513),
            (8, 0, 0, 1),
        ] {
            assert_eq!(
                HistoryCapacityV1::reconciliation_generations(executed, common, eligible).unwrap(),
                expected
            );
        }
        let remaining = HistoryCapacityV1::reconciliation_generations(16, 8, 24).unwrap();
        let capacity =
            HistoryCapacityV1::for_counts(GENERATION_LIMIT_V1 - remaining, 24, 16).unwrap();
        capacity.check_generations(remaining).unwrap();
        assert!(capacity.check_generations(1 + remaining).is_err());
        for counts in [(7, 0, 8), (8, 9, 16), (8, 8, 7), (4096, 0, 4097)] {
            assert!(
                HistoryCapacityV1::reconciliation_generations(counts.0, counts.1, counts.2)
                    .is_err()
            );
        }
    }

    #[test]
    fn capacity_preflight_public_node_report_is_read_only_and_tracks_clock_publication() {
        use std::{fs, os::unix::fs::DirBuilderExt};
        let nonce = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        let root =
            std::env::temp_dir().join(format!("silknode-capacity-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let mut node = Node::create(
            &root.join("node"),
            &root,
            public_testnet_v1::genesis().unwrap(),
        )
        .unwrap();
        let head = node.local_head().unwrap();
        let digest = node.state().unwrap().digest();
        let accounted = node.accounted_bytes();
        let before = node.history_capacity().unwrap();
        assert_eq!(before.generations_remaining, GENERATION_LIMIT_V1 - 1);
        assert_eq!(before.vertices_remaining, HISTORY_LIMIT_V1);
        assert_eq!(node.history_capacity().unwrap(), before);
        assert_eq!(node.local_head().unwrap(), head);
        assert_eq!(node.accounted_bytes(), accounted);
        node.flush_clock().unwrap();
        let after = node.history_capacity().unwrap();
        assert_eq!(
            after.generations_remaining,
            before.generations_remaining - 1
        );
        assert_eq!(after.vertices_remaining, before.vertices_remaining);
        assert_eq!(after.admission_generations, before.admission_generations);
        assert_eq!(node.state().unwrap().digest(), digest);
        assert_eq!(node.vertex_count(), 0);
    }
}
