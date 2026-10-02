//! Third-party-style checks use the public compiled library, not private source.
#[cfg(test)]
mod economics {
    use silk_f04_node::{
        VertexId,
        economics::{CREDIT_MATURITY_V1, EconomicLedgerV1, PRIVATE_BURN_V1, PUBLIC_CREDIT_V1},
        genesis::{parameter_bytes, public_testnet_v1},
        state::BranchState,
    };

    fn synthetic_rows(count: u8) -> (Vec<VertexId>, Vec<[u8; 112]>) {
        let executed = (1..=count).map(|i| VertexId::from_bytes([i; 32])).collect();
        let mut rows = vec![[0_u8; 112]; usize::from(count)];
        for (index, row) in rows.iter_mut().enumerate() {
            row[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            row[8..40].copy_from_slice(&[index as u8 + 1; 32]);
            row[104..].copy_from_slice(&10_u64.to_le_bytes());
        }
        (executed, rows)
    }

    #[test]
    fn economic_ledger_genesis_and_committed_rules_preserve_existing_profile() {
        // Construction checks the independently pinned complete bundle/domain.
        let genesis = public_testnet_v1::genesis().unwrap();
        let state = BranchState::genesis(&genesis).unwrap();
        let ledger = state.economic_ledger();
        ledger.validate(&genesis.domain(), genesis.total()).unwrap();
        assert_eq!(
            (
                ledger.public_issued,
                ledger.private_pool,
                ledger.private_burned
            ),
            (0, 0, 0)
        );
        assert!(ledger.reward_records.is_empty());
        assert_eq!(state.public_balance(&[7; 32]), (0, 0));
        let parameters = parameter_bytes();
        for (id, value, frozen) in [
            (13, PUBLIC_CREDIT_V1, 10),
            (14, CREDIT_MATURITY_V1, 16),
            (29, PRIVATE_BURN_V1, 1),
        ] {
            let at = 16 + 16 * (id - 1) + 8;
            assert_eq!(
                u64::from_le_bytes(parameters[at..at + 8].try_into().unwrap()),
                frozen
            );
            assert_eq!(value, frozen);
        }
    }

    #[test]
    fn economic_ledger_rejects_each_changed_reward_lineage_and_amount() {
        let genesis = public_testnet_v1::genesis().unwrap();
        let state = BranchState::genesis(&genesis).unwrap();
        let mut ledger = state.economic_ledger();
        let (executed, rows) = synthetic_rows(8);
        ledger.executed = &executed;
        ledger.public_issued = 80;
        ledger.reward_records = &rows;
        ledger.validate(&genesis.domain(), 0).unwrap();
        for index in 0..rows.len() {
            for offset in [0, 8, 104] {
                let mut changed = rows.clone();
                changed[index][offset] ^= 1;
                let altered = EconomicLedgerV1 {
                    reward_records: &changed,
                    ..ledger
                };
                assert!(altered.validate(&genesis.domain(), 0).is_err());
            }
        }
        let mut reordered = rows.clone();
        reordered.swap(0, 1);
        ledger.reward_records = &reordered;
        assert!(ledger.validate(&genesis.domain(), 0).is_err());
        ledger.reward_records = &rows[..7];
        assert!(ledger.validate(&genesis.domain(), 0).is_err());
    }

    #[test]
    fn economic_ledger_keeps_credit_issuance_separate_from_private_conservation() {
        let genesis = public_testnet_v1::genesis().unwrap();
        let state = BranchState::genesis(&genesis).unwrap();
        let mut ledger = state.economic_ledger();
        let (executed, rows) = synthetic_rows(8);
        ledger.executed = &executed;
        ledger.reward_records = &rows;
        ledger.public_issued = 80;
        ledger.private_pool = 97;
        ledger.private_burned = 3;
        ledger.accepted_effects = 3;
        ledger.validate(&genesis.domain(), 100).unwrap();
        assert!(ledger.validate(&[99; 32], 100).is_err());
        assert!(ledger.validate(&genesis.domain(), 101).is_err());
        ledger.public_issued = 81; // Credits cannot cover private supply loss.
        assert!(ledger.validate(&genesis.domain(), 100).is_err());
        ledger.public_issued = 80;
        ledger.accepted_effects = 4; // Burn count must equal distinct effect count.
        assert!(ledger.validate(&genesis.domain(), 100).is_err());
        ledger.private_pool = u64::MAX;
        ledger.private_burned = 1;
        ledger.accepted_effects = 1;
        assert!(ledger.validate(&genesis.domain(), 0).is_err());
        ledger.private_pool = 0;
        ledger.private_burned = 50_001;
        ledger.accepted_effects = 50_001;
        assert!(ledger.validate(&genesis.domain(), 50_001).is_err());
        ledger.executed = &[];
        ledger.reward_records = &[];
        ledger.public_issued = 0;
        ledger.private_burned = 1;
        ledger.accepted_effects = 1;
        assert!(ledger.validate(&genesis.domain(), 1).is_err());
    }

    #[test]
    fn economic_ledger_reversible_prefix_recomputes_issuance_not_accumulated_mints() {
        let genesis = public_testnet_v1::genesis().unwrap();
        let state = BranchState::genesis(&genesis).unwrap();
        let mut ledger = state.economic_ledger();
        let (executed, rows) = synthetic_rows(24);
        for count in [24, 8, 0, 16, 24] {
            ledger.executed = &executed[..count];
            ledger.reward_records = &rows[..count];
            ledger.public_issued = count as u128 * 10;
            ledger.validate(&genesis.domain(), 0).unwrap();
            ledger.public_issued += 10;
            assert!(ledger.validate(&genesis.domain(), 0).is_err());
        }
        ledger.executed = &executed[..7];
        ledger.reward_records = &rows[..7];
        ledger.public_issued = 70;
        assert!(ledger.validate(&genesis.domain(), 0).is_err());
    }
}

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
mod storage {
    use silk_f04_node::{
        Error,
        carriage::Body,
        genesis::public_testnet_v1,
        node::{Node, NodeStatus},
        sync::RangeBatchV1,
    };
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
        path::{Path, PathBuf},
    };

    fn fixture() -> (Node, PathBuf, PathBuf) {
        let nonce = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        let root =
            std::env::temp_dir().join(format!("silknode-storage-{}-{nonce}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let margin = root.join("margin");
        fs::DirBuilder::new().mode(0o700).create(&margin).unwrap();
        let node = Node::create(
            &root.join("node"),
            &margin,
            public_testnet_v1::genesis().unwrap(),
        )
        .unwrap();
        (node, root, margin)
    }

    fn candidate() -> Vec<u8> {
        let hex: String = include_str!("public-zero-eight.hex")
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let bytes = hex::decode(hex).unwrap();
        // Use only unverified framing of the first anchor carrier. Neither this
        // helper nor the refusal checks run RandomX or Sapling verification.
        RangeBatchV1::decode(&bytes, 0, 8).unwrap().carriers()[0].to_vec()
    }

    fn inventory(root: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
        fs::read_dir(root)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect()
    }

    #[test]
    fn storage_preflight_capacity_refusal_preserves_ready_node_and_all_store_bytes() {
        let (mut node, root, margin) = fixture();
        let store = root.join("node");
        let before = inventory(&store);
        let accounted = node.accounted_bytes();
        let head = node.local_head().unwrap();
        let digest = node.state().unwrap().digest();
        // Redirect only this fixture's margin mapping. Existing cross-filesystem
        // quota/host-margin checks refuse; no real disk is filled or limit relaxed.
        let retained = root.join("margin-retained");
        fs::rename(&margin, &retained).unwrap();
        symlink("/dev", &margin).unwrap();
        assert!(matches!(
            node.begin_ingest(&candidate()),
            Err(Error::Paused(_))
        ));
        // Mining-entry preflight only: the same refusal precedes all native work.
        assert!(matches!(
            node.mine_current(
                Body::new(&node.genesis().domain(), &[]).unwrap(),
                [2; 32],
                [3; 32],
                None
            ),
            Err(Error::Paused(_))
        ));
        assert_eq!(node.status().unwrap(), NodeStatus::Ready);
        assert_eq!(node.local_head().unwrap(), head);
        assert_eq!(node.state().unwrap().digest(), digest);
        assert_eq!(node.accounted_bytes(), accounted);
        assert_eq!(inventory(&store), before);
        fs::remove_file(&margin).unwrap(); // This exact fixture-owned symlink only.
        fs::rename(retained, &margin).unwrap();
        node.flush_clock().unwrap(); // No reopening or retrying an unfinished job.
        assert_eq!(node.status().unwrap(), NodeStatus::Ready);
        assert_eq!(node.state().unwrap().digest(), digest);
    }

    #[test]
    fn storage_preflight_write_failure_still_faults_writer_and_keeps_complete_head() {
        let (mut node, root, _) = fixture();
        let store = root.join("node");
        let before = inventory(&store);
        let accounted = node.accounted_bytes();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o500)).unwrap();
        let error = node.begin_ingest(&candidate()).unwrap_err();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(error, Error::Io(_)));
        assert!(node.status().is_err());
        assert!(node.flush_clock().is_err());
        assert!(node.accounted_bytes() > accounted); // Attempt reservation stays charged.
        assert_eq!(inventory(&store), before);
    }

    #[test]
    fn storage_preflight_existing_attempt_is_not_a_resumable_capacity_refusal() {
        use sha2::{Digest as _, Sha256};
        let (mut node, root, _) = fixture();
        let store = root.join("node");
        let marker = b"synthetic unfinished attempt, not received validity";
        let id = hex::encode(Sha256::digest(marker));
        fs::write(store.join(format!("{id}.obj")), marker).unwrap();
        fs::write(store.join("ACTIVE_JOB"), id).unwrap();
        let before = inventory(&store);
        assert!(matches!(
            node.begin_ingest(&candidate()),
            Err(Error::Paused(
                "incomplete local job requires explicit bounded authority"
            ))
        ));
        assert!(node.status().is_err());
        assert!(node.begin_ingest(&candidate()).is_err());
        assert_eq!(inventory(&store), before);
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
