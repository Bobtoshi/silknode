//! Synthetic opaque offers/clock/transport seam, no proof or day-long live run.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Valid,
    Absent,
    Rejected,
    Late,
}
#[derive(Clone, Copy)]
enum Offer {
    Idle,
    Ready,
    Delayed,
}
#[derive(Debug, PartialEq, Eq)]
struct Observable {
    index: u16,
    decision: i64,
    cell: Option<(i64, usize)>,
}
struct Model {
    time: i64,
    view: View,
    offer: Offer,
    pending: Option<u8>,
    traces: Vec<Observable>,
    consumed: usize,
    stopped: bool,
    failure_at: Option<i64>,
    delayed_done: bool,
}
impl Model {
    fn new(view: View, offer: Offer) -> Self {
        Self {
            time: DECISION_NS,
            view,
            offer,
            pending: matches!(offer, Offer::Ready).then_some(7),
            traces: Vec::new(),
            consumed: 0,
            stopped: false,
            failure_at: None,
            delayed_done: false,
        }
    }
    fn next_event(&self) -> i64 {
        let next = i64::try_from(self.traces.len()).unwrap() * ROUND_NS + DECISION_NS;
        let end = i64::from(ROUNDS - 1) * ROUND_NS + CLOSE_NS;
        let next = if self.traces.len() < usize::from(ROUNDS) {
            next
        } else {
            end
        };
        self.failure_at
            .filter(|&n| n > self.time)
            .map_or(next, |n| next.min(n))
    }
}
impl Runtime for Model {
    fn now(&self) -> i64 {
        self.time
    }
    fn inspect(&mut self) -> bool {
        true
    }
    fn admit(&mut self, index: u16, allow_offer: bool) -> bool {
        // V1/V3 fail BEFORE the queue branch, including a ready offer.
        if index == 8 && matches!(self.view, View::Absent | View::Late) {
            return false;
        }
        if allow_offer && self.pending.take().is_some() {
            self.consumed += 1;
        }
        let rejected = index == 8 && self.view == View::Rejected;
        if rejected {
            self.failure_at = Some(i64::from(index) * ROUND_NS + CLOSE_NS);
        }
        let provisional = self.failure_at.is_some_and(|n| self.time < n && index > 8);
        self.traces.push(Observable {
            index,
            decision: self.time,
            cell: (!rejected && !provisional)
                .then_some((i64::from(index) * ROUND_NS + 1_000_000_000, 8192)),
        });
        true
    }
    fn poll(&mut self) -> bool {
        self.failure_at.is_none_or(|n| self.time < n)
    }
    fn stop(&mut self) {
        self.pending = None;
        self.stopped = true;
    }
    fn pause(&mut self) {
        if matches!(self.offer, Offer::Delayed) && self.traces.len() == 9 && !self.delayed_done {
            // Preparation finishes AFTER q+8 selected cover; queue it for q+9,
            // never change the already selected cell or its slot.
            self.pending = Some(7);
            self.delayed_done = true;
        }
        self.time = self.next_event();
    }
}

#[test]
fn full_epoch_b1_cross_product_preserves_shape_or_same_terminal_transition() {
    for view in [View::Valid, View::Absent, View::Rejected, View::Late] {
        let mut baseline = None;
        for offer in [Offer::Idle, Offer::Ready, Offer::Delayed] {
            let mut model = Model::new(view, offer);
            let report = pump(&mut model);
            assert_eq!(report.decisions, 2880);
            assert_eq!(report.admitted + report.suppressed, 2880);
            assert!(model.stopped && model.pending.is_none());
            if view == View::Valid {
                assert!(!report.unhealthy);
                assert_eq!(report.admitted, 2880);
                for (i, trace) in model.traces.iter().enumerate() {
                    assert_eq!(
                        trace.decision,
                        i64::try_from(i).unwrap() * ROUND_NS + DECISION_NS
                    );
                    assert!(trace.cell.is_some());
                }
                assert_eq!(model.consumed, usize::from(!matches!(offer, Offer::Idle)));
            } else {
                assert!(report.unhealthy);
                if view == View::Rejected {
                    assert_eq!(report.admitted, 10); // eight warmup, failed q+8, provisional q+9
                    assert_eq!(model.time, 8 * ROUND_NS + CLOSE_NS);
                    assert!(model.traces[8].cell.is_none() && model.traces[9].cell.is_none());
                } else {
                    assert_eq!(report.admitted, 8);
                    assert_eq!(model.consumed, 0);
                    assert_eq!(model.time, 8 * ROUND_NS + DECISION_NS);
                }
            }
            let observable = (report, model.traces);
            if let Some(expected) = &baseline {
                assert_eq!(&observable, expected);
            } else {
                baseline = Some(observable);
            }
        }
    }
}

#[test]
fn missed_decision_is_terminal_without_late_admission_or_queue_consumption() {
    let mut model = Model::new(View::Valid, Offer::Ready);
    model.time = -8_000_000_000;
    let report = pump(&mut model);
    assert!(report.unhealthy);
    assert_eq!(report.suppressed, 2880);
    assert_eq!(model.consumed, 0);
}

#[test]
fn b2_restart_has_no_export_authority_and_fresh_authorization_is_a_distinct_attempt() {
    // Fake journal boundary: old exposed bytes/pins never change. This models
    // transport ownership only, not durability or global duplicate prevention.
    struct FakeJournal {
        exposed: u8,
        pin: [u8; 32],
        exports: usize,
    }
    impl FakeJournal {
        fn authorized_export(&mut self, fresh_human_authorization: bool) -> Option<u8> {
            if !fresh_human_authorization {
                return None;
            }
            self.exports += 1;
            Some(self.exposed)
        }
    }
    for consumed_before_crash in [false, true] {
        let mut journal = FakeJournal {
            exposed: 7,
            pin: [9; 32],
            exports: 0,
        };
        let mut old = Model::new(View::Valid, Offer::Idle);
        old.pending = journal.authorized_export(true);
        if consumed_before_crash {
            old.time = 8 * ROUND_NS + DECISION_NS;
            assert!(old.admit(8, true)); // includes possibly uncertain write
            assert_eq!(old.consumed, 1);
        }
        drop(old); // C0 pending or C1 consumed, no persistence/recovery endpoint
        let mut later = Model::new(View::Valid, Offer::Idle);
        assert!(later.pending.is_none());
        let report = pump(&mut later);
        assert!(!report.unhealthy);
        assert_eq!(later.consumed, 0);
        assert_eq!(journal.exports, 1);
        assert_eq!((journal.exposed, journal.pin), (7, [9; 32]));
        // New explicit authorization in a later selected session is permitted,
        // potentially linkable and NOT a retry concealed by the original claim.
        let mut separately_authorized = Model::new(View::Valid, Offer::Idle);
        separately_authorized.pending = journal.authorized_export(true);
        assert!(!pump(&mut separately_authorized).unhealthy);
        assert_eq!(separately_authorized.consumed, 1);
        assert_eq!(journal.exports, 2);
        assert_eq!((journal.exposed, journal.pin), (7, [9; 32]));
    }
}
