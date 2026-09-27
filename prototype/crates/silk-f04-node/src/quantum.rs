//! One parked worker stack is an opaque continuation of the unchanged algorithms.
//! No saved cursor, decoded metadata or partial result carries validity authority.
use crate::{Error, Result, budget::JobBudget};
use std::{
    sync::mpsc::{self, Receiver, SyncSender, TryRecvError},
    thread::{self, JoinHandle},
};

/// Conservative per-quantum accounting. A probe also counts plain graph reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    pub probes: u32,
    pub sources: u32,
    pub vertices: u32,
}
impl Usage {
    pub fn permits(self, extra: Self) -> bool {
        self.probes.saturating_add(extra.probes) <= 4096
            && self.sources.saturating_add(extra.sources) <= 16
            && self.vertices.saturating_add(extra.vertices) <= 8
    }
    pub fn add(&mut self, extra: Self) {
        self.probes += extra.probes;
        self.sources += extra.sources;
        self.vertices += extra.vertices;
    }
}
enum Event {
    Yielded(Usage),
    Finished,
}
pub(crate) struct Gate {
    permits: Receiver<()>,
    events: SyncSender<Event>,
}
impl Gate {
    pub fn check_cancelled(&self) -> Result<()> {
        match self.permits.try_recv() {
            Err(TryRecvError::Empty) => Ok(()),
            Err(TryRecvError::Disconnected) => Err(Error::Unavailable("continuation cancelled")),
            Ok(()) => Err(Error::Unavailable("unexpected queued continuation permit")),
        }
    }
    pub fn wait(&self) -> Result<()> {
        self.permits
            .recv()
            .map_err(|_| Error::Unavailable("continuation cancelled"))
    }
    pub fn yield_now(&self, used: Usage) -> Result<()> {
        self.events
            .send(Event::Yielded(used))
            .map_err(|_| Error::Unavailable("continuation cancelled"))?;
        self.wait()
    }
}

pub(crate) enum Progress<T> {
    Pending(Usage),
    Complete(Result<T>, JobBudget),
}
type Finished<T> = (Result<T>, JobBudget);

/// Owns the only derivation worker slot. A dropped job disconnects BOTH directions
/// and joins; it never detaches a worker or silently starts a replacement.
pub(crate) struct Job<T> {
    permits: Option<SyncSender<()>>,
    events: Option<Receiver<Event>>,
    result: Receiver<Finished<T>>,
    worker: Option<JoinHandle<()>>,
}
impl<T: Send + 'static> Job<T> {
    pub fn start(
        mut budget: JobBudget,
        work: impl FnOnce(&JobBudget) -> Result<T> + Send + 'static,
    ) -> Result<Self> {
        let (permit_tx, permit_rx) = mpsc::sync_channel(0);
        let (event_tx, event_rx) = mpsc::sync_channel(0);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("f04-derive".into())
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let gate = Gate {
                    permits: permit_rx,
                    events: event_tx.clone(),
                };
                let result = gate.wait().and_then(|()| {
                    budget.attach(gate);
                    budget.check()?;
                    let result = work(&budget);
                    budget.check()?;
                    result
                });
                budget.detach();
                let _ = result_tx.send((result, budget));
                let _ = event_tx.send(Event::Finished);
            })
            .map_err(|_| Error::Unavailable("continuation worker unavailable"))?;
        Ok(Self {
            permits: Some(permit_tx),
            events: Some(event_rx),
            result: result_rx,
            worker: Some(worker),
        })
    }

    /// Runs exactly one quantum. The caller must not start crypto/RandomX until
    /// Complete has joined this worker and returned the ORIGINAL enclosing budget.
    pub fn advance(&mut self) -> Result<Progress<T>> {
        let sent = self
            .permits
            .as_ref()
            .ok_or(Error::Unavailable("finished continuation"))?
            .send(());
        if sent.is_err() {
            self.disconnect();
            self.join()?;
            return Err(Error::Unavailable("continuation worker stopped"));
        }
        let event = self
            .events
            .as_ref()
            .ok_or(Error::Unavailable("finished continuation"))?
            .recv();
        let event = match event {
            Ok(event) => event,
            Err(_) => {
                self.disconnect();
                self.join()?;
                return Err(Error::Unavailable("continuation worker stopped"));
            }
        };
        match event {
            Event::Yielded(used) => Ok(Progress::Pending(used)),
            Event::Finished => {
                self.disconnect();
                self.join()?;
                let (result, budget) = self
                    .result
                    .recv()
                    .map_err(|_| Error::Unavailable("continuation result missing"))?;
                Ok(Progress::Complete(result, budget))
            }
        }
    }
}
impl<T> Job<T> {
    fn disconnect(&mut self) {
        self.permits.take();
        self.events.take();
    }
    fn join(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| Error::Unavailable("continuation worker panicked"))?;
        }
        Ok(())
    }
}
impl<T> Drop for Job<T> {
    fn drop(&mut self) {
        self.disconnect();
        let _ = self.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn exact_quantum_limits_and_no_background_progress() {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let mut job = Job::start(JobBudget::checkpoint().unwrap(), move |b| {
            for _ in 0..8193 {
                b.probe()?;
                observed.fetch_add(1, Ordering::SeqCst);
            }
            for _ in 0..17 {
                b.source()?;
            }
            b.replay()?;
            b.replay()?;
            Ok(27)
        })
        .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        let mut yields = Vec::new();
        let value = loop {
            match job.advance().unwrap() {
                Progress::Pending(used) => {
                    assert!(Usage::default().permits(used));
                    yields.push(used);
                }
                Progress::Complete(value, b) => {
                    b.check().unwrap();
                    break value.unwrap();
                }
            }
        };
        assert_eq!(value, 27);
        assert_eq!(
            yields.iter().map(|u| u.probes).collect::<Vec<_>>(),
            [4096, 4096, 1, 0]
        );
        assert_eq!(yields[2].sources, 16);
        assert_eq!(yields[3].vertices, 8);
        assert!(job.advance().is_err());
    }

    #[test]
    fn dropping_parked_job_reaps_without_running_it() {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let job = Job::start(JobBudget::vertex().unwrap(), move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap();
        drop(job);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dropping_yielded_job_cancels_before_next_probe() {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let mut job = Job::start(JobBudget::vertex().unwrap(), move |b| {
            for _ in 0..4097 {
                b.probe()?;
                observed.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })
        .unwrap();
        assert!(matches!(job.advance().unwrap(), Progress::Pending(_)));
        assert_eq!(count.load(Ordering::SeqCst), 4096);
        drop(job);
        assert_eq!(count.load(Ordering::SeqCst), 4096);
    }

    #[test]
    fn terminal_failure_keeps_original_allowance_across_worker_phases() {
        let mut job = Job::start(
            JobBudget::testing(std::time::Duration::from_millis(50)).unwrap(),
            |_| Err::<(), _>(Error::Invalid("fixture refusal")),
        )
        .unwrap();
        let Progress::Complete(result, budget) = job.advance().unwrap() else {
            panic!("no quantum needed")
        };
        assert!(matches!(result, Err(Error::Invalid("fixture refusal"))));
        std::thread::sleep(std::time::Duration::from_millis(60));
        let mut second = Job::start(budget, |_| {
            panic!("expired allowance cannot execute next phase")
        })
        .unwrap();
        let Progress::<()>::Complete(result, budget) = second.advance().unwrap() else {
            panic!("expired")
        };
        assert!(matches!(result, Err(Error::Paused(_))));
        assert!(matches!(budget.check(), Err(Error::Paused(_))));
    }

    #[test]
    fn wall_time_while_parked_counts_and_panic_is_reaped() {
        let mut job = Job::start(
            JobBudget::testing(std::time::Duration::from_millis(50)).unwrap(),
            |b| {
                for _ in 0..4097 {
                    b.probe()?;
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(matches!(job.advance().unwrap(), Progress::Pending(_)));
        std::thread::sleep(std::time::Duration::from_millis(60));
        assert!(matches!(
            job.advance().unwrap(),
            Progress::Complete(Err(Error::Paused(_)), _)
        ));
        let mut panic_job = Job::<()>::start(JobBudget::vertex().unwrap(), |_| {
            panic!("fixture worker panic")
        })
        .unwrap();
        assert!(matches!(
            panic_job.advance(),
            Err(Error::Unavailable("continuation worker panicked"))
        ));
        assert!(panic_job.worker.is_none());
    }
}
