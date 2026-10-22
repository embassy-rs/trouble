use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Waker;

use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;

struct DiscreteTime {
    now: AtomicU64,
    queue: Mutex<Queue>,
    active: AtomicBool,
}

embassy_time_driver::time_driver_impl!(static DRIVER: DiscreteTime = DiscreteTime {
    now: AtomicU64::new(0),
    queue: Mutex::new(Queue::new()),
    active: AtomicBool::new(false),
});

impl Driver for DiscreteTime {
    fn now(&self) -> u64 {
        self.now.load(Ordering::Acquire)
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        let mut queue = self.queue.lock().unwrap();
        queue.schedule_wake(at, waker);
        queue.next_expiration(self.now());
    }
}

/// Owns the single process-wide clock without resetting Embassy's timebase.
pub(crate) struct ClockLease {
    origin: u64,
}

impl ClockLease {
    pub fn acquire() -> io::Result<Self> {
        DRIVER
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("only one discrete executor may be active per process"))?;
        Ok(Self { origin: DRIVER.now() })
    }

    pub fn advance_to(&self, elapsed_us: u64) -> io::Result<()> {
        let now = self
            .origin
            .checked_add(elapsed_us)
            .filter(|now| *now < u64::MAX)
            .ok_or_else(|| io::Error::other("simulation time overflow"))?;
        if now < DRIVER.now() {
            return Err(io::Error::other("simulation clock moved backwards"));
        }
        DRIVER.now.store(now, Ordering::Release);
        Ok(())
    }

    pub fn next_deadline(&self) -> u64 {
        DRIVER
            .queue
            .lock()
            .unwrap()
            .next_expiration(DRIVER.now())
            .saturating_sub(self.origin)
    }
}

impl Drop for ClockLease {
    fn drop(&mut self) {
        *DRIVER.queue.lock().unwrap() = Queue::new();
        DRIVER.active.store(false, Ordering::Release);
    }
}
