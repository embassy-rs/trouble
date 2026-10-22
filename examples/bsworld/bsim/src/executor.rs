use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use crate::time::ClockLease;
use crate::unix::{Reactor, UnixTransport};

/// A simulation participant that relinquishes execution until an absolute time.
pub trait Clock {
    /// Current simulation time in integer microseconds.
    fn now_us(&self) -> u64;

    /// Yield to the scheduler and return only when the target has been granted.
    /// A target equal to `now_us()` is a synchronization barrier.
    fn wait_until(&mut self, target_us: u64) -> io::Result<()>;
}

struct Ready(AtomicBool);

impl Wake for Ready {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

/// A single-thread executor using simulation time for all Embassy timers.
///
/// Join application futures using ordinary async combinators. Tasks must use
/// this executor's Unix transport and Embassy timers; external worker threads,
/// wall-clock timers, and blocking I/O are outside its scheduling contract.
pub struct Executor<C> {
    pub(crate) clock: C,
    time: ClockLease,
    io: Reactor,
    max_step_us: u64,
}

impl<C: Clock> Executor<C> {
    /// Bind an exclusive Embassy time driver to a clock starting at zero.
    /// HCI input is checked at least every 1,000 simulated microseconds.
    pub fn new(clock: C) -> io::Result<Self> {
        if clock.now_us() != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "clock must start at zero"));
        }
        Ok(Self {
            clock,
            time: ClockLease::acquire()?,
            io: Reactor::default(),
            max_step_us: 1_000,
        })
    }

    /// Set the maximum interval between HCI socket polls, in simulation time.
    pub fn set_max_step_us(&mut self, step: u64) -> io::Result<()> {
        if step == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "step must be positive"));
        }
        self.max_step_us = step;
        Ok(())
    }

    /// Connect an H4 socket for use with `bt_hci::controller::ExternalController`.
    pub fn connect_hci(&self, path: impl AsRef<Path>) -> io::Result<UnixTransport> {
        self.io.connect(path.as_ref())
    }

    /// Run until the root future finishes or the simulation clock fails.
    /// After a pending poll that wakes more work, yield one simulated microsecond
    /// to other devices. Pending polls without a wake use the normal idle wait,
    /// shortened to the next timer deadline, without an extra microsecond.
    pub fn block_on<F: Future>(&mut self, future: F) -> io::Result<F::Output> {
        let ready = Arc::new(Ready(AtomicBool::new(true)));
        let waker = Waker::from(ready.clone());
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);

        self.wait_until(self.clock.now_us())?;
        loop {
            self.time.advance_to(self.clock.now_us())?;
            self.io.poll()?;
            let deadline = self.time.next_deadline();
            if ready.0.swap(false, Ordering::AcqRel) {
                if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
                    return Ok(value);
                }
                if ready.0.load(Ordering::Acquire) {
                    // Keep the wake pending, but relinquish the PHY grant before
                    // polling again. This also covers self-waking OnceLock waits.
                    let target = self.clock.now_us().saturating_add(1);
                    self.wait_until(target)?;
                }
                continue;
            }

            let target = self.clock.now_us().saturating_add(self.max_step_us).min(deadline);
            if target <= self.clock.now_us() || target == u64::MAX {
                return Err(io::Error::other("simulation clock cannot advance"));
            }
            self.wait_until(target)?;
        }
    }

    fn wait_until(&mut self, target: u64) -> io::Result<()> {
        if target == u64::MAX {
            return Err(io::Error::other("simulation time overflow"));
        }
        self.clock.wait_until(target)?;
        if self.clock.now_us() != target {
            return Err(io::Error::other("clock did not grant the requested time"));
        }
        Ok(())
    }
}
