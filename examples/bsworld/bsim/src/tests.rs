use std::cell::RefCell;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixListener;
use std::rc::Rc;
use std::sync::Mutex;
use std::task::Poll;

use bt_hci::controller::{Controller, ControllerCmdSync, ExternalController};
use embassy_futures::join::join;
use embassy_time::{Instant, Timer};

use crate::{Clock, Executor};

// Embassy intentionally has one time driver per process, including test binaries.
static SERIAL: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct TestClock {
    now: u64,
    waits: Rc<RefCell<Vec<u64>>>,
    on_wait: Option<Box<dyn FnMut(u64)>>,
}

impl Clock for TestClock {
    fn now_us(&self) -> u64 {
        self.now
    }

    fn wait_until(&mut self, target_us: u64) -> io::Result<()> {
        self.waits.borrow_mut().push(target_us);
        self.now = target_us;
        if let Some(callback) = self.on_wait.as_mut() {
            callback(target_us);
        }
        Ok(())
    }
}

#[test]
fn timers_follow_exact_microsecond_deadlines() {
    let _guard = SERIAL.lock().unwrap();
    let clock = TestClock::default();
    let waits = clock.waits.clone();
    let mut executor = Executor::new(clock).unwrap();
    executor
        .block_on(async {
            let start = Instant::now();
            let (early, late) = join(
                async {
                    Timer::after_micros(7).await;
                    Instant::now() - start
                },
                async {
                    Timer::after_micros(2_003).await;
                    Instant::now() - start
                },
            )
            .await;
            assert_eq!(early.as_micros(), 7);
            assert_eq!(late.as_micros(), 2_003);
        })
        .unwrap();
    assert_eq!(*waits.borrow(), [0, 7, 1_007, 2_003]);
}

#[test]
fn each_pending_poll_with_a_self_wake_yields_one_microsecond() {
    let _guard = SERIAL.lock().unwrap();
    let clock = TestClock::default();
    let waits = clock.waits.clone();
    let mut executor = Executor::new(clock).unwrap();
    let mut polls = 0;
    executor
        .block_on(poll_fn(|cx| {
            polls += 1;
            if polls < 10 {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }))
        .unwrap();
    // Nine self-waking Pending polls yield; the final Ready result returns directly.
    assert_eq!(*waits.borrow(), (0..10).collect::<Vec<_>>());
}

#[test]
fn waking_another_future_yields_but_idle_timer_wait_does_not() {
    let _guard = SERIAL.lock().unwrap();
    let clock = TestClock::default();
    let waits = clock.waits.clone();
    let mut executor = Executor::new(clock).unwrap();
    let signal = embassy_sync::signal::Signal::<embassy_sync::blocking_mutex::raw::NoopRawMutex, ()>::new();
    executor
        .block_on(async {
            let start = Instant::now();
            let (received_at, ()) = join(
                async {
                    signal.wait().await;
                    Instant::now()
                },
                async {
                    signal.signal(());
                    Timer::after_micros(5).await;
                },
            )
            .await;
            assert_eq!((received_at - start).as_micros(), 1);
            assert_eq!((Instant::now() - start).as_micros(), 5);
        })
        .unwrap();
    assert_eq!(*waits.borrow(), [0, 1, 5]);
}

#[test]
fn self_waking_future_cannot_starve_other_devices_or_timers() {
    let _guard = SERIAL.lock().unwrap();
    let clock = TestClock::default();
    let waits = clock.waits.clone();
    let mut executor = Executor::new(clock).unwrap();
    executor
        .block_on(async {
            embassy_futures::select::select(
                poll_fn::<(), _>(|cx| {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }),
                Timer::after_micros(3),
            )
            .await;
        })
        .unwrap();
    assert_eq!(*waits.borrow(), [0, 1, 2, 3]);
}

#[test]
fn sequential_executors_keep_embassy_time_monotonic() {
    let _guard = SERIAL.lock().unwrap();
    let first = {
        let mut executor = Executor::new(TestClock::default()).unwrap();
        assert!(Executor::new(TestClock::default()).is_err());
        assert!(executor.set_max_step_us(0).is_err());
        executor
            .block_on(async {
                Timer::after_micros(23).await;
                Instant::now()
            })
            .unwrap()
    };
    let mut executor = Executor::new(TestClock::default()).unwrap();
    let second = executor.block_on(async { Instant::now() }).unwrap();
    assert_eq!(first, second);
}

#[test]
fn controller_handles_fragmented_h4_response_and_socket_eof() {
    let _guard = SERIAL.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hci.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut executor = Executor::new(TestClock::default()).unwrap();
    let controller = ExternalController::<_, 8>::new(executor.connect_hci(path).unwrap());
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
    let mut stage = 0;
    executor.clock.on_wait = Some(Box::new(move |target| {
        assert!(target < 10_000, "H4 exchange did not finish within the test deadline");
        if stage == 0 && target >= 1_000 {
            let mut reset = [0; 4];
            peer.read_exact(&mut reset).unwrap();
            assert_eq!(reset, [1, 3, 12, 0]);
            peer.write_all(&[4, 14]).unwrap();
            stage = 1;
        } else if stage == 1 && target >= 2_000 {
            peer.write_all(&[4, 1, 3, 12, 0]).unwrap();
            stage = 2;
        } else if stage == 2 && target >= 3_000 {
            peer.shutdown(std::net::Shutdown::Write).unwrap();
            stage = 3;
        }
    }));
    executor
        .block_on(async {
            let mut buffer = controller.alloc_buf().unwrap();
            let commands = async {
                controller
                    .exec(&bt_hci::cmd::controller_baseband::Reset::new())
                    .await
                    .unwrap();
                Timer::after_micros(1_000).await;
            };
            let reader = async {
                // ExternalController dispatches Command Complete internally.
                assert!(controller.read(&mut buffer).await.is_err());
            };
            join(commands, reader).await;
        })
        .unwrap();
}

#[test]
fn clock_errors_propagate_instead_of_hanging() {
    let _guard = SERIAL.lock().unwrap();
    struct BrokenClock;
    impl Clock for BrokenClock {
        fn now_us(&self) -> u64 {
            0
        }
        fn wait_until(&mut self, _: u64) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "test PHY stopped"))
        }
    }
    let error = Executor::new(BrokenClock)
        .unwrap()
        .block_on(std::future::pending::<()>())
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn invalid_clock_grants_are_rejected() {
    let _guard = SERIAL.lock().unwrap();
    struct StuckClock;
    impl Clock for StuckClock {
        fn now_us(&self) -> u64 {
            0
        }
        fn wait_until(&mut self, _: u64) -> io::Result<()> {
            Ok(())
        }
    }
    let error = Executor::new(StuckClock)
        .unwrap()
        .block_on(std::future::pending::<()>())
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
}
