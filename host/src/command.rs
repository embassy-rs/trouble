use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use embassy_sync::waitqueue::WakerRegistration;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    Active,
    Cancel,
    Idle,
}

pub struct Inner {
    state: State,
    host: WakerRegistration,
    controller: WakerRegistration,
}

/// A helper type for keeping track of the state of a controller command.
pub struct CommandState {
    inner: RefCell<Inner>,
}

impl CommandState {
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(Inner {
                state: State::Idle,
                host: WakerRegistration::new(),
                controller: WakerRegistration::new(),
            }),
        }
    }

    fn with_inner<F: FnMut(&mut Inner) -> R, R>(&self, mut f: F) -> R {
        let mut inner = self.inner.borrow_mut();
        f(&mut inner)
    }

    /// Request a new command
    pub async fn request(&self) {
        poll_fn(|cx| {
            self.with_inner(|inner| {
                inner.host.register(cx.waker());
                match inner.state {
                    State::Idle => {
                        info!("command in state {:?}, ready", inner.state);
                        inner.state = State::Active;
                        Poll::Ready(())
                    }
                    _ => {
                        info!("command in state {:?}, waiting", inner.state);
                        Poll::Pending
                    }
                }
            })
        })
        .await
    }

    /// Request a new command.
    pub async fn wait_idle(&self) {
        poll_fn(|cx| {
            self.with_inner(|inner| {
                inner.host.register(cx.waker());
                match inner.state {
                    State::Idle => Poll::Ready(()),
                    _ => Poll::Pending,
                }
            })
        })
        .await
    }

    /// Poll if the command should be canceled
    pub fn poll_cancelled(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.with_inner(|inner| {
            inner.controller.register(cx.waker());
            match inner.state {
                State::Cancel => Poll::Ready(()),
                _ => Poll::Pending,
            }
        })
    }

    /// Request that any pending command be canceled
    pub fn cancel(&self) {
        self.with_inner(|inner| {
            inner.state = State::Cancel;
            inner.controller.wake();
        })
    }

    /// Signal that a command has been canceled.
    pub fn canceled(&self) {
        self.with_inner(|inner| {
            inner.state = State::Idle;
            inner.host.wake();
        })
    }

    pub fn done(&self) {
        self.with_inner(|inner| {
            inner.state = State::Idle;
        })
    }
}
