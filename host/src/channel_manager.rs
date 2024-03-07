use core::cell::RefCell;

use bt_hci::param::ConnHandle;
use embassy_sync::{
    blocking_mutex::{raw::RawMutex, Mutex},
    channel::Channel,
};

const BASE_ID: u16 = 0x40;

pub enum L2capEvent {
    Bound(ConnHandle, u16),
    Unbound(ConnHandle, u16),
}

pub struct ChannelManager<'d, M: RawMutex> {
    channels: Mutex<M, RefCell<&'d mut [ChannelStorage]>>,
}

impl<'d, M: RawMutex> ChannelManager<'d, M> {
    pub fn new(channels: &'d mut [ChannelStorage]) -> Self {
        Self {
            channels: Mutex::new(RefCell::new(channels)),
        }
    }

    pub fn update<F: FnOnce(&mut ChannelState)>(&self, cid: u16, f: F) -> Result<(), ()> {
        self.channels.lock(|channels| {
            let mut channels = channels.borrow_mut();
            for storage in channels.iter_mut() {
                if let Some(stored) = storage.state.as_mut() {
                    if stored.cid == cid {
                        f(stored);
                        break;
                    }
                }
            }
            Ok(())
        })
    }

    // Remove binding between a connection and a channel
    pub fn unbind(&self, cid: u16) -> Result<(), ()> {
        self.channels.lock(|channels| {
            let mut channels = channels.borrow_mut();
            for storage in channels.iter_mut() {
                if let Some(stored) = &storage.state {
                    if stored.cid == cid {
                        storage.state.take();
                        break;
                    }
                }
            }
            Ok(())
        })
    }

    // Bind a channel to a connection
    pub fn bind(&self, conn: ConnHandle, mut state: ChannelState) -> Result<u16, ()> {
        self.channels.lock(|channels| {
            let mut channels = channels.borrow_mut();
            for (idx, storage) in channels.iter_mut().enumerate() {
                if storage.state.is_none() {
                    let cid: u16 = BASE_ID + idx as u16;
                    state.conn = conn;
                    state.cid = cid;
                    storage.state.replace(state);
                    return Ok(cid);
                }
            }
            Err(())
        })
    }
}

#[derive(Clone)]
pub struct ChannelState {
    pub(crate) conn: ConnHandle,
    pub(crate) scid: u16,
    pub(crate) cid: u16,
    pub(crate) credits: u16,
}

pub struct ChannelStorage {
    state: Option<ChannelState>,
}

impl ChannelStorage {
    pub const UNUSED: Self = Self { state: None };
}
