use core::cell::RefCell;

use embassy_sync::blocking_mutex::{raw::RawMutex, Mutex};

pub struct ChannelManager<'d, M: RawMutex> {
    channels: Mutex<M, RefCell<&'d mut [ChannelStorage]>>,
}

impl<'d, M: RawMutex> ChannelManager<'d, M> {
    pub fn new(channels: &'d mut [ChannelStorage]) -> Self {
        Self {
            channels: Mutex::new(RefCell::new(channels)),
        }
    }

    pub fn update<F: FnOnce(&mut ChannelState)>(&self, f: F) {
        todo!()
    }

    pub fn create(&self, cid: u16, state: &ChannelState) -> Result<(), ()> {
        todo!()
    }
}

#[derive(Clone)]
pub struct ChannelState {
    cid: u16,
    credits: u16,
}

pub struct ChannelStorage {
    state: Option<ChannelState>,
}

impl ChannelStorage {
    pub const UNUSED: Self = Self { state: None };
}
