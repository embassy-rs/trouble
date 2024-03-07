use core::cell::RefCell;

use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::{raw::RawMutex, Mutex};

const BASE_ID: u16 = 0x40;

pub struct ChannelManager<'d, M: RawMutex> {
    channels: Mutex<M, RefCell<&'d mut [ChannelState]>>,
}

impl<'d, M: RawMutex> ChannelManager<'d, M> {
    pub fn new(channels: &'d mut [ChannelState]) -> Self {
        Self {
            channels: Mutex::new(RefCell::new(channels)),
        }
    }

    pub fn update<F: FnOnce(&mut ChannelState)>(&self, c_id: u16, f: F) -> Result<(), ()> {
        self.channels.lock(|channels| {
            let mut channels = channels.borrow_mut();
            for storage in channels.iter_mut() {
                match storage {
                    ChannelState::Bound(BoundChannel { cid, .. }) if *cid == c_id => {
                        f(storage);
                        break;
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    // Remove binding between a connection and a channel
    pub fn free(&self, id: u16) -> Result<(), ()> {
        self.channels.lock(|channels| {
            let mut channels = channels.borrow_mut();
            for storage in channels.iter_mut() {
                match storage {
                    ChannelState::Bound(BoundChannel { cid, .. }) if *cid == id => {
                        *storage = ChannelState::Free;
                        break;
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    pub fn alloc(&self, id: u8, psm: u16) -> Result<u16, ()> {
        self.channels.lock(|channels| {
            let mut channels = channels.borrow_mut();
            for (idx, storage) in channels.iter_mut().enumerate() {
                if let ChannelState::Free = storage {
                    let cid: u16 = BASE_ID + idx as u16;
                    *storage = ChannelState::Reserved(id, cid, psm);
                    return Ok(cid);
                }
            }
            Err(())
        })
    }

    // Bind a channel to a connection
    pub fn bind(&self, id: u8, state: UnboundChannel) -> Result<BoundChannel, ()> {
        self.channels.lock(|channels| {
            let mut channels = channels.borrow_mut();
            for (idx, storage) in channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Reserved(rid, cid, psm) if *rid == id => {
                        let cid: u16 = BASE_ID + idx as u16;
                        let state = BoundChannel {
                            conn: state.conn,
                            cid,
                            idx,
                            psm: *psm,
                            credits: 1,
                            remote_cid: state.scid,
                            remote_credits: state.credits,
                        };
                        *storage = ChannelState::Bound(state.clone());
                        return Ok(state);
                    }
                    _ => {}
                }
            }
            Err(())
        })
    }
}

#[derive(Clone)]
pub enum ChannelState {
    Free,
    Reserved(u8, u16, u16),
    Bound(BoundChannel),
}

#[derive(Clone)]
pub struct UnboundChannel {
    pub(crate) conn: ConnHandle,
    pub(crate) scid: u16,
    pub(crate) credits: u16,
}

#[derive(Clone)]
pub struct BoundChannel {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
    pub(crate) idx: usize,
    pub(crate) psm: u16,

    pub(crate) credits: u16,
    pub(crate) remote_cid: u16,
    pub(crate) remote_credits: u16,
}
