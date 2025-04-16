//! A packet pool for allocating and freeing packet buffers with quality of service policy.
use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::pool::{Packet, PacketRef, Pool};

struct PacketBuf<const MTU: usize> {
    buf: [u8; MTU],
    free: bool,
}

impl<const MTU: usize> PacketBuf<MTU> {
    const NEW: PacketBuf<MTU> = PacketBuf::new();

    pub(crate) const fn new() -> Self {
        Self {
            buf: [0; MTU],
            free: true,
        }
    }
}

struct State<const MTU: usize, const N: usize> {
    packets: [PacketBuf<MTU>; N],
}

impl<const MTU: usize, const N: usize> State<MTU, N> {
    pub(crate) const fn new() -> Self {
        Self {
            packets: [PacketBuf::NEW; N],
        }
    }

    fn alloc(&mut self) -> Option<PacketRef> {
        for (idx, packet) in self.packets.iter_mut().enumerate() {
            if packet.free {
                // info!("[{}] alloc {}", id.0, idx);
                packet.free = false;
                packet.buf.iter_mut().for_each(|b| *b = 0);
                return Some(PacketRef {
                    idx,
                    buf: &mut packet.buf[..],
                });
            }
        }
        None
    }

    fn free(&mut self, p_ref: PacketRef) {
        // info!("[{}] free {}", id.0, p_ref.idx);
        self.packets[p_ref.idx].free = true;
    }

    fn available(&mut self) -> usize {
        self.packets.iter().filter(|p| p.free).count()
    }
}

/// A packet pool holds a pool of packet buffers that can be dynamically allocated
/// and free'd.
pub struct PacketPool<const MTU: usize, const N: usize> {
    state: Mutex<NoopRawMutex, RefCell<State<MTU, N>>>,
}

impl<const MTU: usize, const N: usize> Default for PacketPool<MTU, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MTU: usize, const N: usize> PacketPool<MTU, N> {
    /// Create a new packet pool with the given QoS policy
    pub fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(State::new())),
        }
    }

    fn alloc(&self) -> Option<Packet> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            state.alloc().map(|p_ref| Packet {
                p_ref: Some(p_ref),
                pool: self,
            })
        })
    }

    fn free(&self, p_ref: PacketRef) {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            state.free(p_ref);
        });
    }

    fn available(&self) -> usize {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            state.available()
        })
    }
}

impl<const MTU: usize, const N: usize> Pool for PacketPool<MTU, N> {
    fn new() -> Self {
        PacketPool::new()
    }

    fn alloc(&self) -> Option<Packet> {
        PacketPool::alloc(self)
    }

    fn free(&self, r: PacketRef) {
        PacketPool::free(self, r)
    }

    fn available(&self) -> usize {
        PacketPool::available(self)
    }

    fn mtu(&self) -> usize {
        MTU
    }
}

#[cfg(test)]
mod tests {
    use static_cell::StaticCell;

    use super::*;

    #[test]
    fn test_none_qos() {
        static POOL: StaticCell<PacketPool<1, 8>> = StaticCell::new();
        let pool = POOL.init(PacketPool::new());

        let a1 = pool.alloc();
        assert!(a1.is_some());
        let a2 = pool.alloc();
        assert!(a2.is_some());
        let a3 = pool.alloc();
        assert!(a3.is_some());
        let a4 = pool.alloc();
        assert!(a4.is_some());
        let a5 = pool.alloc();
        assert!(a5.is_some());
        let a6 = pool.alloc();
        assert!(a6.is_some());
        let a7 = pool.alloc();
        assert!(a7.is_some());

        let b1 = pool.alloc();
        assert!(b1.is_some());

        let b2 = pool.alloc();
        assert!(b2.is_none());
    }
}
