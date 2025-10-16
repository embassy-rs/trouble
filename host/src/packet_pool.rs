//! A packet pool for allocating and freeing packet buffers with quality of service policy.
use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use embassy_sync::blocking_mutex::Mutex;

use crate::{config, Packet, PacketPool};

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

    fn alloc(&mut self) -> Option<PacketRef<MTU>> {
        for (idx, packet) in self.packets.iter_mut().enumerate() {
            if packet.free {
                // info!("[{}] alloc {}", id.0, idx);
                packet.free = false;
                packet.buf.iter_mut().for_each(|b| *b = 0);
                return Some(PacketRef {
                    idx,
                    buf: packet.buf.as_mut_ptr(),
                });
            }
        }
        None
    }

    fn free(&mut self, p_ref: &PacketRef<MTU>) {
        // info!("[{}] free {}", id.0, p_ref.idx);
        self.packets[p_ref.idx].free = true;
    }

    fn available(&mut self) -> usize {
        self.packets.iter().filter(|p| p.free).count()
    }
}

/// A packet pool holds a pool of packet buffers that can be dynamically allocated
/// and freed.
pub struct StaticPacketPool<M: RawMutex, const MTU: usize, const N: usize> {
    state: Mutex<M, RefCell<State<MTU, N>>>,
}

impl<M: RawMutex, const MTU: usize, const N: usize> Default for StaticPacketPool<M, MTU, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: RawMutex, const MTU: usize, const N: usize> StaticPacketPool<M, MTU, N> {
    /// Create a new packet pool with the given QoS policy
    const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(State::new())),
        }
    }

    fn alloc(&self) -> Option<PacketRef<MTU>> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            state.alloc()
        })
    }

    fn free(&self, p_ref: &PacketRef<MTU>) {
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

/// Represents a reference to a packet.
#[repr(C)]
pub struct PacketRef<const MTU: usize> {
    idx: usize,
    buf: *mut u8,
}

/// Global default packet pool.
pub type DefaultPacketPool = StaticPacketPool<
    CriticalSectionRawMutex,
    { config::DEFAULT_PACKET_POOL_MTU },
    { config::DEFAULT_PACKET_POOL_SIZE },
>;

static DEFAULT_POOL: StaticPacketPool<
    CriticalSectionRawMutex,
    { config::DEFAULT_PACKET_POOL_MTU },
    { config::DEFAULT_PACKET_POOL_SIZE },
> = StaticPacketPool::new();

impl PacketPool for DefaultPacketPool {
    type Packet = DefaultPacket;
    const MTU: usize = { config::DEFAULT_PACKET_POOL_MTU };
    fn capacity() -> usize {
        config::DEFAULT_PACKET_POOL_SIZE
    }

    fn allocate() -> Option<DefaultPacket> {
        DEFAULT_POOL.alloc().map(|p| DefaultPacket {
            p_ref: p,
            pool: &DEFAULT_POOL,
        })
    }
}

/// Type representing the packet from the default packet pool.
pub struct DefaultPacket {
    p_ref: PacketRef<{ config::DEFAULT_PACKET_POOL_MTU }>,
    pool: &'static DefaultPacketPool,
}

impl Packet for DefaultPacket {}
impl AsRef<[u8]> for DefaultPacket {
    fn as_ref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.p_ref.buf, config::DEFAULT_PACKET_POOL_MTU) }
    }
}

impl AsMut<[u8]> for DefaultPacket {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.p_ref.buf, config::DEFAULT_PACKET_POOL_MTU) }
    }
}

impl Drop for DefaultPacket {
    fn drop(&mut self) {
        self.pool.free(&self.p_ref);
    }
}

#[cfg(test)]
mod tests {
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;

    #[test]
    fn test_none_qos() {
        let pool: StaticPacketPool<NoopRawMutex, 27, 8> = StaticPacketPool::new();

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
