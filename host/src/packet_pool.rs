//! A packet pool for allocating and freeing packet buffers with quality of service policy.
use core::cell::RefCell;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::types::l2cap::{L2CAP_CID_ATT, L2CAP_CID_DYN_START};

// Generic client ID used by ATT PDU
pub(crate) const ATT_ID: AllocId = AllocId(0);

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct AllocId(usize);

impl AllocId {
    pub(crate) fn dynamic(idx: usize) -> AllocId {
        // Dynamic range starts at 2
        AllocId(1 + idx)
    }

    pub(crate) fn from_channel(cid: u16) -> AllocId {
        match cid {
            L2CAP_CID_ATT => ATT_ID,
            cid if cid >= L2CAP_CID_DYN_START => Self::dynamic((cid - L2CAP_CID_DYN_START) as usize),
            cid => {
                panic!("unexpected channel id {}", cid);
            }
        }
    }
}

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

/// Quality of service policy for packet allocation
#[derive(Clone, Copy, Default)]
pub enum Qos {
    /// Distribute evenly among client
    Fair,
    /// Reserve at least N packets for each client
    Guaranteed(usize),
    /// No guarantees
    #[default]
    None,
}

struct State<const MTU: usize, const N: usize, const CLIENTS: usize> {
    packets: [PacketBuf<MTU>; N],
    usage: [usize; CLIENTS],
}

impl<const MTU: usize, const N: usize, const CLIENTS: usize> State<MTU, N, CLIENTS> {
    pub(crate) const fn new() -> Self {
        Self {
            packets: [PacketBuf::NEW; N],
            usage: [0; CLIENTS],
        }
    }

    // Guaranteed available
    fn min_available(&self, qos: Qos, client: AllocId) -> usize {
        let min = match qos {
            Qos::None => N.saturating_sub(self.usage.iter().sum()),
            Qos::Fair => (N / CLIENTS).saturating_sub(self.usage[client.0]),
            Qos::Guaranteed(n) => {
                let usage = self.usage[client.0];
                n.saturating_sub(usage)
            }
        };
        // info!("Min available for {}: {} (usage: {})", client.0, min, usage[client.0]);
        min
    }

    fn available(&self, qos: Qos, client: AllocId) -> usize {
        let available = match qos {
            Qos::None => N.saturating_sub(self.usage.iter().sum()),
            Qos::Fair => (N / CLIENTS).saturating_sub(self.usage[client.0]),
            Qos::Guaranteed(n) => {
                // Reserved for clients that should have minimum
                let reserved = n * self.usage.iter().filter(|c| **c == 0).count();
                let reserved = reserved
                    - if self.usage[client.0] < n {
                        n - self.usage[client.0]
                    } else {
                        0
                    };
                let usage = reserved + self.usage.iter().sum::<usize>();
                N.saturating_sub(usage)
            }
        };
        // info!("Available for {}: {} (usage {})", client.0, available, usage[client.0]);
        available
    }

    fn alloc(&mut self, id: AllocId) -> Option<PacketRef> {
        for (idx, packet) in self.packets.iter_mut().enumerate() {
            if packet.free {
                // info!("[{}] alloc {}", id.0, idx);
                packet.free = false;
                packet.buf.iter_mut().for_each(|b| *b = 0);
                self.usage[id.0] += 1;
                return Some(PacketRef {
                    idx,
                    buf: &mut packet.buf[..],
                });
            }
        }
        None
    }

    fn free(&mut self, id: AllocId, p_ref: PacketRef) {
        // info!("[{}] free {}", id.0, p_ref.idx);
        self.packets[p_ref.idx].free = true;
        self.usage[id.0] -= 1;
    }
}

/// A packet pool holds a pool of packet buffers that can be dynamically allocated
/// and free'd.
///
/// The pool has a concept QoS to control quota for multiple clients.
pub struct PacketPool<M: RawMutex, const MTU: usize, const N: usize, const CLIENTS: usize> {
    state: Mutex<M, RefCell<State<MTU, N, CLIENTS>>>,
    qos: Qos,
}

impl<M: RawMutex, const MTU: usize, const N: usize, const CLIENTS: usize> PacketPool<M, MTU, N, CLIENTS> {
    /// Create a new packet pool with the given QoS policy
    pub fn new(qos: Qos) -> Self {
        // Need at least 1 for gatt
        assert!(CLIENTS >= 1);
        match qos {
            Qos::None => {}
            Qos::Fair => {
                assert!(N >= CLIENTS);
            }
            Qos::Guaranteed(n) => {
                assert!(N >= n);
            }
        }
        Self {
            state: Mutex::new(RefCell::new(State::new())),
            qos,
        }
    }

    fn alloc(&self, id: AllocId) -> Option<Packet> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            let available = state.available(self.qos, id);
            if available == 0 {
                return None;
            }

            state.alloc(id).map(|p_ref| Packet {
                client: id,
                p_ref: Some(p_ref),
                pool: self,
            })
        })
    }

    fn free(&self, id: AllocId, p_ref: PacketRef) {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            state.free(id, p_ref);
        });
    }

    fn min_available(&self, id: AllocId) -> usize {
        self.state.lock(|state| {
            let state = state.borrow();
            state.min_available(self.qos, id)
        })
    }

    fn available(&self, id: AllocId) -> usize {
        self.state.lock(|state| {
            let state = state.borrow();
            state.available(self.qos, id)
        })
    }
}

pub(crate) trait GlobalPacketPool<'d> {
    fn alloc(&'d self, id: AllocId) -> Option<Packet<'d>>;
    fn free(&self, id: AllocId, r: PacketRef);
    fn available(&self, id: AllocId) -> usize;
    fn min_available(&self, id: AllocId) -> usize;
    fn mtu(&self) -> usize;
}

impl<'d, M: RawMutex, const MTU: usize, const N: usize, const CLIENTS: usize> GlobalPacketPool<'d>
    for PacketPool<M, MTU, N, CLIENTS>
{
    fn alloc(&'d self, id: AllocId) -> Option<Packet<'d>> {
        PacketPool::alloc(self, id)
    }

    fn min_available(&self, id: AllocId) -> usize {
        PacketPool::min_available(self, id)
    }

    fn available(&self, id: AllocId) -> usize {
        PacketPool::available(self, id)
    }

    fn free(&self, id: AllocId, r: PacketRef) {
        PacketPool::free(self, id, r)
    }

    fn mtu(&self) -> usize {
        MTU
    }
}

pub(crate) struct PacketRef {
    idx: usize,
    buf: *mut [u8],
}

pub(crate) struct Packet<'d> {
    client: AllocId,
    p_ref: Option<PacketRef>,
    pool: &'d dyn GlobalPacketPool<'d>,
}

impl Packet<'_> {
    pub(crate) fn len(&self) -> usize {
        self.as_ref().len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Drop for Packet<'_> {
    fn drop(&mut self) {
        if let Some(r) = self.p_ref.take() {
            self.pool.free(self.client, r);
        }
    }
}

impl AsRef<[u8]> for Packet<'_> {
    fn as_ref(&self) -> &[u8] {
        let p = self.p_ref.as_ref().unwrap();
        unsafe { &(*p.buf)[..] }
    }
}

impl AsMut<[u8]> for Packet<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        let p = self.p_ref.as_mut().unwrap();
        unsafe { &mut (*p.buf)[..] }
    }
}

#[cfg(test)]
mod tests {
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;
    use static_cell::StaticCell;

    use super::*;

    #[test]
    fn test_fair_qos() {
        static POOL: StaticCell<PacketPool<NoopRawMutex, 1, 8, 4>> = StaticCell::new();
        let pool = POOL.init(PacketPool::new(Qos::Fair));

        let a1 = pool.alloc(AllocId(0));
        assert!(a1.is_some());
        let a2 = pool.alloc(AllocId(0));
        assert!(a2.is_some());
        assert!(pool.alloc(AllocId(0)).is_none());
        drop(a2);
        let a3 = pool.alloc(AllocId(0));
        assert!(a3.is_some());

        let b1 = pool.alloc(AllocId(1));
        assert!(b1.is_some());

        let c1 = pool.alloc(AllocId(2));
        assert!(c1.is_some());
    }

    #[test]
    fn test_none_qos() {
        static POOL: StaticCell<PacketPool<NoopRawMutex, 1, 8, 4>> = StaticCell::new();
        let pool = POOL.init(PacketPool::new(Qos::None));

        let a1 = pool.alloc(AllocId(0));
        assert!(a1.is_some());
        let a2 = pool.alloc(AllocId(0));
        assert!(a2.is_some());
        let a3 = pool.alloc(AllocId(0));
        assert!(a3.is_some());
        let a4 = pool.alloc(AllocId(0));
        assert!(a4.is_some());
        let a5 = pool.alloc(AllocId(0));
        assert!(a5.is_some());
        let a6 = pool.alloc(AllocId(0));
        assert!(a6.is_some());
        let a7 = pool.alloc(AllocId(0));
        assert!(a7.is_some());

        let b1 = pool.alloc(AllocId(1));
        assert!(b1.is_some());

        let b2 = pool.alloc(AllocId(1));
        assert!(b2.is_none());
    }

    #[test]
    fn test_guaranteed_qos() {
        static POOL: StaticCell<PacketPool<NoopRawMutex, 1, 8, 4>> = StaticCell::new();
        let pool = POOL.init(PacketPool::new(Qos::Guaranteed(1)));

        let a1 = pool.alloc(AllocId(0));
        assert!(a1.is_some());
        let a2 = pool.alloc(AllocId(0));
        assert!(a2.is_some());
        let a3 = pool.alloc(AllocId(0));
        assert!(a3.is_some());
        let a4 = pool.alloc(AllocId(0));
        assert!(a4.is_some());
        let a5 = pool.alloc(AllocId(0));
        assert!(a5.is_some());
        // Needs at least 3 for the other clients
        assert!(pool.alloc(AllocId(0)).is_none());

        let b1 = pool.alloc(AllocId(1));
        assert!(b1.is_some());
        assert!(pool.alloc(AllocId(1)).is_none());

        let c1 = pool.alloc(AllocId(2));
        assert!(c1.is_some());
        assert!(pool.alloc(AllocId(2)).is_none());

        let d1 = pool.alloc(AllocId(3));
        assert!(d1.is_some());
        assert!(pool.alloc(AllocId(3)).is_none());
    }

    #[test]
    fn test_guaranteed_qos_many() {
        static POOL: StaticCell<PacketPool<NoopRawMutex, 1, 8, 8>> = StaticCell::new();
        let pool = POOL.init(PacketPool::new(Qos::Guaranteed(1)));

        let a1 = pool.alloc(AllocId(0));
        assert!(a1.is_some());
        // Needs at least 1 for the other clients
        assert!(pool.alloc(AllocId(0)).is_none());

        let b1 = pool.alloc(AllocId(1));
        assert!(b1.is_some());
        assert!(pool.alloc(AllocId(1)).is_none());

        let c1 = pool.alloc(AllocId(2));
        assert!(c1.is_some());
        assert!(pool.alloc(AllocId(2)).is_none());

        let d1 = pool.alloc(AllocId(3));
        assert!(d1.is_some());
        assert!(pool.alloc(AllocId(3)).is_none());
    }
}
