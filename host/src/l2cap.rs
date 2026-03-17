//! L2CAP channels.
use bt_hci::controller::{blocking, Controller};
use bt_hci::param::ConnHandle;

pub use crate::channel_manager::CreditFlowPolicy;
#[cfg(feature = "channel-metrics")]
pub use crate::channel_manager::Metrics as ChannelMetrics;
use crate::channel_manager::{ChannelIndex, ChannelManager};
use crate::connection::Connection;
use crate::pdu::Sdu;
pub use crate::types::l2cap::LeCreditConnResultCode;
use crate::{BleHostError, Error, PacketPool, Stack};

pub(crate) mod sar;

/// Handle representing an L2CAP channel.
pub struct L2capChannel<'d, P: PacketPool> {
    index: ChannelIndex,
    manager: &'d ChannelManager<'d, P>,
}

/// Handle representing an L2CAP channel write endpoint.
pub struct L2capChannelWriter<'d, P: PacketPool> {
    index: ChannelIndex,
    manager: &'d ChannelManager<'d, P>,
}

/// Handle representing an L2CAP channel write endpoint.
pub struct L2capChannelReader<'d, P: PacketPool> {
    index: ChannelIndex,
    manager: &'d ChannelManager<'d, P>,
}

/// Handle to an L2CAP channel for checking it's state.
pub struct L2capChannelRef<'d, P: PacketPool> {
    index: ChannelIndex,
    manager: &'d ChannelManager<'d, P>,
}

#[cfg(feature = "defmt")]
impl<P: PacketPool> defmt::Format for L2capChannel<'_, P> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{}, ", self.index);
        self.manager.print(self.index, f);
    }
}

impl<P: PacketPool> Drop for L2capChannel<'_, P> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

impl<P: PacketPool> Drop for L2capChannelRef<'_, P> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

#[cfg(feature = "defmt")]
impl<P: PacketPool> defmt::Format for L2capChannelWriter<'_, P> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{}, ", self.index);
        self.manager.print(self.index, f);
    }
}

impl<P: PacketPool> Drop for L2capChannelWriter<'_, P> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

#[cfg(feature = "defmt")]
impl<P: PacketPool> defmt::Format for L2capChannelReader<'_, P> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "{}, ", self.index);
        self.manager.print(self.index, f);
    }
}

impl<P: PacketPool> Drop for L2capChannelReader<'_, P> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

/// A pending incoming L2CAP connection that can be inspected, then accepted or rejected.
///
/// Dropping this without calling [`accept`](Self::accept) or [`reject`](Self::reject) will
/// silently free the channel slot (the peer will time out).
pub struct L2capPendingConnection<'d, P: PacketPool> {
    index: Option<ChannelIndex>,
    manager: &'d ChannelManager<'d, P>,
    conn: ConnHandle,
}

impl<'d, P: PacketPool> L2capPendingConnection<'d, P> {
    pub(crate) fn new(index: ChannelIndex, manager: &'d ChannelManager<'d, P>, conn: ConnHandle) -> Self {
        Self {
            index: Some(index),
            manager,
            conn,
        }
    }

    /// Consume the pending connection and return the channel index, preventing the Drop cleanup.
    pub(crate) fn into_index(mut self) -> ChannelIndex {
        self.index.take().unwrap()
    }

    /// Get the PSM of the incoming connection request.
    pub fn psm(&self) -> u16 {
        self.manager.psm(self.index.unwrap())
    }

    /// Get the peer's requested MTU.
    pub fn mtu(&self) -> u16 {
        self.manager.mtu(self.index.unwrap())
    }

    /// Accept the connection, negotiate parameters, and return an established channel.
    pub async fn accept<T: Controller>(
        self,
        stack: &'d Stack<'d, T, P>,
        config: &L2capChannelConfig,
    ) -> Result<L2capChannel<'d, P>, BleHostError<T::Error>> {
        let index = self.into_index();
        stack.host.channels.accept_pending(index, config, &stack.host).await
    }

    /// Reject the connection with the given result code.
    pub async fn reject<T: Controller>(
        mut self,
        stack: &Stack<'_, T, P>,
        result: LeCreditConnResultCode,
    ) -> Result<(), BleHostError<T::Error>> {
        let index = self.index.take().unwrap();
        stack.host.channels.reject_pending(index, result, &stack.host).await
    }
}

impl<P: PacketPool> Drop for L2capPendingConnection<'_, P> {
    fn drop(&mut self) {
        if let Some(index) = self.index.take() {
            error!("L2capPendingConnection dropped without being accepted or rejected");
            self.manager.drop_pending(index);
        }
    }
}

/// Configuration for an L2CAP channel.
#[derive(Default)]
pub struct L2capChannelConfig {
    /// Size of Service Data Unit. Defaults to packet allocator MTU-6.
    pub mtu: Option<u16>,
    /// Frame size (1 frame == 1 credit). Defaults to packet allocator MTU-4.
    pub mps: Option<u16>,
    /// Flow control policy for connection oriented channels.
    pub flow_policy: CreditFlowPolicy,
    /// Initial credits for connection oriented channels.
    pub initial_credits: Option<u16>,
}

impl<'d, P: PacketPool> L2capChannel<'d, P> {
    pub(crate) fn new(index: ChannelIndex, manager: &'d ChannelManager<'d, P>) -> Self {
        Self { index, manager }
    }

    /// Disconnect this channel.
    pub fn disconnect(&mut self) {
        self.manager.disconnect(self.index);
    }

    /// Get the PSM for this channel.
    pub fn psm(&self) -> u16 {
        self.manager.psm(self.index)
    }

    /// Get the negotiated MTU for this channel.
    pub fn mtu(&self) -> u16 {
        self.manager.mtu(self.index)
    }

    /// Get the negotiated MPS for this channel.
    pub fn mps(&self) -> u16 {
        self.manager.mps(self.index)
    }

    /// Get the peer's MTU for this channel.
    pub fn peer_mtu(&self) -> u16 {
        self.manager.peer_mtu(self.index)
    }

    /// Get the peer's MPS for this channel.
    pub fn peer_mps(&self) -> u16 {
        self.manager.peer_mps(self.index)
    }

    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer must be equal to or smaller than the MTU agreed for the channel.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, waits until more credits are available.
    pub async fn send<T: Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let mut p_buf = P::allocate().ok_or(Error::OutOfMemory)?;
        stack
            .host
            .channels
            .send(self.index, buf, p_buf.as_mut(), &stack.host)
            .await
    }

    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer must be equal to or smaller than the MTU agreed for the channel.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, returns Error::Busy.
    pub fn try_send<T: Controller + blocking::Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let mut p_buf = P::allocate().ok_or(Error::OutOfMemory)?;
        stack
            .host
            .channels
            .try_send(self.index, buf, p_buf.as_mut(), &stack.host)
    }

    /// Receive data on this channel and copy it into the buffer.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub async fn receive<T: Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
        buf: &mut [u8],
    ) -> Result<usize, BleHostError<T::Error>> {
        stack.host.channels.receive(self.index, buf, &stack.host).await
    }

    /// Receive the next SDU available on this channel.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub async fn receive_sdu<T: Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
    ) -> Result<Sdu<P::Packet>, BleHostError<T::Error>> {
        stack.host.channels.receive_sdu(self.index, &stack.host).await
    }

    /// Read metrics of the l2cap channel.
    #[cfg(feature = "channel-metrics")]
    pub fn metrics<F: FnOnce(&ChannelMetrics) -> R, R>(&self, f: F) -> R {
        self.manager.metrics(self.index, f)
    }

    /// Listen for an incoming connection request matching the list of PSM.
    ///
    /// Returns a [`L2capPendingConnection`] that can be inspected, then accepted or rejected.
    pub async fn listen(
        stack: &'d Stack<'d, impl Controller, P>,
        connection: &Connection<'_, P>,
        psm: &[u16],
    ) -> L2capPendingConnection<'d, P> {
        stack.host.channels.listen(connection.handle(), psm).await
    }

    /// Await an incoming connection request matching the list of PSM and accept it.
    pub async fn accept<T: Controller>(
        stack: &'d Stack<'d, T, P>,
        connection: &Connection<'_, P>,
        psm: &[u16],
        config: &L2capChannelConfig,
    ) -> Result<Self, BleHostError<T::Error>> {
        let handle = connection.handle();
        stack.host.channels.accept(handle, psm, config, &stack.host).await
    }

    /// Create a new connection request with the provided PSM.
    pub async fn create<T: Controller>(
        stack: &'d Stack<'d, T, P>,
        connection: &Connection<'_, P>,
        psm: u16,
        config: &L2capChannelConfig,
    ) -> Result<Self, BleHostError<T::Error>> {
        stack
            .host
            .channels
            .create(connection.handle(), psm, config, &stack.host)
            .await
    }

    /// Split the channel into a writer and reader for concurrently
    /// writing to/reading from the channel.
    pub fn split(self) -> (L2capChannelWriter<'d, P>, L2capChannelReader<'d, P>) {
        self.manager.inc_ref(self.index);
        self.manager.inc_ref(self.index);
        (
            L2capChannelWriter {
                index: self.index,
                manager: self.manager,
            },
            L2capChannelReader {
                index: self.index,
                manager: self.manager,
            },
        )
    }

    /// Merge writer and reader into a single channel again.
    ///
    /// This function will panic if the channels are not referring to the same channel id.
    pub fn merge(writer: L2capChannelWriter<'d, P>, reader: L2capChannelReader<'d, P>) -> Self {
        // A channel will not be reused unless the refcount is 0, so the index could
        // never be stale.
        assert_eq!(writer.index, reader.index);

        let manager = writer.manager;
        let index = writer.index;
        manager.inc_ref(index);

        Self { index, manager }
    }
}

impl<'d, P: PacketPool> L2capChannelReader<'d, P> {
    /// Disconnect this channel.
    pub fn disconnect(&mut self) {
        self.manager.disconnect(self.index);
    }

    /// Get the negotiated MTU for this channel.
    pub fn mtu(&self) -> u16 {
        self.manager.mtu(self.index)
    }

    /// Get the negotiated MPS for this channel.
    pub fn mps(&self) -> u16 {
        self.manager.mps(self.index)
    }

    /// Receive data on this channel and copy it into the buffer.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub async fn receive<T: Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
        buf: &mut [u8],
    ) -> Result<usize, BleHostError<T::Error>> {
        stack.host.channels.receive(self.index, buf, &stack.host).await
    }

    /// Receive the next SDU available on this channel.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub async fn receive_sdu<T: Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
    ) -> Result<Sdu<P::Packet>, BleHostError<T::Error>> {
        stack.host.channels.receive_sdu(self.index, &stack.host).await
    }

    /// Read metrics of the l2cap channel.
    #[cfg(feature = "channel-metrics")]
    pub fn metrics<F: FnOnce(&ChannelMetrics) -> R, R>(&self, f: F) -> R {
        self.manager.metrics(self.index, f)
    }

    /// Create a channel reference for the l2cap channel.
    pub fn channel_ref(&mut self) -> L2capChannelRef<'d, P> {
        self.manager.inc_ref(self.index);
        L2capChannelRef {
            index: self.index,
            manager: self.manager,
        }
    }
}

impl<'d, P: PacketPool> L2capChannelRef<'d, P> {
    #[cfg(feature = "channel-metrics")]
    /// Read metrics of the l2cap channel.
    pub fn metrics<F: FnOnce(&ChannelMetrics) -> R, R>(&self, f: F) -> R {
        self.manager.metrics(self.index, f)
    }
}

impl<'d, P: PacketPool> L2capChannelWriter<'d, P> {
    /// Disconnect this channel.
    pub fn disconnect(&mut self) {
        self.manager.disconnect(self.index);
    }

    /// Get the peer's MTU for this channel.
    pub fn peer_mtu(&self) -> u16 {
        self.manager.peer_mtu(self.index)
    }

    /// Get the peer's MPS for this channel.
    pub fn peer_mps(&self) -> u16 {
        self.manager.peer_mps(self.index)
    }

    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer must be equal to or smaller than the MTU agreed for the channel.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, waits until more credits are available.
    pub async fn send<T: Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let mut p_buf = P::allocate().ok_or(Error::OutOfMemory)?;
        stack
            .host
            .channels
            .send(self.index, buf, p_buf.as_mut(), &stack.host)
            .await
    }

    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer must be equal to or smaller than the MTU agreed for the channel.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, returns Error::Busy.
    pub fn try_send<T: Controller + blocking::Controller>(
        &mut self,
        stack: &Stack<'_, T, P>,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let mut p_buf = P::allocate().ok_or(Error::OutOfMemory)?;
        stack
            .host
            .channels
            .try_send(self.index, buf, p_buf.as_mut(), &stack.host)
    }

    /// Read metrics of the l2cap channel.
    #[cfg(feature = "channel-metrics")]
    pub fn metrics<F: FnOnce(&ChannelMetrics) -> R, R>(&self, f: F) -> R {
        self.manager.metrics(self.index, f)
    }

    /// Create a channel reference for the l2cap channel.
    pub fn channel_ref(&mut self) -> L2capChannelRef<'d, P> {
        self.manager.inc_ref(self.index);
        L2capChannelRef {
            index: self.index,
            manager: self.manager,
        }
    }
}
