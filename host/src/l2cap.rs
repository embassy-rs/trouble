//! L2CAP channels.
use bt_hci::controller::{blocking, Controller};

pub use crate::channel_manager::CreditFlowPolicy;
use crate::channel_manager::{ChannelIndex, DynamicChannelManager};
use crate::connection::Connection;
use crate::host::BleHost;
use crate::BleHostError;

pub(crate) mod sar;

/// Handle representing an L2CAP channel.
pub struct L2capChannel<'d, const TX_MTU: usize> {
    index: ChannelIndex,
    manager: &'d dyn DynamicChannelManager,
}

impl<'d, const TX_MTU: usize> Clone for L2capChannel<'d, TX_MTU> {
    fn clone(&self) -> Self {
        self.manager.inc_ref(self.index);
        Self {
            index: self.index,
            manager: self.manager,
        }
    }
}

impl<'d, const TX_MTU: usize> Drop for L2capChannel<'d, TX_MTU> {
    fn drop(&mut self) {
        self.manager.dec_ref(self.index);
    }
}

/// Configuration for an L2CAP channel.
pub struct L2capChannelConfig {
    /// Size of Service Data Unit
    pub mtu: u16,
    /// Flow control policy for connection oriented channels.
    pub flow_policy: CreditFlowPolicy,
    /// Initial credits for connection oriented channels.
    pub initial_credits: Option<u16>,
}

impl Default for L2capChannelConfig {
    fn default() -> Self {
        Self {
            mtu: 23,
            flow_policy: Default::default(),
            initial_credits: None,
        }
    }
}

impl<'d, const TX_MTU: usize> L2capChannel<'d, TX_MTU> {
    /// Disconnect this channel.
    pub fn disconnect(&mut self) {
        self.manager.disconnect(self.index);
    }

    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer will be segmented to the maximum payload size agreed in the opening handshake.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, waits until more credits are available.
    pub async fn send<T: Controller>(
        &mut self,
        ble: &BleHost<'_, T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let mut p_buf = [0u8; TX_MTU];
        ble.channels.send(self.index, buf, &mut p_buf[..], ble).await
    }

    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer will be segmented to the maximum payload size agreed in the opening handshake.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, returns Error::Busy.
    pub fn try_send<T: Controller + blocking::Controller>(
        &mut self,
        ble: &BleHost<'_, T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let mut p_buf = [0u8; TX_MTU];
        ble.channels.try_send(self.index, buf, &mut p_buf[..], ble)
    }

    /// Receive data on this channel and copy it into the buffer.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub async fn receive<T: Controller>(
        &mut self,
        ble: &BleHost<'_, T>,
        buf: &mut [u8],
    ) -> Result<usize, BleHostError<T::Error>> {
        ble.channels.receive(self.index, buf, ble).await
    }

    /// Await an incoming connection request matching the list of PSM.
    pub async fn accept<T: Controller>(
        ble: &'d BleHost<'_, T>,
        connection: &Connection<'_>,
        psm: &[u16],
        config: &L2capChannelConfig,
    ) -> Result<Self, BleHostError<T::Error>> {
        let handle = connection.handle();
        let index = ble
            .channels
            .accept(handle, psm, config.mtu, config.flow_policy, config.initial_credits, ble)
            .await?;
        Ok(Self {
            index,
            manager: &ble.channels,
        })
    }

    /// Create a new connection request with the provided PSM.
    pub async fn create<T: Controller>(
        ble: &'d BleHost<'_, T>,
        connection: &Connection<'_>,
        psm: u16,
        config: &L2capChannelConfig,
    ) -> Result<Self, BleHostError<T::Error>>
where {
        let handle = connection.handle();
        let index = ble
            .channels
            .create(
                connection.handle(),
                psm,
                config.mtu,
                config.flow_policy,
                config.initial_credits,
                ble,
            )
            .await?;
        Ok(Self {
            index,
            manager: &ble.channels,
        })
    }
}
