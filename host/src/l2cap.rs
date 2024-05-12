//! L2CAP channels.
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::controller::{blocking, Controller, ControllerCmdSync};
use bt_hci::param::DisconnectReason;
use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::adapter::Stack;
pub use crate::channel_manager::CreditFlowPolicy;
use crate::connection::Connection;
use crate::StackError;

pub(crate) mod sar;

/// Handle representing an L2CAP channel.
#[derive(Clone)]
pub struct L2capChannel {
    cid: u16,
}

/// Configuration for an L2CAP channel.
pub struct L2capChannelConfig {
    /// Desired mtu of the Service Delivery Unit (SDU). May be fragmented according to the host
    /// adapter L2CAP MTU.
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

impl L2capChannel {
    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer will be segmented to the maximum payload size agreed in the opening handshake.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, waits until more credits are available.
    pub async fn send<
        M: RawMutex,
        T: Controller,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Stack<'_, M, T, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &[u8],
    ) -> Result<(), StackError<T::Error>> {
        adapter.channels.send(self.cid, buf, &adapter.hci()).await
    }

    /// Send the provided buffer over this l2cap channel.
    ///
    /// The buffer will be segmented to the maximum payload size agreed in the opening handshake.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    /// If there are no available credits to send, returns Error::Busy.
    pub fn try_send<
        M: RawMutex,
        T: Controller + blocking::Controller,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Stack<'_, M, T, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &[u8],
    ) -> Result<(), StackError<T::Error>> {
        adapter.channels.try_send(self.cid, buf, &adapter.hci())
    }

    /// Receive data on this channel and copy it into the buffer.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub async fn receive<
        M: RawMutex,
        T: Controller,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Stack<'_, M, T, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &mut [u8],
    ) -> Result<usize, StackError<T::Error>> {
        adapter.channels.receive(self.cid, buf, &adapter.hci()).await
    }

    /// Await an incoming connection request matching the list of PSM.
    pub async fn accept<
        M: RawMutex,
        T: Controller,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &Stack<'_, M, T, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection,
        psm: &[u16],
        config: &L2capChannelConfig,
    ) -> Result<L2capChannel, StackError<T::Error>> {
        let handle = connection.handle();
        let cid = adapter
            .channels
            .accept(
                handle,
                psm,
                config.mtu,
                config.flow_policy,
                config.initial_credits,
                &adapter.hci(),
            )
            .await?;

        Ok(Self { cid })
    }

    /// Disconnect this channel.
    pub fn disconnect<
        M: RawMutex,
        T: Controller + ControllerCmdSync<Disconnect>,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Stack<'_, M, T, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        close_connection: bool,
    ) -> Result<(), StackError<T::Error>> {
        let handle = adapter.channels.disconnect(self.cid)?;
        if close_connection {
            adapter
                .connections
                .request_disconnect(handle, DisconnectReason::RemoteUserTerminatedConn)?;
        }
        Ok(())
    }

    /// Create a new connection request with the provided PSM.
    pub async fn create<
        M: RawMutex,
        T: Controller,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &Stack<'_, M, T, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection,
        psm: u16,
        config: &L2capChannelConfig,
    ) -> Result<Self, StackError<T::Error>>
where {
        let handle = connection.handle();
        let cid = adapter
            .channels
            .create(
                connection.handle(),
                psm,
                config.mtu,
                config.flow_policy,
                config.initial_credits,
                &adapter.hci(),
            )
            .await?;

        Ok(Self { cid })
    }
}
