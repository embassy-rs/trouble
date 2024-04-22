use bt_hci::cmd::link_control::Disconnect;
use bt_hci::controller::{Controller, ControllerCmdSync};
use bt_hci::param::{ConnHandle, DisconnectReason};
use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::adapter::Adapter;
pub use crate::channel_manager::CreditFlowPolicy;
use crate::connection::Connection;
use crate::AdapterError;

pub(crate) mod sar;

#[derive(Clone)]
pub struct L2capChannel {
    handle: ConnHandle,
    cid: u16,
}

impl L2capChannel {
    pub async fn send<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &[u8],
    ) -> Result<(), AdapterError<T::Error>> {
        adapter.channels.send(self.cid, buf, &adapter.hci()).await
    }

    pub fn try_send<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &[u8],
    ) -> Result<(), AdapterError<T::Error>> {
        adapter.channels.try_send(self.cid, buf, &adapter.hci())
    }

    pub async fn receive<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        buf: &mut [u8],
    ) -> Result<usize, AdapterError<T::Error>> {
        adapter.channels.receive(self.cid, buf, &adapter.hci()).await
    }

    pub async fn accept<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection,
        psm: &[u16],
        mtu: u16,
        flow_policy: CreditFlowPolicy,
    ) -> Result<L2capChannel, AdapterError<T::Error>> {
        let handle = connection.handle();
        let cid = adapter
            .channels
            .accept(handle, psm, mtu, flow_policy, &adapter.hci())
            .await?;

        Ok(Self { cid, handle })
    }

    pub fn disconnect<
        M: RawMutex,
        T: Controller + ControllerCmdSync<Disconnect>,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        close_connection: bool,
    ) -> Result<(), AdapterError<T::Error>> {
        adapter.channels.disconnect(self.cid)?;
        if close_connection {
            adapter.try_command(Disconnect::new(self.handle, DisconnectReason::RemoteUserTerminatedConn))?;
        }
        Ok(())
    }

    pub async fn create<
        M: RawMutex,
        T: Controller,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        adapter: &Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_MTU, L2CAP_TXQ, L2CAP_RXQ>,
        connection: &Connection,
        psm: u16,
        mtu: u16,
        flow_policy: CreditFlowPolicy,
    ) -> Result<Self, AdapterError<T::Error>>
where {
        let handle = connection.handle();
        let cid = adapter
            .channels
            .create(connection.handle(), psm, mtu, flow_policy, &adapter.hci())
            .await?;

        Ok(Self { handle, cid })
    }
}
