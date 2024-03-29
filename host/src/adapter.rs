use crate::advertise::AdvertiseConfig;
use crate::attribute::AttributeTable;
use crate::attribute_server::AttributeServer;
use crate::channel_manager::ChannelManager;
use crate::connection::Connection;
use crate::connection_manager::{ConnectionInfo, ConnectionManager};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::gatt::GattServer;
use crate::l2cap::{L2capPacket, L2CAP_CID_ATT, L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SIGNAL};
use crate::packet_pool::{self, DynamicPacketPool, PacketPool, Qos, ATT_ID};
use crate::pdu::Pdu;
use crate::scan::{ScanConfig, ScanReport};
use crate::types::l2cap::L2capLeSignal;
use crate::{AdapterError, Error};
use bt_hci::cmd::controller_baseband::{Reset, SetEventMask};
use bt_hci::cmd::le::{
    LeCreateConn, LeCreateConnParams, LeReadBufferSize, LeSetAdvData, LeSetAdvEnable, LeSetAdvParams, LeSetScanEnable,
    LeSetScanParams,
};
use bt_hci::cmd::link_control::{Disconnect, DisconnectParams};
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::Controller;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{BdAddr, ConnHandle, DisconnectReason, EventMask};
use bt_hci::ControllerToHostPacket;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::Channel;
use futures_intrusive::sync::LocalSemaphore;

pub struct HostResources<M: RawMutex, const CHANNELS: usize, const PACKETS: usize, const L2CAP_MTU: usize> {
    pool: PacketPool<M, L2CAP_MTU, PACKETS, CHANNELS>,
}

impl<M: RawMutex, const CHANNELS: usize, const PACKETS: usize, const L2CAP_MTU: usize>
    HostResources<M, CHANNELS, PACKETS, L2CAP_MTU>
{
    pub fn new(qos: Qos) -> Self {
        Self {
            pool: PacketPool::new(qos),
        }
    }
}

pub struct Adapter<
    'd,
    M,
    T,
    const CONNS: usize,
    const CHANNELS: usize,
    const L2CAP_TXQ: usize = 1,
    const L2CAP_RXQ: usize = 1,
> where
    M: RawMutex,
{
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<M, CONNS>,
    pub(crate) channels: ChannelManager<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    pub(crate) att_inbound: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_RXQ>,
    pub(crate) pool: &'d dyn DynamicPacketPool<'d>,
    pub(crate) permits: LocalSemaphore,

    pub(crate) control: Channel<M, ControlCommand, 1>,
    pub(crate) scanner: Channel<M, ScanReport, 1>,
}

pub(crate) enum ControlCommand {
    Init,
    Disconnect(DisconnectParams),
    Connect(LeCreateConnParams),
}

impl<'d, M, T, const CONNS: usize, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
    Adapter<'d, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>
where
    M: RawMutex,
    T: Controller,
{
    const NEW_L2CAP: Channel<M, Pdu<'d>, L2CAP_RXQ> = Channel::new();

    /// Create a new instance of the BLE host adapter.
    ///
    /// The adapter requires a HCI driver (a particular HCI-compatible controller implementing the required traits), and
    /// a reference to resources that are created outside the adapter but which the adapter is the only accessor of.
    pub fn new<const PACKETS: usize, const L2CAP_MTU: usize>(
        controller: T,
        host_resources: &'d mut HostResources<M, CHANNELS, PACKETS, L2CAP_MTU>,
    ) -> Self {
        Self {
            controller,
            connections: ConnectionManager::new(),
            channels: ChannelManager::new(&host_resources.pool),
            pool: &host_resources.pool,
            att_inbound: Channel::new(),
            scanner: Channel::new(),
            control: Channel::new(),
            permits: LocalSemaphore::new(true, 0),
        }
    }

    /// Performs a BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan(&self, config: &ScanConfig) -> Result<ScanReport, AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeSetScanEnable> + ControllerCmdSync<LeSetScanParams>,
    {
        let params = config.params.unwrap_or(LeSetScanParams::new(
            bt_hci::param::LeScanKind::Passive,
            bt_hci::param::Duration::from_millis(1_000),
            bt_hci::param::Duration::from_millis(1_000),
            bt_hci::param::AddrKind::PUBLIC,
            bt_hci::param::ScanningFilterPolicy::BasicUnfiltered,
        ));
        params.exec(&self.controller).await?;

        LeSetScanEnable::new(true, true).exec(&self.controller).await?;

        let report = self.scanner.receive().await;
        LeSetScanEnable::new(false, false).exec(&self.controller).await?;
        Ok(report)
    }

    /// Starts sending BLE advertisements according to the provided config.
    ///
    /// Advertisements are stopped when a connection is made against this host,
    /// in which case a handle for the connection is returned.
    pub async fn advertise<'m>(&'m self, config: &AdvertiseConfig<'_>) -> Result<Connection<'m>, AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeSetAdvData> + ControllerCmdSync<LeSetAdvEnable> + ControllerCmdSync<LeSetAdvParams>,
    {
        let params = &config.params.unwrap_or(LeSetAdvParams::new(
            bt_hci::param::Duration::from_millis(400),
            bt_hci::param::Duration::from_millis(400),
            bt_hci::param::AdvKind::AdvInd,
            bt_hci::param::AddrKind::PUBLIC,
            bt_hci::param::AddrKind::PUBLIC,
            BdAddr::default(),
            bt_hci::param::AdvChannelMap::ALL,
            bt_hci::param::AdvFilterPolicy::default(),
        ));

        params.exec(&self.controller).await?;

        let mut data = [0; 31];
        let mut w = WriteCursor::new(&mut data[..]);
        for item in config.data.iter() {
            item.encode(&mut w)?;
        }
        let len = w.len();
        drop(w);
        LeSetAdvData::new(len as u8, data).exec(&self.controller).await?;
        LeSetAdvEnable::new(true).exec(&self.controller).await?;
        let conn = Connection::accept(self).await;
        LeSetAdvEnable::new(false).exec(&self.controller).await?;
        Ok(conn)
    }

    /// Creates a GATT server capable of processing the GATT protocol using the provided table of attributes.
    pub fn gatt_server<'reference, 'values, const MAX: usize>(
        &'reference self,
        table: &'reference AttributeTable<'values, M, MAX>,
    ) -> GattServer<'reference, 'values, 'd, M, T, MAX> {
        GattServer {
            server: AttributeServer::new(table),
            pool: self.pool,
            pool_id: packet_pool::ATT_ID,
            rx: self.att_inbound.receiver().into(),
            tx: self.hci(),
            connections: &self.connections,
        }
    }

    async fn handle_acl(&self, acl: AclPacket<'_>) -> Result<(), Error> {
        let (conn, packet) = L2capPacket::decode(acl)?;
        match packet.channel {
            L2CAP_CID_ATT => {
                if let Some(mut p) = self.pool.alloc(ATT_ID) {
                    let len = packet.payload.len();
                    p.as_mut()[..len].copy_from_slice(packet.payload);
                    self.att_inbound.send((conn, Pdu { packet: p, len })).await;
                } else {
                    // TODO: Signal back
                }
            }
            L2CAP_CID_LE_U_SIGNAL => {
                let mut r = ReadCursor::new(packet.payload);
                let signal: L2capLeSignal = r.read()?;
                match self.channels.control(conn, signal).await {
                    Ok(_) => {}
                    Err(_) => {
                        return Err(Error::Other);
                    }
                }
            }

            other if other >= L2CAP_CID_DYN_START => match self.channels.dispatch(packet).await {
                Ok(_) => {}
                Err(e) => {
                    warn!("Error dispatching l2cap packet to channel: {:?}", e);
                }
            },
            _ => {
                unimplemented!()
            }
        }
        Ok(())
    }

    pub async fn run(&self) -> Result<(), AdapterError<T::Error>>
    where
        T: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<Reset>
            + ControllerCmdAsync<LeCreateConn>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        self.control.send(ControlCommand::Init).await;

        loop {
            // Task handling receiving data from the controller.
            let rx_fut = async {
                let mut rx = [0u8; 259];
                match self.controller.read(&mut rx).await {
                    // info!("Incoming event: {:?}", result);
                    Ok(ControllerToHostPacket::Acl(acl)) => match self.handle_acl(acl).await {
                        Ok(_) => {}
                        Err(e) => {
                            info!("Error processing ACL packet: {:?}", e);
                        }
                    },
                    Ok(ControllerToHostPacket::Event(event)) => match event {
                        Event::Le(event) => match event {
                            LeEvent::LeConnectionComplete(e) => {
                                if let Err(err) = self.connections.connect(
                                    e.handle,
                                    ConnectionInfo {
                                        handle: e.handle,
                                        status: e.status,
                                        role: e.role,
                                        peer_address: e.peer_addr,
                                        interval: e.conn_interval.as_u16(),
                                        latency: e.peripheral_latency,
                                        timeout: e.supervision_timeout.as_u16(),
                                        att_mtu: 23,
                                    },
                                ) {
                                    warn!("Error establishing connection: {:?}", err);
                                    Disconnect::new(e.handle, DisconnectReason::RemoteDeviceTerminatedConnLowResources)
                                        .exec(&self.controller)
                                        .await?;
                                }
                            }
                            LeEvent::LeAdvertisingReport(data) => {
                                self.scanner
                                    .send(ScanReport::new(data.reports.num_reports, &data.reports.bytes))
                                    .await;
                            }
                            _ => {
                                warn!("Unknown event: {:?}", event);
                            }
                        },
                        Event::DisconnectionComplete(e) => {
                            info!("Disconnected: {:?}", e);
                            let _ = self.connections.disconnect(e.handle);
                        }
                        Event::NumberOfCompletedPackets(c) => {
                            // trace!("Confirmed {} packets sent", c.completed_packets.len());
                            self.permits.release(c.completed_packets.len());
                        }
                        _ => {
                            warn!("Unknown event: {:?}", event);
                        }
                    },
                    Ok(p) => {
                        info!("Ignoring packet: {:?}", p);
                    }
                    Err(e) => {
                        #[cfg(feature = "defmt")]
                        let e = defmt::Debug2Format(&e);
                        info!("Error from controller: {:?}", e);
                    }
                }
                Ok(())
            };

            // Task issuing control.
            // TODO: This does not necessarily need to go through the channel and could be dispatch directly
            let control_fut = async {
                let command = self.control.receive().await;
                match command {
                    ControlCommand::Connect(params) => {
                        LeCreateConn::new(
                            params.le_scan_interval,
                            params.le_scan_window,
                            params.use_filter_accept_list,
                            params.peer_addr_kind,
                            params.peer_addr,
                            params.own_addr_kind,
                            params.conn_interval_min,
                            params.conn_interval_max,
                            params.max_latency,
                            params.supervision_timeout,
                            params.min_ce_length,
                            params.max_ce_length,
                        )
                        .exec(&self.controller)
                        .await?;
                    }
                    ControlCommand::Disconnect(params) => {
                        self.connections.disconnect(params.handle)?;
                        Disconnect::new(params.handle, params.reason)
                            .exec(&self.controller)
                            .await?;
                    }
                    ControlCommand::Init => {
                        Reset::new().exec(&self.controller).await?;
                        SetEventMask::new(
                            EventMask::new()
                                .enable_le_meta(true)
                                .enable_conn_request(true)
                                .enable_conn_complete(true)
                                .enable_hardware_error(true)
                                .enable_disconnection_complete(true),
                        )
                        .exec(&self.controller)
                        .await?;

                        let ret = LeReadBufferSize::new().exec(&self.controller).await?;
                        info!(
                            "Setting max flow control packets to {}",
                            ret.total_num_le_acl_data_packets
                        );
                        self.permits.release(ret.total_num_le_acl_data_packets as usize);
                        // TODO: Configure ACL max buffer size as well?
                    }
                }
                Ok(())
            };

            // info!("Entering select loop");
            let result: Result<(), AdapterError<T::Error>> = match select(rx_fut, control_fut).await {
                Either::First(result) => result,
                Either::Second(result) => result,
            };
            result?;
        }
    }

    pub(crate) fn hci(&self) -> HciController<'_, T> {
        HciController {
            controller: &self.controller,
            permits: &self.permits,
        }
    }
}

pub struct HciController<'d, T: Controller> {
    controller: &'d T,
    permits: &'d LocalSemaphore,
}

impl<'d, T: Controller> HciController<'d, T> {
    pub(crate) async fn send(&self, handle: ConnHandle, pdu: &[u8]) -> Result<(), AdapterError<T::Error>> {
        self.permits.acquire(1).await.disarm();
        let acl = AclPacket::new(
            handle,
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            pdu,
        );
        self.controller
            .write_acl_data(&acl)
            .await
            .map_err(AdapterError::Controller)?;
        Ok(())
    }

    pub(crate) async fn signal(
        &self,
        handle: ConnHandle,
        response: L2capLeSignal,
    ) -> Result<(), AdapterError<T::Error>> {
        // TODO: Refactor signal to avoid encode/decode
        let mut tx = [0; 64];
        let mut w = WriteCursor::new(&mut tx);
        let (mut header, mut body) = w.split(4)?;

        body.write(response)?;

        // TODO: Move into l2cap packet type
        header.write(body.len() as u16)?;
        header.write(L2CAP_CID_LE_U_SIGNAL)?;
        let len = header.len() + body.len();

        header.finish();
        body.finish();
        w.finish();
        self.send(handle, &tx[..len]).await?;

        Ok(())
    }
}
