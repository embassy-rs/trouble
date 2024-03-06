use crate::ad_structure::AdStructure;
use crate::channel_manager::{ChannelManager, ChannelStorage};
use crate::connection_manager::{ConnectionManager, ConnectionState, ConnectionStorage};
use crate::cursor::WriteCursor;
use crate::l2cap::{self, L2capPacket}; //self, L2capLeSignal, L2capPacket, L2capState, LeCreditConnReq, SignalCode};
use crate::packet_pool::{DynamicPacketPool, Packet, PacketPool, Qos, POOL_ATT_CLIENT_ID};
use crate::Error;
use bt_hci::cmd::controller_baseband::SetEventMask;
use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams};
use bt_hci::cmd::link_control::{Disconnect, DisconnectParams};
use bt_hci::cmd::SyncCmd;
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{BdAddr, ConnHandle, DisconnectReason, EventMask, LeConnRole, Status};
use bt_hci::ControllerCmdSync;
use bt_hci::ControllerToHostPacket;
use embassy_futures::select::{select3, Either3};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, DynamicReceiver, DynamicSender};

pub struct HostResources<
    M: RawMutex,
    const CONNS: usize,
    const CHANNELS: usize,
    const PACKETS: usize,
    const L2CAP_MTU: usize,
> {
    connections: [ConnectionStorage; CONNS],
    channels: [ChannelStorage; CHANNELS],
    pool: PacketPool<M, L2CAP_MTU, PACKETS, CHANNELS>,
    // TODO: Separate ATT pool?
}

impl<M: RawMutex, const CONNS: usize, const CHANNELS: usize, const PACKETS: usize, const L2CAP_MTU: usize>
    HostResources<M, CONNS, CHANNELS, PACKETS, L2CAP_MTU>
{
    pub const fn new(qos: Qos) -> Self {
        Self {
            connections: [ConnectionStorage::UNUSED; CONNS],
            channels: [ChannelStorage::UNUSED; CHANNELS],
            pool: PacketPool::new(qos),
        }
    }
}

pub struct AdapterResources<'d, M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize> {
    pub(crate) l2cap_channels: [Channel<M, Pdu<'d>, L2CAP_RXQ>; CHANNELS],
    pub(crate) att_channel: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_RXQ>,
    pub(crate) outbound: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_TXQ>,
    pub(crate) control: Channel<M, ControlCommand, 1>,
    pub(crate) acceptor: Channel<M, ConnHandle, 1>,
}

impl<'d, M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
    AdapterResources<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>
{
    const NEW_L2CAP: Channel<M, Pdu<'d>, L2CAP_RXQ> = Channel::new();
    pub const fn new() -> Self {
        Self {
            l2cap_channels: [Self::NEW_L2CAP; CHANNELS],
            att_channel: Channel::new(),
            outbound: Channel::new(),
            control: Channel::new(),
            acceptor: Channel::new(),
        }
    }
}

pub struct Pdu<'d> {
    pub packet: Packet<'d>,
    pub len: usize,
}

impl<'d> Pdu<'d> {
    pub fn new(packet: Packet<'d>, len: usize) -> Self {
        Self { packet, len }
    }
}

impl<'d> AsRef<[u8]> for Pdu<'d> {
    fn as_ref(&self) -> &[u8] {
        &self.packet.as_ref()[..self.len]
    }
}

impl<'d> AsMut<[u8]> for Pdu<'d> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.packet.as_mut()[..self.len]
    }
}

#[derive(Clone)]
pub struct Connection<'d> {
    handle: ConnHandle,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
    control: DynamicSender<'d, ControlCommand>,
}

impl<'d> Connection<'d> {
    pub async fn accept<M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>(
        resources: &'d AdapterResources<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    ) -> Self {
        let handle = resources.acceptor.receive().await;
        Connection {
            handle,
            tx: resources.outbound.sender().into(),
            control: resources.control.sender().into(),
        }
    }

    pub async fn disconnect(&mut self) {
        self.control
            .send(ControlCommand::Disconnect(DisconnectParams {
                handle: self.handle,
                reason: DisconnectReason::RemoteUserTerminatedConn,
            }))
            .await;
    }
}

pub struct AdvertiseConfig<'d> {
    pub params: Option<LeSetAdvParams>,
    pub data: &'d [AdStructure<'d>],
}

pub struct Config<'a> {
    pub advertise: Option<AdvertiseConfig<'a>>,
}

impl<'a> Default for Config<'a> {
    fn default() -> Self {
        Self { advertise: None }
    }
}

pub struct Adapter<'d, M, const L2CAP_RXQ: usize>
where
    M: RawMutex + 'd,
{
    connections: ConnectionManager<'d, M>,
    channels: ChannelManager<'d, M>,
    pool: &'d dyn DynamicPacketPool<'d>,

    outbound: DynamicReceiver<'d, (ConnHandle, Pdu<'d>)>,
    att: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
    acceptor: DynamicSender<'d, ConnHandle>,
    control: DynamicReceiver<'d, ControlCommand>,
    l2cap: &'d [Channel<M, Pdu<'d>, L2CAP_RXQ>],
}

pub(crate) enum ControlCommand {
    Disconnect(DisconnectParams),
}

impl<'d, M, const L2CAP_RXQ: usize> Adapter<'d, M, L2CAP_RXQ>
where
    M: RawMutex + 'd,
{
    pub fn new<
        const CONN: usize,
        const CHANNELS: usize,
        const PACKETS: usize,
        const L2CAP_MTU: usize,
        const L2CAP_TXQ: usize,
    >(
        host_resources: &'d mut HostResources<M, CONN, CHANNELS, PACKETS, L2CAP_MTU>,
        adapter_resources: &'d AdapterResources<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    ) -> Self {
        Self {
            connections: ConnectionManager::new(&mut host_resources.connections),
            channels: ChannelManager::new(&mut host_resources.channels),
            pool: &host_resources.pool,

            l2cap: &adapter_resources.l2cap_channels,
            outbound: adapter_resources.outbound.receiver().into(),
            att: adapter_resources.att_channel.sender().into(),
            acceptor: adapter_resources.acceptor.sender().into(),
            control: adapter_resources.control.receiver().into(),
        }
    }
}

const L2CAP_CID_ATT: u16 = 0x0004;
const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
const L2CAP_CID_DYN_START: u16 = 0x0040;

impl<'d, M, const L2CAP_RXQ: usize> Adapter<'d, M, L2CAP_RXQ>
where
    M: RawMutex + 'd,
{
    pub async fn advertise<T>(&self, controller: &T, config: Config<'_>) -> Result<(), Error<T::Error>>
    where
        T: ControllerCmdSync<LeSetAdvData> + ControllerCmdSync<LeSetAdvEnable> + ControllerCmdSync<LeSetAdvParams>,
    {
        if let Some(adv) = &config.advertise {
            let params = &adv.params.unwrap_or(LeSetAdvParams::new(
                bt_hci::param::Duration::from_millis(1280),
                bt_hci::param::Duration::from_millis(1280),
                bt_hci::param::AdvKind::AdvInd,
                bt_hci::param::AddrKind::PUBLIC,
                bt_hci::param::AddrKind::PUBLIC,
                BdAddr::default(),
                bt_hci::param::AdvChannelMap::ALL,
                bt_hci::param::AdvFilterPolicy::default(),
            ));

            params.exec(controller).await?;

            let mut data = [0; 31];
            let mut w = WriteCursor::new(&mut data[..]);
            for item in adv.data.iter() {
                item.encode(&mut w)?;
            }
            let len = w.len();
            drop(w);
            LeSetAdvData::new(len as u8, data).exec(controller).await?;
            LeSetAdvEnable::new(true).exec(controller).await?;
        }
        Ok(())
    }

    async fn handle_acl(&mut self, packet: AclPacket<'_>) -> Result<(), crate::codec::Error> {
        let (conn, packet) = L2capPacket::decode(packet)?;
        match packet.channel {
            L2CAP_CID_ATT => {
                if let Some(mut p) = self.pool.alloc(POOL_ATT_CLIENT_ID) {
                    let len = packet.payload.len();
                    p.as_mut()[..len].copy_from_slice(packet.payload);
                    self.att.send((conn, Pdu { packet: p, len })).await;
                } else {
                    // TODO: Signal back
                }
            }
            L2CAP_CID_LE_U_SIGNAL => {
                // let signal = L2capLeSignal::decode(packet)?;
                // info!("l2cap signalling: {:?}", signal);
                // match signal.code {
                //     SignalCode::LeCreditConnReq => {
                //         let req = LeCreditConnReq::decode(signal)?;
                //         info!("Creating LE connection");
                //         let mtu = req.mtu.min(L2CAP_MTU);
                //         let found = {
                //             let mut inner = self.inner.borrow_mut();
                //             let chan = inner.alloc_channel(req);

                //             chan
                //         };
                //     }
                //     _ => unimplemented!(),
                // }
            }
            other if other >= L2CAP_CID_DYN_START => {
                info!("Got data on dynamic channel {}", other);
            }
            _ => {
                unimplemented!()
            }
        }
        Ok(())
    }

    pub async fn run<T>(&mut self, controller: &T) -> Result<(), Error<T::Error>>
    where
        T: ControllerCmdSync<Disconnect> + ControllerCmdSync<SetEventMask>,
    {
        SetEventMask::new(
            EventMask::new()
                .enable_le_meta(true)
                .enable_conn_request(true)
                .enable_conn_complete(true)
                .enable_hardware_error(true)
                .enable_disconnection_complete(true),
        )
        .exec(controller)
        .await?;
        loop {
            let mut rx = [0u8; 259];
            match select3(
                controller.read(&mut rx),
                self.outbound.receive(),
                self.control.receive(),
            )
            .await
            {
                Either3::First(result) => match result {
                    Ok(ControllerToHostPacket::Acl(acl)) => match self.handle_acl(acl).await {
                        Ok(_) => {}
                        Err(e) => {
                            info!("Error processing ACL packet: {:?}", e);
                        }
                    },
                    Ok(ControllerToHostPacket::Event(event)) => match event {
                        Event::Le(event) => match event {
                            LeEvent::LeConnectionComplete(e) => {
                                info!("Connection complete: {:?}!", e);
                                if let Ok(_) = self.connections.create(
                                    e.handle,
                                    ConnectionState {
                                        handle: e.handle,
                                        status: e.status,
                                        role: e.role,
                                        peer_address: e.peer_addr,
                                        interval: e.conn_interval.as_u16(),
                                        latency: e.peripheral_latency,
                                        timeout: e.supervision_timeout.as_u16(),
                                    },
                                ) {
                                    // TODO:
                                    self.acceptor.try_send(e.handle).unwrap();
                                } else {
                                    Disconnect::new(e.handle, DisconnectReason::RemoteDeviceTerminatedConnLowResources)
                                        .exec(controller)
                                        .await
                                        .unwrap();
                                }
                            }
                            _ => {
                                warn!("Unknown event: {:?}", event);
                            }
                        },
                        Event::DisconnectionComplete(e) => {
                            info!("Disconnected: {:?}", e);
                            // TODO:
                            self.connections.delete(e.handle).unwrap();
                        }
                        Event::NumberOfCompletedPackets(c) => {}
                        _ => {
                            warn!("Unknown event: {:?}", event);
                        }
                    },
                    Ok(p) => {
                        info!("Ignoring packet: {:?}", p);
                    }
                    Err(e) => {
                        info!("Error receiving packet: {:?}", e);
                    }
                },
                Either3::Second((handle, pdu)) => {
                    let acl = AclPacket::new(
                        handle,
                        AclPacketBoundary::FirstNonFlushable,
                        AclBroadcastFlag::PointToPoint,
                        pdu.as_ref(),
                    );
                    match controller.write_acl_data(&acl).await {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Error writing some ACL data to controller: {:?}", e);
                            panic!(":(");
                        }
                    }
                }
                Either3::Third(command) => match command {
                    ControlCommand::Disconnect(params) => {
                        Disconnect::new(params.handle, params.reason)
                            .exec(controller)
                            .await
                            .unwrap();
                    }
                },
            }
        }
    }
}

pub struct L2capChannel<'d, M, const RXQ: usize>
where
    M: RawMutex,
{
    conn: ConnHandle,
    rx: Channel<M, Packet<'d>, RXQ>,
    tx: DynamicSender<'d, (ConnHandle, Packet<'d>)>,
}
