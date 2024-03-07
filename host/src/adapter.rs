use crate::ad_structure::AdStructure;
use crate::channel_manager::{ChannelManager, ChannelState, UnboundChannel};
use crate::connection::ConnEvent;
use crate::connection_manager::{ConnectionManager, ConnectionState, ConnectionStorage};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::l2cap::{self, L2capPacket, L2CAP_CID_DYN_START}; //self, L2capLeSignal, L2capPacket, L2capState, LeCreditConnReq, SignalCode};
use crate::packet_pool::{DynamicPacketPool, Packet, PacketPool, Qos, ATT_ID};
use crate::pdu::Pdu;
use crate::types::l2cap::{L2capLeSignal, L2capLeSignalData, SignalCode};
use crate::{codec, Error};
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
    events: [Channel<M, ConnEvent, 1>; CONNS],

    channels: [ChannelState; CHANNELS],
    pool: PacketPool<M, L2CAP_MTU, PACKETS, CHANNELS>,
}

impl<M: RawMutex, const CONNS: usize, const CHANNELS: usize, const PACKETS: usize, const L2CAP_MTU: usize>
    HostResources<M, CONNS, CHANNELS, PACKETS, L2CAP_MTU>
{
    const EVENT_CHAN: Channel<M, ConnEvent, 1> = Channel::new();
    const FREE_CHAN: ChannelState = ChannelState::Free;
    pub const fn new(qos: Qos) -> Self {
        Self {
            connections: [ConnectionStorage::UNUSED; CONNS],
            events: [Self::EVENT_CHAN; CONNS],
            channels: [Self::FREE_CHAN; CHANNELS],
            pool: PacketPool::new(qos),
        }
    }
}

pub(crate) struct ConnectedEvent<'d> {
    pub(crate) handle: ConnHandle,
    pub(crate) events: DynamicReceiver<'d, ConnEvent>,
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

pub struct Adapter<'d, M, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
where
    M: RawMutex + 'd,
{
    l2cap_mtu: usize,
    pub(crate) connections: ConnectionManager<'d, M>,
    pub(crate) channels: ChannelManager<'d, M>,
    pub(crate) pool: &'d dyn DynamicPacketPool<'d>,

    pub(crate) l2cap_channels: [Channel<M, Pdu<'d>, L2CAP_RXQ>; CHANNELS],
    pub(crate) att_channel: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_RXQ>,
    pub(crate) outbound: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_TXQ>,
    pub(crate) control: Channel<M, ControlCommand, 1>,
    pub(crate) acceptor: Channel<M, ConnectedEvent<'d>, 1>,
}

pub(crate) enum ControlCommand {
    Disconnect(DisconnectParams),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HandleError {
    Codec(codec::Error),
    Other,
}

impl From<codec::Error> for HandleError {
    fn from(e: codec::Error) -> Self {
        Self::Codec(e)
    }
}

impl<'d, M, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
    Adapter<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>
where
    M: RawMutex + 'd,
{
    const NEW_L2CAP: Channel<M, Pdu<'d>, L2CAP_RXQ> = Channel::new();
    pub fn new<const CONN: usize, const PACKETS: usize, const L2CAP_MTU: usize>(
        host_resources: &'d mut HostResources<M, CONN, CHANNELS, PACKETS, L2CAP_MTU>,
    ) -> Self {
        Self {
            connections: ConnectionManager::new(&mut host_resources.connections, &host_resources.events),
            channels: ChannelManager::new(&mut host_resources.channels),
            pool: &host_resources.pool,

            l2cap_channels: [Self::NEW_L2CAP; CHANNELS],
            l2cap_mtu: L2CAP_MTU,
            att_channel: Channel::new(),
            outbound: Channel::new(),
            control: Channel::new(),
            acceptor: Channel::new(),
        }
    }
}

impl<'d, M, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
    Adapter<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>
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

    async fn handle_l2cap_le(&self, conn: ConnHandle, packet: L2capPacket<'_>) -> Result<(), HandleError> {
        let mut r = ReadCursor::new(packet.payload);
        let signal: L2capLeSignal = r.read()?;
        info!("l2cap signalling: {:?}", signal);
        match signal.data {
            L2capLeSignalData::CreditConnReq(req) => {
                info!("[req] Creating LE connection");
                let mtu = req.mtu.min(self.l2cap_mtu as u16);
                let cid = self.channels.alloc(signal.id).map_err(|_| HandleError::Other)?;
                match self.channels.bind(
                    signal.id,
                    UnboundChannel {
                        conn,
                        scid: req.scid,
                        credits: req.credits,
                    },
                ) {
                    Ok(bound) => {
                        self.connections
                            .notify(conn, ConnEvent::Bound(bound))
                            .await
                            .map_err(|_| HandleError::Other)?;
                        Ok(())
                    }
                    Err(_) => Err(HandleError::Other),
                }
            }
            L2capLeSignalData::CreditConnRes(req) => {
                // Must be a response of a previous request which should already by allocated a channel for
                match self.channels.bind(
                    signal.id,
                    UnboundChannel {
                        conn,
                        scid: req.dcid,
                        credits: req.credits,
                    },
                ) {
                    Ok(bound) => {
                        self.connections
                            .notify(conn, ConnEvent::Bound(bound))
                            .await
                            .map_err(|_| HandleError::Other)?;
                        Ok(())
                    }
                    Err(_) => Err(HandleError::Other),
                }
            }
            _ => unimplemented!(),
        }
    }

    async fn handle_acl(&self, packet: AclPacket<'_>) -> Result<(), HandleError> {
        let (conn, packet) = L2capPacket::decode(packet)?;
        match packet.channel {
            L2CAP_CID_ATT => {
                if let Some(mut p) = self.pool.alloc(ATT_ID) {
                    let len = packet.payload.len();
                    p.as_mut()[..len].copy_from_slice(packet.payload);
                    self.att_channel.send((conn, Pdu { packet: p, len })).await;
                } else {
                    // TODO: Signal back
                }
            }
            L2CAP_CID_LE_U_SIGNAL => self.handle_l2cap_le(conn, packet).await?,
            other if other >= L2CAP_CID_DYN_START => {
                info!("Got data on dynamic channel {}", other);
            }
            _ => {
                unimplemented!()
            }
        }
        Ok(())
    }

    pub async fn run<T>(&'d self, controller: &T) -> Result<(), Error<T::Error>>
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
                                if let Ok(events) = self.connections.create(
                                    e.handle,
                                    ConnectionState::new(
                                        e.handle,
                                        e.status,
                                        e.role,
                                        e.peer_addr,
                                        e.conn_interval.as_u16(),
                                        e.peripheral_latency,
                                        e.supervision_timeout.as_u16(),
                                    ),
                                ) {
                                    self.acceptor
                                        .send(ConnectedEvent {
                                            handle: e.handle,
                                            events,
                                        })
                                        .await;
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
