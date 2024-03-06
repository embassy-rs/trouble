use core::cell::RefCell;

use crate::ad_structure::AdStructure;
use crate::attribute::Attribute;
use crate::attribute_server::AttributeServer;
use crate::cursor::WriteCursor;
use crate::gatt::GattServer;
use crate::l2cap::{L2capPacket, L2capState}; //self, L2capLeSignal, L2capPacket, L2capState, LeCreditConnReq, SignalCode};
use crate::packet_pool::{DynamicPacketPool, Packet, PacketPool, POOL_ATT_CLIENT_ID};
use crate::Error;
use crate::L2CAP_MTU;
use crate::L2CAP_TXQ;
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

pub struct AdapterResources<M: RawMutex, const CONNS: usize, const CHANNELS: usize, const PACKETS: usize> {
    connections: [ConnectionStorage; CONNS],
    channels: [ChannelStorage<M>; CHANNELS],
    pool: PacketPool<M, L2CAP_MTU, PACKETS, CHANNELS>,
}

impl<M: RawMutex, const CONNS: usize, const CHANNELS: usize, const PACKETS: usize>
    AdapterResources<M, CONNS, CHANNELS, PACKETS>
{
    pub fn new() -> Self {
        Self {
            connections: [ConnectionStorage::EMPTY; CONNS],
            channels: [ChannelStorage::EMPTY; CHANNELS],
            pool: PacketPool::new(crate::packet_pool::Qos::None),
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

struct ConnectionStorage {
    state: Option<ConnectionState>,
}

impl ConnectionStorage {
    const EMPTY: Self = Self { state: None };
}

struct ChannelStorage<M: RawMutex> {
    state: Option<L2capState<M>>,
}

impl<M: RawMutex> ChannelStorage<M> {
    const EMPTY: Self = Self { state: None };
}

pub struct ConnectionState {
    handle: ConnHandle,
    status: Status,
    role: LeConnRole,
    peer_address: BdAddr,
    interval: u16,
    latency: u16,
    timeout: u16,
}

#[derive(Clone)]
pub struct Connection<'d> {
    handle: ConnHandle,
    tx: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
    control: DynamicSender<'d, ControlCommand>,
}

impl<'d> Connection<'d> {
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

pub struct Inner<'d, M>
where
    M: RawMutex + 'd,
{
    connections: &'d mut [ConnectionStorage],
    channels: &'d mut [ChannelStorage<M>],
}

impl<'d, M> Inner<'d, M>
where
    M: RawMutex,
{
    //fn alloc_channel(&mut self, conn: ConnHandle, req: LeCreditConnReq) -> Option<&'d mut L2capState<'d, M>> {
    //    for chan in self.channels.iter_mut() {
    //        if chan.state.is_none() {
    //            info!("Found free channel");
    //            // TODO: Channel id counter
    //            //    chan.state.replace(L2capState::new(
    //            //        conn,
    //            //        0x40,
    //            //        req.scid,
    //            //        req.mtu.min(L2CAP_MTU as u16),
    //            //        req.credits,
    //            //    ));
    //            //    return &mut chan.state;
    //        }
    //    }
    //    None
    //}
}

pub struct AdapterState<'d, M>
where
    M: RawMutex + 'd,
{
    connections: &'d mut [ConnectionStorage],
    channels: &'d mut [ChannelStorage<M>],
}

pub struct Adapter<'d, M>
where
    M: RawMutex + 'd,
{
    state: RefCell<AdapterState<'d, M>>,
    att: Channel<M, (ConnHandle, Pdu<'d>), 1>,
    outbound: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_TXQ>,
    control: Channel<M, ControlCommand, 1>,
    acceptor: Channel<M, ConnHandle, 1>,
    pool: &'d dyn DynamicPacketPool<'d>,
}

enum ControlCommand {
    Disconnect(DisconnectParams),
}

impl<'d, M> Adapter<'d, M>
where
    M: RawMutex + 'd,
{
    pub fn new<const CONN: usize, const CHANNELS: usize, const PACKETS: usize>(
        resources: &'d mut AdapterResources<M, CONN, CHANNELS, PACKETS>,
    ) -> Self {
        Self {
            state: RefCell::new(AdapterState {
                connections: &mut resources.connections,
                channels: &mut resources.channels,
            }),

            pool: &resources.pool,
            att: Channel::new(),
            outbound: Channel::new(),
            control: Channel::new(),
            acceptor: Channel::new(),
        }
    }

    pub fn gatt<'a, 'b>(&'d self, attributes: &'a mut [Attribute<'b>]) -> GattServer<'a, 'd, 'b> {
        GattServer {
            server: AttributeServer::new(attributes),
            rx: self.att.receiver().into(),
            tx: self.outbound.sender().into(),
        }
    }

    pub async fn accept(&'d self) -> Connection<'_> {
        let handle = self.acceptor.receive().await;
        Connection {
            handle,
            tx: self.outbound.sender().into(),
            control: self.control.sender().into(),
        }
    }
}

impl<'d, M> Adapter<'d, M>
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

    pub async fn run<T>(&'d self, controller: &T) -> Result<(), Error<T::Error>>
    where
        T: ControllerCmdSync<Disconnect> + ControllerCmdSync<SetEventMask>,
    {
        let mut runner = AdapterRunner {
            state: &self.state,
            att: self.att.sender().into(),
            outbound: self.outbound.receiver().into(),
            control: self.control.receiver().into(),
            acceptor: self.acceptor.sender().into(),
            pool: self.pool,
        };

        runner.run(controller).await?;
        Ok(())
    }
}

pub struct AdapterRunner<'a, 'd, M>
where
    M: RawMutex + 'd,
{
    state: &'a RefCell<AdapterState<'d, M>>,
    att: DynamicSender<'d, (ConnHandle, Pdu<'d>)>,
    outbound: DynamicReceiver<'d, (ConnHandle, Pdu<'d>)>,
    control: DynamicReceiver<'d, ControlCommand>,
    acceptor: DynamicSender<'d, ConnHandle>,
    pool: &'d dyn DynamicPacketPool<'d>,
}

const L2CAP_CID_ATT: u16 = 0x0004;
const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
const L2CAP_CID_DYN_START: u16 = 0x0040;
impl<'a, 'd, M> AdapterRunner<'a, 'd, M>
where
    M: RawMutex + 'd,
{
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
                                let mut inner = self.state.borrow_mut();
                                for conn in inner.connections.iter_mut() {
                                    if conn.state.is_none() {
                                        conn.state.replace(ConnectionState {
                                            handle: e.handle,
                                            status: e.status,
                                            role: e.role,
                                            peer_address: e.peer_addr,
                                            interval: e.conn_interval.as_u16(),
                                            latency: e.peripheral_latency,
                                            timeout: e.supervision_timeout.as_u16(),
                                        });
                                        // TODO:
                                        self.acceptor.try_send(e.handle).unwrap();
                                        break;
                                    }
                                }
                            }
                            _ => {
                                warn!("Unknown event: {:?}", event);
                            }
                        },
                        Event::DisconnectionComplete(e) => {
                            info!("Disconnected: {:?}", e);
                            let mut inner = self.state.borrow_mut();
                            for conn in inner.connections.iter_mut() {
                                if let Some(state) = &mut conn.state {
                                    if state.handle == e.handle {
                                        conn.state.take();
                                    }
                                    break;
                                }
                            }
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
