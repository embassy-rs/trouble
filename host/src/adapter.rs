use core::cell::RefCell;

use crate::ad_structure::AdStructure;
use crate::cursor::WriteCursor;
use crate::l2cap::{L2capPacket, L2capState}; //self, L2capLeSignal, L2capPacket, L2capState, LeCreditConnReq, SignalCode};
use crate::Error;
use crate::ATT_MTU;
use crate::L2CAP_MTU;
use crate::L2CAP_RXQ;
use crate::L2CAP_TXQ;
use bt_hci::cmd::controller_baseband::SetEventMask;
use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams};
use bt_hci::cmd::link_control::{Disconnect, DisconnectParams};
use bt_hci::cmd::SyncCmd;
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{BdAddr, ConnHandle, DisconnectReason, EventMask, LeConnRole, Status};
use bt_hci::Controller;
use bt_hci::ControllerCmdSync;
use bt_hci::ControllerToHostPacket;
use embassy_futures::select::{select3, Either3};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, DynamicReceiver, DynamicSender, Receiver, Sender};
use embassy_sync::signal::Signal;
use heapless::Vec;

pub struct AdapterResources<M: RawMutex, const CONNS: usize, const CHANNELS: usize> {
    connections: [ConnectionStorage; CONNS],
    channels: [ChannelStorage<M>; CHANNELS],
    att: L2capState<M, ATT_MTU>,
}

impl<M: RawMutex, const CONNS: usize, const CHANNELS: usize> AdapterResources<M, CONNS, CHANNELS> {
    pub fn new() -> Self {
        Self {
            connections: [ConnectionStorage::EMPTY; CONNS],
            channels: [ChannelStorage::EMPTY; CHANNELS],
            att: L2capState::new(),
        }
    }
}

struct ConnectionStorage {
    state: Option<ConnectionState>,
}

impl ConnectionStorage {
    const EMPTY: Self = Self { state: None };
}

struct ChannelStorage<M: RawMutex> {
    state: Option<L2capState<M, L2CAP_MTU>>,
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
    tx: DynamicSender<'d, (ConnHandle, Vec<u8, L2CAP_MTU>)>,
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

pub struct Adapter<'d, M, T>
where
    M: RawMutex + 'd,
    T: Controller,
{
    controller: T,
    inner: RefCell<Inner<'d, M>>,
    att: &'d mut L2capState<M, ATT_MTU>,
    outbound: Channel<M, (ConnHandle, Vec<u8, L2CAP_MTU>), L2CAP_TXQ>,
    control: Channel<M, ControlCommand, 1>,
    acceptor: Signal<M, ConnHandle>,
}

enum ControlCommand {
    Disconnect(DisconnectParams),
}

impl<'d, M, T> Adapter<'d, M, T>
where
    M: RawMutex + 'd,
    T: Controller + 'd,
{
    pub fn new<const CONN: usize, const CHANNEL_PER_CONN: usize>(
        controller: T,
        resources: &'d mut AdapterResources<M, CONN, CHANNEL_PER_CONN>,
    ) -> Self {
        Self {
            controller,
            att: &mut resources.att,
            inner: RefCell::new(Inner {
                connections: &mut resources.connections,
                channels: &mut resources.channels,
            }),
            outbound: Channel::new(),
            control: Channel::new(),
            acceptor: Signal::new(),
        }
    }

    pub(crate) fn att_receiver(&self) -> Receiver<'_, M, (ConnHandle, Vec<u8, ATT_MTU>), L2CAP_RXQ> {
        self.att.receiver()
    }

    pub(crate) fn outbound_sender(&self) -> Sender<'_, M, (ConnHandle, Vec<u8, L2CAP_MTU>), L2CAP_TXQ> {
        self.outbound.sender()
    }

    pub async fn accept(&self) -> Result<Connection<'_>, Error<T::Error>> {
        let handle = self.acceptor.wait().await;
        Ok(Connection {
            handle,
            tx: self.outbound.sender().into(),
            control: self.control.sender().into(),
        })
    }

    async fn l2cap_connect(&self) -> Result<Connection<'_>, Error<T::Error>> {
        todo!()
    }
}

impl<'d, M, T> Adapter<'d, M, T>
where
    M: RawMutex + 'd,
    T: ControllerCmdSync<LeSetAdvData>
        + ControllerCmdSync<LeSetAdvEnable>
        + ControllerCmdSync<LeSetAdvParams>
        + ControllerCmdSync<Disconnect>
        + ControllerCmdSync<SetEventMask>,
{
    pub async fn run(&self, config: Config<'_>) -> Result<(), Error<T::Error>> {
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

            params.exec(&self.controller).await?;

            let mut data = [0; 31];
            let mut w = WriteCursor::new(&mut data[..]);
            for item in adv.data.iter() {
                item.encode(&mut w)?;
            }
            let len = w.len();
            drop(w);
            LeSetAdvData::new(len as u8, data).exec(&self.controller).await?;
            LeSetAdvEnable::new(true).exec(&self.controller).await?;
        }

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

        let mut runner = BleRunner {
            outbound: self.outbound.receiver(),
            control: self.control.receiver(),
            att: self.att.sender(),
            inner: &self.inner,
            acceptor: &self.acceptor,
        };

        runner.run(&self.controller).await;
        Ok(())
    }
}

struct BleRunner<'a, 'b, M: RawMutex> {
    outbound: Receiver<'a, M, (ConnHandle, Vec<u8, L2CAP_MTU>), L2CAP_TXQ>,
    control: Receiver<'a, M, ControlCommand, 1>,
    att: Sender<'a, M, (ConnHandle, Vec<u8, ATT_MTU>), L2CAP_RXQ>,
    inner: &'a RefCell<Inner<'b, M>>,
    acceptor: &'a Signal<M, ConnHandle>,
}

const L2CAP_CID_ATT: u16 = 0x0004;
const L2CAP_CID_LE_U_SIGNAL: u16 = 0x0005;
const L2CAP_CID_DYN_START: u16 = 0x0040;

impl<'a, 'b, M: RawMutex> BleRunner<'a, 'b, M> {
    async fn handle_acl(&mut self, packet: AclPacket<'_>) -> Result<(), crate::codec::Error> {
        let (conn, packet) = L2capPacket::decode(packet)?;
        match packet.channel {
            L2CAP_CID_ATT => {
                self.att.send((conn, Vec::from_slice(packet.payload).unwrap())).await;
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

    async fn run<T>(&mut self, controller: &T)
    where
        T: ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvEnable>
            + ControllerCmdSync<LeSetAdvParams>
            + ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>,
    {
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
                                let mut inner = self.inner.borrow_mut();
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
                                        self.acceptor.signal(e.handle);
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
                            let mut inner = self.inner.borrow_mut();
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
                        &pdu[..],
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

pub struct L2capChannel<'d> {
    rx: DynamicReceiver<'d, (ConnHandle, Vec<u8, L2CAP_MTU>)>,
    tx: DynamicSender<'d, (ConnHandle, Vec<u8, L2CAP_MTU>)>,
}

impl<'d> L2capChannel<'d> {
    pub async fn connect<M: RawMutex, T: Controller>(
        connection: Connection<'d>,
        adapter: &'d Adapter<'d, M, T>,
    ) -> Result<(), Error<T::Error>> {
        //        let mut packet: [u8; L2CAP_MTU] = [0; L2CAP_MTU];
        //        let req = LeCreditConnReq {
        //            psm: 0,  // TODO: Make configurable?
        //            scid: 1, // TODO: Check available
        //            mtu: L2CAP_MTU as u16,
        //            mps: L2CAP_MTU as u16 - 6, // TODO: What is this vs. mtu?
        //            credits: 1,                // TODO: Make configurable
        //        };
        //
        //        let pdu = L2capLeSignal {
        //            code: SignalCode::LeCreditConnReq,
        //            id: 1, // TODO: Muxing
        //            data: l2cap::L2capLeSignalData::CreditConnReq(req),
        //        };
        //
        //        let mut w = ByteWriter::new(&mut packet);
        //        let lpos = w.reserve(2);
        //        w.append(&L2CAP_CID_LE_U_SIGNAL.to_le_bytes());
        //
        //        w.set(lpos, &012_u16.to_le_bytes());
        //        w.write_u16_le(L2CAP_CID_LE_U_SIGNAL);
        //        pdu.encode(&mut w);
        Ok(())
    }
}
