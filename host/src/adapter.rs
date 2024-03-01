use core::cell::RefCell;

use crate::ad_structure::AdStructure;
use crate::byte_writer::ByteWriter;
use crate::l2cap::{L2capPacket, L2capState};
use crate::Error;
use crate::ATT_MTU;
use crate::L2CAP_MTU;
use crate::L2CAP_RXQ;
use crate::L2CAP_TXQ;
use bt_hci::cmd::controller_baseband::SetEventMask;
use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams};
use bt_hci::cmd::SyncCmd;
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{BdAddr, ConnHandle, EventMask};
use bt_hci::Controller;
use bt_hci::ControllerToHostPacket;
use bt_hci::{ControllerCmdSync, FromHciBytesError};
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{Channel, DynamicReceiver, DynamicSender, Receiver, Sender};
use embassy_sync::waitqueue::WakerRegistration;
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
    handle: u16,
    status: u8,
    role: u8,
    peer_address: BdAddr,
    interval: u16,
    latency: u16,
    timeout: u16,
    waker: WakerRegistration,
}

#[derive(Clone)]
pub struct Connection<'d> {
    handle: ConnHandle,
    tx: DynamicSender<'d, (ConnHandle, Vec<u8, L2CAP_MTU>)>,
}

impl<'d> Connection<'d> {
    pub async fn accept<M: RawMutex, T: Controller>(
        adapter: &'d Adapter<'d, M, T>,
    ) -> Result<Connection<'d>, Error<T::Error>> {
        adapter.accept().await
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

pub struct Adapter<'d, M, T>
where
    M: RawMutex + 'd,
    T: Controller,
{
    controller: T,
    inner: RefCell<Inner<'d, M>>,
    att: &'d mut L2capState<M, ATT_MTU>,
    outbound: Channel<M, (ConnHandle, Vec<u8, L2CAP_MTU>), L2CAP_TXQ>,
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
        }
    }

    pub(crate) fn att_receiver(&self) -> Receiver<'_, M, (ConnHandle, Vec<u8, ATT_MTU>), L2CAP_RXQ> {
        self.att.receiver()
    }

    pub(crate) fn outbound_sender(&self) -> Sender<'_, M, (ConnHandle, Vec<u8, L2CAP_MTU>), L2CAP_TXQ> {
        self.outbound.sender()
    }

    async fn accept(&self) -> Result<Connection<'d>, Error<T::Error>> {
        todo!()
    }
}

impl<'d, M, T> Adapter<'d, M, T>
where
    M: RawMutex + 'd,
    T: ControllerCmdSync<LeSetAdvData>
        + ControllerCmdSync<LeSetAdvEnable>
        + ControllerCmdSync<LeSetAdvParams>
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
            let mut w = ByteWriter::new(&mut data[..]);
            for item in adv.data.iter() {
                item.encode(&mut w);
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
                .enable_link_key_kind_changed(true)
                .enable_link_key_notification(true)
                .enable_disconnection_complete(true),
        )
        .exec(&self.controller)
        .await?;

        let mut runner = BleRunner {
            outbound: self.outbound.receiver(),
            att: self.att.sender(),
        };

        runner.run(&self.controller).await;
        Ok(())
    }
}

struct BleRunner<'a, M: RawMutex> {
    outbound: Receiver<'a, M, (ConnHandle, Vec<u8, L2CAP_MTU>), L2CAP_TXQ>,
    att: Sender<'a, M, (ConnHandle, Vec<u8, ATT_MTU>), L2CAP_RXQ>,
}

impl<'a, M: RawMutex> BleRunner<'a, M> {
    async fn handle_acl(&mut self, packet: AclPacket<'_>) -> Result<(), FromHciBytesError> {
        let (conn, packet) = L2capPacket::decode(packet)?;
        if packet.channel == 4 {
            self.att.send((conn, Vec::from_slice(packet.payload).unwrap())).await;
        } else {
            info!("Got ACL packet not for GATT: {:?}", packet);
        }
        Ok(())
    }

    async fn run<T: Controller>(&mut self, controller: &T) {
        loop {
            let mut rx = [0u8; 512];
            match select(controller.read(&mut rx), self.outbound.receive()).await {
                Either::First(result) => match result {
                    Ok(ControllerToHostPacket::Acl(acl)) => match self.handle_acl(acl).await {
                        Ok(_) => {}
                        Err(e) => {
                            info!("Error processing ACL packet: {:?}", e);
                        }
                    },
                    Ok(ControllerToHostPacket::Event(event)) => match event {
                        Event::Le(event) => match event {
                            LeEvent::LeConnectionComplete(_) => {
                                info!("Connection complete!");
                            }
                            _ => {
                                warn!("Unknown event: {:?}", event);
                            }
                        },
                        Event::NumberOfCompletedPackets(c) => {
                            info!("Completed packets: {:?}", c)
                        }
                        _ => {
                            warn!("Unknown event: {:?}", event);
                        }
                    },
                    Ok(p) => {
                        info!("Ignoring packet: {:?}", p);
                    }
                    Err(e) => {
                        info!("Error receiving packet: {:?}", e);
                        panic!(":(");
                    }
                },
                Either::Second((handle, pdu)) => {
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
            }
        }
    }
}

pub struct L2capChannel<'d> {
    rx: DynamicReceiver<'d, (ConnHandle, Vec<u8, L2CAP_MTU>)>,
    tx: DynamicSender<'d, (ConnHandle, Vec<u8, L2CAP_MTU>)>,
}

impl<'d> L2capChannel<'d> {
    pub async fn create<M: RawMutex, T: Controller>(
        connection: Connection<'d>,
        adapter: &'d Adapter<'d, M, T>,
    ) -> Result<(), Error<T::Error>> {
        Ok(())
    }
}
