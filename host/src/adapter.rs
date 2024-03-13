use crate::advertise::{AdvertiseConfig, Advertiser};
use crate::channel_manager::ChannelManager;
use crate::connection_manager::{ConnectionInfo, ConnectionManager};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::l2cap::{L2capPacket, L2CAP_CID_ATT, L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SIGNAL};
use crate::packet_pool::{DynamicPacketPool, PacketPool, Qos, ATT_ID};
use crate::pdu::Pdu;
use crate::scan::ScanConfig;
use crate::scan::{ScanReports, Scanner};
use crate::types::l2cap::L2capLeSignal;
use crate::{codec, Error};
use bt_hci::cmd::controller_baseband::SetEventMask;
use bt_hci::cmd::le::{LeCreateConn, LeCreateConnParams, LeSetScanEnable};
use bt_hci::cmd::link_control::{Disconnect, DisconnectParams};
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{ConnHandle, DisconnectReason, EventMask};
use bt_hci::{Controller, ControllerToHostPacket};
use bt_hci::{ControllerCmdAsync, ControllerCmdSync};
use embassy_futures::select::{select4, Either4};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::Channel;
use heapless::Vec;

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

pub struct Adapter<'d, M, T, const CONNS: usize, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
where
    M: RawMutex,
{
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<M, CONNS>,
    pub(crate) channels: ChannelManager<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    pub(crate) att_inbound: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_RXQ>,
    pub(crate) pool: &'d dyn DynamicPacketPool<'d>,

    pub(crate) outbound: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_TXQ>,
    pub(crate) control: Channel<M, ControlCommand, 1>,
    pub(crate) scanner: Channel<M, ScanReports, 1>,
}

pub(crate) enum ControlCommand {
    Disconnect(DisconnectParams),
    Connect(LeCreateConnParams),
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

impl<'d, M, T, const CONNS: usize, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
    Adapter<'d, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>
where
    M: RawMutex,
    T: Controller,
{
    const NEW_L2CAP: Channel<M, Pdu<'d>, L2CAP_RXQ> = Channel::new();
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

            outbound: Channel::new(),
            control: Channel::new(),
        }
    }

    pub fn scanner<'m>(&'m self, config: ScanConfig) -> Scanner<'m> {
        Scanner::new(config, self.scanner.receiver().into())
    }

    pub fn advertiser<'m>(&self, adv: AdvertiseConfig<'m>) -> Advertiser<'m> {
        Advertiser::new(adv)
    }

    async fn handle_acl(&self, acl: AclPacket<'_>) -> Result<(), HandleError> {
        let (conn, packet) = L2capPacket::decode(acl)?;
        match packet.channel {
            L2CAP_CID_ATT => {
                if let Some(mut p) = self.pool.alloc(ATT_ID) {
                    let len = packet.payload.len();
                    p.as_mut()[..len].copy_from_slice(packet.payload);
                    self.att_inbound
                        .send((
                            conn,
                            Pdu {
                                packet: p,
                                pb: acl.boundary_flag(),
                                len,
                            },
                        ))
                        .await;
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
                        return Err(HandleError::Other);
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

    pub async fn run(&self) -> Result<(), Error<T::Error>>
    where
        T: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdAsync<LeCreateConn>
            + ControllerCmdSync<LeSetScanEnable>,
    {
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

        loop {
            let mut rx = [0u8; 259];
            let mut tx = [0u8; 259];
            // info!("Entering select");
            match select4(
                self.controller.read(&mut rx),
                self.outbound.receive(),
                self.control.receive(),
                self.channels.signal(),
            )
            .await
            {
                Either4::First(result) => {
                    // info!("Incoming event");
                    match result {
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
                                        },
                                    ) {
                                        warn!("Error establishing connection: {:?}", err);
                                        Disconnect::new(
                                            e.handle,
                                            DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                        )
                                        .exec(&self.controller)
                                        .await
                                        .unwrap();
                                    }
                                }
                                LeEvent::LeAdvertisingReport(data) => {
                                    let mut reports = Vec::new();
                                    reports.extend_from_slice(&data.reports.bytes).unwrap();
                                    self.scanner
                                        .send(ScanReports {
                                            num_reports: data.reports.num_reports,
                                            reports,
                                        })
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
                                //info!("Confirmed {} packets sent", c.completed_packets.len());
                            }
                            _ => {
                                warn!("Unknown event: {:?}", event);
                            }
                        },
                        Ok(p) => {
                            info!("Ignoring packet: {:?}", p);
                        }
                        Err(e) => {
                            info!("Error from controller: {:?}", e);
                        }
                    }
                }
                Either4::Second((handle, mut pdu)) => {
                    // info!("Outgoing packet");
                    let acl = AclPacket::new(handle, pdu.pb, AclBroadcastFlag::PointToPoint, pdu.as_ref());
                    match self.controller.write_acl_data(&acl).await {
                        Ok(_) => {
                            pdu.as_mut().iter_mut().for_each(|b| *b = 0xFF);
                        }
                        Err(e) => {
                            warn!("Error writing some ACL data to controller: {:?}", e);
                            panic!(":(");
                        }
                    }
                }
                Either4::Third(command) => {
                    // info!("Outgoing command");
                    match command {
                        ControlCommand::Connect(params) => {
                            LeSetScanEnable::new(false, false).exec(&self.controller).await.unwrap();
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
                            .await
                            .unwrap();
                        }
                        ControlCommand::Disconnect(params) => {
                            self.connections.disconnect(params.handle).unwrap();
                            Disconnect::new(params.handle, params.reason)
                                .exec(&self.controller)
                                .await
                                .unwrap();
                        }
                    }
                }
                Either4::Fourth((handle, response)) => {
                    // info!("Outgoing signal: {:?}", response);
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

                    let acl = AclPacket::new(
                        handle,
                        AclPacketBoundary::FirstNonFlushable,
                        AclBroadcastFlag::PointToPoint,
                        &tx[..len],
                    );
                    match self.controller.write_acl_data(&acl).await {
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
