use crate::advertise::{AdvertisementConfig, RawAdvertisement};
use crate::channel_manager::ChannelManager;
use crate::connection::{ConnectConfig, Connection};
use crate::connection_manager::{ConnectionInfo, ConnectionManager};
use crate::cursor::{ReadCursor, WriteCursor};
use crate::l2cap::{L2capHeader, PacketReassembly, L2CAP_CID_ATT, L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SIGNAL};
use crate::packet_pool::{AllocId, DynamicPacketPool, PacketPool, Qos};
use crate::pdu::Pdu;
use crate::scan::{PhySet, ScanConfig, ScanReport};
use crate::types::l2cap::L2capLeSignal;
use crate::Address;
use crate::{AdapterError, Error};
use bt_hci::cmd::controller_baseband::{HostBufferSize, Reset, SetEventMask};
use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearAdvSets, LeClearFilterAcceptList, LeCreateConn, LeCreateConnParams,
    LeExtCreateConn, LeReadBufferSize, LeSetAdvSetRandomAddr, LeSetEventMask, LeSetExtAdvData, LeSetExtAdvEnable,
    LeSetExtAdvParams, LeSetExtScanEnable, LeSetExtScanParams, LeSetExtScanResponseData, LeSetRandomAddr,
    LeSetScanEnable, LeSetScanParams,
};
use bt_hci::cmd::link_control::{Disconnect, DisconnectParams};
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::Controller;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::param::{
    AddrKind, AdvHandle, BdAddr, ConnHandle, DisconnectReason, EventMask, FilterDuplicates, InitiatingPhy, LeEventMask,
    Operation, PhyParams, ScanningPhy,
};
use bt_hci::ControllerToHostPacket;
use core::task::Poll;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::Channel;
use futures_intrusive::sync::LocalSemaphore;

#[cfg(feature = "gatt")]
use crate::{attribute::AttributeTable, gatt::GattServer};

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
    pub(crate) address: Option<Address>,
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<M, CONNS>,
    pub(crate) reassembly: PacketReassembly<'d, CONNS>,
    pub(crate) channels: ChannelManager<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    pub(crate) att_inbound: Channel<M, (ConnHandle, Pdu<'d>), L2CAP_RXQ>,
    pub(crate) pool: &'d dyn DynamicPacketPool<'d>,
    pub(crate) permits: LocalSemaphore,

    pub(crate) control: Channel<M, ControlCommand, 1>,
    pub(crate) scanner: Channel<M, Option<ScanReport>, 1>,
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
            address: None,
            controller,
            connections: ConnectionManager::new(),
            reassembly: PacketReassembly::new(),
            channels: ChannelManager::new(&host_resources.pool),
            pool: &host_resources.pool,
            att_inbound: Channel::new(),
            scanner: Channel::new(),
            control: Channel::new(),
            permits: LocalSemaphore::new(true, 0),
        }
    }

    pub async fn set_random_address(&mut self, address: Address) -> Result<(), AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeSetRandomAddr>,
    {
        LeSetRandomAddr::new(address.addr).exec(&self.controller).await?;
        self.address.replace(address);
        Ok(())
    }

    pub(crate) async fn set_accept_filter(
        &self,
        filter_accept_list: &[(AddrKind, &BdAddr)],
    ) -> Result<(), AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList> + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        LeClearFilterAcceptList::new().exec(&self.controller).await?;
        for entry in filter_accept_list {
            LeAddDeviceToFilterAcceptList::new(entry.0, *entry.1)
                .exec(&self.controller)
                .await?;
        }
        Ok(())
    }

    pub async fn command<C>(&self, cmd: C) -> Result<C::Return, AdapterError<T::Error>>
    where
        C: SyncCmd,
        T: ControllerCmdSync<C>,
    {
        let ret = cmd.exec(&self.controller).await?;
        Ok(ret)
    }

    pub async fn async_command<C>(&self, cmd: C) -> Result<(), AdapterError<T::Error>>
    where
        C: AsyncCmd,
        T: ControllerCmdAsync<C>,
    {
        cmd.exec(&self.controller).await?;
        Ok(())
    }

    pub(crate) async fn connect(&self, config: &ConnectConfig<'_>) -> Result<Connection<'_>, AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>
            + ControllerCmdAsync<LeExtCreateConn>
            + ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }
        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        if config.scan_config.extended {
            let initiating = InitiatingPhy {
                scan_interval: config.scan_config.interval.into(),
                scan_window: config.scan_config.window.into(),
                conn_interval_min: config.connect_params.min_connection_interval.into(),
                conn_interval_max: config.connect_params.max_connection_interval.into(),
                max_latency: config.connect_params.max_latency,
                supervision_timeout: config.connect_params.supervision_timeout.into(),
                min_ce_len: config.connect_params.event_length.into(),
                max_ce_len: config.connect_params.event_length.into(),
            };
            let phy_params = Self::create_phy_params(initiating, config.scan_config.phys);
            LeExtCreateConn::new(
                true,
                self.address.map(|a| a.kind).unwrap_or(AddrKind::RANDOM),
                AddrKind::RANDOM,
                BdAddr::default(),
                phy_params,
            )
            .exec(&self.controller)
            .await?;
            let info = self.connections.accept(config.scan_config.filter_accept_list).await;
            return Ok(Connection {
                info,
                control: self.control.sender().into(),
            });
        } else {
            LeCreateConn::new(
                config.scan_config.interval.into(),
                config.scan_config.window.into(),
                true,
                AddrKind::RANDOM,
                BdAddr::default(),
                self.address.map(|a| a.kind).unwrap_or(AddrKind::RANDOM),
                config.connect_params.min_connection_interval.into(),
                config.connect_params.max_connection_interval.into(),
                config.connect_params.max_latency,
                config.connect_params.supervision_timeout.into(),
                config.connect_params.event_length.into(),
                config.connect_params.event_length.into(),
            )
            .exec(&self.controller)
            .await?;
            let info = self.connections.accept(config.scan_config.filter_accept_list).await;
            return Ok(Connection {
                info,
                control: self.control.sender().into(),
            });
        }
    }

    fn create_phy_params<P: Copy>(phy: P, phys: PhySet) -> PhyParams<P> {
        let phy_params: PhyParams<P> = PhyParams {
            le_1m_phy: match phys {
                PhySet::M1 | PhySet::M1M2 | PhySet::M1Coded | PhySet::M1M2Coded => Some(phy),
                _ => None,
            },
            le_2m_phy: match phys {
                PhySet::M2 | PhySet::M1M2 | PhySet::M2Coded | PhySet::M1M2Coded => Some(phy),
                _ => None,
            },
            le_coded_phy: match phys {
                PhySet::M2Coded | PhySet::Coded | PhySet::M1Coded | PhySet::M1M2Coded => Some(phy),
                _ => None,
            },
        };
        phy_params
    }

    async fn start_scan(&self, config: &ScanConfig<'_>) -> Result<(), AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        self.set_accept_filter(config.filter_accept_list).await?;

        if config.extended {
            let scanning = ScanningPhy {
                active_scan: config.active,
                scan_interval: config.interval.into(),
                scan_window: config.window.into(),
            };
            let phy_params = Self::create_phy_params(scanning, config.phys);
            LeSetExtScanParams::new(
                self.address.map(|s| s.kind).unwrap_or(AddrKind::RANDOM),
                if config.filter_accept_list.is_empty() {
                    bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
                } else {
                    bt_hci::param::ScanningFilterPolicy::BasicFiltered
                },
                phy_params,
            )
            .exec(&self.controller)
            .await?;
            LeSetExtScanEnable::new(
                true,
                FilterDuplicates::Disabled,
                config.timeout.into(),
                bt_hci::param::Duration::from_secs(0),
            )
            .exec(&self.controller)
            .await?;
        } else {
            let params = LeSetScanParams::new(
                if config.active {
                    bt_hci::param::LeScanKind::Active
                } else {
                    bt_hci::param::LeScanKind::Passive
                },
                config.interval.into(),
                config.interval.into(),
                bt_hci::param::AddrKind::RANDOM,
                if config.filter_accept_list.is_empty() {
                    bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
                } else {
                    bt_hci::param::ScanningFilterPolicy::BasicFiltered
                },
            );
            params.exec(&self.controller).await?;

            LeSetScanEnable::new(true, true).exec(&self.controller).await?;
        }
        Ok(())
    }

    async fn stop_scan(&self, config: &ScanConfig<'_>) -> Result<(), AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeSetExtScanEnable> + ControllerCmdSync<LeSetScanEnable>,
    {
        if config.extended {
            LeSetExtScanEnable::new(
                false,
                FilterDuplicates::Disabled,
                bt_hci::param::Duration::from_secs(0),
                bt_hci::param::Duration::from_secs(0),
            )
            .exec(&self.controller)
            .await?;
        } else {
            LeSetScanEnable::new(false, false).exec(&self.controller).await?;
        }
        Ok(())
    }

    /// Performs a BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan(&self, config: &ScanConfig<'_>) -> Result<ScanReport, AdapterError<T::Error>>
    where
        T: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        self.start_scan(config).await?;
        let Some(report) = self.scanner.receive().await else {
            return Err(Error::Timeout.into());
        };
        self.stop_scan(config).await?;
        Ok(report)
    }

    /// Starts sending BLE advertisements according to the provided config.
    ///
    /// Advertisements are stopped when a connection is made against this host,
    /// in which case a handle for the connection is returned.
    pub async fn advertise<'m, 'k>(
        &'m self,
        config: &AdvertisementConfig,
        params: impl Into<RawAdvertisement<'k>>,
    ) -> Result<Connection<'m>, AdapterError<T::Error>>
    where
        T: for<'t> ControllerCmdSync<LeSetExtAdvData<'t>>
            + ControllerCmdSync<LeClearAdvSets>
            + ControllerCmdSync<LeSetExtAdvParams>
            + ControllerCmdSync<LeSetAdvSetRandomAddr>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>,
    {
        // May fail if already disabled
        let _ = LeSetExtAdvEnable::new(false, &[]).exec(&self.controller).await;
        let _ = LeClearAdvSets::new().exec(&self.controller).await;
        let handle = AdvHandle::new(0); // TODO: Configurable?

        let mut params = params.into();
        let timeout = config
            .timeout
            .map(|m| m.into())
            .unwrap_or(bt_hci::param::Duration::from_secs(0));
        let max_events = config.max_events.unwrap_or(0);

        params.set.duration = timeout;
        params.set.max_ext_adv_events = max_events;

        let peer = params.peer.unwrap_or(Address {
            kind: AddrKind::RANDOM,
            addr: BdAddr::default(),
        });
        LeSetExtAdvParams::new(
            handle,
            params.props,
            config.interval_min.into(),
            config.interval_min.into(),
            config.channel_map,
            self.address.map(|a| a.kind).unwrap_or(AddrKind::RANDOM),
            peer.kind,
            peer.addr,
            config.filter_policy,
            config.tx_power as i8,
            config.primary_phy,
            0,
            config.secondary_phy,
            params.set.adv_handle.as_raw(),
            false,
        )
        .exec(&self.controller)
        .await?;

        if let Some(address) = self.address {
            LeSetAdvSetRandomAddr::new(handle, address.addr)
                .exec(&self.controller)
                .await?;
        }

        if !params.adv_data.is_empty() {
            //          let mut data = [0; 31];
            //          let mut w = WriteCursor::new(&mut data[..]);
            //          for item in params.adv_data.iter() {
            //              item.encode(&mut w)?;
            //          }
            //          let len = w.len();
            LeSetExtAdvData::new(handle, Operation::Complete, false, params.adv_data)
                .exec(&self.controller)
                .await?;
        }

        if !params.scan_data.is_empty() {
            //let mut data = [0; 31];
            //let mut w = WriteCursor::new(&mut data[..]);
            //for item in params.scan_data.iter() {
            //    item.encode(&mut w)?;
            //}
            //let len = w.len();
            LeSetExtScanResponseData::new(handle, Operation::Complete, false, params.scan_data)
                .exec(&self.controller)
                .await?;
        }

        LeSetExtAdvEnable::new(true, &[params.set])
            .exec(&self.controller)
            .await?;
        let conn = Connection::accept(self).await;
        LeSetExtAdvEnable::new(false, &[]).exec(&self.controller).await?;
        Ok(conn)
    }

    /// Creates a GATT server capable of processing the GATT protocol using the provided table of attributes.
    #[cfg(feature = "gatt")]
    pub fn gatt_server<'reference, 'values, const MAX: usize>(
        &'reference self,
        table: &'reference AttributeTable<'values, M, MAX>,
    ) -> GattServer<'reference, 'values, 'd, M, T, MAX> {
        use crate::attribute_server::AttributeServer;
        GattServer {
            server: AttributeServer::new(table),
            pool: self.pool,
            pool_id: crate::packet_pool::ATT_ID,
            rx: self.att_inbound.receiver().into(),
            tx: self.hci(),
            connections: &self.connections,
        }
    }

    async fn handle_acl(&self, acl: AclPacket<'_>) -> Result<(), Error> {
        let (header, packet) = match acl.boundary_flag() {
            AclPacketBoundary::FirstFlushable => {
                let (header, data) = L2capHeader::decode(&acl)?;

                // Avoids using the packet buffer for signalling packets
                if header.channel == L2CAP_CID_LE_U_SIGNAL {
                    assert!(data.len() == header.length as usize);
                    let mut r = ReadCursor::new(data);
                    let signal: L2capLeSignal = r.read()?;
                    self.channels.control(acl.handle(), signal).await?;
                    return Ok(());
                }

                let Some(mut p) = self.pool.alloc(AllocId::from_channel(header.channel)) else {
                    return Err(Error::OutOfMemory);
                };
                p.as_mut()[..data.len()].copy_from_slice(data);

                if header.length as usize != data.len() {
                    self.reassembly.init(acl.handle(), header, p, data.len())?;
                    return Ok(());
                }
                (header, p)
            }
            // Next (potentially last) in a fragment
            AclPacketBoundary::Continuing => {
                // Get the existing fragment
                if let Some((header, p)) = self.reassembly.update(acl.handle(), acl.data())? {
                    (header, p)
                } else {
                    // Do not process yet
                    return Ok(());
                }
            }
            other => {
                warn!("Unexpected boundary flag: {:?}!", other);
                return Err(Error::NotSupported);
            }
        };

        match header.channel {
            L2CAP_CID_ATT => {
                #[cfg(feature = "gatt")]
                self.att_inbound
                    .send((acl.handle(), Pdu::new(packet, header.length as usize)))
                    .await;
                #[cfg(not(feature = "gatt"))]
                return Err(Error::NotSupported);
            }
            L2CAP_CID_LE_U_SIGNAL => {
                panic!("le signalling channel was fragmented, impossible!");
            }
            other if other >= L2CAP_CID_DYN_START => match self.channels.dispatch(header, packet).await {
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
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdSync<Reset>
            + ControllerCmdAsync<LeCreateConn>
            //            + ControllerCmdSync<LeReadLocalSupportedFeatures>
            //            + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        const MAX_HCI_PACKET_LEN: usize = 259;
        self.control.send(ControlCommand::Init).await;
        let mut disconnects = 0;
        loop {
            // Task handling receiving data from the controller.
            let rx_fut = async {
                let mut rx = [0u8; MAX_HCI_PACKET_LEN];
                match self.controller.read(&mut rx).await {
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
                                        peer_addr_kind: e.peer_addr_kind,
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
                            LeEvent::LeScanTimeout(_) => {
                                self.scanner.send(None).await;
                            }
                            LeEvent::LeExtendedAdvertisingReport(data) => {
                                self.scanner
                                    .send(Some(ScanReport::new(data.reports.num_reports, &data.reports.bytes)))
                                    .await;
                            }
                            LeEvent::LeAdvertisingReport(data) => {
                                self.scanner
                                    .send(Some(ScanReport::new(data.reports.num_reports, &data.reports.bytes)))
                                    .await;
                            }
                            _ => {
                                error!("Unknown event: {:?}", event);
                            }
                        },
                        Event::DisconnectionComplete(e) => {
                            disconnects += 1;
                            info!("Disconnected (total {}): {:?}", disconnects, e);
                            let _ = self.connections.disconnect(e.handle);
                            let _ = self.channels.disconnected_connection(e.handle);
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
                        info!("Informing controller we have buffer size of {}", self.pool.mtu());
                        HostBufferSize::new(
                            self.pool.mtu() as u16,
                            self.pool.mtu() as u8,
                            L2CAP_RXQ as u16,
                            L2CAP_RXQ as u16,
                        )
                        .exec(&self.controller)
                        .await?;
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

                        LeSetEventMask::new(
                            LeEventMask::new()
                                .enable_le_conn_complete(true)
                                .enable_le_conn_update_complete(true)
                                .enable_le_adv_report(true)
                                .enable_le_scan_timeout(true)
                                .enable_le_ext_adv_report(true),
                        )
                        .exec(&self.controller)
                        .await?;

                        let ret = LeReadBufferSize::new().exec(&self.controller).await?;
                        trace!(
                            "Setting max flow control packets to {}",
                            ret.total_num_le_acl_data_packets
                        );
                        self.permits.release(ret.total_num_le_acl_data_packets as usize);

                        //                        let feats = LeReadLocalSupportedFeatures::new().exec(&self.controller).await?;
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
    pub(crate) controller: &'d T,
    pub(crate) permits: &'d LocalSemaphore,
}

impl<'d, T: Controller> HciController<'d, T> {
    pub(crate) fn try_send(&self, handle: ConnHandle, pdu: &[u8]) -> Result<(), AdapterError<T::Error>> {
        let permit = self
            .permits
            .try_acquire(1)
            .ok_or::<AdapterError<T::Error>>(Error::NoPermits.into())?;
        let acl = AclPacket::new(
            handle,
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            pdu,
        );
        // info!("Sent ACL {:?}", acl);
        let fut = self.controller.write_acl_data(&acl);
        match embassy_futures::poll_once(fut) {
            Poll::Ready(result) => result.map_err(AdapterError::Controller),
            Poll::Pending => Err(Error::Busy.into()),
        }
    }

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
        // info!("[{}] sending signal: {:?}", handle, response);
        let mut tx = [0; 32];
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
