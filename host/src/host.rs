//! BleHost
//!
//! The host module contains the main entry point for the TrouBLE host.
use core::future::poll_fn;
use core::task::Poll;

use bt_hci::cmd::controller_baseband::{HostBufferSize, Reset, SetEventMask};
use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearAdvSets, LeClearFilterAcceptList, LeCreateConn, LeCreateConnCancel,
    LeExtCreateConn, LeReadBufferSize, LeSetAdvData, LeSetAdvEnable, LeSetAdvParams, LeSetAdvSetRandomAddr,
    LeSetEventMask, LeSetExtAdvData, LeSetExtAdvEnable, LeSetExtAdvParams, LeSetExtScanEnable, LeSetExtScanParams,
    LeSetExtScanResponseData, LeSetRandomAddr, LeSetScanEnable, LeSetScanParams, LeSetScanResponseData,
};
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::{blocking, Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::{Event, Vendor};
use bt_hci::param::{
    AddrKind, AdvChannelMap, AdvHandle, AdvKind, BdAddr, ConnHandle, DisconnectReason, EventMask, FilterDuplicates,
    InitiatingPhy, LeEventMask, Operation, PhyParams, ScanningPhy,
};
use bt_hci::{ControllerToHostPacket, FromHciBytes, WriteHci};
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::once_lock::OnceLock;
use futures::pin_mut;

use crate::advertise::{Advertisement, AdvertisementConfig, RawAdvertisement};
use crate::channel_manager::{ChannelManager, ChannelStorage, RxChannel, RX_CHANNEL};
use crate::connection::{ConnectConfig, Connection};
use crate::connection_manager::{ConnectionManager, ConnectionStorage, PacketGrant};
use crate::cursor::WriteCursor;
use crate::l2cap::sar::{PacketReassembly, SarType, EMPTY_SAR};
use crate::packet_pool::{AllocId, GlobalPacketPool, PacketPool, Qos};
use crate::pdu::Pdu;
use crate::scan::{PhySet, ScanConfig, ScanReport};
use crate::types::l2cap::{
    L2capHeader, L2capSignal, L2capSignalHeader, L2CAP_CID_ATT, L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SIGNAL,
};
#[cfg(feature = "gatt")]
use crate::{attribute::AttributeTable, gatt::GattServer};
use crate::{Address, BleHostError, Error};

/// BleHostResources holds the resources used by the host.
///
/// The packet pool is used by the host to multiplex data streams, by allocating space for
/// incoming packets and dispatching to the appropriate connection and channel.
pub struct BleHostResources<const CONNS: usize, const CHANNELS: usize, const PACKETS: usize, const L2CAP_MTU: usize> {
    pool: PacketPool<NoopRawMutex, L2CAP_MTU, PACKETS, CHANNELS>,
    connections: [ConnectionStorage; CONNS],
    channels: [ChannelStorage; CHANNELS],
    channels_rx: [RxChannel; CHANNELS],
    sar: [SarType; CONNS],
}

impl<const CONNS: usize, const CHANNELS: usize, const PACKETS: usize, const L2CAP_MTU: usize>
    BleHostResources<CONNS, CHANNELS, PACKETS, L2CAP_MTU>
{
    /// Create a new instance of host resources with the provided QoS requirements for packets.
    pub fn new(qos: Qos) -> Self {
        Self {
            pool: PacketPool::new(qos),
            connections: [ConnectionStorage::DISCONNECTED; CONNS],
            sar: [EMPTY_SAR; CONNS],
            channels: [ChannelStorage::DISCONNECTED; CHANNELS],
            channels_rx: [RX_CHANNEL; CHANNELS],
        }
    }
}

/// Event handler for vendor-specific events handled outside the host.
pub trait VendorEventHandler {
    fn on_event(&self, event: &Vendor<'_>);
}

/// A BLE Host.
///
/// The BleHost holds the runtime state of the host, and is the entry point
/// for all interactions with the controller.
///
/// The host performs connection management, l2cap channel management, and
/// multiplexes events and data across connections and l2cap channels.
pub struct BleHost<'d, T> {
    address: Option<Address>,
    initialized: OnceLock<()>,
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<'d>,
    pub(crate) reassembly: PacketReassembly<'d>,
    pub(crate) channels: ChannelManager<'d>,
    pub(crate) att_inbound: Channel<NoopRawMutex, (ConnHandle, Pdu), 1>,
    pub(crate) pool: &'static dyn GlobalPacketPool,

    pub(crate) scanner: Channel<NoopRawMutex, Option<ScanReport>, 1>,
}

impl<'d, T> BleHost<'d, T>
where
    T: Controller,
{
    /// Create a new instance of the BLE host.
    ///
    /// The host requires a HCI driver (a particular HCI-compatible controller implementing the required traits), and
    /// a reference to resources that are created outside the host but which the host is the only accessor of.
    pub fn new<const CONNS: usize, const CHANNELS: usize, const PACKETS: usize, const L2CAP_MTU: usize>(
        controller: T,
        host_resources: &'static mut BleHostResources<CONNS, CHANNELS, PACKETS, L2CAP_MTU>,
    ) -> Self {
        Self {
            address: None,
            initialized: OnceLock::new(),
            controller,
            connections: ConnectionManager::new(&mut host_resources.connections[..]),
            reassembly: PacketReassembly::new(&mut host_resources.sar[..]),
            channels: ChannelManager::new(
                &host_resources.pool,
                &mut host_resources.channels[..],
                &mut host_resources.channels_rx[..],
            ),
            pool: &host_resources.pool,
            att_inbound: Channel::new(),
            scanner: Channel::new(),
        }
    }

    /// Set the random address used by this host.
    pub fn set_random_address(&mut self, address: Address) {
        self.address.replace(address);
    }

    pub(crate) async fn set_accept_filter(
        &self,
        filter_accept_list: &[(AddrKind, &BdAddr)],
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList> + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        self.command(LeClearFilterAcceptList::new()).await?;
        for entry in filter_accept_list {
            self.command(LeAddDeviceToFilterAcceptList::new(entry.0, *entry.1))
                .await?;
        }
        Ok(())
    }

    /// Run a HCI command and return the response.
    pub async fn command<C>(&self, cmd: C) -> Result<C::Return, BleHostError<T::Error>>
    where
        C: SyncCmd,
        T: ControllerCmdSync<C>,
    {
        let _ = self.initialized.get().await;
        let ret = cmd.exec(&self.controller).await?;
        Ok(ret)
    }

    /// Run an async HCI command where the response will generate an event later.
    pub async fn async_command<C>(&self, cmd: C) -> Result<(), BleHostError<T::Error>>
    where
        C: AsyncCmd,
        T: ControllerCmdAsync<C>,
    {
        let _ = self.initialized.get().await;
        cmd.exec(&self.controller).await?;
        Ok(())
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect(&self, config: &ConnectConfig<'_>) -> Result<Connection, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>
            + ControllerCmdSync<LeCreateConnCancel>,
    {
        // Cancel any ongoing connection process
        let r = self.command(LeCreateConnCancel::new()).await;
        if let Ok(()) = r {
            self.connections.wait_canceled().await;
        }

        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        self.async_command(LeCreateConn::new(
            config.scan_config.interval.into(),
            config.scan_config.window.into(),
            true,
            AddrKind::PUBLIC,
            BdAddr::default(),
            self.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            config.connect_params.min_connection_interval.into(),
            config.connect_params.max_connection_interval.into(),
            config.connect_params.max_latency,
            config.connect_params.supervision_timeout.into(),
            config.connect_params.event_length.into(),
            config.connect_params.event_length.into(),
        ))
        .await?;
        let handle = self.connections.accept(config.scan_config.filter_accept_list).await;
        Ok(Connection::new(handle))
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect_ext(&self, config: &ConnectConfig<'_>) -> Result<Connection, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeExtCreateConn>
            + ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeCreateConnCancel>,
    {
        // Cancel any ongoing connection process
        let r = self.command(LeCreateConnCancel::new()).await;
        if let Ok(()) = r {
            self.connections.wait_canceled().await;
        }

        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

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
        self.async_command(LeExtCreateConn::new(
            true,
            self.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            AddrKind::PUBLIC,
            BdAddr::default(),
            phy_params,
        ))
        .await?;
        let handle = self.connections.accept(config.scan_config.filter_accept_list).await;
        Ok(Connection::new(handle))
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

    async fn start_scan(&self, config: &ScanConfig<'_>) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeSetScanParams>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        self.set_accept_filter(config.filter_accept_list).await?;

        let params = LeSetScanParams::new(
            if config.active {
                bt_hci::param::LeScanKind::Active
            } else {
                bt_hci::param::LeScanKind::Passive
            },
            config.interval.into(),
            config.interval.into(),
            bt_hci::param::AddrKind::PUBLIC,
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
        );
        self.command(params).await?;
        self.command(LeSetScanEnable::new(true, true)).await?;
        Ok(())
    }

    async fn start_scan_ext(&self, config: &ScanConfig<'_>) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        self.set_accept_filter(config.filter_accept_list).await?;

        let scanning = ScanningPhy {
            active_scan: config.active,
            scan_interval: config.interval.into(),
            scan_window: config.window.into(),
        };
        let phy_params = Self::create_phy_params(scanning, config.phys);
        self.command(LeSetExtScanParams::new(
            self.address.map(|s| s.kind).unwrap_or(AddrKind::PUBLIC),
            if config.filter_accept_list.is_empty() {
                bt_hci::param::ScanningFilterPolicy::BasicUnfiltered
            } else {
                bt_hci::param::ScanningFilterPolicy::BasicFiltered
            },
            phy_params,
        ))
        .await?;
        self.command(LeSetExtScanEnable::new(
            true,
            FilterDuplicates::Disabled,
            config.timeout.into(),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        Ok(())
    }

    async fn stop_scan(&self, config: &ScanConfig<'_>) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeSetScanEnable>,
    {
        self.command(LeSetScanEnable::new(false, false)).await?;
        Ok(())
    }

    async fn stop_scan_ext(&self, config: &ScanConfig<'_>) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeSetExtScanEnable>,
    {
        self.command(LeSetExtScanEnable::new(
            false,
            FilterDuplicates::Disabled,
            bt_hci::param::Duration::from_secs(0),
            bt_hci::param::Duration::from_secs(0),
        ))
        .await?;
        Ok(())
    }

    /// Performs an extended BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan_ext(&self, config: &ScanConfig<'_>) -> Result<ScanReport, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>
            + ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        self.start_scan_ext(config).await?;
        let Some(report) = self.scanner.receive().await else {
            return Err(Error::Timeout.into());
        };
        self.stop_scan_ext(config).await?;
        Ok(report)
    }

    /// Performs a BLE scan, return a report for discovering peripherals.
    ///
    /// Scan is stopped when a report is received. Call this method repeatedly to continue scanning.
    pub async fn scan(&self, config: &ScanConfig<'_>) -> Result<ScanReport, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeSetScanParams>
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

    //
    pub async fn advertise<'k>(
        &self,
        config: &AdvertisementConfig,
        params: Advertisement<'k>,
    ) -> Result<Connection, BleHostError<T::Error>>
    where
        T: for<'t> ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetScanResponseData>,
    {
        // May fail if already disabled
        let _ = self.command(LeSetAdvEnable::new(false)).await;

        let mut params: RawAdvertisement = params.into();
        let timeout = config
            .timeout
            .map(|m| m.into())
            .unwrap_or(bt_hci::param::Duration::from_secs(0));
        let max_events = config.max_events.unwrap_or(0);

        params.set.duration = timeout;
        params.set.max_ext_adv_events = max_events;

        if !params.props.legacy_adv() {
            return Err(Error::InvalidValue.into());
        }

        let kind = match (params.props.connectable_adv(), params.props.scannable_adv()) {
            (true, true) => AdvKind::AdvInd,
            (true, false) => AdvKind::AdvDirectIndLow,
            (false, true) => AdvKind::AdvScanInd,
            (false, false) => AdvKind::AdvNonconnInd,
        };
        let peer = params.peer.unwrap_or(Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::default(),
        });

        self.command(LeSetAdvParams::new(
            config.interval_min.into(),
            config.interval_max.into(),
            kind,
            self.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            peer.kind,
            peer.addr,
            config.channel_map.unwrap_or(AdvChannelMap::ALL),
            config.filter_policy,
        ))
        .await?;

        if !params.adv_data.is_empty() {
            let mut data = [0; 31];
            let to_copy = params.adv_data.len().min(data.len());
            data[..to_copy].copy_from_slice(&params.adv_data[..to_copy]);
            self.command(LeSetAdvData::new(to_copy as u8, data)).await?;
        }

        if !params.scan_data.is_empty() {
            let mut data = [0; 31];
            let to_copy = params.scan_data.len().min(data.len());
            data[..to_copy].copy_from_slice(&params.scan_data[..to_copy]);
            self.command(LeSetScanResponseData::new(to_copy as u8, data)).await?;
        }

        self.command(LeSetAdvEnable::new(true)).await?;
        let handle = self.connections.accept(&[]).await;
        self.command(LeSetAdvEnable::new(false)).await?;
        Ok(Connection::new(handle))
    }

    /// Starts sending BLE advertisements according to the provided config.
    ///
    /// Advertisements are stopped when a connection is made against this host,
    /// in which case a handle for the connection is returned.
    pub async fn advertise_ext<'k>(
        &self,
        config: &AdvertisementConfig,
        params: impl Into<RawAdvertisement<'k>>,
    ) -> Result<Connection, BleHostError<T::Error>>
    where
        T: for<'t> ControllerCmdSync<LeSetExtAdvData<'t>>
            + ControllerCmdSync<LeClearAdvSets>
            + ControllerCmdSync<LeSetExtAdvParams>
            + ControllerCmdSync<LeSetAdvSetRandomAddr>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>,
    {
        // May fail if already disabled
        let _ = self.command(LeSetExtAdvEnable::new(false, &[])).await;
        let _ = self.command(LeClearAdvSets::new()).await;
        let handle = AdvHandle::new(0); // TODO: Configurable?

        let mut params: RawAdvertisement = params.into();
        let timeout = config
            .timeout
            .map(|m| m.into())
            .unwrap_or(bt_hci::param::Duration::from_secs(0));
        let max_events = config.max_events.unwrap_or(0);

        params.set.duration = timeout;
        params.set.max_ext_adv_events = max_events;

        let peer = params.peer.unwrap_or(Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::default(),
        });
        self.command(LeSetExtAdvParams::new(
            handle,
            params.props,
            config.interval_min.into(),
            config.interval_max.into(),
            config.channel_map.unwrap_or(AdvChannelMap::ALL),
            self.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            peer.kind,
            peer.addr,
            config.filter_policy,
            config.tx_power as i8,
            config.primary_phy,
            0,
            config.secondary_phy,
            0,
            false,
        ))
        .await?;

        if let Some(address) = self.address {
            self.command(LeSetAdvSetRandomAddr::new(handle, address.addr)).await?;
        }

        if !params.adv_data.is_empty() {
            self.command(LeSetExtAdvData::new(
                handle,
                Operation::Complete,
                false,
                params.adv_data,
            ))
            .await?;
        }

        if !params.scan_data.is_empty() {
            self.command(LeSetExtScanResponseData::new(
                handle,
                Operation::Complete,
                false,
                params.scan_data,
            ))
            .await?;
        }

        self.command(LeSetExtAdvEnable::new(true, &[params.set])).await?;
        let handle = self.connections.accept(&[]).await;
        self.command(LeSetExtAdvEnable::new(false, &[])).await?;
        Ok(Connection::new(handle))
    }

    /// Creates a GATT server capable of processing the GATT protocol using the provided table of attributes.
    #[cfg(feature = "gatt")]
    pub fn gatt_server<'reference, 'values, M: embassy_sync::blocking_mutex::raw::RawMutex, const MAX: usize>(
        &'reference self,
        table: &'reference AttributeTable<'values, M, MAX>,
    ) -> GattServer<'reference, 'values, 'd, M, T, MAX> {
        use crate::attribute_server::AttributeServer;
        GattServer {
            server: AttributeServer::new(table),
            pool: self.pool,
            pool_id: crate::packet_pool::ATT_ID,
            rx: self.att_inbound.receiver().into(),
            tx: self,
            connections: &self.connections,
        }
    }

    async fn handle_acl(&self, acl: AclPacket<'_>) -> Result<(), Error> {
        let (header, packet) = match acl.boundary_flag() {
            AclPacketBoundary::FirstFlushable => {
                let (header, data) = L2capHeader::from_hci_bytes(acl.data())?;

                // Avoids using the packet buffer for signalling packets
                if header.channel == L2CAP_CID_LE_U_SIGNAL {
                    assert!(data.len() == header.length as usize);
                    self.channels.signal(acl.handle(), data).await?;
                    return Ok(());
                }

                let Some(mut p) = self.pool.alloc(AllocId::from_channel(header.channel)) else {
                    trace!("No memory for packets on channel {}", header.channel);
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

    pub async fn run(&self) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdSync<Reset>
            //            + ControllerCmdSync<LeReadLocalSupportedFeatures>
            //            + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        self.run_with_handler(None).await
    }

    pub async fn run_with_handler(
        &self,
        vendor_handler: Option<&dyn VendorEventHandler>,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdSync<Reset>
            //            + ControllerCmdSync<LeReadLocalSupportedFeatures>
            //            + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        const MAX_HCI_PACKET_LEN: usize = 259;
        let mut disconnects = 0;

        // Control future that initializes system and handles controller changes.
        let control_fut = async {
            Reset::new().exec(&self.controller).await?;

            if let Some(addr) = self.address {
                LeSetRandomAddr::new(addr.addr).exec(&self.controller).await?;
                info!("BleHost address set to {:?}", addr.addr);
            }

            HostBufferSize::new(self.pool.mtu() as u16, self.pool.mtu() as u8, 1, 1)
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
                    //                    .enable_le_conn_update_complete(true)
                    //                    .enable_le_enhanced_conn_complete(true)
                    //                    .enable_le_conn_iq_report(true)
                    //                    .enable_le_transmit_power_reporting(true)
                    //                    .enable_le_enhanced_conn_complete_v2(true)
                    //                    .enable_le_adv_set_terminated(true)
                    .enable_le_adv_report(true)
                    .enable_le_scan_timeout(true)
                    .enable_le_ext_adv_report(true),
            )
            .exec(&self.controller)
            .await?;

            let ret = LeReadBufferSize::new().exec(&self.controller).await?;
            info!("[host] setting txq to {}", ret.total_num_le_acl_data_packets as usize);
            self.connections
                .set_link_credits(ret.total_num_le_acl_data_packets as usize);
            // TODO: Configure ACL max buffer size as well?
            let _ = self.initialized.init(());

            loop {
                let it = poll_fn(|cx| self.connections.poll_disconnecting(cx)).await;
                for entry in it {
                    self.command(Disconnect::new(entry.0, entry.1)).await?;
                }
            }
        };
        pin_mut!(control_fut);

        loop {
            // Task handling receiving data from the controller.
            let rx_fut = async {
                let mut rx = [0u8; MAX_HCI_PACKET_LEN];
                let result = self.controller.read(&mut rx).await;
                match result {
                    Ok(ControllerToHostPacket::Acl(acl)) => match self.handle_acl(acl).await {
                        Ok(_) => {}
                        Err(e) => {
                            info!("Error processing ACL packet: {:?}", e);
                        }
                    },
                    Ok(ControllerToHostPacket::Event(event)) => match event {
                        Event::Le(event) => match event {
                            LeEvent::LeConnectionComplete(e) => match e.status.to_result() {
                                Ok(_) => {
                                    if let Err(err) = self.connections.connect(e.handle, &e) {
                                        warn!("Error establishing connection: {:?}", err);
                                        let _ = self
                                            .command(Disconnect::new(
                                                e.handle,
                                                DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                            ))
                                            .await;
                                    }
                                }
                                Err(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER) => {
                                    self.connections.canceled();
                                }
                                Err(e) => {
                                    warn!("Error connection complete");
                                    warn!("Error connection complete event: {:?}", e);
                                }
                            },
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
                                warn!("Unknown LE event!");
                            }
                        },
                        Event::DisconnectionComplete(e) => {
                            disconnects += 1;
                            let handle = e.handle;
                            #[cfg(feature = "defmt")]
                            let e = defmt::Debug2Format(&e);
                            info!("Disconnected (total {}): {:?}", disconnects, e);
                            let _ = self.connections.disconnect(handle);
                            let _ = self.channels.disconnected(handle);
                        }
                        Event::NumberOfCompletedPackets(c) => {
                            // Explicitly ignoring for now
                            for entry in c.completed_packets.iter() {
                                if let (Ok(handle), Ok(completed)) = (entry.handle(), entry.num_completed_packets()) {
                                    let _ = self.connections.confirm_sent(handle, completed as usize);
                                }
                            }
                        }
                        Event::Vendor(vendor) => {
                            if let Some(handler) = vendor_handler {
                                handler.on_event(&vendor);
                            }
                        }
                        _ => {
                            warn!("Unknown event");
                        }
                    },
                    Ok(p) => {
                        warn!("Ignoring packet: {:?}", p);
                    }
                    Err(e) => {
                        #[cfg(feature = "defmt")]
                        let e = defmt::Debug2Format(&e);
                        warn!("Error from controller: {:?}", e);
                    }
                }
                Ok(())
            };

            // info!("Entering select loop");
            let result: Result<(), BleHostError<T::Error>> = match select(&mut control_fut, rx_fut).await {
                Either::First(result) => result,
                Either::Second(result) => result,
            };
            result?;
        }
    }

    // Request to send n ACL packets to the HCI controller for a connection
    pub(crate) async fn acl(&self, handle: ConnHandle, n: u16) -> Result<AclSender<'_, 'd, T>, BleHostError<T::Error>> {
        let grant = poll_fn(|cx| self.connections.poll_request_to_send(handle, n as usize, Some(cx))).await?;
        Ok(AclSender {
            controller: &self.controller,
            handle,
            grant,
        })
    }

    // Request to send n ACL packets to the HCI controller for a connection
    pub(crate) fn try_acl(&self, handle: ConnHandle, n: u16) -> Result<AclSender<'_, 'd, T>, BleHostError<T::Error>> {
        let grant = match self.connections.poll_request_to_send(handle, n as usize, None) {
            Poll::Ready(res) => res?,
            Poll::Pending => {
                return Err(Error::Busy.into());
            }
        };
        Ok(AclSender {
            controller: &self.controller,
            handle,
            grant,
        })
    }
}

pub struct AclSender<'a, 'd, T: Controller> {
    pub(crate) controller: &'a T,
    pub(crate) handle: ConnHandle,
    pub(crate) grant: PacketGrant<'a, 'd>,
}

impl<'a, 'd, T: Controller> AclSender<'a, 'd, T> {
    pub(crate) fn try_send(&mut self, pdu: &[u8]) -> Result<(), BleHostError<T::Error>>
    where
        T: blocking::Controller,
    {
        let acl = AclPacket::new(
            self.handle,
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            pdu,
        );
        // info!("Sent ACL {:?}", acl);
        match self.controller.try_write_acl_data(&acl) {
            Ok(result) => {
                self.grant.confirm(1);
                Ok(result)
            }
            Err(blocking::TryError::Busy) => {
                warn!("hci: acl data send busy");
                Err(Error::Busy.into())
            }
            Err(blocking::TryError::Error(e)) => Err(BleHostError::Controller(e)),
        }
    }

    pub(crate) async fn send(&mut self, pdu: &[u8]) -> Result<(), BleHostError<T::Error>> {
        let acl = AclPacket::new(
            self.handle,
            AclPacketBoundary::FirstNonFlushable,
            AclBroadcastFlag::PointToPoint,
            pdu,
        );
        self.controller
            .write_acl_data(&acl)
            .await
            .map_err(BleHostError::Controller)?;
        self.grant.confirm(1);
        Ok(())
    }

    pub(crate) async fn signal<D: L2capSignal>(
        &mut self,
        identifier: u8,
        signal: &D,
        p_buf: &mut [u8],
    ) -> Result<(), BleHostError<T::Error>> {
        trace!(
            "[l2cap] sending control signal (req = {}) signal: {:?}",
            identifier,
            signal
        );
        let header = L2capSignalHeader {
            identifier,
            code: D::code(),
            length: signal.size() as u16,
        };
        let l2cap = L2capHeader {
            channel: D::channel(),
            length: header.size() as u16 + header.length,
        };

        let mut w = WriteCursor::new(p_buf);
        w.write_hci(&l2cap)?;
        w.write_hci(&header)?;
        w.write_hci(signal)?;

        self.send(w.finish()).await?;

        Ok(())
    }
}
