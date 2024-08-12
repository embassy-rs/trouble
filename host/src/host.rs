//! BleHost
//!
//! The host module contains the main entry point for the TrouBLE host.
use core::cell::RefCell;
use core::future::poll_fn;
use core::mem::MaybeUninit;
use core::task::Poll;

use bt_hci::cmd::controller_baseband::{HostBufferSize, Reset, SetEventMask};
use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearAdvSets, LeClearFilterAcceptList, LeCreateConn, LeCreateConnCancel,
    LeExtCreateConn, LeReadBufferSize, LeReadNumberOfSupportedAdvSets, LeSetAdvData, LeSetAdvEnable, LeSetAdvParams,
    LeSetAdvSetRandomAddr, LeSetEventMask, LeSetExtAdvData, LeSetExtAdvEnable, LeSetExtAdvParams, LeSetExtScanEnable,
    LeSetExtScanParams, LeSetExtScanResponseData, LeSetRandomAddr, LeSetScanEnable, LeSetScanParams,
    LeSetScanResponseData,
};
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::{blocking, Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::{Event, Vendor};
use bt_hci::param::{
    AddrKind, AdvChannelMap, AdvHandle, AdvKind, AdvSet, BdAddr, ConnHandle, DisconnectReason, EventMask,
    FilterDuplicates, InitiatingPhy, LeConnRole, LeEventMask, Operation, PhyParams, ScanningPhy, Status,
};
use bt_hci::{ControllerToHostPacket, FromHciBytes, WriteHci};
use embassy_futures::select::{select, select3, select4, Either, Either3, Either4};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::once_lock::OnceLock;
use embassy_sync::waitqueue::WakerRegistration;
use futures::pin_mut;

use crate::advertise::{Advertisement, AdvertisementParameters, AdvertisementSet, RawAdvertisement};
use crate::channel_manager::{ChannelManager, ChannelStorage, PacketChannel};
use crate::command::CommandState;
use crate::connection::{ConnectConfig, Connection};
use crate::connection_manager::{ConnectionManager, ConnectionStorage, DynamicConnectionManager, PacketGrant};
use crate::cursor::WriteCursor;
use crate::l2cap::sar::{PacketReassembly, SarType, EMPTY_SAR};
use crate::packet_pool::{AllocId, GlobalPacketPool, PacketPool, Qos};
use crate::pdu::Pdu;
use crate::scan::{PhySet, ScanConfig, ScanReport};
use crate::types::l2cap::{
    L2capHeader, L2capSignal, L2capSignalHeader, L2CAP_CID_ATT, L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SIGNAL,
};
use crate::{att, config, Address, BleHostError, Error};
#[cfg(feature = "gatt")]
use crate::{
    attribute::AttributeTable,
    gatt::{GattClient, GattServer},
};

/// BleHostResources holds the resources used by the host.
///
/// The l2cap packet pool is used by the host to handle inbound data, by allocating space for
/// incoming packets and dispatching to the appropriate connection and channel.
pub struct BleHostResources<
    const CONNS: usize,
    const CHANNELS: usize,
    const L2CAP_MTU: usize,
    const ADV_SETS: usize = 1,
> {
    rx_pool: PacketPool<NoopRawMutex, L2CAP_MTU, { config::L2CAP_RX_PACKET_POOL_SIZE }, CHANNELS>,
    connections: [ConnectionStorage; CONNS],
    channels: [ChannelStorage; CHANNELS],
    channels_rx: [PacketChannel<{ config::L2CAP_RX_QUEUE_SIZE }>; CHANNELS],
    sar: [SarType; CONNS],
    advertise_handles: [AdvHandleState; ADV_SETS],
}

impl<const CONNS: usize, const CHANNELS: usize, const L2CAP_MTU: usize, const ADV_SETS: usize>
    BleHostResources<CONNS, CHANNELS, L2CAP_MTU, ADV_SETS>
{
    /// Create a new instance of host resources with the provided QoS requirements for packets.
    pub fn new(qos: Qos) -> Self {
        Self {
            rx_pool: PacketPool::new(qos),
            connections: [ConnectionStorage::DISCONNECTED; CONNS],
            sar: [EMPTY_SAR; CONNS],
            channels: [ChannelStorage::DISCONNECTED; CHANNELS],
            channels_rx: [PacketChannel::NEW; CHANNELS],
            advertise_handles: [AdvHandleState::None; ADV_SETS],
        }
    }
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
    metrics: RefCell<Metrics>,
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<'d>,
    pub(crate) reassembly: PacketReassembly<'d>,
    pub(crate) channels: ChannelManager<'d, { config::L2CAP_RX_QUEUE_SIZE }>,
    pub(crate) att_inbound: Channel<NoopRawMutex, (ConnHandle, Pdu), 1>,
    pub(crate) rx_pool: &'static dyn GlobalPacketPool,
    outbound: Channel<NoopRawMutex, (ConnHandle, Pdu), 1>,

    pub(crate) scanner: Channel<NoopRawMutex, Option<ScanReport>, 1>,
    advertise_state: AdvState<'d>,
    advertise_command_state: CommandState<bool>,
    connect_command_state: CommandState<bool>,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum AdvHandleState {
    None,
    Advertising(AdvHandle),
    Terminated(AdvHandle),
}

pub(crate) struct AdvInnerState<'d> {
    handles: &'d mut [AdvHandleState],
    waker: WakerRegistration,
}

pub(crate) struct AdvState<'d> {
    state: RefCell<AdvInnerState<'d>>,
}

impl<'d> AdvState<'d> {
    pub fn new(handles: &'d mut [AdvHandleState]) -> Self {
        Self {
            state: RefCell::new(AdvInnerState {
                handles,
                waker: WakerRegistration::new(),
            }),
        }
    }

    pub fn reset(&self) {
        let mut state = self.state.borrow_mut();
        for entry in state.handles.iter_mut() {
            *entry = AdvHandleState::None;
        }
        state.waker.wake();
    }

    // Terminate handle
    pub fn terminate(&self, handle: AdvHandle) {
        let mut state = self.state.borrow_mut();
        for entry in state.handles.iter_mut() {
            match entry {
                AdvHandleState::Advertising(h) if *h == handle => {
                    *entry = AdvHandleState::Terminated(handle);
                }
                _ => {}
            }
        }
        state.waker.wake();
    }

    pub fn len(&self) -> usize {
        let state = self.state.borrow();
        state.handles.len()
    }

    pub fn start(&self, sets: &[AdvSet]) {
        let mut state = self.state.borrow_mut();
        assert!(sets.len() <= state.handles.len());
        for handle in state.handles.iter_mut() {
            *handle = AdvHandleState::None;
        }

        for (idx, entry) in sets.iter().enumerate() {
            state.handles[idx] = AdvHandleState::Advertising(entry.adv_handle);
        }
    }

    pub async fn wait(&self) {
        poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            state.waker.register(cx.waker());

            let mut terminated = 0;
            for entry in state.handles.iter() {
                match entry {
                    AdvHandleState::Terminated(handle) => {
                        terminated += 1;
                    }
                    AdvHandleState::None => {
                        terminated += 1;
                    }
                    _ => {}
                }
            }
            if terminated == state.handles.len() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

#[derive(Default)]
struct Metrics {
    connect_events: u32,
    disconnect_events: u32,
    rx_errors: u32,
}

impl<'d, T> BleHost<'d, T>
where
    T: Controller,
{
    /// Create a new instance of the BLE host.
    ///
    /// The host requires a HCI driver (a particular HCI-compatible controller implementing the required traits), and
    /// a reference to resources that are created outside the host but which the host is the only accessor of.
    pub fn new<const CONNS: usize, const CHANNELS: usize, const L2CAP_MTU: usize, const ADV_SETS: usize>(
        controller: T,
        host_resources: &'static mut BleHostResources<CONNS, CHANNELS, L2CAP_MTU, ADV_SETS>,
    ) -> Self {
        Self {
            address: None,
            initialized: OnceLock::new(),
            metrics: RefCell::new(Metrics::default()),
            controller,
            connections: ConnectionManager::new(&mut host_resources.connections[..]),
            reassembly: PacketReassembly::new(&mut host_resources.sar[..]),
            channels: ChannelManager::new(
                &host_resources.rx_pool,
                &mut host_resources.channels[..],
                &mut host_resources.channels_rx[..],
            ),
            rx_pool: &host_resources.rx_pool,
            att_inbound: Channel::new(),
            scanner: Channel::new(),
            advertise_state: AdvState::new(&mut host_resources.advertise_handles[..]),
            advertise_command_state: CommandState::new(),
            connect_command_state: CommandState::new(),
            outbound: Channel::new(),
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
    pub async fn connect(&self, config: &ConnectConfig<'_>) -> Result<Connection<'_>, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        let _drop = OnDrop::new(|| {
            self.connect_command_state.cancel(true);
        });
        self.connect_command_state.request().await;

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
        match select(
            self.connections
                .accept(LeConnRole::Central, config.scan_config.filter_accept_list),
            self.connect_command_state.wait_idle(),
        )
        .await
        {
            Either::First(conn) => {
                _drop.defuse();
                self.connect_command_state.done();
                Ok(conn)
            }
            Either::Second(_) => Err(Error::Timeout.into()),
        }
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect_ext(&self, config: &ConnectConfig<'_>) -> Result<Connection<'_>, BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeExtCreateConn>
            + ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<LeSetExtScanParams>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        // Ensure no other connect ongoing.
        let _drop = OnDrop::new(|| {
            self.connect_command_state.cancel(true);
        });
        self.connect_command_state.request().await;

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

        match select(
            self.connections
                .accept(LeConnRole::Central, config.scan_config.filter_accept_list),
            self.connect_command_state.wait_idle(),
        )
        .await
        {
            Either::First(conn) => {
                _drop.defuse();
                self.connect_command_state.done();
                Ok(conn)
            }
            Either::Second(_) => Err(Error::Timeout.into()),
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
        params: &AdvertisementParameters,
        data: Advertisement<'k>,
    ) -> Result<Advertiser<'_, 'd>, BleHostError<T::Error>>
    where
        T: for<'t> ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetScanResponseData>,
    {
        // Ensure no other advertise ongoing.
        let drop = OnDrop::new(|| {
            self.advertise_command_state.cancel(false);
        });
        self.advertise_command_state.request().await;

        // Clear current advertising terminations
        self.advertise_state.reset();

        let data: RawAdvertisement = data.into();
        if !data.props.legacy_adv() {
            return Err(Error::InvalidValue.into());
        }

        let kind = match (data.props.connectable_adv(), data.props.scannable_adv()) {
            (true, true) => AdvKind::AdvInd,
            (true, false) => AdvKind::AdvDirectIndLow,
            (false, true) => AdvKind::AdvScanInd,
            (false, false) => AdvKind::AdvNonconnInd,
        };
        let peer = data.peer.unwrap_or(Address {
            kind: AddrKind::PUBLIC,
            addr: BdAddr::default(),
        });

        self.command(LeSetAdvParams::new(
            params.interval_min.into(),
            params.interval_max.into(),
            kind,
            self.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            peer.kind,
            peer.addr,
            params.channel_map.unwrap_or(AdvChannelMap::ALL),
            params.filter_policy,
        ))
        .await?;

        if !data.adv_data.is_empty() {
            let mut buf = [0; 31];
            let to_copy = data.adv_data.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&data.adv_data[..to_copy]);
            self.command(LeSetAdvData::new(to_copy as u8, buf)).await?;
        }

        if !data.scan_data.is_empty() {
            let mut buf = [0; 31];
            let to_copy = data.scan_data.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&data.scan_data[..to_copy]);
            self.command(LeSetScanResponseData::new(to_copy as u8, buf)).await?;
        }

        let advset: [AdvSet; 1] = [AdvSet {
            adv_handle: AdvHandle::new(0),
            duration: bt_hci::param::Duration::from_secs(0),
            max_ext_adv_events: 0,
        }];

        self.advertise_state.start(&advset[..]);
        self.command(LeSetAdvEnable::new(true)).await?;
        drop.defuse();
        Ok(Advertiser {
            advertise_state: &self.advertise_state,
            advertise_command_state: &self.advertise_command_state,
            connections: &self.connections,
            extended: false,
        })
    }

    /// Starts sending BLE advertisements according to the provided config.
    ///
    /// The handles are required to provide the storage while advertising, and
    /// can be created by calling AdvertisementSet::handles(sets).
    ///
    /// Advertisements are stopped when a connection is made against this host,
    /// in which case a handle for the connection is returned.
    pub async fn advertise_ext<'k>(
        &self,
        sets: &[AdvertisementSet<'k>],
        handles: &mut [AdvSet],
    ) -> Result<Advertiser<'_, 'd>, BleHostError<T::Error>>
    where
        T: for<'t> ControllerCmdSync<LeSetExtAdvData<'t>>
            + ControllerCmdSync<LeClearAdvSets>
            + ControllerCmdSync<LeSetExtAdvParams>
            + ControllerCmdSync<LeSetAdvSetRandomAddr>
            + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>,
    {
        assert_eq!(sets.len(), handles.len());
        // Check host supports the required advertisement sets
        {
            let result = self.command(LeReadNumberOfSupportedAdvSets::new()).await?;
            if result < sets.len() as u8 || self.advertise_state.len() < sets.len() {
                return Err(Error::InsufficientSpace.into());
            }
        }

        // Ensure no other advertise ongoing.
        let drop = OnDrop::new(|| {
            self.advertise_command_state.cancel(true);
        });
        self.advertise_command_state.request().await;

        // Clear current advertising terminations
        self.advertise_state.reset();

        for (i, set) in sets.iter().enumerate() {
            let handle = AdvHandle::new(i as u8);
            let data: RawAdvertisement<'k> = set.data.into();
            let params = set.params;
            let peer = data.peer.unwrap_or(Address {
                kind: AddrKind::PUBLIC,
                addr: BdAddr::default(),
            });
            self.command(LeSetExtAdvParams::new(
                handle,
                data.props,
                params.interval_min.into(),
                params.interval_max.into(),
                params.channel_map.unwrap_or(AdvChannelMap::ALL),
                self.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
                peer.kind,
                peer.addr,
                params.filter_policy,
                params.tx_power as i8,
                params.primary_phy,
                0,
                params.secondary_phy,
                0,
                false,
            ))
            .await?;

            if let Some(address) = self.address {
                self.command(LeSetAdvSetRandomAddr::new(handle, address.addr)).await?;
            }

            if !data.adv_data.is_empty() {
                self.command(LeSetExtAdvData::new(
                    handle,
                    Operation::Complete,
                    params.fragment,
                    data.adv_data,
                ))
                .await?;
            }

            if !data.scan_data.is_empty() {
                self.command(LeSetExtScanResponseData::new(
                    handle,
                    Operation::Complete,
                    params.fragment,
                    data.scan_data,
                ))
                .await?;
            }
            handles[i].adv_handle = handle;
            handles[i].duration = set
                .params
                .timeout
                .unwrap_or(embassy_time::Duration::from_micros(0))
                .into();
            handles[i].max_ext_adv_events = set.params.max_events.unwrap_or(0);
        }

        trace!("[host] enabling advertising");
        self.advertise_state.start(handles);
        self.command(LeSetExtAdvEnable::new(true, handles)).await?;
        drop.defuse();
        Ok(Advertiser {
            advertise_state: &self.advertise_state,
            advertise_command_state: &self.advertise_command_state,
            connections: &self.connections,
            extended: true,
        })
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
            rx: self.att_inbound.receiver().into(),
            ble: self,
        }
    }

    /// Creates a GATT client capable of processing the GATT protocol using the provided table of attributes.
    #[cfg(feature = "gatt")]
    pub async fn gatt_client<'reference, const MAX: usize, const ATT_MTU: usize>(
        &'reference self,
        connection: &Connection<'reference>,
    ) -> Result<GattClient<'reference, 'd, T, MAX, ATT_MTU>, BleHostError<T::Error>> {
        let l2cap = L2capHeader { channel: 4, length: 3 };
        let mut buf = [0; 7];
        let mut w = WriteCursor::new(&mut buf);
        w.write_hci(&l2cap)?;
        w.write(att::AttReq::ExchangeMtu { mtu: ATT_MTU as u16 })?;

        let mut grant = self.acl(connection.handle(), 1).await?;

        grant.send(w.finish()).await?;

        Ok(GattClient {
            services: heapless::Vec::new(),
            rx: self.att_inbound.receiver().into(),
            ble: self,
            connection: connection.clone(),
        })
    }

    fn handle_connection(
        &self,
        status: Status,
        handle: ConnHandle,
        peer_addr_kind: AddrKind,
        peer_addr: BdAddr,
        role: LeConnRole,
    ) -> bool {
        match status.to_result() {
            Ok(_) => {
                if let Err(err) = self.connections.connect(handle, peer_addr_kind, peer_addr, role) {
                    warn!("Error establishing connection: {:?}", err);
                    return false;
                } else {
                    #[cfg(feature = "defmt")]
                    trace!(
                        "[host] connection with handle {:?} established to {:02x}",
                        handle,
                        peer_addr
                    );
                    let mut m = self.metrics.borrow_mut();
                    m.connect_events = m.connect_events.wrapping_add(1);
                }
            }
            Err(bt_hci::param::Error::ADV_TIMEOUT) => {
                self.advertise_state.reset();
            }
            Err(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER) => {
                warn!("[host] connect cancelled");
                self.connect_command_state.canceled();
            }
            Err(e) => {
                warn!("Error connection complete event: {:?}", e);
                self.connect_command_state.canceled();
            }
        }
        true
    }

    fn handle_acl(&self, acl: AclPacket<'_>) -> Result<(), Error> {
        if !self.connections.is_handle_connected(acl.handle()) {
            return Err(Error::Disconnected);
        }
        let (header, mut packet) = match acl.boundary_flag() {
            AclPacketBoundary::FirstFlushable => {
                let (header, data) = L2capHeader::from_hci_bytes(acl.data())?;

                // Ignore channels we don't support
                if header.channel < L2CAP_CID_DYN_START
                    && !(&[L2CAP_CID_LE_U_SIGNAL, L2CAP_CID_ATT].contains(&header.channel))
                {
                    warn!("[host] unsupported l2cap channel id {}", header.channel);
                    return Err(Error::NotSupported);
                }

                // Avoids using the packet buffer for signalling packets
                if header.channel == L2CAP_CID_LE_U_SIGNAL {
                    assert!(data.len() == header.length as usize);
                    self.channels.signal(acl.handle(), data)?;
                    return Ok(());
                }

                let Some(mut p) = self.rx_pool.alloc(AllocId::from_channel(header.channel)) else {
                    info!("No memory for packets on channel {}", header.channel);
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
                // Handle ATT MTU exchange here since it doesn't strictly require
                // gatt to be enabled.
                if let Ok(att::AttReq::ExchangeMtu { mtu }) =
                    att::AttReq::decode(&packet.as_ref()[..header.length as usize])
                {
                    let mtu = self.connections.exchange_att_mtu(acl.handle(), mtu);

                    let rsp = att::AttRsp::ExchangeMtu { mtu };
                    let l2cap = L2capHeader {
                        channel: L2CAP_CID_ATT,
                        length: 3,
                    };

                    let mut w = WriteCursor::new(packet.as_mut());
                    w.write_hci(&l2cap)?;
                    w.write(rsp)?;

                    let len = w.len();
                    if let Err(e) = self.outbound.try_send((acl.handle(), Pdu::new(packet, len))) {
                        return Err(Error::OutOfMemory);
                    }
                } else if let Ok(att::AttRsp::ExchangeMtu { mtu }) =
                    att::AttRsp::decode(&packet.as_ref()[..header.length as usize])
                {
                    self.connections.exchange_att_mtu(acl.handle(), mtu);
                } else {
                    #[cfg(feature = "gatt")]
                    if let Err(e) = self
                        .att_inbound
                        .try_send((acl.handle(), Pdu::new(packet, header.length as usize)))
                    {
                        return Err(Error::OutOfMemory);
                    }

                    #[cfg(not(feature = "gatt"))]
                    return Err(Error::NotSupported);
                }
            }
            L2CAP_CID_LE_U_SIGNAL => {
                panic!("le signalling channel was fragmented, impossible!");
            }
            other if other >= L2CAP_CID_DYN_START => match self.channels.dispatch(header, packet) {
                Ok(_) => {}
                Err(e) => {
                    warn!("Error dispatching l2cap packet to channel: {:?}", e);
                    return Err(e);
                }
            },
            _ => {
                return Err(Error::NotSupported);
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
            + ControllerCmdSync<LeCreateConnCancel>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        self.run_with_handler(|_| {}).await
    }

    pub async fn run_with_handler<F: Fn(&Vendor)>(&self, vendor_handler: F) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + ControllerCmdSync<LeReadBufferSize>,
    {
        const MAX_HCI_PACKET_LEN: usize = 259;

        // Control future that initializes system and handles controller changes.
        let control_fut = async {
            Reset::new().exec(&self.controller).await?;

            if let Some(addr) = self.address {
                LeSetRandomAddr::new(addr.addr).exec(&self.controller).await?;
            }

            HostBufferSize::new(
                self.rx_pool.mtu() as u16,
                0,
                config::L2CAP_RX_PACKET_POOL_SIZE as u16,
                0,
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
                    .enable_le_enhanced_conn_complete(true)
                    .enable_le_adv_set_terminated(true)
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
                match select4(
                    poll_fn(|cx| self.connections.poll_disconnecting(Some(cx))),
                    poll_fn(|cx| self.channels.poll_disconnecting(Some(cx))),
                    poll_fn(|cx| self.connect_command_state.poll_cancelled(cx)),
                    poll_fn(|cx| self.advertise_command_state.poll_cancelled(cx)),
                )
                .await
                {
                    Either4::First(request) => {
                        self.command(Disconnect::new(request.handle(), request.reason()))
                            .await?;
                        request.confirm();
                    }
                    Either4::Second(request) => {
                        let mut grant = self.acl(request.handle(), 1).await?;
                        request.send(&mut grant).await?;
                        request.confirm();
                    }
                    Either4::Third(_) => {
                        // trace!("[host] cancelling create connection");
                        if let Err(e) = self.command(LeCreateConnCancel::new()).await {
                            // Signal to ensure no one is stuck
                            self.connect_command_state.canceled();
                        }
                    }
                    Either4::Fourth(ext) => {
                        trace!("[host] disabling advertising");
                        if ext {
                            self.command(LeSetExtAdvEnable::new(false, &[])).await?
                        } else {
                            self.command(LeSetAdvEnable::new(false)).await?
                        }
                        self.advertise_command_state.canceled();
                    }
                }
            }
        };
        pin_mut!(control_fut);

        let tx_fut = async {
            loop {
                let (conn, pdu) = self.outbound.receive().await;
                match self.acl(conn, 1).await {
                    Ok(mut sender) => {
                        if let Err(e) = sender.send(pdu.as_ref()).await {
                            warn!("[host] error sending outbound pdu");
                            return Err(e);
                        }
                    }
                    Err(e) => {
                        warn!("[host] error requesting sending outbound pdu");
                        return Err(e);
                    }
                }
            }
        };
        pin_mut!(tx_fut);

        let rx_fut = async {
            loop {
                // Task handling receiving data from the controller.
                let mut rx = [0u8; MAX_HCI_PACKET_LEN];
                let result = self.controller.read(&mut rx).await;
                match result {
                    Ok(ControllerToHostPacket::Acl(acl)) => match self.handle_acl(acl) {
                        Ok(_) => {}
                        Err(e) => {
                            // We disconnect on errors to ensure we don't leave the other end thinking
                            // everything is ok.
                            let reason = match e {
                                Error::OutOfMemory => {
                                    // Disconnect link due to low resources.
                                    warn!("[host] out of memory error when processing ACL packet");
                                    DisconnectReason::RemoteDeviceTerminatedConnLowResources
                                }
                                Error::Disconnected => {
                                    // Already disconnected, request a disconnect to ensure we don't have
                                    // any lingering connections, should be a noop
                                    warn!("[host] already disconnected when processing ACL packet");
                                    DisconnectReason::RemoteUserTerminatedConn
                                }
                                Error::NotSupported => {
                                    // Attempt to use a feature not supported
                                    warn!("[host] attempted to use unsupported feature when processing ACL packet");
                                    DisconnectReason::UnsupportedRemoteFeature
                                }
                                e => {
                                    // Otherwise blame the user.
                                    warn!("[host] encountered error processing ACL packet: {:?}", e);
                                    DisconnectReason::RemoteUserTerminatedConn
                                }
                            };
                            warn!("[host] disconnecting handle {:?} after error", acl.handle());
                            self.connections.request_handle_disconnect(acl.handle(), reason);
                            let mut m = self.metrics.borrow_mut();
                            m.rx_errors = m.rx_errors.wrapping_add(1);
                        }
                    },
                    Ok(ControllerToHostPacket::Event(event)) => match event {
                        Event::Le(event) => match event {
                            LeEvent::LeConnectionComplete(e) => {
                                if !self.handle_connection(e.status, e.handle, e.peer_addr_kind, e.peer_addr, e.role) {
                                    let _ = self
                                        .command(Disconnect::new(
                                            e.handle,
                                            DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                        ))
                                        .await;
                                    self.connect_command_state.canceled();
                                }
                            }
                            LeEvent::LeEnhancedConnectionComplete(e) => {
                                if !self.handle_connection(e.status, e.handle, e.peer_addr_kind, e.peer_addr, e.role) {
                                    let _ = self
                                        .command(Disconnect::new(
                                            e.handle,
                                            DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                        ))
                                        .await;
                                    self.connect_command_state.canceled();
                                }
                            }
                            LeEvent::LeScanTimeout(_) => {
                                let _ = self.scanner.try_send(None);
                            }
                            LeEvent::LeAdvertisingSetTerminated(set) => {
                                self.advertise_state.terminate(set.adv_handle);
                            }
                            LeEvent::LeExtendedAdvertisingReport(data) => {
                                let _ = self
                                    .scanner
                                    .try_send(Some(ScanReport::new(data.reports.num_reports, &data.reports.bytes)));
                            }
                            LeEvent::LeAdvertisingReport(data) => {
                                let _ = self
                                    .scanner
                                    .try_send(Some(ScanReport::new(data.reports.num_reports, &data.reports.bytes)));
                            }
                            _ => {
                                warn!("Unknown LE event!");
                            }
                        },
                        Event::DisconnectionComplete(e) => {
                            let handle = e.handle;
                            info!("Disconnection event on handle {}", handle.raw());
                            let _ = self.connections.disconnected(handle);
                            let _ = self.channels.disconnected(handle);
                            self.reassembly.disconnected(handle);
                            let mut m = self.metrics.borrow_mut();
                            m.disconnect_events = m.disconnect_events.wrapping_add(1);
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
                            vendor_handler(&vendor);
                        }
                        // Ignore
                        _ => {}
                    },
                    // Ignore
                    Ok(_) => {}
                    Err(e) => {
                        return Err(BleHostError::Controller(e));
                    }
                }
            }
        };
        pin_mut!(rx_fut);

        // info!("Entering select loop");
        match select3(&mut control_fut, &mut rx_fut, &mut tx_fut).await {
            Either3::First(result) => result,
            Either3::Second(result) => result,
            Either3::Third(result) => result,
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

    /// Log status information of the host
    pub fn log_status(&self, verbose: bool) {
        let m = self.metrics.borrow();
        debug!("[host] connect events: {}", m.connect_events);
        debug!("[host] disconnect events: {}", m.disconnect_events);
        debug!("[host] rx errors: {}", m.rx_errors);
        self.connections.log_status(verbose);
        self.channels.log_status(verbose);
    }
}

/// Handle to an active advertiser which can accept connections.
pub struct Advertiser<'a, 'd> {
    advertise_state: &'a AdvState<'d>,
    advertise_command_state: &'a CommandState<bool>,
    connections: &'a ConnectionManager<'d>,
    extended: bool,
}

impl<'a, 'd> Advertiser<'a, 'd> {
    /// Accept the next peripheral connection for this advertiser.
    ///
    /// Returns Error::Timeout if advertiser stopped.
    pub async fn accept(&mut self) -> Result<Connection<'a>, Error> {
        match select(
            self.connections.accept(LeConnRole::Peripheral, &[]),
            self.advertise_state.wait(),
        )
        .await
        {
            Either::First(conn) => Ok(conn),
            Either::Second(_) => Err(Error::Timeout),
        }
    }
}

impl<'a, 'd> Drop for Advertiser<'a, 'd> {
    fn drop(&mut self) {
        self.advertise_command_state.cancel(self.extended);
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
        //trace!(
        //    "[l2cap] sending control signal (req = {}) signal: {:?}",
        //    identifier,
        //    signal
        //);
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

/// A type to delay the drop handler invocation.
#[must_use = "to delay the drop handler invocation to the end of the scope"]
pub struct OnDrop<F: FnOnce()> {
    f: MaybeUninit<F>,
}

impl<F: FnOnce()> OnDrop<F> {
    /// Create a new instance.
    pub fn new(f: F) -> Self {
        Self { f: MaybeUninit::new(f) }
    }

    /// Prevent drop handler from running.
    pub fn defuse(self) {
        core::mem::forget(self)
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        unsafe { self.f.as_ptr().read()() }
    }
}
