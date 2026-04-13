//! BleHost
//!
//! The host module contains the main entry point for the TrouBLE host.
#[cfg(feature = "security")]
use core::cell::Cell;
use core::cell::RefCell;
use core::future::poll_fn;
use core::mem::MaybeUninit;
use core::task::{Context, Poll};

use bt_hci::cmd::controller_baseband::{
    HostBufferSize, HostNumberOfCompletedPackets, Reset, SetControllerToHostFlowControl, SetEventMask,
    SetEventMaskPage2,
};
use bt_hci::cmd::info::ReadBdAddr;
#[cfg(feature = "security")]
use bt_hci::cmd::le::{
    LeAddDeviceToResolvingList, LeClearResolvingList, LeRemoveDeviceFromResolvingList, LeSetAddrResolutionEnable,
    LeSetPrivacyMode, LeSetResolvablePrivateAddrTimeout,
};
use bt_hci::cmd::le::{
    LeConnUpdate, LeCreateConnCancel, LeReadBufferSize, LeReadFilterAcceptListSize, LeSetAdvEnable, LeSetEventMask,
    LeSetExtAdvEnable, LeSetExtScanEnable, LeSetRandomAddr, LeSetScanEnable,
};
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::{blocking, Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
#[cfg(feature = "scan")]
use bt_hci::event::le::LeAdvertisingReport;
#[cfg(feature = "scan")]
use bt_hci::event::le::LeExtendedAdvertisingReport;
use bt_hci::event::le::{
    LeAdvertisingSetTerminated, LeConnectionComplete, LeConnectionRateChange, LeConnectionUpdateComplete,
    LeDataLengthChange, LeEnhancedConnectionComplete, LeEventKind, LeEventPacket, LeFrameSpaceUpdateComplete,
    LePhyUpdateComplete, LeRemoteConnectionParameterRequest,
};
use bt_hci::event::{DisconnectionComplete, EventKind, NumberOfCompletedPackets, Vendor};
#[cfg(feature = "security")]
use bt_hci::param::BdAddr;
use bt_hci::param::{
    AddrKind, AdvHandle, AdvSet, ConnHandle, DisconnectReason, EventMask, EventMaskPage2, FilterDuplicates, LeConnRole,
    LeEventMask, Status,
};
use bt_hci::{ControllerToHostPacket, FromHciBytes, WriteHci};
use embassy_futures::select::{select3, select4, Either3, Either4};
use embassy_sync::once_lock::OnceLock;
use embassy_sync::waitqueue::WakerRegistration;
use embassy_time::Duration;
use futures::pin_mut;

use crate::att::{AttClient, AttServer};
use crate::channel_manager::{ChannelManager, ChannelStorage};
use crate::command::CommandState;
use crate::connection::{ConnParams, ConnectionEvent};
#[cfg(feature = "security")]
use crate::connection_manager::ResolvablePrivateAddrs;
use crate::connection_manager::{ConnectionManager, ConnectionStorage, PacketGrant};
use crate::cursor::WriteCursor;
use crate::pdu::Pdu;
use crate::prelude::{ConnectionParamsRequest, RequestedConnParams};
#[cfg(feature = "security")]
use crate::security_manager::SecurityEventData;
use crate::types::l2cap::{
    ConnParamUpdateReq, ConnParamUpdateRes, L2capHeader, L2capSignal, L2capSignalHeader, L2CAP_CID_ATT,
    L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SECURITY_MANAGER, L2CAP_CID_LE_U_SIGNAL,
};
use crate::{att, Address, BleHostError, Error, PacketPool};

#[cfg(feature = "security")]
#[derive(Clone, Copy)]
pub(crate) enum ResolvingListUpdate {
    FullSync,
    Add(crate::Identity),
    Remove(crate::Identity),
}

#[cfg(feature = "security")]
pub(crate) struct ResolvingListSignal {
    state: Option<ResolvingListUpdate>,
    waker: WakerRegistration,
}

#[cfg(feature = "security")]
impl ResolvingListSignal {
    const fn new() -> Self {
        Self {
            state: None,
            waker: WakerRegistration::new(),
        }
    }

    /// Push an update and wake the control loop.
    pub(crate) fn push(&mut self, update: ResolvingListUpdate) {
        self.state = Some(match self.state {
            Some(_) => ResolvingListUpdate::FullSync,
            None => update,
        });
        self.waker.wake();
    }

    /// Discard any pending update.
    pub(crate) fn clear(&mut self) {
        self.state = None;
    }

    /// Poll for a pending update. Takes the value on Ready.
    fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<ResolvingListUpdate> {
        self.waker.register(cx.waker());
        match self.state.take() {
            Some(state) => Poll::Ready(state),
            None => Poll::Pending,
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
pub(crate) struct BleHost<'d, T, P: PacketPool> {
    initialized: OnceLock<InitialState>,
    metrics: RefCell<HostMetrics>,
    pub(crate) address: Option<Address>,
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<'d, P>,
    pub(crate) channels: ChannelManager<'d, P>,
    pub(crate) advertise_state: AdvState<'d>,
    pub(crate) advertise_command_state: CommandState<bool>,
    pub(crate) connect_command_state: CommandState<bool>,
    pub(crate) scan_command_state: CommandState<bool>,
    #[cfg(feature = "security")]
    pub(crate) rpa_timeout: Cell<embassy_time::Duration>,
    #[cfg(feature = "security")]
    pub(crate) resolving_list_state: RefCell<ResolvingListSignal>,
}

#[derive(Clone, Copy)]
pub(crate) struct InitialState {
    acl_max: usize,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Copy, Debug)]
pub(crate) enum AdvHandleState {
    None,
    Advertising(AdvHandle),
    Terminated(AdvHandle),
}

pub(crate) struct AdvState<'d> {
    handles: &'d RefCell<[AdvHandleState]>,
    waker: RefCell<WakerRegistration>,
}

impl<'d> AdvState<'d> {
    pub(crate) fn new(handles: &'d RefCell<[AdvHandleState]>) -> Self {
        Self {
            handles,
            waker: RefCell::new(WakerRegistration::new()),
        }
    }

    pub(crate) fn reset(&self) {
        for entry in self.handles.borrow_mut().iter_mut() {
            *entry = AdvHandleState::None;
        }
        self.waker.borrow_mut().wake();
    }

    // Terminate handle
    pub(crate) fn terminate(&self, handle: AdvHandle) {
        for entry in self.handles.borrow_mut().iter_mut() {
            match entry {
                AdvHandleState::Advertising(h) if *h == handle => {
                    *entry = AdvHandleState::Terminated(handle);
                }
                _ => {}
            }
        }
        self.waker.borrow_mut().wake();
    }

    pub(crate) fn len(&self) -> usize {
        self.handles.as_ptr().len()
    }

    pub(crate) fn start(&self, sets: &[AdvSet]) {
        assert!(sets.len() <= self.handles.as_ptr().len());
        let mut handles = self.handles.borrow_mut();
        for handle in handles.iter_mut() {
            *handle = AdvHandleState::None;
        }

        for (idx, entry) in sets.iter().enumerate() {
            handles[idx] = AdvHandleState::Advertising(entry.adv_handle);
        }
    }

    pub async fn wait(&self) {
        poll_fn(|cx| {
            self.waker.borrow_mut().register(cx.waker());

            let mut terminated = 0;
            for entry in self.handles.borrow().iter() {
                match entry {
                    AdvHandleState::Terminated(_) => {
                        terminated += 1;
                    }
                    AdvHandleState::None => {
                        terminated += 1;
                    }
                    _ => {}
                }
            }
            if terminated == self.handles.as_ptr().len() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

/// Host metrics
#[derive(Default, Clone)]
pub struct HostMetrics {
    /// How many connect events have been received.
    pub connect_events: u32,
    /// How many disconnect events have been received.
    pub disconnect_events: u32,
    /// How many errors processing received data.
    pub rx_errors: u32,
}

impl<'d, T, P> BleHost<'d, T, P>
where
    T: Controller,
    P: PacketPool,
{
    /// Create a new instance of the BLE host.
    ///
    /// The host requires a HCI driver (a particular HCI-compatible controller implementing the required traits), and
    /// a reference to resources that are created outside the host but which the host is the only accessor of.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        controller: T,
        connections: &'d RefCell<[ConnectionStorage<P::Packet>]>,
        channels: &'d RefCell<[ChannelStorage<P::Packet>]>,
        advertise_handles: &'d RefCell<[AdvHandleState]>,
        #[cfg(feature = "security")] bond_storage: &'d RefCell<heapless::VecView<crate::BondInformation>>,
    ) -> Self {
        Self {
            address: None,
            initialized: OnceLock::new(),
            metrics: RefCell::new(HostMetrics::default()),
            controller,
            connections: ConnectionManager::new(
                connections,
                P::MTU as u16 - 4,
                #[cfg(feature = "security")]
                bond_storage,
            ),
            channels: ChannelManager::new(channels),
            advertise_state: AdvState::new(advertise_handles),
            advertise_command_state: CommandState::new(),
            scan_command_state: CommandState::new(),
            connect_command_state: CommandState::new(),
            #[cfg(feature = "security")]
            rpa_timeout: Cell::new(embassy_time::Duration::from_secs(900)),
            #[cfg(feature = "security")]
            resolving_list_state: RefCell::new(ResolvingListSignal::new()),
        }
    }

    /// Poll whether any command should be cancelled or the resolving list should be synced.
    fn poll_cancelled(&self, cx: &mut Context<'_>) -> Poll<CancelledCommandState> {
        if let Poll::Ready(ctx) = self.connect_command_state.poll_cancelled(cx) {
            return Poll::Ready(CancelledCommandState::Connect(ctx));
        }
        if let Poll::Ready(ctx) = self.advertise_command_state.poll_cancelled(cx) {
            return Poll::Ready(CancelledCommandState::Advertise(ctx));
        }
        if let Poll::Ready(ctx) = self.scan_command_state.poll_cancelled(cx) {
            return Poll::Ready(CancelledCommandState::Scan(ctx));
        }

        #[cfg(feature = "security")]
        if self.connect_command_state.is_idle()
            && self.advertise_command_state.is_idle()
            && self.scan_command_state.is_idle()
        {
            if let Poll::Ready(update) = self.resolving_list_state.borrow_mut().poll_changed(cx) {
                return Poll::Ready(CancelledCommandState::SyncResolvingList(update));
            }
        }

        Poll::Pending
    }

    /// Check whether BLE address privacy is enabled.
    #[cfg(feature = "security")]
    pub(crate) fn is_privacy_enabled(&self) -> bool {
        self.connections.security_manager.get_local_irk().is_some()
    }

    /// Get the appropriate own address kind based on the host address and privacy state.
    pub(crate) fn own_addr_kind(&self) -> AddrKind {
        #[cfg(feature = "security")]
        if self.is_privacy_enabled() {
            return if self.address.is_some() {
                AddrKind::RESOLVABLE_PRIVATE_OR_RANDOM
            } else {
                AddrKind::RESOLVABLE_PRIVATE_OR_PUBLIC
            };
        }
        self.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC)
    }

    /// Sync the controller's resolving list based on a pending update.
    #[cfg(feature = "security")]
    pub(crate) async fn sync_resolving_list(&self, update: ResolvingListUpdate) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeClearResolvingList>
            + ControllerCmdSync<LeSetAddrResolutionEnable>
            + ControllerCmdSync<LeRemoveDeviceFromResolvingList>
            + ControllerCmdSync<LeAddDeviceToResolvingList>
            + ControllerCmdSync<LeSetPrivacyMode>,
        T::Error: crate::fmt::Format,
    {
        let local_irk = self.connections.security_manager.get_local_irk();
        let local_irk_bytes = local_irk.map(|k| k.to_le_bytes()).unwrap_or_default();

        // Disable address resolution while modifying the list
        LeSetAddrResolutionEnable::new(false).exec(&self.controller).await?;

        let res = match update {
            ResolvingListUpdate::FullSync => self.full_resolving_list_sync(local_irk).await,
            ResolvingListUpdate::Add(identity) => {
                if let Some(peer_irk) = identity.irk {
                    let peer_addr_kind = identity.addr.kind;
                    let peer_irk_bytes = peer_irk.to_le_bytes();

                    info!("[host] incremental resolving list add");

                    // Remove first in case this is an update (device already in list)
                    let _ = LeRemoveDeviceFromResolvingList::new(peer_addr_kind, identity.addr.addr)
                        .exec(&self.controller)
                        .await;

                    if let Err(e) = LeAddDeviceToResolvingList::new(
                        peer_addr_kind,
                        identity.addr.addr,
                        peer_irk_bytes,
                        local_irk_bytes,
                    )
                    .exec(&self.controller)
                    .await
                    {
                        warn!("[host] failed to add device to resolving list: {:?}", e);
                    }

                    if let Err(e) =
                        LeSetPrivacyMode::new(peer_addr_kind, identity.addr.addr, bt_hci::param::PrivacyMode::Device)
                            .exec(&self.controller)
                            .await
                    {
                        warn!("[host] failed to set privacy mode: {:?}", e);
                    }
                }
                Ok(())
            }
            ResolvingListUpdate::Remove(identity) => {
                let peer_addr_kind = identity.addr.kind;

                info!("[host] incremental resolving list remove");

                if let Err(e) = LeRemoveDeviceFromResolvingList::new(peer_addr_kind, identity.addr.addr)
                    .exec(&self.controller)
                    .await
                {
                    warn!("[host] failed to remove device from resolving list: {:?}", e);
                }
                Ok(())
            }
        };

        // Always re-enable address resolution
        if let Err(e) = LeSetAddrResolutionEnable::new(true).exec(&self.controller).await {
            warn!("[host] failed to re-enable address resolution: {:?}", e);
            return res.and(Err(e.into()));
        }

        res
    }

    /// Full clear-and-rebuild of the resolving list.
    #[cfg(feature = "security")]
    async fn full_resolving_list_sync(
        &self,
        local_irk: Option<crate::security_manager::IdentityResolvingKey>,
    ) -> Result<(), BleHostError<T::Error>>
    where
        T: ControllerCmdSync<LeClearResolvingList>
            + ControllerCmdSync<LeAddDeviceToResolvingList>
            + ControllerCmdSync<LeSetPrivacyMode>,
        T::Error: crate::fmt::Format,
    {
        info!("[host] full resolving list sync");

        // Clear resolving list
        LeClearResolvingList::new().exec(&self.controller).await?;

        let local_irk_bytes = local_irk.map(|k| k.to_le_bytes()).unwrap_or_default();

        // Add a default entry with just the local IRK so the controller can generate RPAs
        // even when no peers are bonded yet. Only needed when we have our own IRK.
        if local_irk.is_some() {
            if let Err(e) =
                LeAddDeviceToResolvingList::new(AddrKind::PUBLIC, BdAddr::default(), [0u8; 16], local_irk_bytes)
                    .exec(&self.controller)
                    .await
            {
                warn!("[host] failed to add default resolving list entry: {:?}", e);
            }
        }

        // Add entries for all bonded peers with IRKs
        let mut i = 0;
        while let Some(bond) = self.connections.security_manager.get_bond(i) {
            i += 1;
            if let Some(peer_irk) = bond.identity.irk {
                let peer_addr_kind = bond.identity.addr.kind;
                let peer_irk_bytes = peer_irk.to_le_bytes();
                if let Err(e) = LeAddDeviceToResolvingList::new(
                    peer_addr_kind,
                    bond.identity.addr.addr,
                    peer_irk_bytes,
                    local_irk_bytes,
                )
                .exec(&self.controller)
                .await
                {
                    warn!("[host] failed to add device to resolving list: {:?}", e);
                    break;
                }
                // Set device privacy mode so we can receive both RPAs and identity addresses
                if let Err(e) = LeSetPrivacyMode::new(
                    peer_addr_kind,
                    bond.identity.addr.addr,
                    bt_hci::param::PrivacyMode::Device,
                )
                .exec(&self.controller)
                .await
                {
                    warn!("[host] failed to set privacy mode: {:?}", e);
                }
            }
        }

        info!("[host] resolving list synced");
        Ok(())
    }

    /// Returns true if the host has been initialized by the Runner.
    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized.try_get().is_some()
    }

    /// Run a HCI command and return the response.
    pub(crate) async fn command<C>(&self, cmd: C) -> Result<C::Return, BleHostError<T::Error>>
    where
        C: SyncCmd,
        T: ControllerCmdSync<C>,
    {
        let _ = self.initialized.get().await;
        let ret = cmd.exec(&self.controller).await?;
        Ok(ret)
    }

    /// Run an async HCI command where the response will generate an event later.
    pub(crate) async fn async_command<C>(&self, cmd: C) -> Result<(), BleHostError<T::Error>>
    where
        C: AsyncCmd,
        T: ControllerCmdAsync<C>,
    {
        let _ = self.initialized.get().await;
        cmd.exec(&self.controller).await?;
        Ok(())
    }

    fn handle_connection(
        &self,
        status: Status,
        handle: ConnHandle,
        peer_addr: Address,
        role: LeConnRole,
        params: ConnParams,
        #[cfg(feature = "security")] resolvable_addrs: ResolvablePrivateAddrs,
    ) -> bool {
        match status.to_result() {
            Ok(_) => {
                if let Err(err) = self.connections.connect_with_rpas(
                    handle,
                    peer_addr,
                    role,
                    params,
                    #[cfg(feature = "security")]
                    resolvable_addrs,
                ) {
                    warn!("Error establishing connection: {:?}", err);
                    return false;
                } else {
                    #[cfg(feature = "defmt")]
                    debug!(
                        "[host] connection with handle {:?} established to {}",
                        handle, peer_addr
                    );

                    #[cfg(feature = "log")]
                    debug!(
                        "[host] connection with handle {:?} established to {}",
                        handle, peer_addr
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

    fn handle_acl(&self, acl: AclPacket<'_>, event_handler: &dyn EventHandler) -> Result<(), Error> {
        self.connections.received(acl.handle())?;
        let handle = acl.handle();
        let (header, pdu) = match acl.boundary_flag() {
            AclPacketBoundary::FirstFlushable => {
                let (header, data) = L2capHeader::from_hci_bytes(acl.data())?;

                // Ignore channels we don't support
                if header.channel < L2CAP_CID_DYN_START
                    && !(&[L2CAP_CID_LE_U_SIGNAL, L2CAP_CID_ATT, L2CAP_CID_LE_U_SECURITY_MANAGER]
                        .contains(&header.channel))
                {
                    // Apple devices probe this channel id even if it's outside the dynamic range.
                    if header.channel == 0x3a {
                        info!(
                            "[host] unsupported l2cap channel id {} (Apple devices which always probe this channel, so this is safe to ignore).",
                            header.channel
                        );
                    } else {
                        warn!("[host] unsupported l2cap channel id {}", header.channel);
                    }
                    return Err(Error::NotSupported);
                }

                // Fast-path for complete signalling packets
                if header.channel == L2CAP_CID_LE_U_SIGNAL && data.len() == header.length as usize {
                    return self.channels.signal(acl.handle(), data, &self.connections);
                }

                trace!(
                    "[host] inbound l2cap header channel = {}, fragment len = {}, total = {}",
                    header.channel,
                    data.len(),
                    header.length
                );

                // We must be prepared to receive fragments.
                if header.length as usize != data.len() {
                    // Dynamic channels can be optimized.
                    #[cfg(feature = "l2cap-sdu-reassembly-optimization")]
                    if header.channel >= L2CAP_CID_DYN_START {
                        // This is the start of the frame, so make sure to adjust the credits.
                        self.channels.received(header.channel, 1)?;
                        self.channels.check_pdu_len(header.channel, header.length)?;

                        self.connections
                            .reassembly(acl.handle(), |p| {
                                let r = if !p.in_progress() {
                                    // Init the new assembly assuming the length of the SDU.
                                    let (first, payload) = data.split_at(2);
                                    let len: u16 = u16::from_le_bytes([first[0], first[1]]);
                                    self.channels.check_sdu_len(header.channel, len)?;
                                    let Some(packet) = P::allocate() else {
                                        warn!("[host] no memory for packets on channel {}", header.channel);
                                        return Err(Error::OutOfMemory);
                                    };
                                    p.init(header.channel, len, packet)?;
                                    p.update(payload)?
                                } else {
                                    p.update(data)?
                                };
                                // Something is wrong if assembly was finished since we've not received the last fragment.
                                if r.is_some() {
                                    Err(Error::InvalidState)
                                } else {
                                    Ok(())
                                }
                            })
                            .inspect_err(|_| self.channels.disconnect_by_cid(header.channel))?;
                        return Ok(());
                    }

                    // For dynamic channels, validate PDU length against MPS before reassembly.
                    if header.channel >= L2CAP_CID_DYN_START {
                        self.channels.check_pdu_len(header.channel, header.length)?;
                    }

                    let Some(packet) = P::allocate() else {
                        warn!("[host] no memory for packets on channel {}", header.channel);
                        return Err(Error::OutOfMemory);
                    };
                    self.connections.reassembly(acl.handle(), |p| {
                        p.init(header.channel, header.length, packet)?;
                        let r = p.update(data)?;
                        if r.is_some() {
                            Err(Error::InvalidState)
                        } else {
                            Ok(())
                        }
                    })?;
                    return Ok(());
                } else {
                    #[allow(unused_mut)]
                    let mut result = None;

                    // For dynamic channels, validate PDU length against MPS and handle
                    // credit accounting and SDU reassembly before HCI reassembly.
                    #[cfg(feature = "l2cap-sdu-reassembly-optimization")]
                    if header.channel >= L2CAP_CID_DYN_START {
                        // This is a complete L2CAP K-frame, so make sure to adjust the credits.
                        self.channels.received(header.channel, 1)?;
                        self.channels.check_pdu_len(header.channel, header.length)?;

                        if let Some((state, pdu)) = self
                            .connections
                            .reassembly(acl.handle(), |p| {
                                if !p.in_progress() {
                                    let (first, payload) = data.split_at(2);
                                    let len: u16 = u16::from_le_bytes([first[0], first[1]]);
                                    self.channels.check_sdu_len(header.channel, len)?;
                                    let Some(packet) = P::allocate() else {
                                        warn!("[host] no memory for packets on channel {}", header.channel);
                                        return Err(Error::OutOfMemory);
                                    };
                                    p.init(header.channel, len, packet)?;
                                    p.update(payload)
                                } else {
                                    p.update(data)
                                }
                            })
                            .inspect_err(|_| self.channels.disconnect_by_cid(header.channel))?
                        {
                            result.replace((state, pdu));
                        } else {
                            return Ok(());
                        }
                    }

                    if let Some((state, pdu)) = result {
                        (state, pdu)
                    } else {
                        // For dynamic channels, validate PDU length against MPS before reassembly.
                        if header.channel >= L2CAP_CID_DYN_START {
                            self.channels.check_pdu_len(header.channel, header.length)?;
                        }

                        let Some(packet) = P::allocate() else {
                            warn!("[host] no memory for packets on channel {}", header.channel);
                            return Err(Error::OutOfMemory);
                        };
                        let result = self.connections.reassembly(acl.handle(), |p| {
                            p.init(header.channel, header.length, packet)?;
                            p.update(data)
                        })?;
                        let Some((state, pdu)) = result else {
                            return Err(Error::InvalidState);
                        };
                        (state, pdu)
                    }
                }
            }
            // Next (potentially last) in a fragment
            AclPacketBoundary::Continuing => {
                trace!("[host] inbound l2cap len = {}", acl.data().len(),);
                // Get the existing fragment
                if let Some((header, p)) = self.connections.reassembly(acl.handle(), |p| {
                    if !p.in_progress() {
                        warn!(
                            "[host] unexpected continuation fragment of length {} for handle {}: {:?}",
                            acl.data().len(),
                            acl.handle().raw(),
                            p
                        );
                        return Err(Error::InvalidState);
                    }
                    p.update(acl.data())
                })? {
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
                let a = att::Att::decode(pdu.as_ref());
                if let Ok(att::Att::Client(AttClient::Request(att::AttReq::ExchangeMtu { mtu }))) = a {
                    let mtu = self.connections.exchange_att_mtu(acl.handle(), mtu);

                    let rsp = att::Att::Server(AttServer::Response(att::AttRsp::ExchangeMtu { mtu }));
                    let l2cap = L2capHeader {
                        channel: L2CAP_CID_ATT,
                        length: 3,
                    };

                    let mut packet = pdu.into_inner();
                    let mut w = WriteCursor::new(packet.as_mut());
                    w.write_hci(&l2cap)?;
                    w.write(rsp)?;

                    info!("[host] agreed att MTU of {}", mtu);
                    let len = w.len();
                    self.connections.try_outbound(acl.handle(), Pdu::new(packet, len))?;
                } else if let Ok(att::Att::Server(AttServer::Response(att::AttRsp::ExchangeMtu { mtu }))) = a {
                    info!("[host] remote agreed att MTU of {}", mtu);
                    self.connections.exchange_att_mtu(acl.handle(), mtu);
                    #[cfg(feature = "gatt")]
                    self.connections.post_gatt_client(acl.handle(), pdu)?;
                } else {
                    #[cfg(feature = "gatt")]
                    match a {
                        Ok(att::Att::Client(_)) => {
                            self.connections.post_gatt(acl.handle(), pdu)?;
                        }
                        Ok(att::Att::Server(AttServer::Unsolicited(att::AttUns::Indicate { .. }))) => {
                            // Per BLE spec, ATT_HANDLE_VALUE_CFM must always be sent in response
                            // to an indication, regardless of whether a GATT client task is running.
                            let cfm = att::Att::Client(AttClient::Confirmation(crate::att::AttCfm::ConfirmIndication));
                            let l2cap = L2capHeader {
                                channel: L2CAP_CID_ATT,
                                length: cfm.size() as u16,
                            };
                            let mut buf = P::allocate().ok_or(Error::OutOfMemory)?;
                            let mut w = WriteCursor::new(buf.as_mut());
                            w.write_hci(&l2cap)?;
                            w.write(cfm)?;
                            let len = w.len();
                            self.connections.try_outbound(acl.handle(), Pdu::new(buf, len))?;

                            // Also queue the indication for the GATT client if possible
                            let _ = self.connections.post_gatt_client(acl.handle(), pdu);
                        }
                        Ok(att::Att::Server(_)) => {
                            if let Err(e) = self.connections.post_gatt_client(acl.handle(), pdu) {
                                return Err(Error::OutOfMemory);
                            }
                        }
                        Err(e) => {
                            warn!("Error decoding attribute payload: {:?}", e);
                            let opcode = pdu.as_ref()[0];
                            // Bit 6 = Command Flag. Only send error responses for requests (flag=0)
                            if opcode & 0x40 == 0 {
                                let rsp = att::Att::Server(AttServer::Response(att::AttRsp::Error {
                                    request: opcode,
                                    handle: 0,
                                    code: att::AttErrorCode::REQUEST_NOT_SUPPORTED,
                                }));
                                let l2cap = L2capHeader {
                                    channel: L2CAP_CID_ATT,
                                    length: rsp.size() as u16,
                                };
                                let mut packet = pdu.into_inner();
                                let mut w = WriteCursor::new(packet.as_mut());
                                w.write_hci(&l2cap)?;
                                w.write(rsp)?;
                                let len = w.len();
                                self.connections.try_outbound(acl.handle(), Pdu::new(packet, len))?;
                            }
                        }
                    }
                    #[cfg(not(feature = "gatt"))]
                    {
                        if let Ok(att::Att::Client(_)) = a {
                            drop(a);

                            let opcode = pdu.as_ref()[0];
                            let rsp = att::Att::Server(AttServer::Response(att::AttRsp::Error {
                                request: opcode,
                                handle: acl.handle().raw(),
                                code: att::AttErrorCode::ATTRIBUTE_NOT_FOUND,
                            }));

                            let mut packet = pdu.into_inner();
                            let mut w = WriteCursor::new(packet.as_mut());

                            let l2cap = L2capHeader {
                                channel: L2CAP_CID_ATT,
                                length: rsp.size() as u16,
                            };

                            w.write_hci(&l2cap)?;
                            w.write(rsp)?;

                            let len = w.len();
                            self.connections.try_outbound(acl.handle(), Pdu::new(packet, len))?;
                            warn!("[host] got attribute request but 'gatt' feature is not enabled.");
                            return Ok(());
                        } else {
                            warn!("Got unsupported ATT: {:?}", a);
                            return Err(Error::NotSupported);
                        }
                    }
                }
            }
            L2CAP_CID_LE_U_SIGNAL => {
                self.channels.signal(handle, pdu.as_ref(), &self.connections)?;
            }
            L2CAP_CID_LE_U_SECURITY_MANAGER => {
                self.connections
                    .handle_security_channel(acl.handle(), pdu, event_handler)?;
            }
            other if other >= L2CAP_CID_DYN_START => match self.channels.dispatch(header.channel, pdu) {
                Ok(_) => {}
                Err(e) => {
                    warn!("Error dispatching l2cap packet to channel: {:?}", e);
                    return Err(e);
                }
            },
            chan => {
                debug!(
                    "[host] conn {:?} attempted to use unsupported l2cap channel {}, ignoring",
                    acl.handle(),
                    chan
                );
                return Ok(());
            }
        }
        Ok(())
    }

    // Send l2cap signal payload
    pub(crate) async fn l2cap_signal<D: L2capSignal>(
        &self,
        conn: ConnHandle,
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

        let mut sender = self.l2cap(conn, w.len() as u16, 1).await?;
        sender.send(w.finish()).await?;

        Ok(())
    }

    // Request to an L2CAP payload of len to the HCI controller for a connection.
    //
    // This function will request the appropriate number of ACL packets to be sent and
    // the returned sender will handle fragmentation.
    pub(crate) async fn l2cap(
        &self,
        handle: ConnHandle,
        len: u16,
        n_packets: u16,
    ) -> Result<L2capSender<'_, T, P::Packet>, BleHostError<T::Error>> {
        // Take into account l2cap header.
        let acl_max = self.initialized.get().await.acl_max as u16;
        let len = len + (4 * n_packets);
        let n_acl = len.div_ceil(acl_max);
        let grant = poll_fn(|cx| self.connections.poll_request_to_send(handle, n_acl as usize, Some(cx))).await?;
        trace!("[host] granted send packets = {}, len = {}", n_packets, len);
        Ok(L2capSender {
            controller: &self.controller,
            handle,
            grant,
            fragment_size: acl_max,
        })
    }

    // Request to an L2CAP payload of len to the HCI controller for a connection.
    //
    // This function will request the appropriate number of ACL packets to be sent and
    // the returned sender will handle fragmentation.
    pub(crate) fn try_l2cap(
        &self,
        handle: ConnHandle,
        len: u16,
        n_packets: u16,
    ) -> Result<L2capSender<'_, T, P::Packet>, BleHostError<T::Error>> {
        let acl_max = self.initialized.try_get().map(|i| i.acl_max).unwrap_or(27) as u16;
        let len = len + (4 * n_packets);
        let n_acl = len.div_ceil(acl_max);
        let grant = match self.connections.poll_request_to_send(handle, n_acl as usize, None) {
            Poll::Ready(res) => res?,
            Poll::Pending => {
                return Err(Error::Busy.into());
            }
        };
        Ok(L2capSender {
            controller: &self.controller,
            handle,
            grant,
            fragment_size: acl_max,
        })
    }

    pub(crate) async fn send_conn_param_update_req(
        &self,
        handle: ConnHandle,
        param: &ConnParamUpdateReq,
    ) -> Result<(), BleHostError<T::Error>> {
        self.channels.send_conn_param_update_req(handle, self, param).await
    }

    pub(crate) async fn send_conn_param_update_res(
        &self,
        handle: ConnHandle,
        param: &ConnParamUpdateRes,
    ) -> Result<(), BleHostError<T::Error>> {
        self.channels.send_conn_param_update_res(handle, self, param).await
    }

    /// Read current host metrics
    pub(crate) fn metrics<F: FnOnce(&HostMetrics) -> R, R>(&self, f: F) -> R {
        let m = self.metrics.borrow();
        f(&m)
    }

    /// Log status information of the host
    pub(crate) fn log_status(&self, verbose: bool) {
        let m = self.metrics.borrow();
        debug!("[host] connect events: {}", m.connect_events);
        debug!("[host] disconnect events: {}", m.disconnect_events);
        debug!("[host] rx errors: {}", m.rx_errors);
        self.connections.log_status(verbose);
        self.channels.log_status(verbose);
    }
}

/// Runs the host with the given controller.
pub struct Runner<'d, C, P: PacketPool> {
    rx: RxRunner<'d, C, P>,
    control: ControlRunner<'d, C, P>,
    tx: TxRunner<'d, C, P>,
}

/// The receiver part of the host runner.
pub struct RxRunner<'d, C, P: PacketPool> {
    host: &'d BleHost<'d, C, P>,
}

/// The control part of the host runner.
pub struct ControlRunner<'d, C, P: PacketPool> {
    host: &'d BleHost<'d, C, P>,
}

/// The transmit part of the host runner.
pub struct TxRunner<'d, C, P: PacketPool> {
    host: &'d BleHost<'d, C, P>,
}

/// Event handler.
pub trait EventHandler {
    /// Handle vendor events
    fn on_vendor(&self, vendor: &Vendor) {}
    /// Handle advertising reports
    #[cfg(feature = "scan")]
    fn on_adv_reports(&self, reports: bt_hci::param::LeAdvReportsIter) {}
    /// Handle extended advertising reports
    #[cfg(feature = "scan")]
    fn on_ext_adv_reports(&self, reports: bt_hci::param::LeExtAdvReportsIter) {}
    /// Handle HCI NumberOfCompletedPackets event.
    ///
    /// Called for each connection handle entry when the controller confirms
    /// ACL data packets have been transmitted over the air. Useful for
    /// measuring actual air delivery rate and estimating connection event timing.
    fn on_packets_completed(&self, _num_completed: usize) {}
}

struct DummyHandler;
impl EventHandler for DummyHandler {}

impl<'d, C: Controller, P: PacketPool> Runner<'d, C, P> {
    pub(crate) fn new(host: &'d BleHost<'d, C, P>) -> Self {
        Self {
            rx: RxRunner { host },
            control: ControlRunner { host },
            tx: TxRunner { host },
        }
    }

    /// Split the runner into separate independent async tasks
    pub fn split(self) -> (RxRunner<'d, C, P>, ControlRunner<'d, C, P>, TxRunner<'d, C, P>) {
        (self.rx, self.control, self.tx)
    }

    /// Run the host.
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<SetEventMaskPage2>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeSetExtScanEnable>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeReadBufferSize>
            + ControllerCmdSync<ReadBdAddr>
            + crate::SecurityCmds,
        C::Error: crate::fmt::Format,
    {
        let dummy = DummyHandler;
        self.run_with_handler(&dummy).await
    }

    /// Run the host with a vendor event handler for custom events.
    pub async fn run_with_handler<E: EventHandler>(&mut self, event_handler: &E) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<SetEventMaskPage2>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeSetExtScanEnable>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + ControllerCmdSync<LeReadBufferSize>
            + ControllerCmdSync<ReadBdAddr>
            + crate::SecurityCmds,
        C::Error: crate::fmt::Format,
    {
        let control_fut = self.control.run();
        let rx_fut = self.rx.run_with_handler(event_handler);
        let tx_fut = self.tx.run();
        pin_mut!(control_fut, rx_fut, tx_fut);
        match select3(&mut tx_fut, &mut rx_fut, &mut control_fut).await {
            Either3::First(result) => {
                trace!("[host] tx_fut exit");
                result
            }
            Either3::Second(result) => {
                trace!("[host] rx_fut exit");
                result
            }
            Either3::Third(result) => {
                trace!("[host] control_fut exit");
                result
            }
        }
    }
}

impl<'d, C: Controller, P: PacketPool> RxRunner<'d, C, P> {
    /// Run the receive loop that polls the controller for events.
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>,
    {
        let dummy = DummyHandler;
        self.run_with_handler(&dummy).await
    }

    /// Runs the receive loop that pools the controller for events, dispatching
    /// vendor events to the provided closure.
    pub async fn run_with_handler<E: EventHandler>(&mut self, event_handler: &E) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>,
    {
        const MAX_HCI_PACKET_LEN: usize = 259;
        let host = &self.host;
        // use embassy_time::Instant;
        // let mut last = Instant::now();
        loop {
            // Task handling receiving data from the controller.
            let mut rx = [0u8; MAX_HCI_PACKET_LEN];
            // let now = Instant::now();
            // let elapsed = (now - last).as_millis();
            // if elapsed >= 1 {
            //     trace!("[host] time since last poll was {} us", elapsed);
            // }
            let result = host.controller.read(&mut rx).await;
            // last = Instant::now();
            //        trace!("[host] polling took {} ms", (polled - started).as_millis());
            match result {
                Ok(ControllerToHostPacket::Acl(acl)) => match host.handle_acl(acl, event_handler) {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "[host] encountered error processing ACL data for {:?}: {:?}",
                            acl.handle(),
                            e
                        );

                        match e {
                            Error::InvalidState | Error::Disconnected => {
                                warn!("[host] requesting {:?} to be disconnected", acl.handle());
                                host.connections.log_status(true);
                                host.connections.request_handle_disconnect(
                                    acl.handle(),
                                    DisconnectReason::RemoteUserTerminatedConn,
                                );
                            }
                            _ => {}
                        }

                        let mut m = host.metrics.borrow_mut();
                        m.rx_errors = m.rx_errors.wrapping_add(1);
                    }
                },
                Ok(ControllerToHostPacket::Event(event)) => {
                    match event.kind {
                        EventKind::Le => {
                            let event = unwrap!(LeEventPacket::from_hci_bytes_complete(event.data));
                            match event.kind {
                                LeEventKind::LeConnectionComplete => {
                                    let e = unwrap!(LeConnectionComplete::from_hci_bytes_complete(event.data));
                                    if !host.handle_connection(
                                        e.status,
                                        e.handle,
                                        Address::new(e.peer_addr_kind, e.peer_addr),
                                        e.role,
                                        ConnParams {
                                            conn_interval: Duration::from_micros(e.conn_interval.as_micros()),
                                            peripheral_latency: e.peripheral_latency,
                                            supervision_timeout: Duration::from_micros(
                                                e.supervision_timeout.as_micros(),
                                            ),
                                        },
                                        #[cfg(feature = "security")]
                                        ResolvablePrivateAddrs::none(),
                                    ) {
                                        let _ = host
                                            .command(Disconnect::new(
                                                e.handle,
                                                DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                            ))
                                            .await;
                                        host.connect_command_state.canceled();
                                    }
                                }
                                LeEventKind::LeEnhancedConnectionComplete => {
                                    let e = unwrap!(LeEnhancedConnectionComplete::from_hci_bytes_complete(event.data));
                                    if !host.handle_connection(
                                        e.status,
                                        e.handle,
                                        Address::new(e.peer_addr_kind, e.peer_addr),
                                        e.role,
                                        ConnParams {
                                            conn_interval: Duration::from_micros(e.conn_interval.as_micros()),
                                            peripheral_latency: e.peripheral_latency,
                                            supervision_timeout: Duration::from_micros(
                                                e.supervision_timeout.as_micros(),
                                            ),
                                        },
                                        #[cfg(feature = "security")]
                                        ResolvablePrivateAddrs {
                                            local: Some(e.local_resolvable_private_addr).filter(|a| *a.raw() != [0; 6]),
                                            peer: Some(e.peer_resolvable_private_addr).filter(|a| *a.raw() != [0; 6]),
                                        },
                                    ) {
                                        let _ = host
                                            .command(Disconnect::new(
                                                e.handle,
                                                DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                            ))
                                            .await;
                                        host.connect_command_state.canceled();
                                    }
                                }
                                LeEventKind::LeScanTimeout => {}
                                LeEventKind::LeAdvertisingSetTerminated => {
                                    let set = unwrap!(LeAdvertisingSetTerminated::from_hci_bytes_complete(event.data));
                                    host.advertise_state.terminate(set.adv_handle);
                                }
                                LeEventKind::LeExtendedAdvertisingReport => {
                                    #[cfg(feature = "scan")]
                                    {
                                        let data =
                                            unwrap!(LeExtendedAdvertisingReport::from_hci_bytes_complete(event.data));
                                        event_handler.on_ext_adv_reports(data.reports.iter());
                                    }
                                }
                                LeEventKind::LeAdvertisingReport => {
                                    #[cfg(feature = "scan")]
                                    {
                                        let data = unwrap!(LeAdvertisingReport::from_hci_bytes_complete(event.data));
                                        event_handler.on_adv_reports(data.reports.iter());
                                    }
                                }
                                LeEventKind::LeLongTermKeyRequest => {
                                    host.connections.handle_security_hci_le_event(event)?;
                                }
                                LeEventKind::LePhyUpdateComplete => {
                                    let event = unwrap!(LePhyUpdateComplete::from_hci_bytes_complete(event.data));
                                    if let Err(e) = event.status.to_result() {
                                        warn!("[host] error updating phy for {:?}: {:?}", event.handle, e);
                                    } else {
                                        let _ = host.connections.post_handle_event(
                                            event.handle,
                                            ConnectionEvent::PhyUpdated {
                                                tx_phy: event.tx_phy,
                                                rx_phy: event.rx_phy,
                                            },
                                        );
                                    }
                                }
                                LeEventKind::LeConnectionUpdateComplete => {
                                    let event =
                                        unwrap!(LeConnectionUpdateComplete::from_hci_bytes_complete(event.data));
                                    if let Err(e) = event.status.to_result() {
                                        warn!(
                                            "[host] error updating connection parameters for {:?}: {:?}",
                                            event.handle, e
                                        );
                                    } else {
                                        let _ = host.connections.post_handle_event(
                                            event.handle,
                                            ConnectionEvent::ConnectionParamsUpdated {
                                                conn_interval: Duration::from_micros(event.conn_interval.as_micros()),
                                                peripheral_latency: event.peripheral_latency,
                                                supervision_timeout: Duration::from_micros(
                                                    event.supervision_timeout.as_micros(),
                                                ),
                                            },
                                        );
                                    }
                                }
                                LeEventKind::LeDataLengthChange => {
                                    let event = unwrap!(LeDataLengthChange::from_hci_bytes_complete(event.data));
                                    let _ = host.connections.post_handle_event(
                                        event.handle,
                                        ConnectionEvent::DataLengthUpdated {
                                            max_tx_octets: event.max_tx_octets,
                                            max_tx_time: event.max_tx_time,
                                            max_rx_octets: event.max_rx_octets,
                                            max_rx_time: event.max_rx_time,
                                        },
                                    );
                                }
                                LeEventKind::LeFrameSpaceUpdateComplete => {
                                    let event =
                                        unwrap!(LeFrameSpaceUpdateComplete::from_hci_bytes_complete(event.data));
                                    if let Err(e) = event.status.to_result() {
                                        warn!("[host] error updating frame space for {:?}: {:?}", event.handle, e);
                                    } else {
                                        let _ = host.connections.post_handle_event(
                                            event.handle,
                                            ConnectionEvent::FrameSpaceUpdated {
                                                frame_space: Duration::from_micros(event.frame_space.as_micros()),
                                                initiator: event.initiator,
                                                phys: event.phys,
                                                spacing_types: event.spacing_types,
                                            },
                                        );
                                    }
                                }
                                LeEventKind::LeConnectionRateChange => {
                                    let event = unwrap!(LeConnectionRateChange::from_hci_bytes_complete(event.data));
                                    if let Err(e) = event.status.to_result() {
                                        warn!("[host] error in connection rate change for {:?}: {:?}", event.handle, e);
                                    } else {
                                        let _ = host.connections.post_handle_event(
                                            event.handle,
                                            ConnectionEvent::ConnectionRateChanged {
                                                conn_interval: Duration::from_micros(event.conn_interval.as_micros()),
                                                subrate_factor: event.subrate_factor,
                                                peripheral_latency: event.peripheral_latency,
                                                continuation_number: event.continuation_number,
                                                supervision_timeout: Duration::from_micros(
                                                    event.supervision_timeout.as_micros(),
                                                ),
                                            },
                                        );
                                    }
                                }
                                LeEventKind::LeRemoteConnectionParameterRequest => {
                                    let event = unwrap!(LeRemoteConnectionParameterRequest::from_hci_bytes_complete(
                                        event.data
                                    ));
                                    let req = ConnectionParamsRequest::new(
                                        RequestedConnParams {
                                            min_connection_interval: Duration::from_micros(
                                                event.interval_min.as_micros(),
                                            ),
                                            max_connection_interval: Duration::from_micros(
                                                event.interval_min.as_micros(),
                                            ),
                                            max_latency: event.max_latency,
                                            supervision_timeout: Duration::from_micros(event.timeout.as_micros()),
                                            ..Default::default()
                                        },
                                        event.handle,
                                        #[cfg(feature = "connection-params-update")]
                                        false,
                                    );
                                    let _ = host
                                        .connections
                                        .post_handle_event(event.handle, ConnectionEvent::RequestConnectionParams(req));
                                }
                                _ => {
                                    warn!("Unknown LE event!");
                                }
                            }
                        }
                        EventKind::DisconnectionComplete => {
                            let e = unwrap!(DisconnectionComplete::from_hci_bytes_complete(event.data));
                            let handle = e.handle;
                            let reason = if let Err(e) = e.status.to_result() {
                                info!("[host] disconnection event on handle {}, status: {:?}", handle.raw(), e);
                                None
                            } else if let Err(err) = e.reason.to_result() {
                                info!(
                                    "[host] disconnection event on handle {}, reason: {:?}",
                                    handle.raw(),
                                    err
                                );
                                Some(e.reason)
                            } else {
                                info!("[host] disconnection event on handle {}", handle.raw());
                                None
                            }
                            .unwrap_or(Status::UNSPECIFIED);
                            let _ = host.connections.disconnected(handle, reason);
                            let _ = host.channels.disconnected(handle);
                            let mut m = host.metrics.borrow_mut();
                            m.disconnect_events = m.disconnect_events.wrapping_add(1);
                        }
                        EventKind::NumberOfCompletedPackets => {
                            let c = unwrap!(NumberOfCompletedPackets::from_hci_bytes_complete(event.data));
                            // Explicitly ignoring for now
                            for entry in c.completed_packets.iter() {
                                match (entry.handle(), entry.num_completed_packets()) {
                                    (Ok(handle), Ok(completed)) => {
                                        let _ = host.connections.confirm_sent(handle, completed as usize);
                                        event_handler.on_packets_completed(completed as usize);
                                    }
                                    (Ok(handle), Err(e)) => {
                                        warn!("[host] error processing completed packets for {:?}: {:?}", handle, e);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        EventKind::Vendor => {
                            let vendor = unwrap!(Vendor::from_hci_bytes_complete(event.data));
                            event_handler.on_vendor(&vendor);
                        }
                        EventKind::EncryptionChangeV1 | EventKind::EncryptionKeyRefreshComplete => {
                            host.connections.handle_security_hci_event(event)?;
                        }
                        // Ignore
                        _ => {}
                    }
                }
                // Ignore
                Ok(_) => {}
                Err(e) => {
                    return Err(BleHostError::Controller(e));
                }
            }
        }
    }
}

enum CancelledCommandState {
    Connect(bool),
    Advertise(bool),
    Scan(bool),
    #[cfg(feature = "security")]
    SyncResolvingList(ResolvingListUpdate),
}

impl<'d, C: Controller, P: PacketPool> ControlRunner<'d, C, P> {
    /// Run the control loop for the host
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<SetEventMaskPage2>
            + ControllerCmdSync<LeSetEventMask>
            + ControllerCmdSync<LeSetRandomAddr>
            + ControllerCmdSync<HostBufferSize>
            + ControllerCmdAsync<LeConnUpdate>
            + ControllerCmdSync<LeReadFilterAcceptListSize>
            + ControllerCmdSync<SetControllerToHostFlowControl>
            + ControllerCmdSync<Reset>
            + ControllerCmdSync<LeCreateConnCancel>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + ControllerCmdSync<LeSetScanEnable>
            + ControllerCmdSync<LeSetExtScanEnable>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeReadBufferSize>
            + ControllerCmdSync<ReadBdAddr>
            + crate::SecurityCmds,
        C::Error: crate::fmt::Format,
    {
        let host = &self.host;
        Reset::new().exec(&host.controller).await?;

        if let Some(addr) = host.address {
            LeSetRandomAddr::new(addr.addr).exec(&host.controller).await?;
        }

        SetEventMask::new(
            EventMask::new()
                .enable_le_meta(true)
                .enable_conn_request(true)
                .enable_conn_complete(true)
                .enable_hardware_error(true)
                .enable_disconnection_complete(true)
                .enable_encryption_change_v1(true)
                .enable_encryption_key_refresh_complete(true),
        )
        .exec(&host.controller)
        .await?;

        SetEventMaskPage2::new(EventMaskPage2::new().enable_encryption_change_v2(true))
            .exec(&host.controller)
            .await?;

        let mask = LeEventMask::new()
            .enable_le_conn_complete(true)
            .enable_le_enhanced_conn_complete(true)
            .enable_le_conn_update_complete(true)
            .enable_le_adv_set_terminated(true)
            .enable_le_adv_report(true)
            .enable_le_scan_timeout(true)
            .enable_le_ext_adv_report(true)
            .enable_le_long_term_key_request(true)
            .enable_le_phy_update_complete(true)
            .enable_le_data_length_change(true);

        #[cfg(feature = "connection-params-update")]
        let mask = mask.enable_le_remote_conn_parameter_request(true);

        LeSetEventMask::new(mask).exec(&host.controller).await?;

        info!(
            "[host] using packet pool with MTU {} capacity {}",
            P::MTU,
            P::capacity(),
        );

        let ret = LeReadFilterAcceptListSize::new().exec(&host.controller).await?;
        info!("[host] filter accept list size: {}", ret);

        let ret = LeReadBufferSize::new().exec(&host.controller).await?;
        info!(
            "[host] setting txq to {}, fragmenting at {}",
            ret.total_num_le_acl_data_packets as usize, ret.le_acl_data_packet_length as usize
        );
        host.connections
            .set_link_credits(ret.total_num_le_acl_data_packets as usize);

        {
            const ACL_LEN: u16 = 255;
            const ACL_N: u16 = 1;
            info!(
                "[host] configuring host buffers ({} packets of size {})",
                ACL_N, ACL_LEN,
            );
            if let Err(_e) = HostBufferSize::new(ACL_LEN, 0, ACL_N, 0).exec(&host.controller).await {
                warn!("[host] error configuring host buffers (continuing)");
            }
        }

        /*
                #[cfg(feature = "controller-host-flow-control")]
                {
                    info!("[host] enabling flow control");
                    SetControllerToHostFlowControl::new(ControllerToHostFlowControl::AclOnSyncOff)
                        .exec(&host.controller)
                        .await?;
                }
        */

        let _ = host.initialized.init(InitialState {
            acl_max: ret.le_acl_data_packet_length as usize,
        });
        info!("[host] initialized");

        let device_address = host.command(ReadBdAddr::new()).await?;
        if *device_address.raw() != [0, 0, 0, 0, 0, 0] {
            let device_address = Address::new(AddrKind::PUBLIC, device_address);
            info!("[host] Device Address {}", device_address);
            if host.address.is_none() {
                #[cfg(feature = "security")]
                host.connections.security_manager.set_local_address(device_address);
            }
        }

        // Set default RPA timeout in controller
        #[cfg(feature = "security")]
        {
            let timeout_secs = host.rpa_timeout.get().as_secs();
            LeSetResolvablePrivateAddrTimeout::new(bt_hci::param::Duration::from_secs(timeout_secs as u32))
                .exec(&host.controller)
                .await?;
            info!("[host] RPA timeout set to {}s", timeout_secs);
        }

        // Initialize privacy: sync resolving list
        #[cfg(feature = "security")]
        if host.is_privacy_enabled() {
            host.resolving_list_state.borrow_mut().clear();
            host.sync_resolving_list(ResolvingListUpdate::FullSync).await?;
            info!("[host] privacy initialized");
        }

        loop {
            match select4(
                poll_fn(|cx| host.connections.poll_disconnecting(Some(cx))),
                poll_fn(|cx| host.channels.poll_disconnecting(Some(cx))),
                poll_fn(|cx| host.poll_cancelled(cx)),
                #[cfg(feature = "security")]
                {
                    host.connections.poll_security_events()
                },
                #[cfg(not(feature = "security"))]
                {
                    poll_fn(|cx| Poll::<()>::Pending)
                },
            )
            .await
            {
                Either4::First(request) => {
                    trace!("[host] poll disconnecting links");
                    match host.command(Disconnect::new(request.handle(), request.reason())).await {
                        Ok(_) => {}
                        Err(BleHostError::BleHost(Error::Hci(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER))) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    }
                    request.confirm();
                }
                Either4::Second(request) => {
                    trace!("[host] poll disconnecting channels");
                    match request.send(host).await {
                        Ok(_) => {}
                        Err(BleHostError::BleHost(Error::Hci(bt_hci::param::Error::UNKNOWN_CONN_IDENTIFIER))) => {}
                        Err(BleHostError::BleHost(Error::NotFound)) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    }
                    request.confirm();
                }
                Either4::Third(action) => match action {
                    CancelledCommandState::Connect(_) => {
                        trace!("[host] cancel connection create");
                        if host.command(LeCreateConnCancel::new()).await.is_err() {
                            warn!("[host] error cancelling connection");
                        }
                        // Signal to ensure no one is stuck
                        host.connect_command_state.canceled();
                    }
                    CancelledCommandState::Advertise(ext) => {
                        trace!("[host] disabling advertising");
                        if ext {
                            host.command(LeSetExtAdvEnable::new(false, &[])).await?
                        } else {
                            host.command(LeSetAdvEnable::new(false)).await?
                        }
                        host.advertise_command_state.canceled();
                    }
                    CancelledCommandState::Scan(ext) => {
                        trace!("[host] disabling scanning");
                        if ext {
                            // TODO: A bit opinionated but not more than before
                            host.command(LeSetExtScanEnable::new(
                                false,
                                FilterDuplicates::Disabled,
                                bt_hci::param::Duration::from_secs(0),
                                bt_hci::param::Duration::from_secs(0),
                            ))
                            .await?;
                        } else {
                            host.command(LeSetScanEnable::new(false, false)).await?;
                        }
                        host.scan_command_state.canceled();
                    }
                    #[cfg(feature = "security")]
                    CancelledCommandState::SyncResolvingList(update) => {
                        host.sync_resolving_list(update).await?;
                    }
                },
                Either4::Fourth(request) => {
                    #[cfg(feature = "security")]
                    {
                        let event_data = request.unwrap_or(SecurityEventData::Timeout);
                        host.connections.handle_security_event(host, event_data).await?;
                    }
                }
            }
        }
    }
}

impl<'d, C: Controller, P: PacketPool> TxRunner<'d, C, P> {
    /// Run the transmit loop for the host.
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>> {
        let host = &self.host;
        let params = host.initialized.get().await;
        loop {
            let (conn, pdu) = host.connections.outbound().await;
            match host.l2cap(conn, pdu.len() as u16, 1).await {
                Ok(mut sender) => {
                    if let Err(e) = sender.send(pdu.as_ref()).await {
                        warn!("[host] error sending outbound pdu");
                        return Err(e);
                    }
                }
                Err(BleHostError::BleHost(Error::NotFound)) => {
                    warn!("[host] unable to send data to disconnected host (ignored)");
                }
                Err(BleHostError::BleHost(Error::Disconnected)) => {
                    warn!("[host] unable to send data to disconnected host (ignored)");
                }
                Err(e) => {
                    warn!("[host] error requesting sending outbound pdu");
                    return Err(e);
                }
            }
        }
    }
}

pub struct L2capSender<'a, T: Controller, P> {
    pub(crate) controller: &'a T,
    pub(crate) handle: ConnHandle,
    pub(crate) grant: PacketGrant<'a, P>,
    pub(crate) fragment_size: u16,
}

impl<'a, T: Controller, P> L2capSender<'a, T, P> {
    pub(crate) fn try_send(&mut self, pdu: &[u8]) -> Result<(), BleHostError<T::Error>>
    where
        T: blocking::Controller,
    {
        let mut pbf = AclPacketBoundary::FirstNonFlushable;
        //info!(
        //    "[host] fragmenting PDU of size {} into {} sized fragments",
        //    pdu.len(),
        //    self.fragment_size
        //);
        for chunk in pdu.chunks(self.fragment_size as usize) {
            let acl = AclPacket::new(self.handle, pbf, AclBroadcastFlag::PointToPoint, chunk);
            match self.controller.try_write_acl_data(&acl) {
                Ok(result) => {
                    self.grant.confirm(1);
                    trace!("[host] sent acl packet len = {}", chunk.len());
                }
                Err(blocking::TryError::Busy) => {
                    warn!("hci: acl data send busy");
                    return Err(Error::Busy.into());
                }
                Err(blocking::TryError::Error(e)) => return Err(BleHostError::Controller(e)),
            }
            pbf = AclPacketBoundary::Continuing;
        }
        Ok(())
    }

    pub(crate) async fn send(&mut self, pdu: &[u8]) -> Result<(), BleHostError<T::Error>> {
        //info!(
        //    "[host] fragmenting PDU of size {} into {} sized fragments",
        //    pdu.len(),
        //    self.fragment_size
        //);
        let mut pbf = AclPacketBoundary::FirstNonFlushable;
        for chunk in pdu.chunks(self.fragment_size as usize) {
            let acl = AclPacket::new(self.handle, pbf, AclBroadcastFlag::PointToPoint, chunk);
            self.controller
                .write_acl_data(&acl)
                .await
                .map_err(BleHostError::Controller)?;
            self.grant.confirm(1);
            pbf = AclPacketBoundary::Continuing;
            trace!("[host] sent acl packet len = {}", chunk.len());
        }
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
