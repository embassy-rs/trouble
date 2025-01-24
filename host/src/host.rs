//! BleHost
//!
//! The host module contains the main entry point for the TrouBLE host.
use core::cell::RefCell;
use core::future::poll_fn;
use core::mem::MaybeUninit;
use core::task::Poll;

use bt_hci::cmd::controller_baseband::{
    HostBufferSize, HostNumberOfCompletedPackets, Reset, SetControllerToHostFlowControl, SetEventMask,
};
use bt_hci::cmd::le::{
    LeConnUpdate, LeCreateConnCancel, LeReadBufferSize, LeReadFilterAcceptListSize, LeSetAdvEnable, LeSetEventMask,
    LeSetExtAdvEnable, LeSetExtScanEnable, LeSetRandomAddr, LeSetScanEnable,
};
use bt_hci::cmd::link_control::Disconnect;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::controller::{blocking, Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::data::{AclBroadcastFlag, AclPacket, AclPacketBoundary};
use bt_hci::event::le::LeEvent;
use bt_hci::event::{Event, Vendor};
use bt_hci::param::{
    AddrKind, AdvHandle, AdvSet, BdAddr, ConnHandle, DisconnectReason, EventMask, FilterDuplicates, LeConnRole,
    LeEventMask, Status,
};
#[cfg(feature = "controller-host-flow-control")]
use bt_hci::param::{ConnHandleCompletedPackets, ControllerToHostFlowControl};
use bt_hci::{ControllerToHostPacket, FromHciBytes, WriteHci};
use embassy_futures::select::{select3, Either3};
use embassy_sync::once_lock::OnceLock;
use embassy_sync::waitqueue::WakerRegistration;
#[cfg(feature = "gatt")]
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, channel::Channel};
use futures::pin_mut;

use crate::channel_manager::{ChannelManager, ChannelStorage, PacketChannel};
use crate::command::CommandState;
#[cfg(feature = "gatt")]
use crate::connection::ConnectionEventData;
use crate::connection_manager::{ConnectionManager, ConnectionStorage, EventChannel, PacketGrant};
use crate::cursor::WriteCursor;
use crate::l2cap::sar::{PacketReassembly, SarType};
use crate::packet_pool::Pool;
use crate::pdu::Pdu;
use crate::types::l2cap::{
    L2capHeader, L2capSignal, L2capSignalHeader, L2CAP_CID_ATT, L2CAP_CID_DYN_START, L2CAP_CID_LE_U_SIGNAL,
};
use crate::{att, config, Address, BleHostError, Error, Stack};

/// A BLE Host.
///
/// The BleHost holds the runtime state of the host, and is the entry point
/// for all interactions with the controller.
///
/// The host performs connection management, l2cap channel management, and
/// multiplexes events and data across connections and l2cap channels.
pub(crate) struct BleHost<'d, T> {
    initialized: OnceLock<InitialState>,
    metrics: RefCell<HostMetrics>,
    pub(crate) address: Option<Address>,
    pub(crate) controller: T,
    pub(crate) connections: ConnectionManager<'d>,
    pub(crate) reassembly: PacketReassembly<'d>,
    pub(crate) channels: ChannelManager<'d>,
    #[cfg(feature = "gatt")]
    pub(crate) att_client: Channel<NoopRawMutex, (ConnHandle, Pdu), { config::L2CAP_RX_QUEUE_SIZE }>,
    pub(crate) rx_pool: &'d dyn Pool,
    #[cfg(feature = "gatt")]
    pub(crate) tx_pool: &'d dyn Pool,

    pub(crate) advertise_state: AdvState<'d>,
    pub(crate) advertise_command_state: CommandState<bool>,
    pub(crate) connect_command_state: CommandState<bool>,
    pub(crate) scan_command_state: CommandState<bool>,
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

pub(crate) struct AdvInnerState<'d> {
    handles: &'d mut [AdvHandleState],
    waker: WakerRegistration,
}

pub(crate) struct AdvState<'d> {
    state: RefCell<AdvInnerState<'d>>,
}

impl<'d> AdvState<'d> {
    pub(crate) fn new(handles: &'d mut [AdvHandleState]) -> Self {
        Self {
            state: RefCell::new(AdvInnerState {
                handles,
                waker: WakerRegistration::new(),
            }),
        }
    }

    pub(crate) fn reset(&self) {
        let mut state = self.state.borrow_mut();
        for entry in state.handles.iter_mut() {
            *entry = AdvHandleState::None;
        }
        state.waker.wake();
    }

    // Terminate handle
    pub(crate) fn terminate(&self, handle: AdvHandle) {
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

    pub(crate) fn len(&self) -> usize {
        let state = self.state.borrow();
        state.handles.len()
    }

    pub(crate) fn start(&self, sets: &[AdvSet]) {
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
                    AdvHandleState::Terminated(_) => {
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

impl<'d, T> BleHost<'d, T>
where
    T: Controller,
{
    /// Create a new instance of the BLE host.
    ///
    /// The host requires a HCI driver (a particular HCI-compatible controller implementing the required traits), and
    /// a reference to resources that are created outside the host but which the host is the only accessor of.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        controller: T,
        rx_pool: &'d dyn Pool,
        #[cfg(feature = "gatt")] tx_pool: &'d dyn Pool,
        connections: &'d mut [ConnectionStorage],
        events: &'d mut [EventChannel],
        channels: &'d mut [ChannelStorage],
        channels_rx: &'d mut [PacketChannel<{ config::L2CAP_RX_QUEUE_SIZE }>],
        sar: &'d mut [SarType],
        advertise_handles: &'d mut [AdvHandleState],
    ) -> Self {
        Self {
            address: None,
            initialized: OnceLock::new(),
            metrics: RefCell::new(HostMetrics::default()),
            controller,
            #[cfg(feature = "gatt")]
            connections: ConnectionManager::new(connections, events, rx_pool.mtu() as u16 - 4, tx_pool),
            #[cfg(not(feature = "gatt"))]
            connections: ConnectionManager::new(connections, events, rx_pool.mtu() as u16 - 4),
            reassembly: PacketReassembly::new(sar),
            channels: ChannelManager::new(rx_pool, channels, channels_rx),
            rx_pool,
            #[cfg(feature = "gatt")]
            tx_pool,
            #[cfg(feature = "gatt")]
            att_client: Channel::new(),
            advertise_state: AdvState::new(advertise_handles),
            advertise_command_state: CommandState::new(),
            scan_command_state: CommandState::new(),
            connect_command_state: CommandState::new(),
        }
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

                    #[cfg(feature = "log")]
                    trace!(
                        "[host] connection with handle {:?} established to {:02x?}",
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
        self.connections.received(acl.handle())?;
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

                let Some(mut p) = self.rx_pool.alloc() else {
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
                let a = att::Att::decode(&packet.as_ref()[..header.length as usize]);
                if let Ok(att::Att::Req(att::AttReq::ExchangeMtu { mtu })) = a {
                    let mtu = self.connections.exchange_att_mtu(acl.handle(), mtu);

                    let rsp = att::AttRsp::ExchangeMtu { mtu };
                    let l2cap = L2capHeader {
                        channel: L2CAP_CID_ATT,
                        length: 3,
                    };

                    let mut w = WriteCursor::new(packet.as_mut());
                    w.write_hci(&l2cap)?;
                    w.write(rsp)?;

                    info!("[host] agreed att MTU of {}", mtu);
                    let len = w.len();
                    self.connections.try_outbound(acl.handle(), Pdu::new(packet, len))?;
                } else if let Ok(att::Att::Rsp(att::AttRsp::ExchangeMtu { mtu })) = a {
                    info!("[host] remote agreed att MTU of {}", mtu);
                    self.connections.exchange_att_mtu(acl.handle(), mtu);
                } else {
                    #[cfg(feature = "gatt")]
                    match a {
                        Ok(att::Att::Req(_)) => {
                            let event = ConnectionEventData::Gatt {
                                data: Pdu::new(packet, header.length as usize),
                            };
                            self.connections.post_handle_event(acl.handle(), event)?;
                        }
                        Ok(att::Att::Rsp(_)) => {
                            if let Err(e) = self
                                .att_client
                                .try_send((acl.handle(), Pdu::new(packet, header.length as usize)))
                            {
                                return Err(Error::OutOfMemory);
                            }
                        }
                        Err(e) => {
                            warn!("Error decoding attribute payload: {:?}", e);
                        }
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
    ) -> Result<L2capSender<'_, 'd, T>, BleHostError<T::Error>> {
        // Take into account l2cap header.
        let acl_max = self.initialized.get().await.acl_max as u16;
        let len = len + (4 * n_packets);
        let n_acl = len.div_ceil(acl_max);
        let grant = poll_fn(|cx| self.connections.poll_request_to_send(handle, n_acl as usize, Some(cx))).await?;
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
    ) -> Result<L2capSender<'_, 'd, T>, BleHostError<T::Error>> {
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

    /// Read current host metrics
    pub(crate) fn metrics(&self) -> HostMetrics {
        let m = self.metrics.borrow_mut().clone();
        m
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
pub struct Runner<'d, C> {
    rx: RxRunner<'d, C>,
    control: ControlRunner<'d, C>,
    tx: TxRunner<'d, C>,
}

/// The receiver part of the host runner.
pub struct RxRunner<'d, C> {
    stack: &'d Stack<'d, C>,
}

/// The control part of the host runner.
pub struct ControlRunner<'d, C> {
    stack: &'d Stack<'d, C>,
}

/// The transmit part of the host runner.
pub struct TxRunner<'d, C> {
    stack: &'d Stack<'d, C>,
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
}

struct DummyHandler;
impl EventHandler for DummyHandler {}

impl<'d, C: Controller> Runner<'d, C> {
    pub(crate) fn new(stack: &'d Stack<'d, C>) -> Self {
        Self {
            rx: RxRunner { stack },
            control: ControlRunner { stack },
            tx: TxRunner { stack },
        }
    }

    /// Split the runner into separate independent async tasks
    pub fn split(self) -> (RxRunner<'d, C>, ControlRunner<'d, C>, TxRunner<'d, C>) {
        (self.rx, self.control, self.tx)
    }

    /// Run the host.
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
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
            + ControllerCmdSync<LeReadBufferSize>,
    {
        let dummy = DummyHandler;
        self.run_with_handler(&dummy).await
    }

    /// Run the host with a vendor event handler for custom events.
    pub async fn run_with_handler<E: EventHandler>(&mut self, event_handler: &E) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
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
            + ControllerCmdSync<LeReadBufferSize>,
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

impl<'d, C: Controller> RxRunner<'d, C> {
    /// Run the receive loop that polls the controller for events.
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect> + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>,
    {
        let dummy = DummyHandler;
        self.run_with_handler(&dummy).await
    }

    /// Runs the receive loop that pools the controller for events, dispatching
    /// vendor events to the provided closure.
    pub async fn run_with_handler<E: EventHandler>(&mut self, event_handler: &E) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect> + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>,
    {
        const MAX_HCI_PACKET_LEN: usize = 259;
        let host = &self.stack.host;
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
                Ok(ControllerToHostPacket::Acl(acl)) => match host.handle_acl(acl) {
                    Ok(_) => {
                        //let processed = Instant::now();
                        // trace!("[host] ACL process to {} ms", (processed - last).as_millis());
                        #[cfg(feature = "controller-host-flow-control")]
                        if let Err(e) =
                            HostNumberOfCompletedPackets::new(&[ConnHandleCompletedPackets::new(acl.handle(), 1)])
                                .exec(&host.controller)
                                .await
                        {
                            // Only serious error if it's supposed to be connected
                            if host.connections.get_connected_handle(acl.handle()).is_some() {
                                error!("[host] error performing flow control on {:?}", acl.handle());
                                return Err(e.into());
                            }
                        }
                    }
                    Err(e) => {
                        #[cfg(feature = "controller-host-flow-control")]
                        if let Err(e) =
                            HostNumberOfCompletedPackets::new(&[ConnHandleCompletedPackets::new(acl.handle(), 1)])
                                .exec(&host.controller)
                                .await
                        {
                            // Only serious error if it's supposed to be connected
                            if host.connections.get_connected_handle(acl.handle()).is_some() {
                                error!("[host] error performing flow control on {:?}", acl.handle());
                                return Err(e.into());
                            }
                        }

                        warn!(
                            "[host] encountered error processing ACL data for {:?}: {:?}",
                            acl.handle(),
                            e
                        );

                        if let Error::Disconnected = e {
                            warn!("[host] requesting {:?} to be disconnected", acl.handle());
                            let _ = host
                                .command(Disconnect::new(
                                    acl.handle(),
                                    DisconnectReason::RemoteUserTerminatedConn,
                                ))
                                .await;
                            host.connections.log_status(true);
                        }

                        let mut m = host.metrics.borrow_mut();
                        m.rx_errors = m.rx_errors.wrapping_add(1);
                    }
                },
                Ok(ControllerToHostPacket::Event(event)) => {
                    match event {
                        Event::Le(event) => match event {
                            LeEvent::LeConnectionComplete(e) => {
                                if !host.handle_connection(e.status, e.handle, e.peer_addr_kind, e.peer_addr, e.role) {
                                    let _ = host
                                        .command(Disconnect::new(
                                            e.handle,
                                            DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                        ))
                                        .await;
                                    host.connect_command_state.canceled();
                                }
                            }
                            LeEvent::LeEnhancedConnectionComplete(e) => {
                                if !host.handle_connection(e.status, e.handle, e.peer_addr_kind, e.peer_addr, e.role) {
                                    let _ = host
                                        .command(Disconnect::new(
                                            e.handle,
                                            DisconnectReason::RemoteDeviceTerminatedConnLowResources,
                                        ))
                                        .await;
                                    host.connect_command_state.canceled();
                                }
                            }
                            LeEvent::LeScanTimeout(_) => {}
                            LeEvent::LeAdvertisingSetTerminated(set) => {
                                host.advertise_state.terminate(set.adv_handle);
                            }
                            LeEvent::LeExtendedAdvertisingReport(data) => {
                                #[cfg(feature = "scan")]
                                {
                                    event_handler.on_ext_adv_reports(data.reports.iter());
                                }
                            }
                            LeEvent::LeAdvertisingReport(data) => {
                                #[cfg(feature = "scan")]
                                {
                                    event_handler.on_adv_reports(data.reports.iter());
                                }
                            }
                            _ => {
                                warn!("Unknown LE event!");
                            }
                        },
                        Event::DisconnectionComplete(e) => {
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
                            host.reassembly.disconnected(handle);
                            let mut m = host.metrics.borrow_mut();
                            m.disconnect_events = m.disconnect_events.wrapping_add(1);
                        }
                        Event::NumberOfCompletedPackets(c) => {
                            // Explicitly ignoring for now
                            for entry in c.completed_packets.iter() {
                                match (entry.handle(), entry.num_completed_packets()) {
                                    (Ok(handle), Ok(completed)) => {
                                        let _ = host.connections.confirm_sent(handle, completed as usize);
                                    }
                                    (Ok(handle), Err(e)) => {
                                        warn!("[host] error processing completed packets for {:?}: {:?}", handle, e);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Event::Vendor(vendor) => {
                            event_handler.on_vendor(&vendor);
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

impl<'d, C: Controller> ControlRunner<'d, C> {
    /// Run the control loop for the host
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
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
            + ControllerCmdSync<LeReadBufferSize>,
    {
        let host = &self.stack.host;
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
                .enable_disconnection_complete(true),
        )
        .exec(&host.controller)
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
        .exec(&host.controller)
        .await?;

        let ret = LeReadFilterAcceptListSize::new().exec(&host.controller).await?;
        info!("[host] filter accept list size: {}", ret);

        let ret = LeReadBufferSize::new().exec(&host.controller).await?;
        info!(
            "[host] setting txq to {}, fragmenting at {}",
            ret.total_num_le_acl_data_packets as usize, ret.le_acl_data_packet_length as usize
        );
        host.connections
            .set_link_credits(ret.total_num_le_acl_data_packets as usize);

        info!(
            "[host] configuring host buffers ({} packets of size {})",
            config::L2CAP_RX_PACKET_POOL_SIZE,
            host.rx_pool.mtu()
        );
        HostBufferSize::new(
            host.rx_pool.mtu() as u16,
            0,
            config::L2CAP_RX_PACKET_POOL_SIZE as u16,
            0,
        )
        .exec(&host.controller)
        .await?;

        #[cfg(feature = "controller-host-flow-control")]
        {
            info!("[host] enabling flow control");
            SetControllerToHostFlowControl::new(ControllerToHostFlowControl::AclOnSyncOff)
                .exec(&host.controller)
                .await?;
        }

        let _ = host.initialized.init(InitialState {
            acl_max: ret.le_acl_data_packet_length as usize,
        });
        info!("[host] initialized");

        loop {
            match select3(
                poll_fn(|cx| host.connections.poll_disconnecting(Some(cx))),
                poll_fn(|cx| host.channels.poll_disconnecting(Some(cx))),
                select3(
                    poll_fn(|cx| host.connect_command_state.poll_cancelled(cx)),
                    poll_fn(|cx| host.advertise_command_state.poll_cancelled(cx)),
                    poll_fn(|cx| host.scan_command_state.poll_cancelled(cx)),
                ),
            )
            .await
            {
                Either3::First(request) => {
                    trace!("[host] poll disconnecting links");
                    host.command(Disconnect::new(request.handle(), request.reason()))
                        .await?;
                    request.confirm();
                }
                Either3::Second(request) => {
                    trace!("[host] poll disconnecting channels");
                    request.send(host).await?;
                    request.confirm();
                }
                Either3::Third(states) => match states {
                    Either3::First(_) => {
                        trace!("[host] cancel connection create");
                        // trace!("[host] cancelling create connection");
                        if host.command(LeCreateConnCancel::new()).await.is_err() {
                            // Signal to ensure no one is stuck
                            host.connect_command_state.canceled();
                        }
                    }
                    Either3::Second(ext) => {
                        trace!("[host] disabling advertising");
                        if ext {
                            host.command(LeSetExtAdvEnable::new(false, &[])).await?
                        } else {
                            host.command(LeSetAdvEnable::new(false)).await?
                        }
                        host.advertise_command_state.canceled();
                    }
                    Either3::Third(ext) => {
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
                },
            }
        }
    }
}

impl<'d, C: Controller> TxRunner<'d, C> {
    /// Run the transmit loop for the host.
    pub async fn run(&mut self) -> Result<(), BleHostError<C::Error>> {
        let host = &self.stack.host;
        let params = host.initialized.get().await;
        loop {
            let (conn, pdu) = host.connections.outbound().await;
            match host.l2cap(conn, pdu.len as u16, 1).await {
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
    }
}

pub struct L2capSender<'a, 'd, T: Controller> {
    pub(crate) controller: &'a T,
    pub(crate) handle: ConnHandle,
    pub(crate) grant: PacketGrant<'a, 'd>,
    pub(crate) fragment_size: u16,
}

impl<'a, 'd, T: Controller> L2capSender<'a, 'd, T> {
    pub(crate) fn try_send(&mut self, pdu: &[u8]) -> Result<(), BleHostError<T::Error>>
    where
        T: blocking::Controller,
    {
        let mut pbf = AclPacketBoundary::FirstNonFlushable;
        for chunk in pdu.chunks(self.fragment_size as usize) {
            let acl = AclPacket::new(self.handle, pbf, AclBroadcastFlag::PointToPoint, chunk);
            // info!("Sent ACL {:?}", acl);
            match self.controller.try_write_acl_data(&acl) {
                Ok(result) => {
                    self.grant.confirm(1);
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
        let mut pbf = AclPacketBoundary::FirstNonFlushable;
        for chunk in pdu.chunks(self.fragment_size as usize) {
            let acl = AclPacket::new(self.handle, pbf, AclBroadcastFlag::PointToPoint, chunk);
            // info!("Sent ACL {:?}", acl);
            self.controller
                .write_acl_data(&acl)
                .await
                .map_err(BleHostError::Controller)?;
            self.grant.confirm(1);
            pbf = AclPacketBoundary::Continuing;
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
