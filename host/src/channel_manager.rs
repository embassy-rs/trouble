use core::cell::{Ref, RefCell, RefMut};
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::controller::{blocking, Controller};
use bt_hci::param::{ConnHandle, LeConnRole};
use bt_hci::{FromHciBytes, WriteHci};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;

use crate::connection_manager::ConnectionManager;
use crate::cursor::WriteCursor;
use crate::host::{BleHost, OnDrop};
#[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
use crate::l2cap::sar::PacketReassembly;
use crate::l2cap::{L2capChannel, L2capPendingConnection};
use crate::pdu::{Pdu, Sdu};
use crate::prelude::{ConnectionEvent, ConnectionParamsRequest, L2capChannelConfig};
use crate::types::l2cap::{
    CommandRejectRes, ConnParamUpdateReq, ConnParamUpdateRes, DisconnectionReq, DisconnectionRes, L2capHeader,
    L2capSignal, L2capSignalCode, L2capSignalHeader, LeCreditConnReq, LeCreditConnRes, LeCreditConnResultCode,
    LeCreditFlowInd, L2CAP_CID_LE_U_SIGNAL,
};
use crate::{config, BleHostError, Error, PacketPool};

const BASE_ID: u16 = 0x40;

struct State {
    next_req_id: u8,
    accept_waker: WakerRegistration,
    create_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
    /// Bitmask tracking which PSMs (0x0001..=0x00FF) have active listeners.
    registered_psms: [u32; 8],
}

/// Channel manager for L2CAP channels used directly by clients.
pub struct ChannelManager<'d, P: PacketPool> {
    state: RefCell<State>,
    channels: &'d RefCell<[ChannelStorage<P::Packet>]>,
}

pub(crate) struct PacketChannel<P, const QLEN: usize> {
    chan: Channel<NoopRawMutex, Option<Pdu<P>>, QLEN>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelIndex(u8);

impl<P, const QLEN: usize> PacketChannel<P, QLEN> {
    pub(crate) const fn new() -> Self {
        Self { chan: Channel::new() }
    }

    pub fn close(&self) -> Result<(), ()> {
        self.chan.try_send(None).map_err(|_| ())
    }

    pub async fn send(&self, pdu: Pdu<P>) {
        self.chan.send(Some(pdu)).await;
    }

    pub fn try_send(&self, pdu: Pdu<P>) -> Result<(), Error> {
        self.chan.try_send(Some(pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub fn poll_receive(&self, cx: &mut Context<'_>) -> Poll<Option<Pdu<P>>> {
        self.chan.poll_receive(cx)
    }

    pub fn clear(&self) {
        self.chan.clear()
    }
}

impl State {
    /// Register a PSM for listening.
    fn register_psm(&mut self, psm: u16) {
        if (1..=255).contains(&psm) {
            let idx = psm as usize / 32;
            let bit = psm as usize % 32;
            self.registered_psms[idx] |= 1 << bit;
        }
    }

    /// Check if a PSM has an active listener.
    fn is_psm_registered(&self, psm: u16) -> bool {
        if !(1..=255).contains(&psm) {
            // When the allow-reserved-l2ca-psu feature is enable, treat all reserved PSUs as registered
            return cfg!(feature = "allow-reserved-l2cap-psu");
        }
        let idx = psm as usize / 32;
        let bit = psm as usize % 32;
        self.registered_psms[idx] & (1 << bit) != 0
    }

    fn next_request_id(&mut self) -> u8 {
        // 0 is an invalid identifier
        if self.next_req_id == 0 {
            self.next_req_id += 1;
        }
        let next = self.next_req_id;
        self.next_req_id = self.next_req_id.wrapping_add(1);
        next
    }
}

impl<'d, P: PacketPool> ChannelManager<'d, P> {
    pub fn new(channels: &'d RefCell<[ChannelStorage<P::Packet>]>) -> Self {
        Self {
            state: RefCell::new(State {
                next_req_id: 0,
                accept_waker: WakerRegistration::new(),
                create_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
                registered_psms: [0; 8],
            }),
            channels,
        }
    }

    fn channel(&self, index: ChannelIndex) -> Ref<'_, ChannelStorage<P::Packet>> {
        Ref::map(self.channels.borrow(), |x| &x[index.0 as usize])
    }

    fn channel_mut(&self, index: ChannelIndex) -> RefMut<'_, ChannelStorage<P::Packet>> {
        RefMut::map(self.channels.borrow_mut(), |x| &mut x[index.0 as usize])
    }

    pub(crate) fn register_psm(&self, psm: u16) {
        self.state.borrow_mut().register_psm(psm);
    }

    fn next_request_id(&self) -> u8 {
        self.state.borrow_mut().next_request_id()
    }

    pub(crate) fn psm(&self, index: ChannelIndex) -> u16 {
        self.channel(index).psm
    }

    pub(crate) fn mtu(&self, index: ChannelIndex) -> u16 {
        self.channel(index).mtu
    }

    pub(crate) fn mps(&self, index: ChannelIndex) -> u16 {
        self.channel(index).mps
    }

    pub(crate) fn peer_mtu(&self, index: ChannelIndex) -> u16 {
        self.channel(index).peer_mtu
    }

    pub(crate) fn peer_mps(&self, index: ChannelIndex) -> u16 {
        self.channel(index).peer_mps
    }

    pub(crate) fn disconnect(&self, index: ChannelIndex) {
        self.channel_mut(index).disconnect();
        self.state.borrow_mut().disconnect_waker.wake();
    }

    pub(crate) fn disconnect_by_cid(&self, channel: u16) {
        if channel >= BASE_ID && usize::from(channel - BASE_ID) < self.channels.as_ptr().len() {
            let index = ChannelIndex((channel - BASE_ID) as u8);
            self.channel_mut(index).disconnect();
            self.state.borrow_mut().disconnect_waker.wake();
        }
    }

    /// Validate an incoming length against a channel limit (MTU or MPS).
    ///
    /// If the length exceeds the limit, the channel is disconnected per Bluetooth spec
    /// Vol 3, Part A, Section 10.1 and `Err(Error::InvalidValue)` is returned.
    fn check_len(
        &self,
        channel: u16,
        actual: u16,
        limit: impl FnOnce(&ChannelStorage<P::Packet>) -> u16,
        label: &str,
    ) -> Result<(), Error> {
        if channel < BASE_ID || usize::from(channel - BASE_ID) >= self.channels.as_ptr().len() {
            return Err(Error::InvalidChannelId);
        }
        let index = ChannelIndex((channel - BASE_ID) as u8);
        let mut storage = self.channel_mut(index);
        let max = limit(&storage);
        storage
            .check_len(actual, max, label)
            .inspect_err(|_| self.state.borrow_mut().disconnect_waker.wake())
    }

    pub(crate) fn check_sdu_len(&self, channel: u16, sdu_len: u16) -> Result<(), Error> {
        self.check_len(channel, sdu_len, |s| s.mtu, "SDU")
    }

    pub(crate) fn check_pdu_len(&self, channel: u16, pdu_len: u16) -> Result<(), Error> {
        self.check_len(channel, pdu_len, |s| s.mps, "PDU")
    }

    pub(crate) fn disconnected(&self, conn: ConnHandle) -> Result<(), Error> {
        for storage in self.channels.borrow_mut().iter_mut() {
            if Some(conn) == storage.conn {
                let _ = storage.inbound.close();
                #[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
                storage.reassembly.clear();
                #[cfg(feature = "channel-metrics")]
                storage.metrics.reset();
                storage.close();
            }
        }
        let mut state = self.state.borrow_mut();
        state.accept_waker.wake();
        state.create_waker.wake();
        Ok(())
    }

    fn alloc<F: FnOnce(&mut ChannelStorage<P::Packet>)>(
        &self,
        conn: ConnHandle,
        peer_cid: Option<u16>,
        f: F,
    ) -> Result<ChannelIndex, Error> {
        // Check that the peer CID isn't already in use on this connection.
        let mut channels = self.channels.borrow_mut();
        if let Some(peer_cid) = peer_cid {
            let in_use = channels.iter().any(|s| {
                s.conn == Some(conn) && s.peer_cid == peer_cid && !matches!(s.state, ChannelState::Disconnected)
            });
            if in_use {
                return Err(Error::L2capConnectError(LeCreditConnResultCode::ScidAlreadyAllocated));
            }
        }

        let idx = channels
            .iter()
            .position(|s| s.state == ChannelState::Disconnected && s.refcount == 0)
            .ok_or(Error::NoChannelAvailable)?;

        let storage = &mut channels[idx];
        storage.inbound.clear();
        #[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
        storage.reassembly.clear();
        storage.conn = Some(conn);
        storage.cid = BASE_ID + idx as u16;
        storage.peer_cid = peer_cid.unwrap_or(0);
        f(storage);

        Ok(ChannelIndex(idx as u8))
    }

    /// Wait for an incoming L2CAP connection request on the given connection.
    ///
    /// Returns a [`L2capPendingConnection`] that can be inspected and then accepted or rejected.
    /// PSMs must be registered globally via [`StackBuilder::register_l2cap_psm`].
    pub(crate) async fn next_pending(
        &'d self,
        conn: ConnHandle,
        connections: &ConnectionManager<'_, P>,
    ) -> Result<L2capPendingConnection<'d, P>, Error> {
        poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            state.accept_waker.register(cx.waker());
            core::mem::drop(state);

            let mut channels = self.channels.borrow_mut();
            for (idx, chan) in channels.iter_mut().enumerate() {
                match chan.state {
                    ChannelState::PeerConnecting(_) if chan.conn == Some(conn) => {
                        if chan.refcount != 0 {
                            log_status(&channels, true);
                            panic!("unexpected refcount");
                        }
                        chan.inc_ref();
                        let index = ChannelIndex(idx as u8);
                        return Poll::Ready(Ok(L2capPendingConnection::new(index, self, conn)));
                    }
                    _ => {}
                }
            }
            if !connections.is_handle_connected(conn) {
                return Poll::Ready(Err(Error::Disconnected));
            }
            Poll::Pending
        })
        .await
    }

    /// Reject all pending L2CAP connections on the given connection that have not yet been
    /// returned by `next_pending` (refcount == 0). Sends a `NoResources` rejection response
    /// for each, then closes the channel slot.
    pub(crate) fn reject_all_pending(&self, conn: ConnHandle, manager: &ConnectionManager<'_, P>) {
        let mut channels = self.channels.borrow_mut();
        for chan in channels.iter_mut() {
            if chan.conn == Some(conn) && chan.refcount == 0 {
                if let ChannelState::PeerConnecting(identifier) = chan.state {
                    if let Err(e) = Self::try_send_signal(
                        conn,
                        identifier,
                        &LeCreditConnRes::reject(LeCreditConnResultCode::NoResources),
                        manager,
                    ) {
                        warn!(
                            "[l2cap] error rejecting pending channel connect request {:?}: {:?}",
                            identifier, e
                        );
                    }
                    chan.close();
                }
            }
        }
    }

    /// Accept a pending L2CAP connection: negotiate parameters, transition to Connected, send success response.
    pub(crate) async fn accept_pending<T: Controller>(
        &'d self,
        index: ChannelIndex,
        config: &L2capChannelConfig,
        ble: &BleHost<'d, T, P>,
    ) -> Result<L2capChannel<'d, P>, BleHostError<T::Error>> {
        let L2capChannelConfig {
            mtu,
            mps,
            flow_policy,
            initial_credits,
        } = config;

        let mtu = mtu.unwrap_or(P::MTU as u16 - 6);
        let mps = mps.unwrap_or(P::MTU as u16 - 4);
        if mps > P::MTU as u16 - 4 {
            return Err(Error::InsufficientSpace.into());
        }

        let (conn, req_id, mps, mtu, cid, credits) = {
            let mut chan = self.channel_mut(index);
            let req_id = match chan.state {
                ChannelState::PeerConnecting(req_id) => req_id,
                _ => return Err(Error::NotFound.into()),
            };
            chan.mtu = mtu;
            chan.mps = mps;
            chan.flow_control = CreditFlowControl::new(
                *flow_policy,
                initial_credits.unwrap_or(config::L2CAP_RX_QUEUE_SIZE.min(P::capacity()) as u16),
            );
            chan.state = ChannelState::Connected;
            let conn = chan.conn.unwrap();
            (
                conn,
                req_id,
                chan.mps,
                chan.mtu,
                chan.cid,
                chan.flow_control.available(),
            )
        };

        let mut tx = [0; 18];
        ble.l2cap_signal(
            conn,
            req_id,
            &LeCreditConnRes {
                mps,
                dcid: cid,
                mtu,
                credits,
                result: LeCreditConnResultCode::Success,
            },
            &mut tx[..],
        )
        .await?;
        Ok(L2capChannel::new(index, self))
    }

    /// Reject a pending L2CAP connection: send rejection response and free the channel slot.
    pub(crate) async fn reject_pending<T: Controller>(
        &self,
        index: ChannelIndex,
        result: LeCreditConnResultCode,
        ble: &BleHost<'_, T, P>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, req_id) = {
            let mut chan = self.channel_mut(index);
            let req_id = match chan.state {
                ChannelState::PeerConnecting(req_id) => req_id,
                _ => return Err(Error::NotFound.into()),
            };
            let conn = chan.conn.unwrap();
            chan.refcount = unwrap!(chan.refcount.checked_sub(1), "bug: dropping a channel with refcount 0");
            chan.close();
            (conn, req_id)
        };

        let mut tx = [0; 18];
        ble.l2cap_signal(conn, req_id, &LeCreditConnRes::reject(result), &mut tx[..])
            .await?;
        Ok(())
    }

    /// Drop a pending connection without sending a response (peer will time out).
    pub(crate) fn drop_pending(&self, index: ChannelIndex) {
        let mut chan = self.channel_mut(index);
        if matches!(chan.state, ChannelState::PeerConnecting(_)) {
            chan.refcount = unwrap!(chan.refcount.checked_sub(1), "bug: dropping a channel with refcount 0");
            chan.close();
        }
    }

    pub(crate) async fn create<T: Controller>(
        &'d self,
        conn: ConnHandle,
        psm: u16,
        config: &L2capChannelConfig,
        ble: &BleHost<'_, T, P>,
    ) -> Result<L2capChannel<'d, P>, BleHostError<T::Error>> {
        let L2capChannelConfig {
            mtu,
            mps,
            flow_policy,
            initial_credits,
        } = config;

        let req_id = self.next_request_id();
        let mut credits = 0;
        let mut cid: u16 = 0;

        let mtu = mtu.unwrap_or(P::MTU as u16 - 6);
        let mps = mps.unwrap_or(P::MTU as u16 - 4);
        if mps > P::MTU as u16 - 4 {
            return Err(Error::InsufficientSpace.into());
        }

        // Allocate space for our new channel.
        let idx = self.alloc(conn, None, |storage| {
            cid = storage.cid;
            credits = initial_credits.unwrap_or(config::L2CAP_RX_QUEUE_SIZE.min(P::capacity()) as u16);
            storage.psm = psm;
            storage.mtu = mtu;
            storage.mps = mps;
            storage.flow_control = CreditFlowControl::new(*flow_policy, credits);
            storage.state = ChannelState::Connecting(req_id);
        })?;

        let mut tx = [0; 18];
        // Send the initial connect request.
        let command = LeCreditConnReq {
            psm,
            mps,
            scid: cid,
            mtu,
            credits,
        };
        ble.l2cap_signal(conn, req_id, &command, &mut tx[..]).await?;

        // Clean up the channel slot if the future is dropped before completion.
        let ondrop = OnDrop::new(|| self.channel_mut(idx).close());

        // Wait until a response is accepted.
        let result = poll_fn(|cx| self.poll_created(conn, idx, ble, Some(cx))).await;
        ondrop.defuse();
        result
    }

    fn poll_created<T: Controller>(
        &'d self,
        conn: ConnHandle,
        idx: ChannelIndex,
        ble: &BleHost<'_, T, P>,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Result<L2capChannel<'d, P>, BleHostError<T::Error>>> {
        if let Some(cx) = cx {
            self.state.borrow_mut().create_waker.register(cx.waker());
        }
        let mut storage = self.channel_mut(idx);
        // Check if we've been disconnected while waiting
        if !ble.connections.is_handle_connected(conn) {
            return Poll::Ready(Err(Error::Disconnected.into()));
        }

        //// Make sure something hasn't gone wrong
        assert_eq!(Some(conn), storage.conn);

        match storage.state {
            ChannelState::ConnectFailed(result) => {
                storage.state = ChannelState::Disconnected;
                return Poll::Ready(Err(Error::L2capConnectError(result).into()));
            }
            ChannelState::Disconnected | ChannelState::Disconnecting | ChannelState::PeerDisconnecting(_) => {
                return Poll::Ready(Err(Error::Disconnected.into()));
            }
            ChannelState::Connected => {
                if storage.refcount != 0 {
                    core::mem::drop(storage);
                    self.log_status(true);
                    panic!("unexpected refcount");
                }
                assert_eq!(storage.refcount, 0);
                storage.inc_ref();
                return Poll::Ready(Ok(L2capChannel::new(idx, self)));
            }
            _ => {}
        }
        Poll::Pending
    }

    pub(crate) fn received(&self, channel: u16, credits: u16) -> Result<(), Error> {
        if channel < BASE_ID || usize::from(channel - BASE_ID) >= self.channels.as_ptr().len() {
            return Err(Error::InvalidChannelId);
        }

        let index = ChannelIndex((channel - BASE_ID) as u8);
        let mut storage = self.channel_mut(index);
        match storage.state {
            ChannelState::Connected if channel == storage.cid => {
                if storage.flow_control.available() == 0 {
                    #[cfg(feature = "channel-metrics")]
                    storage.metrics.blocked_receive();
                    // NOTE: This will trigger closing of the link, which might be a bit
                    // too strict. But it should be controllable via the credits given,
                    // which the remote should respect.
                    debug!("[l2cap][cid = {}] no credits available", channel);
                    return Err(Error::OutOfMemory);
                }
                storage.flow_control.confirm_received(1);
                #[cfg(feature = "channel-metrics")]
                storage.metrics.received(1);
                return Ok(());
            }
            _ => {}
        }
        Err(Error::NotFound)
    }

    pub(crate) fn dispatch(&self, channel: u16, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        if channel < BASE_ID || usize::from(channel - BASE_ID) >= self.channels.as_ptr().len() {
            return Err(Error::InvalidChannelId);
        }

        let index = ChannelIndex((channel - BASE_ID) as u8);
        #[allow(unused_mut)]
        let mut storage = self.channel_mut(index);

        let mut sdu = None;
        match storage.state {
            ChannelState::Connected if channel == storage.cid => {
                // Reassembly and accounting is already done
                #[cfg(feature = "l2cap-sdu-reassembly-optimization")]
                sdu.replace(pdu);

                // Reassembly is done in the channel
                #[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
                {
                    if storage.flow_control.available() == 0 {
                        #[cfg(feature = "channel-metrics")]
                        storage.metrics.blocked_receive();
                        // NOTE: This will trigger closing of the link, which might be a bit
                        // too strict. But it should be controllable via the credits given,
                        // which the remote should respect.
                        debug!("[l2cap][cid = {}] no credits available", channel);
                        return Err(Error::OutOfMemory);
                    }

                    storage.flow_control.confirm_received(1);

                    #[cfg(feature = "channel-metrics")]
                    storage.metrics.received(1);
                    if !storage.reassembly.in_progress() {
                        let (first, _) = pdu.as_ref().split_at(2);
                        let sdu_len: u16 = u16::from_le_bytes([first[0], first[1]]);

                        storage
                            .check_sdu_len(sdu_len)
                            .inspect_err(|_| self.state.borrow_mut().disconnect_waker.wake())?;

                        let len = pdu.len() - 2;

                        let mut packet = pdu.into_inner();
                        packet.as_mut().rotate_left(2);

                        // A complete fragment
                        if sdu_len as usize == len {
                            sdu.replace(Pdu::new(packet, sdu_len as usize));
                        } else {
                            // Need another fragment
                            storage.reassembly.init_with_written(channel, sdu_len, packet, len)?;
                        }
                    } else {
                        match storage.reassembly.update(pdu.as_ref()) {
                            Ok(Some((_, pdu))) => {
                                sdu.replace(pdu);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                storage.disconnect();
                                self.state.borrow_mut().disconnect_waker.wake();
                                return Err(e);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        if let Some(sdu) = sdu {
            storage.inbound.try_send(sdu)?;
        }

        Ok(())
    }

    /// Handle incoming L2CAP signal
    pub(crate) fn signal(
        &self,
        conn: ConnHandle,
        data: &[u8],
        manager: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        // Validate that all signal headers fit within the PDU before processing.
        {
            let mut remaining = data;
            while !remaining.is_empty() {
                let (header, rest) = L2capSignalHeader::from_hci_bytes(remaining)?;
                if header.length as usize > rest.len() {
                    Self::try_send_signal(conn, header.identifier, &CommandRejectRes { reason: 0 }, manager)?;
                    return Err(Error::InvalidValue);
                }
                remaining = &rest[header.length as usize..];
            }
        }

        let mut data = data;
        while !data.is_empty() {
            let (header, remaining) = L2capSignalHeader::from_hci_bytes(data)?;
            let (signal_data, next) = remaining.split_at(header.length as usize);
            let result = (|| match header.code {
                L2capSignalCode::LE_CREDIT_CONN_REQ => {
                    let req = LeCreditConnReq::from_hci_bytes_complete(signal_data)?;
                    self.handle_connect_request(conn, header.identifier, &req, manager)
                }
                L2capSignalCode::LE_CREDIT_CONN_RES => {
                    let res = LeCreditConnRes::from_hci_bytes_complete(signal_data)?;
                    self.handle_connect_response(conn, header.identifier, &res)
                }
                L2capSignalCode::LE_CREDIT_FLOW_IND => {
                    let req = LeCreditFlowInd::from_hci_bytes_complete(signal_data)?;
                    //trace!("[l2cap] credit flow: {:?}", req);
                    self.handle_credit_flow(conn, &req)
                }
                L2capSignalCode::COMMAND_REJECT_RES => {
                    let (_reject, _) = CommandRejectRes::from_hci_bytes(signal_data)?;
                    Ok(())
                }
                L2capSignalCode::DISCONNECTION_REQ => {
                    let req = DisconnectionReq::from_hci_bytes_complete(signal_data)?;
                    debug!("[l2cap][conn = {:?}, cid = {}] disconnect request", conn, req.dcid);
                    self.handle_disconnect_request(conn, header.identifier, req.dcid, manager)
                }
                L2capSignalCode::DISCONNECTION_RES => {
                    let res = DisconnectionRes::from_hci_bytes_complete(signal_data)?;
                    debug!("[l2cap][conn = {:?}, cid = {}] disconnect response", conn, res.scid);
                    self.handle_disconnect_response(res.scid)
                }
                L2capSignalCode::CONN_PARAM_UPDATE_REQ => {
                    if manager.role_by_handle(conn) != Some(LeConnRole::Central) {
                        warn!(
                            "[l2cap][conn = {:?}] rejecting connection param update request: not Central",
                            conn
                        );
                        Self::try_send_signal(conn, header.identifier, &CommandRejectRes { reason: 0 }, manager)?;
                        return Ok(());
                    }

                    let req = ConnParamUpdateReq::from_hci_bytes_complete(signal_data)?;
                    debug!("[l2cap][conn = {:?}] connection param update request: {:?}", conn, req);
                    let interval_min: bt_hci::param::Duration<1_250> =
                        bt_hci::param::Duration::from_u16(req.interval_min);
                    let interval_max: bt_hci::param::Duration<1_250> =
                        bt_hci::param::Duration::from_u16(req.interval_max);
                    let timeout: bt_hci::param::Duration<10_000> = bt_hci::param::Duration::from_u16(req.timeout);

                    use embassy_time::Duration;
                    let params = crate::prelude::RequestedConnParams {
                        min_connection_interval: Duration::from_micros(interval_min.as_micros()),
                        max_connection_interval: Duration::from_micros(interval_max.as_micros()),
                        max_latency: req.latency,
                        supervision_timeout: Duration::from_micros(timeout.as_micros()),
                        ..Default::default()
                    };

                    if !params.is_valid() {
                        warn!(
                            "[l2cap][conn = {:?}] rejecting connection param update request with invalid parameters",
                            conn
                        );
                        Self::try_send_signal(conn, header.identifier, &ConnParamUpdateRes { result: 1 }, manager)?;
                    } else {
                        let req = ConnectionParamsRequest::new(
                            params,
                            conn,
                            #[cfg(feature = "connection-params-update")]
                            true,
                        );

                        let _ = manager.post_handle_event(conn, ConnectionEvent::RequestConnectionParams(req));
                    }
                    Ok(())
                }
                L2capSignalCode::CONN_PARAM_UPDATE_RES => {
                    let res = ConnParamUpdateRes::from_hci_bytes_complete(signal_data)?;
                    debug!(
                        "[l2cap][conn = {:?}] connection param update response: {}",
                        conn, res.result,
                    );
                    Ok(())
                }
                _ => {
                    warn!("[l2cap][conn = {:?}] unsupported signal: {:?}", conn, header.code);
                    Self::try_send_signal(conn, header.identifier, &CommandRejectRes { reason: 0 }, manager)?;
                    Err(Error::NotSupported)
                }
            })();
            if let Err(e) = result {
                warn!("[l2cap][conn = {:?}] error processing signal: {:?}", conn, e);
                if matches!(e, Error::HciDecode(_)) {
                    Self::try_send_signal(conn, header.identifier, &CommandRejectRes { reason: 0 }, manager)?;
                }
            }
            data = next;
        }
        Ok(())
    }

    fn handle_connect_request(
        &self,
        conn: ConnHandle,
        identifier: u8,
        req: &LeCreditConnReq,
        manager: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        let result = {
            let mut state = self.state.borrow_mut();
            if !state.is_psm_registered(req.psm) {
                Err(LeCreditConnResultCode::SpsmNotSupported)
            } else if !manager.is_l2cap_listening(conn) {
                Err(LeCreditConnResultCode::NoResources)
            } else {
                match self.alloc(conn, Some(req.scid), |storage| {
                    storage.conn = Some(conn);
                    storage.psm = req.psm;
                    storage.peer_credits = req.credits;
                    storage.peer_mps = req.mps;
                    storage.peer_mtu = req.mtu;
                    storage.state = ChannelState::PeerConnecting(identifier);
                }) {
                    Ok(_) => {
                        state.accept_waker.wake();
                        Ok(())
                    }
                    Err(Error::L2capConnectError(result)) => Err(result),
                    Err(Error::NoChannelAvailable) => Err(LeCreditConnResultCode::NoResources),
                    Err(e) => return Err(e),
                }
            }
        };

        match result {
            Ok(()) => Ok(()),
            Err(result) => {
                debug!(
                    "[l2cap][conn = {:?}] rejecting connection for PSM 0x{:04x}: {:?}",
                    conn, req.psm, result
                );
                Self::try_send_signal(conn, identifier, &LeCreditConnRes::reject(result), manager)
            }
        }
    }

    fn handle_connect_response(&self, conn: ConnHandle, identifier: u8, res: &LeCreditConnRes) -> Result<(), Error> {
        let mut channels = self.channels.borrow_mut();

        // Find the channel matching this response identifier
        let matched = channels.iter_mut().find(|storage| {
            matches!(storage.state, ChannelState::Connecting(req_id) if identifier == req_id && Some(conn) == storage.conn)
        });

        let Some(storage) = matched else {
            // No channel matched this identifier. Clean up any Connecting channels
            // on this connection — the peer has sent a response (with a wrong identifier),
            // so the connection attempt has effectively failed.
            for storage in channels.iter_mut() {
                if let ChannelState::Connecting(_) = storage.state {
                    if Some(conn) == storage.conn {
                        debug!(
                            "[l2cap][handle_connect_response][link = {}] cleaning up channel with mismatched identifier {}",
                            conn.raw(),
                            identifier
                        );
                        storage.state = ChannelState::Disconnected;
                    }
                }
            }
            self.state.borrow_mut().create_waker.wake();
            return Err(Error::NotFound);
        };

        match res.result {
            LeCreditConnResultCode::Success => {
                storage.peer_cid = res.dcid;
                storage.peer_credits = res.credits;
                storage.peer_mps = res.mps;
                storage.peer_mtu = res.mtu;
                storage.state = ChannelState::Connected;
                self.state.borrow_mut().create_waker.wake();
                Ok(())
            }
            other => {
                warn!("Channel open request failed: {:?}", other);
                storage.state = ChannelState::ConnectFailed(other);
                self.state.borrow_mut().create_waker.wake();
                Err(Error::L2capConnectError(other))
            }
        }
    }

    fn handle_credit_flow(&self, conn: ConnHandle, req: &LeCreditFlowInd) -> Result<(), Error> {
        for storage in self.channels.borrow_mut().iter_mut() {
            match storage.state {
                ChannelState::Connected if storage.peer_cid == req.cid && Some(conn) == storage.conn => {
                    trace!(
                        "[l2cap][handle_credit_flow][cid = {}] {} += {} credits",
                        req.cid,
                        storage.peer_credits,
                        req.credits
                    );
                    match storage.peer_credits.checked_add(req.credits) {
                        Some(credits) => {
                            storage.peer_credits = credits;
                            storage.credit_waker.wake();
                        }
                        None => {
                            warn!(
                                "[l2cap][cid = {}] credit overflow ({} + {}), disconnecting channel",
                                req.cid, storage.peer_credits, req.credits
                            );
                            storage.disconnect();
                            self.state.borrow_mut().disconnect_waker.wake();
                            return Err(Error::InvalidValue);
                        }
                    }
                    return Ok(());
                }
                _ => {}
            }
        }
        //    trace!("[l2cap][handle_credit_flow] peer channel {} not found", req.cid);
        Err(Error::NotFound)
    }

    fn handle_disconnect_request(
        &self,
        conn: ConnHandle,
        identifier: u8,
        cid: u16,
        manager: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        for storage in self.channels.borrow_mut().iter_mut() {
            if cid == storage.cid {
                storage.state = ChannelState::PeerDisconnecting(identifier);
                let _ = storage.inbound.close();
                self.state.borrow_mut().disconnect_waker.wake();
                return Ok(());
            }
        }
        warn!(
            "[l2cap][conn = {:?}, cid = {}] disconnect request for unknown channel",
            conn, cid
        );
        Self::try_send_signal(conn, identifier, &CommandRejectRes { reason: 2 }, manager)
    }

    fn handle_disconnect_response(&self, cid: u16) -> Result<(), Error> {
        for storage in self.channels.borrow_mut().iter_mut() {
            if storage.state == ChannelState::Disconnecting && cid == storage.cid {
                storage.close();
                break;
            }
        }
        Ok(())
    }

    /// Receive SDU on a given channel.
    ///
    /// The MTU of the channel must be <= the MTU of the packet.
    pub(crate) async fn receive_sdu<T: Controller>(
        &self,
        chan: ChannelIndex,
        ble: &BleHost<'d, T, P>,
    ) -> Result<Sdu<P::Packet>, BleHostError<T::Error>> {
        let pdu = self.receive_pdu(&ble.connections, chan).await?;
        let mut p_buf: [u8; 16] = [0; 16];
        self.flow_control(chan, ble, &mut p_buf).await?;
        Ok(Sdu::from_pdu(pdu))
    }

    /// Receive data on a given channel and copy it into the buffer.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub(crate) async fn receive<T: Controller>(
        &self,
        chan: ChannelIndex,
        buf: &mut [u8],
        ble: &BleHost<'d, T, P>,
    ) -> Result<usize, BleHostError<T::Error>> {
        let pdu = self.receive_pdu(&ble.connections, chan).await?;

        let to_copy = pdu.len().min(buf.len());
        // info!("[host] received a pdu of len {}, copying {} bytes", pdu.len(), to_copy);
        buf[..to_copy].copy_from_slice(&pdu.as_ref()[..to_copy]);

        let mut p_buf: [u8; 16] = [0; 16];
        self.flow_control(chan, ble, &mut p_buf).await?;
        Ok(to_copy)
    }

    async fn receive_pdu<'m>(
        &self,
        ble: &'m ConnectionManager<'d, P>,
        chan: ChannelIndex,
    ) -> Result<Pdu<P::Packet>, Error> {
        poll_fn(|cx| {
            let chan = self.channel(chan);
            if chan.state == ChannelState::Connected {
                let conn = chan.conn.unwrap();
                match chan.inbound.poll_receive(cx) {
                    Poll::Ready(Some(pdu)) => Poll::Ready(Ok(pdu)),
                    Poll::Ready(None) => Poll::Ready(Err(Error::ChannelClosed)),
                    Poll::Pending => Poll::Pending,
                }
            } else {
                Poll::Ready(Err(Error::ChannelClosed))
            }
        })
        .await
    }

    /// Send the provided buffer over a given l2cap channel.
    ///
    /// The buffer will be segmented to the maximum payload size agreed in the opening handshake.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    pub(crate) async fn send<T: Controller>(
        &self,
        index: ChannelIndex,
        buf: &[u8],
        p_buf: &mut [u8],
        ble: &BleHost<'d, T, P>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, mps, mtu, peer_cid) = self.connected_channel_params(index)?;
        if buf.len() > mtu as usize {
            return Err(Error::InsufficientSpace.into());
        }
        // The number of packets we'll need to send for this payload
        let len = (buf.len() as u16).saturating_add(2);
        let n_packets = len.div_ceil(mps);
        // info!("[host] sending {} LE K frames, len {}, mps {}", n_packets, len, mps);

        let mut grant = poll_fn(|cx| self.poll_request_to_send(index, n_packets, Some(cx))).await?;

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(mps as usize - 2));

        let len = encode(first, &mut p_buf[..], peer_cid, Some(buf.len() as u16))?;
        ble.l2cap(conn, (len - 4) as u16, 1).await?.send(&p_buf[..len]).await?;
        grant.confirm(1);

        let chunks = remaining.chunks(mps as usize);

        for chunk in chunks {
            let len = encode(chunk, &mut p_buf[..], peer_cid, None)?;
            ble.l2cap(conn, (len - 4) as u16, 1).await?.send(&p_buf[..len]).await?;
            grant.confirm(1);
        }
        Ok(())
    }

    /// Send the provided buffer over a given l2cap channel.
    ///
    /// The buffer must be equal to or smaller than the MTU agreed for the channel.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    pub(crate) fn try_send<T: Controller + blocking::Controller>(
        &self,
        index: ChannelIndex,
        buf: &[u8],
        p_buf: &mut [u8],
        ble: &BleHost<'d, T, P>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, mps, mtu, peer_cid) = self.connected_channel_params(index)?;
        if buf.len() > mtu as usize {
            return Err(Error::InsufficientSpace.into());
        }

        // The number of packets we'll need to send for this payload
        let len = (buf.len() as u16).saturating_add(2);
        let n_packets = len.div_ceil(mps);

        let mut grant = match self.poll_request_to_send(index, n_packets, None) {
            Poll::Ready(res) => res?,
            Poll::Pending => {
                return Err(Error::Busy.into());
            }
        };

        // Pre-request
        let mut sender = ble.try_l2cap(conn, len, n_packets)?;

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(mps as usize - 2));

        let len = encode(first, &mut p_buf[..], peer_cid, Some(buf.len() as u16))?;
        sender.try_send(&p_buf[..len])?;
        grant.confirm(1);

        let chunks = remaining.chunks(mps as usize);
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.enumerate() {
            let len = encode(chunk, &mut p_buf[..], peer_cid, None)?;
            sender.try_send(&p_buf[..len])?;
            grant.confirm(1);
        }
        Ok(())
    }

    fn try_send_signal<D: L2capSignal>(
        conn: ConnHandle,
        identifier: u8,
        signal: &D,
        manager: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        let signal_header = L2capSignalHeader {
            code: D::code(),
            identifier,
            length: signal.size() as u16,
        };
        let l2cap = L2capHeader {
            channel: L2CAP_CID_LE_U_SIGNAL,
            length: signal_header.size() as u16 + signal_header.length,
        };
        let mut buf = P::allocate().ok_or(Error::OutOfMemory)?;
        let mut w = WriteCursor::new(buf.as_mut());
        w.write_hci(&l2cap)?;
        w.write_hci(&signal_header)?;
        w.write_hci(signal)?;
        let len = w.len();
        manager.try_outbound(conn, Pdu::new(buf, len))
    }

    pub(crate) async fn send_conn_param_update_req<T: Controller>(
        &self,
        handle: ConnHandle,
        host: &BleHost<'d, T, P>,
        param: &ConnParamUpdateReq,
    ) -> Result<(), BleHostError<T::Error>> {
        let identifier = self.next_request_id();
        let mut tx = [0; 16];
        host.l2cap_signal(handle, identifier, param, &mut tx[..]).await
    }

    pub(crate) async fn send_conn_param_update_res<T: Controller>(
        &self,
        handle: ConnHandle,
        host: &BleHost<'d, T, P>,
        param: &ConnParamUpdateRes,
    ) -> Result<(), BleHostError<T::Error>> {
        let identifier = self.next_request_id();
        let mut tx = [0; 16];
        host.l2cap_signal(handle, identifier, param, &mut tx[..]).await
    }

    fn connected_channel_params(&self, index: ChannelIndex) -> Result<(ConnHandle, u16, u16, u16), Error> {
        let chan = self.channel(index);
        if chan.state == ChannelState::Connected {
            return Ok((chan.conn.unwrap(), chan.peer_mps, chan.peer_mtu, chan.peer_cid));
        }
        //trace!("[l2cap][connected_channel_params] channel {} closed", index);
        Err(Error::ChannelClosed)
    }

    // Check the current state of flow control and send flow indications if
    // our policy says so.
    async fn flow_control<T: Controller>(
        &self,
        index: ChannelIndex,
        ble: &BleHost<'d, T, P>,
        p_buf: &mut [u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, cid, credits) = {
            let mut chan = self.channel_mut(index);
            if chan.state == ChannelState::Connected {
                (chan.conn.unwrap(), chan.cid, chan.flow_control.process())
            } else {
                debug!("[l2cap][flow_control_process] channel {:?} not found", index);
                return Err(Error::NotFound.into());
            }
        };

        if let Some(credits) = credits {
            let identifier = self.next_request_id();
            let signal = LeCreditFlowInd { cid, credits };
            // info!("[host] sending credit flow {} credits on cid {}", credits, cid);

            // Reuse packet buffer for signalling data to save the extra TX buffer
            ble.l2cap_signal(conn, identifier, &signal, p_buf).await?;

            let mut chan = self.channel_mut(index);
            if chan.state == ChannelState::Connected {
                chan.flow_control.confirm_granted(credits);
                return Ok(());
            } else {
                debug!("[l2cap][flow_control_grant] channel {:?} not found", index);
                return Err(Error::NotFound.into());
            }
        }
        Ok(())
    }

    fn poll_request_to_send(
        &self,
        index: ChannelIndex,
        credits: u16,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Result<CreditGrant<'_, P::Packet>, Error>> {
        let mut chan = self.channel_mut(index);
        if chan.state == ChannelState::Connected {
            if let Some(cx) = cx {
                chan.credit_waker.register(cx.waker());
            }
            if credits <= chan.peer_credits {
                chan.peer_credits -= credits;
                #[cfg(feature = "channel-metrics")]
                chan.metrics.sent(credits as usize);
                return Poll::Ready(Ok(CreditGrant::new(self.channels, index, credits)));
            } else {
                #[cfg(feature = "channel-metrics")]
                chan.metrics.blocked_send();
                return Poll::Pending;
            }
        }
        debug!("[l2cap][pool_request_to_send] channel index {:?} not found", index);
        Poll::Ready(Err(Error::NotFound))
    }

    pub(crate) fn poll_disconnecting<'m>(&'m self, cx: Option<&mut Context<'_>>) -> Poll<DisconnectRequest<'m, P>> {
        let mut state = self.state.borrow_mut();
        if let Some(cx) = cx {
            state.disconnect_waker.register(cx.waker());
        }
        for (idx, storage) in self.channels.borrow().iter().enumerate() {
            match storage.state {
                ChannelState::Disconnecting | ChannelState::PeerDisconnecting(_) => {
                    return Poll::Ready(DisconnectRequest {
                        index: ChannelIndex(idx as u8),
                        handle: storage.conn.unwrap(),
                        state: &self.state,
                        channels: self.channels,
                    });
                }
                _ => {}
            }
        }
        Poll::Pending
    }

    pub(crate) fn inc_ref(&self, index: ChannelIndex) {
        self.channel_mut(index).inc_ref();
    }

    pub(crate) fn dec_ref(&self, index: ChannelIndex) {
        let mut chan = self.channel_mut(index);
        chan.refcount = unwrap!(
            chan.refcount.checked_sub(1),
            "bug: dropping a channel (i = {}) with refcount 0",
            index.0
        );
        if chan.refcount == 0 {
            chan.disconnect();
            self.state.borrow_mut().disconnect_waker.wake();
        }
    }

    pub(crate) fn log_status(&self, verbose: bool) {
        log_status(&self.channels.borrow(), verbose);
    }

    #[cfg(feature = "defmt")]
    pub(crate) fn print(&self, index: ChannelIndex, f: defmt::Formatter) {
        use defmt::Format;
        self.channel(index).format(f);
    }

    #[cfg(feature = "channel-metrics")]
    pub(crate) fn metrics<F: FnOnce(&Metrics) -> R, R>(&self, index: ChannelIndex, f: F) -> R {
        f(&self.channel(index).metrics)
    }
}

fn log_status<P>(channels: &[ChannelStorage<P>], verbose: bool) {
    for (idx, storage) in channels.iter().enumerate() {
        if verbose || storage.state != ChannelState::Disconnected {
            debug!("[l2cap][idx = {}] {:?}", idx, storage);
        }
    }
}

pub struct DisconnectRequest<'a, P: PacketPool> {
    index: ChannelIndex,
    handle: ConnHandle,
    state: &'a RefCell<State>,
    channels: &'a RefCell<[ChannelStorage<P::Packet>]>,
}

impl<'a, P: PacketPool> DisconnectRequest<'a, P> {
    pub fn handle(&self) -> ConnHandle {
        self.handle
    }

    pub async fn send<T: Controller>(&self, host: &BleHost<'_, T, P>) -> Result<(), BleHostError<T::Error>> {
        let (state, conn, our_cid, peer_cid) = {
            let state = self.channels.borrow();
            let chan = &state[self.index.0 as usize];
            (chan.state.clone(), chan.conn, chan.cid, chan.peer_cid)
        };

        let mut tx = [0; 18];
        match state {
            ChannelState::PeerDisconnecting(identifier) => {
                assert_eq!(Some(self.handle), conn);
                host.l2cap_signal(
                    self.handle,
                    identifier,
                    &DisconnectionRes {
                        dcid: our_cid,
                        scid: peer_cid,
                    },
                    &mut tx[..],
                )
                .await?;
            }
            ChannelState::Disconnecting => {
                let identifier = self.state.borrow_mut().next_request_id();
                assert_eq!(Some(self.handle), conn);
                host.l2cap_signal(
                    self.handle,
                    identifier,
                    &DisconnectionReq {
                        dcid: peer_cid,
                        scid: our_cid,
                    },
                    &mut tx[..],
                )
                .await?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn confirm(self) {
        self.channels.borrow_mut()[self.index.0 as usize].state = ChannelState::Disconnected;
    }
}

fn encode(data: &[u8], packet: &mut [u8], peer_cid: u16, header: Option<u16>) -> Result<usize, Error> {
    let mut w = WriteCursor::new(packet);
    if header.is_some() {
        w.write(2 + data.len() as u16)?;
    } else {
        w.write(data.len() as u16)?;
    }
    w.write(peer_cid)?;

    if let Some(len) = header {
        w.write(len)?;
    }

    w.append(data)?;
    Ok(w.len())
}

pub struct ChannelStorage<P> {
    state: ChannelState,
    conn: Option<ConnHandle>,
    cid: u16,
    psm: u16,
    mps: u16,
    mtu: u16,
    flow_control: CreditFlowControl,
    refcount: u8,

    peer_cid: u16,
    peer_mps: u16,
    peer_mtu: u16,
    peer_credits: u16,
    credit_waker: WakerRegistration,

    inbound: PacketChannel<P, { config::L2CAP_RX_QUEUE_SIZE }>,
    #[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
    reassembly: PacketReassembly<P>,

    #[cfg(feature = "channel-metrics")]
    metrics: Metrics,
}

/// Metrics for this channel
#[cfg(feature = "channel-metrics")]
#[derive(Debug)]
pub struct Metrics {
    /// Number of sent l2cap packets.
    pub num_sent: usize,
    /// Number of received l2cap packets.
    pub num_received: usize,
    /// Number of l2cap packets blocked from sending.
    pub blocked_send: usize,
    /// Number of l2cap packets blocked from receiving.
    pub blocked_receive: usize,
}

#[cfg(feature = "channel-metrics")]
impl Metrics {
    pub(crate) const fn new() -> Self {
        Self {
            num_sent: 0,
            num_received: 0,
            blocked_send: 0,
            blocked_receive: 0,
        }
    }
    pub(crate) fn sent(&mut self, num: usize) {
        self.num_sent = self.num_sent.wrapping_add(num);
    }

    pub(crate) fn received(&mut self, num: usize) {
        self.num_received = self.num_received.wrapping_add(num);
    }

    pub(crate) fn blocked_send(&mut self) {
        self.blocked_send = self.blocked_send.wrapping_add(1);
    }

    pub(crate) fn blocked_receive(&mut self) {
        self.blocked_receive = self.blocked_receive.wrapping_add(1);
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }
}

#[cfg(feature = "channel-metrics")]
#[cfg(feature = "defmt")]
impl defmt::Format for Metrics {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "sent = {}, recvd = {}, blocked send = {}, blocked receive = {}",
            self.num_sent,
            self.num_received,
            self.blocked_send,
            self.blocked_receive,
        );
    }
}

impl<P> core::fmt::Debug for ChannelStorage<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("ChannelStorage");
        let d = d
            .field("state", &self.state)
            .field("conn", &self.conn)
            .field("cid", &self.cid)
            .field("peer_cid", &self.peer_cid)
            .field("mps", &self.mps)
            .field("mtu", &self.mtu)
            .field("peer_mps", &self.peer_mps)
            .field("peer_mtu", &self.peer_mtu)
            .field("peer_credits", &self.peer_credits)
            .field("available", &self.flow_control.available())
            .field("refcount", &self.refcount);
        #[cfg(feature = "channel-metrics")]
        let d = d.field("metrics", &self.metrics);
        d.finish()
    }
}

#[cfg(feature = "defmt")]
impl<P> defmt::Format for ChannelStorage<P> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "state = {}, c = {}, cid = {}, peer = {}, mps = {}, mtu = {}, peer_mps = {}, peer_mtu = {}, cred out {}, cred in = {}, ref = {}",
            self.state,
            self.conn,
            self.cid,
            self.peer_cid,
            self.mps,
            self.mtu,
            self.peer_mps,
            self.peer_mtu,
            self.peer_credits,
            self.flow_control.available(),
            self.refcount,
        );
        #[cfg(feature = "channel-metrics")]
        defmt::write!(f, ", {}", self.metrics);
    }
}

impl<P> ChannelStorage<P> {
    pub(crate) const fn new() -> ChannelStorage<P> {
        ChannelStorage {
            state: ChannelState::Disconnected,
            conn: None,
            cid: 0,
            mps: 0,
            mtu: 0,
            psm: 0,

            flow_control: CreditFlowControl::new(CreditFlowPolicy::Every(1), 0),
            peer_cid: 0,
            peer_mps: 0,
            peer_mtu: 0,
            peer_credits: 0,
            credit_waker: WakerRegistration::new(),
            refcount: 0,
            inbound: PacketChannel::new(),
            #[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
            reassembly: PacketReassembly::new(),
            #[cfg(feature = "channel-metrics")]
            metrics: Metrics::new(),
        }
    }

    fn inc_ref(&mut self) {
        self.refcount = unwrap!(self.refcount.checked_add(1), "Too many references to the same channel");
    }

    /// Check a received length against a limit. If exceeded, log a warning and disconnect.
    /// Returns `Err(Error::InvalidValue)` on violation.
    /// Callers must wake `State::disconnect_waker` on error.
    fn check_len(&mut self, actual: u16, limit: u16, label: &str) -> Result<(), Error> {
        if actual > limit {
            warn!(
                "[l2cap][cid = {}] received {} length {} exceeds {}, disconnecting channel",
                self.cid, label, actual, limit
            );
            self.disconnect();
            return Err(Error::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn check_sdu_len(&mut self, sdu_len: u16) -> Result<(), Error> {
        self.check_len(sdu_len, self.mtu, "SDU")
    }

    /// Begin a local-initiated disconnect. Sets the channel to `Disconnecting`, closes the
    /// inbound queue, and resets metrics. Callers must wake `State::disconnect_waker` afterwards.
    fn disconnect(&mut self) {
        if self.state == ChannelState::Connected {
            self.state = ChannelState::Disconnecting;
            let _ = self.inbound.close();
            #[cfg(feature = "channel-metrics")]
            self.metrics.reset();
        }
    }

    fn close(&mut self) {
        self.state = ChannelState::Disconnected;
        self.cid = 0;
        self.conn = None;
        self.mps = 0;
        self.mtu = 0;
        self.psm = 0;
        self.peer_cid = 0;
        self.peer_mps = 0;
        self.peer_mtu = 0;
        self.flow_control = CreditFlowControl::new(CreditFlowPolicy::Every(1), 0);
        self.peer_credits = 0;
    }
}

#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChannelState {
    Disconnected,
    Connecting(u8),
    PeerConnecting(u8),
    Connected,
    ConnectFailed(LeCreditConnResultCode),
    PeerDisconnecting(u8),
    Disconnecting,
}

/// Control how credits are issued by the receiving end.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CreditFlowPolicy {
    /// Issue credits for every N messages received
    Every(u16),
    /// Issue credits when below a threshold
    MinThreshold(u16),
}

impl Default for CreditFlowPolicy {
    fn default() -> Self {
        Self::Every(1)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct CreditFlowControl {
    policy: CreditFlowPolicy,
    credits: u16,
    received: u16,
}

impl CreditFlowControl {
    const fn new(policy: CreditFlowPolicy, initial_credits: u16) -> Self {
        Self {
            policy,
            credits: initial_credits,
            received: 0,
        }
    }
    fn available(&self) -> u16 {
        self.credits
    }

    fn confirm_received(&mut self, n: u16) {
        self.credits = self.credits.saturating_sub(n);
        self.received = self.received.saturating_add(n);
    }

    // Confirm that we've granted amount credits
    fn confirm_granted(&mut self, amount: u16) {
        self.received = self.received.saturating_sub(amount);
        self.credits = self.credits.saturating_add(amount);
    }

    // Check if policy says we should grant more credits
    fn process(&mut self) -> Option<u16> {
        match self.policy {
            CreditFlowPolicy::Every(count) => {
                if self.received >= count {
                    Some(self.received)
                } else {
                    None
                }
            }
            CreditFlowPolicy::MinThreshold(threshold) => {
                if self.credits < threshold {
                    Some(self.received)
                } else {
                    None
                }
            }
        }
    }
}

pub struct CreditGrant<'reference, P> {
    channels: &'reference RefCell<[ChannelStorage<P>]>,
    index: ChannelIndex,
    credits: u16,
}

impl<'reference, P> CreditGrant<'reference, P> {
    fn new(channels: &'reference RefCell<[ChannelStorage<P>]>, index: ChannelIndex, credits: u16) -> Self {
        Self {
            channels,
            index,
            credits,
        }
    }

    pub(crate) fn confirm(&mut self, sent: u16) {
        self.credits = self.credits.saturating_sub(sent);
    }

    pub(crate) fn remaining(&self) -> u16 {
        self.credits
    }

    fn done(&mut self) {
        self.credits = 0;
    }
}

impl<P> Drop for CreditGrant<'_, P> {
    fn drop(&mut self) {
        if self.credits > 0 {
            let mut channels = self.channels.borrow_mut();
            let chan = &mut channels[self.index.0 as usize];
            if chan.state == ChannelState::Connected {
                chan.peer_credits += self.credits;
                chan.credit_waker.wake();
            }
            // make it an assert?
            //        warn!("[l2cap][credit grant drop] channel {} not found", self.index);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use bt_hci::param::{AddrKind, BdAddr, LeConnRole, Status};

    use super::*;
    use crate::mock_controller::MockController;
    use crate::prelude::{ConnParams, DefaultPacketPool};
    use crate::{Address, HostResources};

    #[test]
    fn channel_refcount() {
        let mut resources: HostResources<_, DefaultPacketPool, 2, 2> = HostResources::new();
        let ble = MockController::new();

        let mut builder = crate::new(ble, &mut resources);
        let ble = builder.host();

        let conn = ConnHandle::new(33);
        ble.connections
            .connect(
                conn,
                Address::new(AddrKind::PUBLIC, BdAddr::new([0; 6])),
                LeConnRole::Central,
                ConnParams::new(),
            )
            .unwrap();
        let idx = ble
            .channels
            .alloc(conn, None, |storage| {
                storage.state = ChannelState::Connecting(42);
            })
            .unwrap();

        let chan = ble.channels.poll_created(conn, idx, ble, None);
        assert!(matches!(chan, Poll::Pending));

        ble.connections.disconnected(conn, Status::UNSPECIFIED).unwrap();
        ble.channels.disconnected(conn).unwrap();

        let chan = ble.channels.poll_created(conn, idx, ble, None);
        assert!(matches!(
            chan,
            Poll::Ready(Err(BleHostError::BleHost(Error::Disconnected)))
        ));
    }
}
