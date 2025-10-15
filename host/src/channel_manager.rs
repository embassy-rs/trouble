use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::controller::{blocking, Controller};
use bt_hci::param::ConnHandle;
use bt_hci::FromHciBytes;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;

use crate::connection_manager::ConnectionManager;
use crate::cursor::WriteCursor;
use crate::host::BleHost;
#[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
use crate::l2cap::sar::PacketReassembly;
use crate::l2cap::L2capChannel;
use crate::pdu::{Pdu, Sdu};
use crate::prelude::{ConnectionEvent, L2capChannelConfig};
use crate::types::l2cap::{
    CommandRejectRes, ConnParamUpdateReq, ConnParamUpdateRes, DisconnectionReq, DisconnectionRes, L2capSignalCode,
    L2capSignalHeader, LeCreditConnReq, LeCreditConnRes, LeCreditConnResultCode, LeCreditFlowInd,
};
use crate::{config, BleHostError, Error, PacketPool};

const BASE_ID: u16 = 0x40;

struct State<'d, P> {
    next_req_id: u8,
    channels: &'d mut [ChannelStorage<P>],
    accept_waker: WakerRegistration,
    create_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
}

/// Channel manager for L2CAP channels used directly by clients.
pub struct ChannelManager<'d, P: PacketPool> {
    state: RefCell<State<'d, P::Packet>>,
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

impl<P> State<'_, P> {
    fn print(&self, verbose: bool) {
        for (idx, storage) in self.channels.iter().enumerate() {
            if verbose || storage.state != ChannelState::Disconnected {
                debug!("[l2cap][idx = {}] {:?}", idx, storage);
            }
        }
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

    fn inc_ref(&mut self, index: ChannelIndex) {
        let state = &mut self.channels[index.0 as usize];
        state.refcount = unwrap!(state.refcount.checked_add(1), "Too many references to the same channel");
    }
}

impl<'d, P: PacketPool> ChannelManager<'d, P> {
    pub fn new(channels: &'d mut [ChannelStorage<P::Packet>]) -> Self {
        Self {
            state: RefCell::new(State {
                next_req_id: 0,
                channels,
                accept_waker: WakerRegistration::new(),
                create_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
            }),
        }
    }

    fn next_request_id(&self) -> u8 {
        self.state.borrow_mut().next_request_id()
    }

    pub(crate) fn psm(&self, index: ChannelIndex) -> u16 {
        self.with_mut(|state| {
            let chan = &mut state.channels[index.0 as usize];
            chan.psm
        })
    }

    pub(crate) fn disconnect(&self, index: ChannelIndex) {
        self.with_mut(|state| {
            let chan = &mut state.channels[index.0 as usize];
            if chan.state == ChannelState::Connected {
                chan.state = ChannelState::Disconnecting;
                let _ = chan.inbound.close();
                #[cfg(feature = "channel-metrics")]
                chan.metrics.reset();
                state.disconnect_waker.wake();
            }
        })
    }

    pub(crate) fn disconnected(&self, conn: ConnHandle) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for storage in state.channels.iter_mut() {
            if Some(conn) == storage.conn {
                let _ = storage.inbound.close();
                #[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
                storage.reassembly.clear();
                #[cfg(feature = "channel-metrics")]
                storage.metrics.reset();
                storage.close();
            }
        }
        state.accept_waker.wake();
        state.create_waker.wake();
        Ok(())
    }

    fn alloc<F: FnOnce(&mut ChannelStorage<P::Packet>)>(&self, conn: ConnHandle, f: F) -> Result<ChannelIndex, Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.channels.iter_mut().enumerate() {
            if ChannelState::Disconnected == storage.state && storage.refcount == 0 {
                // Ensure inbound is empty.
                storage.inbound.clear();
                #[cfg(not(feature = "l2cap-sdu-reassembly-optimization"))]
                storage.reassembly.clear();
                let cid: u16 = BASE_ID + idx as u16;
                storage.conn = Some(conn);
                storage.cid = cid;
                f(storage);
                return Ok(ChannelIndex(idx as u8));
            }
        }
        Err(Error::NoChannelAvailable)
    }

    pub(crate) async fn accept<T: Controller>(
        &'d self,
        conn: ConnHandle,
        psm: &[u16],
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

        // Wait until we find a channel for our connection in the connecting state matching our PSM.
        let (channel, req_id, mps, mtu, cid, credits) = poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            state.accept_waker.register(cx.waker());
            for (idx, chan) in state.channels.iter_mut().enumerate() {
                match chan.state {
                    ChannelState::PeerConnecting(req_id) if chan.conn == Some(conn) && psm.contains(&chan.psm) => {
                        chan.mtu = chan.mtu.min(mtu);
                        chan.mps = chan.mps.min(mps);
                        chan.flow_control = CreditFlowControl::new(
                            *flow_policy,
                            initial_credits.unwrap_or(config::L2CAP_RX_QUEUE_SIZE.min(P::capacity()) as u16),
                        );
                        chan.state = ChannelState::Connected;
                        let mps = chan.mps;
                        let mtu = chan.mtu;
                        let cid = chan.cid;
                        let available = chan.flow_control.available();
                        if chan.refcount != 0 {
                            state.print(true);
                            panic!("unexpected refcount");
                        }
                        assert_eq!(chan.refcount, 0);
                        let index = ChannelIndex(idx as u8);

                        state.inc_ref(index);
                        return Poll::Ready((L2capChannel::new(index, self), req_id, mps, mtu, cid, available));
                    }
                    _ => {}
                }
            }
            Poll::Pending
        })
        .await;

        let mut tx = [0; 18];
        // Respond that we accept the channel.
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
        Ok(channel)
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
        let idx = self.alloc(conn, |storage| {
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

        // Wait until a response is accepted.
        poll_fn(|cx| self.poll_created(conn, idx, ble, Some(cx))).await
    }

    fn poll_created<T: Controller>(
        &'d self,
        conn: ConnHandle,
        idx: ChannelIndex,
        ble: &BleHost<'_, T, P>,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Result<L2capChannel<'d, P>, BleHostError<T::Error>>> {
        let mut state = self.state.borrow_mut();
        if let Some(cx) = cx {
            state.create_waker.register(cx.waker());
        }
        let storage = &mut state.channels[idx.0 as usize];
        // Check if we've been disconnected while waiting
        if !ble.connections.is_handle_connected(conn) {
            return Poll::Ready(Err(Error::Disconnected.into()));
        }

        //// Make sure something hasn't gone wrong
        assert_eq!(Some(conn), storage.conn);

        match storage.state {
            ChannelState::Disconnecting | ChannelState::PeerDisconnecting => {
                return Poll::Ready(Err(Error::Disconnected.into()));
            }
            ChannelState::Connected => {
                if storage.refcount != 0 {
                    state.print(true);
                    panic!("unexpected refcount");
                }
                assert_eq!(storage.refcount, 0);
                state.inc_ref(idx);
                return Poll::Ready(Ok(L2capChannel::new(idx, self)));
            }
            _ => {}
        }
        Poll::Pending
    }

    pub(crate) fn received(&self, channel: u16, credits: u16) -> Result<(), Error> {
        if channel < BASE_ID {
            return Err(Error::InvalidChannelId);
        }

        let chan = (channel - BASE_ID) as usize;
        self.with_mut(|state| {
            if chan >= state.channels.len() {
                return Err(Error::InvalidChannelId);
            }

            let storage = &mut state.channels[chan];
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
        })
    }

    pub(crate) fn dispatch(&self, channel: u16, pdu: Pdu<P::Packet>) -> Result<(), Error> {
        if channel < BASE_ID {
            return Err(Error::InvalidChannelId);
        }

        let chan = (channel - BASE_ID) as usize;
        self.with_mut(|state| {
            if chan >= state.channels.len() {
                return Err(Error::InvalidChannelId);
            }

            let mut sdu = None;
            let storage = &mut state.channels[chan];
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
                        } else if let Some((state, pdu)) = storage.reassembly.update(pdu.as_ref())? {
                            sdu.replace(pdu);
                        }
                    }
                }
                _ => {}
            }

            if let Some(sdu) = sdu {
                storage.inbound.try_send(sdu)?;
            }

            Ok(())
        })
    }

    /// Handle incoming L2CAP signal
    pub(crate) fn signal(
        &self,
        conn: ConnHandle,
        data: &[u8],
        manager: &ConnectionManager<'_, P>,
    ) -> Result<(), Error> {
        let (header, data) = L2capSignalHeader::from_hci_bytes(data)?;
        //trace!(
        //    "[l2cap][conn = {:?}] received signal (req {}) code {:?}",
        //    conn,
        //    header.identifier,
        //    header.code
        //);
        match header.code {
            L2capSignalCode::LeCreditConnReq => {
                let req = LeCreditConnReq::from_hci_bytes_complete(data)?;
                self.handle_connect_request(conn, header.identifier, &req)?;
            }
            L2capSignalCode::LeCreditConnRes => {
                let res = LeCreditConnRes::from_hci_bytes_complete(data)?;
                self.handle_connect_response(conn, header.identifier, &res)?;
            }
            L2capSignalCode::LeCreditFlowInd => {
                let req = LeCreditFlowInd::from_hci_bytes_complete(data)?;
                //trace!("[l2cap] credit flow: {:?}", req);
                self.handle_credit_flow(conn, &req)?;
            }
            L2capSignalCode::CommandRejectRes => {
                let (reject, _) = CommandRejectRes::from_hci_bytes(data)?;
            }
            L2capSignalCode::DisconnectionReq => {
                let req = DisconnectionReq::from_hci_bytes_complete(data)?;
                debug!("[l2cap][conn = {:?}, cid = {}] disconnect request", conn, req.dcid);
                self.handle_disconnect_request(req.dcid)?;
            }
            L2capSignalCode::DisconnectionRes => {
                let res = DisconnectionRes::from_hci_bytes_complete(data)?;
                debug!("[l2cap][conn = {:?}, cid = {}] disconnect response", conn, res.scid);
                self.handle_disconnect_response(res.scid)?;
            }
            L2capSignalCode::ConnParamUpdateReq => {
                let req = ConnParamUpdateReq::from_hci_bytes_complete(data)?;
                debug!("[l2cap][conn = {:?}] connection param update request: {:?}", conn, req);
                let interval_min: bt_hci::param::Duration<1_250> = bt_hci::param::Duration::from_u16(req.interval_min);
                let interval_max: bt_hci::param::Duration<1_250> = bt_hci::param::Duration::from_u16(req.interval_max);
                let timeout: bt_hci::param::Duration<10_000> = bt_hci::param::Duration::from_u16(req.timeout);
                use embassy_time::Duration;
                let _ = manager.post_handle_event(
                    conn,
                    ConnectionEvent::RequestConnectionParams {
                        min_connection_interval: Duration::from_micros(interval_min.as_micros()),
                        max_connection_interval: Duration::from_micros(interval_min.as_micros()), // Q: why didn't anything catch 'interva_max' unused?
                        max_latency: req.latency,
                        supervision_timeout: Duration::from_micros(timeout.as_micros()),
                    },
                );
            }
            L2capSignalCode::ConnParamUpdateRes => {
                let res = ConnParamUpdateRes::from_hci_bytes_complete(data)?;
                debug!(
                    "[l2cap][conn = {:?}] connection param update response: {}",
                    conn, res.result,
                );
            }
            r => {
                warn!("[l2cap][conn = {:?}] unsupported signal: {:?}", conn, r);
                return Err(Error::NotSupported);
            }
        }
        Ok(())
    }

    fn handle_connect_request(&self, conn: ConnHandle, identifier: u8, req: &LeCreditConnReq) -> Result<(), Error> {
        self.alloc(conn, |storage| {
            storage.conn = Some(conn);
            storage.psm = req.psm;
            storage.peer_cid = req.scid;
            storage.peer_credits = req.credits;
            storage.mps = req.mps;
            storage.mtu = req.mtu;
            storage.state = ChannelState::PeerConnecting(identifier);
        })?;
        self.state.borrow_mut().accept_waker.wake();
        Ok(())
    }

    fn handle_connect_response(&self, conn: ConnHandle, identifier: u8, res: &LeCreditConnRes) -> Result<(), Error> {
        match res.result {
            LeCreditConnResultCode::Success => {
                // Must be a response of a previous request which should already by allocated a channel for
                let mut state = self.state.borrow_mut();
                for storage in state.channels.iter_mut() {
                    match storage.state {
                        ChannelState::Connecting(req_id) if identifier == req_id && Some(conn) == storage.conn => {
                            storage.peer_cid = res.dcid;
                            storage.peer_credits = res.credits;
                            storage.mps = storage.mps.min(res.mps);
                            storage.mtu = storage.mtu.min(res.mtu);
                            storage.state = ChannelState::Connected;
                            state.create_waker.wake();
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                debug!(
                    "[l2cap][handle_connect_response][link = {}] request with id {} not found",
                    conn.raw(),
                    identifier
                );
                Err(Error::NotFound)
            }
            other => {
                warn!("Channel open request failed: {:?}", other);
                Err(Error::NotSupported)
            }
        }
    }

    fn handle_credit_flow(&self, conn: ConnHandle, req: &LeCreditFlowInd) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for storage in state.channels.iter_mut() {
            match storage.state {
                ChannelState::Connected if storage.peer_cid == req.cid && Some(conn) == storage.conn => {
                    trace!(
                        "[l2cap][handle_credit_flow][cid = {}] {} += {} credits",
                        req.cid,
                        storage.peer_credits,
                        req.credits
                    );
                    storage.peer_credits = storage.peer_credits.saturating_add(req.credits);
                    storage.credit_waker.wake();
                    return Ok(());
                }
                _ => {}
            }
        }
        //    trace!("[l2cap][handle_credit_flow] peer channel {} not found", req.cid);
        Err(Error::NotFound)
    }

    fn handle_disconnect_request(&self, cid: u16) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.channels.iter_mut().enumerate() {
            if cid == storage.cid {
                storage.state = ChannelState::PeerDisconnecting;
                let _ = storage.inbound.close();
                state.disconnect_waker.wake();
                break;
            }
        }
        Ok(())
    }

    fn handle_disconnect_response(&self, cid: u16) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for storage in state.channels.iter_mut() {
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
            let state = self.state.borrow();
            let chan = &state.channels[chan.0 as usize];
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
        let state = self.state.borrow();
        let chan = &state.channels[index.0 as usize];
        if chan.state == ChannelState::Connected {
            return Ok((chan.conn.unwrap(), chan.mps, chan.mtu, chan.peer_cid));
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
        let (conn, cid, credits) = self.with_mut(|state| {
            let chan = &mut state.channels[index.0 as usize];
            if chan.state == ChannelState::Connected {
                return Ok((chan.conn.unwrap(), chan.cid, chan.flow_control.process()));
            }
            debug!("[l2cap][flow_control_process] channel {:?} not found", index);
            Err(Error::NotFound)
        })?;

        if let Some(credits) = credits {
            let identifier = self.next_request_id();
            let signal = LeCreditFlowInd { cid, credits };
            // info!("[host] sending credit flow {} credits on cid {}", credits, cid);

            // Reuse packet buffer for signalling data to save the extra TX buffer
            ble.l2cap_signal(conn, identifier, &signal, p_buf).await?;
            self.with_mut(|state| {
                let chan = &mut state.channels[index.0 as usize];
                if chan.state == ChannelState::Connected {
                    chan.flow_control.confirm_granted(credits);
                    return Ok(());
                }
                debug!("[l2cap][flow_control_grant] channel {:?} not found", index);
                Err(Error::NotFound)
            })?;
        }
        Ok(())
    }

    fn with_mut<F: FnOnce(&mut State<'d, P::Packet>) -> R, R>(&self, f: F) -> R {
        let mut state = self.state.borrow_mut();
        f(&mut state)
    }

    fn poll_request_to_send(
        &self,
        index: ChannelIndex,
        credits: u16,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Result<CreditGrant<'_, 'd, P::Packet>, Error>> {
        let mut state = self.state.borrow_mut();
        let chan = &mut state.channels[index.0 as usize];
        if chan.state == ChannelState::Connected {
            if let Some(cx) = cx {
                chan.credit_waker.register(cx.waker());
            }
            if credits <= chan.peer_credits {
                chan.peer_credits -= credits;
                #[cfg(feature = "channel-metrics")]
                chan.metrics.sent(credits as usize);
                return Poll::Ready(Ok(CreditGrant::new(&self.state, index, credits)));
            } else {
                #[cfg(feature = "channel-metrics")]
                chan.metrics.blocked_send();
                return Poll::Pending;
            }
        }
        debug!("[l2cap][pool_request_to_send] channel index {:?} not found", index);
        Poll::Ready(Err(Error::NotFound))
    }

    pub(crate) fn poll_disconnecting<'m>(&'m self, cx: Option<&mut Context<'_>>) -> Poll<DisconnectRequest<'m, 'd, P>> {
        let mut state = self.state.borrow_mut();
        if let Some(cx) = cx {
            state.disconnect_waker.register(cx.waker());
        }
        for (idx, storage) in state.channels.iter().enumerate() {
            match storage.state {
                ChannelState::Disconnecting | ChannelState::PeerDisconnecting => {
                    return Poll::Ready(DisconnectRequest {
                        index: ChannelIndex(idx as u8),
                        handle: storage.conn.unwrap(),
                        state: &self.state,
                    });
                }
                _ => {}
            }
        }
        Poll::Pending
    }

    pub(crate) fn inc_ref(&self, index: ChannelIndex) {
        self.with_mut(|state| {
            state.inc_ref(index);
        });
    }

    pub(crate) fn dec_ref(&self, index: ChannelIndex) {
        self.with_mut(|state| {
            let state = &mut state.channels[index.0 as usize];
            state.refcount = unwrap!(
                state.refcount.checked_sub(1),
                "bug: dropping a channel (i = {}) with refcount 0",
                index.0
            );
            if state.refcount == 0 && state.state == ChannelState::Connected {
                state.state = ChannelState::Disconnecting;
            }
        });
    }

    pub(crate) fn log_status(&self, verbose: bool) {
        let state = self.state.borrow();
        state.print(verbose);
    }

    #[cfg(feature = "defmt")]
    pub(crate) fn print(&self, index: ChannelIndex, f: defmt::Formatter) {
        use defmt::Format;
        self.with_mut(|state| {
            let chan = &mut state.channels[index.0 as usize];
            chan.format(f);
        })
    }

    #[cfg(feature = "channel-metrics")]
    pub(crate) fn metrics<F: FnOnce(&Metrics) -> R, R>(&self, index: ChannelIndex, f: F) -> R {
        self.with_mut(|state| {
            let state = &state.channels[index.0 as usize];
            f(&state.metrics)
        })
    }
}

pub struct DisconnectRequest<'a, 'd, P: PacketPool> {
    index: ChannelIndex,
    handle: ConnHandle,
    state: &'a RefCell<State<'d, P::Packet>>,
}

impl<'a, 'd, P: PacketPool> DisconnectRequest<'a, 'd, P> {
    pub fn handle(&self) -> ConnHandle {
        self.handle
    }

    pub async fn send<T: Controller>(&self, host: &BleHost<'_, T, P>) -> Result<(), BleHostError<T::Error>> {
        let (state, conn, identifier, dcid, scid) = {
            let mut state = self.state.borrow_mut();
            let identifier = state.next_request_id();
            let chan = &state.channels[self.index.0 as usize];
            (chan.state.clone(), chan.conn, identifier, chan.peer_cid, chan.cid)
        };

        let mut tx = [0; 18];
        match state {
            ChannelState::PeerDisconnecting => {
                assert_eq!(Some(self.handle), conn);
                host.l2cap_signal(self.handle, identifier, &DisconnectionRes { dcid, scid }, &mut tx[..])
                    .await?;
            }
            ChannelState::Disconnecting => {
                assert_eq!(Some(self.handle), conn);
                host.l2cap_signal(self.handle, identifier, &DisconnectionReq { dcid, scid }, &mut tx[..])
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn confirm(self) {
        self.state.borrow_mut().channels[self.index.0 as usize].state = ChannelState::Disconnected;
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
            "state = {}, c = {}, cid = {}, peer = {}, mps = {}, mtu = {}, cred out {}, cred in = {}, ref = {}",
            self.state,
            self.conn,
            self.cid,
            self.peer_cid,
            self.mps,
            self.mtu,
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

    fn close(&mut self) {
        self.state = ChannelState::Disconnected;
        self.cid = 0;
        self.conn = None;
        self.mps = 0;
        self.mtu = 0;
        self.psm = 0;
        self.peer_cid = 0;
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
    PeerDisconnecting,
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

pub struct CreditGrant<'reference, 'state, P> {
    state: &'reference RefCell<State<'state, P>>,
    index: ChannelIndex,
    credits: u16,
}

impl<'reference, 'state, P> CreditGrant<'reference, 'state, P> {
    fn new(state: &'reference RefCell<State<'state, P>>, index: ChannelIndex, credits: u16) -> Self {
        Self { state, index, credits }
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

impl<P> Drop for CreditGrant<'_, '_, P> {
    fn drop(&mut self) {
        if self.credits > 0 {
            let mut state = self.state.borrow_mut();
            let chan = &mut state.channels[self.index.0 as usize];
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
    use crate::prelude::DefaultPacketPool;
    use crate::HostResources;

    #[test]
    fn channel_refcount() {
        let mut resources: HostResources<DefaultPacketPool, 2, 2> = HostResources::new();
        let ble = MockController::new();

        let builder = crate::new(ble, &mut resources);
        let ble = builder.host;

        let conn = ConnHandle::new(33);
        ble.connections
            .connect(conn, AddrKind::PUBLIC, BdAddr::new([0; 6]), LeConnRole::Central)
            .unwrap();
        let idx = ble
            .channels
            .alloc(conn, |storage| {
                storage.state = ChannelState::Connecting(42);
            })
            .unwrap();

        let chan = ble.channels.poll_created(conn, idx, &ble, None);
        assert!(matches!(chan, Poll::Pending));

        ble.connections.disconnected(conn, Status::UNSPECIFIED).unwrap();
        ble.channels.disconnected(conn).unwrap();

        let chan = ble.channels.poll_created(conn, idx, &ble, None);
        assert!(matches!(
            chan,
            Poll::Ready(Err(BleHostError::BleHost(Error::Disconnected)))
        ));
    }
}
