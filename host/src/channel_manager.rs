use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::controller::{blocking, Controller};
use bt_hci::param::ConnHandle;
use bt_hci::FromHciBytes;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;

use crate::cursor::WriteCursor;
use crate::host::BleHost;
use crate::l2cap::L2capChannel;
use crate::packet_pool::{AllocId, GlobalPacketPool, Packet};
use crate::pdu::Pdu;
use crate::types::l2cap::{
    CommandRejectRes, DisconnectionReq, DisconnectionRes, L2capHeader, L2capSignalCode, L2capSignalHeader,
    LeCreditConnReq, LeCreditConnRes, LeCreditConnResultCode, LeCreditFlowInd,
};
use crate::{AclSender, BleHostError, Error};

const BASE_ID: u16 = 0x40;

struct State<'d> {
    next_req_id: u8,
    channels: &'d mut [ChannelStorage],
    accept_waker: WakerRegistration,
    create_waker: WakerRegistration,
    disconnect_waker: WakerRegistration,
}

/// Channel manager for L2CAP channels used directly by clients.
pub struct ChannelManager<'d, const RXQ: usize> {
    pool: &'static dyn GlobalPacketPool,
    state: RefCell<State<'d>>,
    inbound: &'d mut [PacketChannel<RXQ>],
}

pub(crate) struct PacketChannel<const QLEN: usize> {
    chan: Channel<NoopRawMutex, Option<Pdu>, QLEN>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ChannelIndex(u8);

impl<const QLEN: usize> PacketChannel<QLEN> {
    #[allow(clippy::declare_interior_mutable_const)]
    pub(crate) const NEW: PacketChannel<QLEN> = PacketChannel { chan: Channel::new() };

    pub fn close(&self) -> Result<(), ()> {
        self.chan.try_send(None).map_err(|_| ())
    }

    pub async fn send(&self, pdu: Pdu) {
        self.chan.send(Some(pdu)).await;
    }

    pub fn try_send(&self, pdu: Pdu) -> Result<(), Error> {
        self.chan.try_send(Some(pdu)).map_err(|_| Error::OutOfMemory)
    }

    pub async fn receive(&self) -> Option<Pdu> {
        self.chan.receive().await
    }

    pub fn clear(&self) {
        self.chan.clear()
    }
}

impl<'d> State<'d> {
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

impl<'d, const RXQ: usize> ChannelManager<'d, RXQ> {
    pub fn new(
        pool: &'static dyn GlobalPacketPool,
        channels: &'d mut [ChannelStorage],
        inbound: &'d mut [PacketChannel<RXQ>],
    ) -> Self {
        Self {
            pool,
            state: RefCell::new(State {
                next_req_id: 0,
                channels,
                accept_waker: WakerRegistration::new(),
                create_waker: WakerRegistration::new(),
                disconnect_waker: WakerRegistration::new(),
            }),
            inbound,
        }
    }

    fn next_request_id(&self) -> u8 {
        self.state.borrow_mut().next_request_id()
    }

    pub(crate) fn disconnect(&self, index: ChannelIndex) {
        self.with_mut(|state| {
            let chan = &mut state.channels[index.0 as usize];
            if chan.state == ChannelState::Connected {
                chan.state = ChannelState::Disconnecting;
                let _ = self.inbound[index.0 as usize].close();
                state.disconnect_waker.wake();
            }
        })
    }

    pub(crate) fn disconnected(&self, conn: ConnHandle) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.channels.iter_mut().enumerate() {
            if Some(conn) == storage.conn {
                let _ = self.inbound[idx].close();
                storage.close();
            }
        }
        state.accept_waker.wake();
        state.create_waker.wake();
        Ok(())
    }

    fn alloc<F: FnOnce(&mut ChannelStorage)>(&self, conn: ConnHandle, f: F) -> Result<ChannelIndex, Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.channels.iter_mut().enumerate() {
            if ChannelState::Disconnected == storage.state && storage.refcount == 0 {
                // Ensure inbound is empty.
                self.inbound[idx].clear();
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
        &self,
        conn: ConnHandle,
        psm: &[u16],
        mtu: u16,
        credit_flow: CreditFlowPolicy,
        initial_credits: Option<u16>,
        ble: &BleHost<'_, T>,
    ) -> Result<L2capChannel<'_>, BleHostError<T::Error>> {
        // Wait until we find a channel for our connection in the connecting state matching our PSM.
        let (channel, req_id, mps, mtu, cid, credits) = poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            for (idx, chan) in state.channels.iter_mut().enumerate() {
                match chan.state {
                    ChannelState::PeerConnecting(req_id) if chan.conn == Some(conn) && psm.contains(&chan.psm) => {
                        chan.mps = chan.mps.min(self.pool.mtu() as u16 - 4);
                        chan.mtu = chan.mtu.min(mtu);
                        chan.mtu = mtu;
                        chan.flow_control = CreditFlowControl::new(
                            credit_flow,
                            initial_credits.unwrap_or(self.pool.min_available(AllocId::from_channel(chan.cid)) as u16),
                        );
                        chan.state = ChannelState::Connected;
                        let mps = chan.mps;
                        let mtu = chan.mtu;
                        let cid = chan.cid;
                        let available = chan.flow_control.available();
                        assert_eq!(chan.refcount, 0);
                        let index = ChannelIndex(idx as u8);

                        state.inc_ref(index);
                        return Poll::Ready((L2capChannel::new(index, self), req_id, mps, mtu, cid, available));
                    }
                    _ => {}
                }
            }
            state.accept_waker.register(cx.waker());
            Poll::Pending
        })
        .await;

        let mut tx = [0; 18];
        // Respond that we accept the channel.
        let mut hci = ble.acl(conn, 1).await?;
        hci.signal(
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
        &self,
        conn: ConnHandle,
        psm: u16,
        mtu: u16,
        credit_flow: CreditFlowPolicy,
        initial_credits: Option<u16>,
        ble: &BleHost<'_, T>,
    ) -> Result<L2capChannel<'_>, BleHostError<T::Error>> {
        let req_id = self.next_request_id();
        let mut credits = 0;
        let mut cid: u16 = 0;
        let mps = self.pool.mtu() as u16 - 4;

        // Allocate space for our new channel.
        let idx = self.alloc(conn, |storage| {
            cid = storage.cid;
            credits = initial_credits.unwrap_or(self.pool.min_available(AllocId::from_channel(storage.cid)) as u16);
            storage.psm = psm;
            storage.mps = mps;
            storage.mtu = mtu;
            storage.flow_control = CreditFlowControl::new(credit_flow, credits);
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
        let mut hci = ble.acl(conn, 1).await?;
        hci.signal(req_id, &command, &mut tx[..]).await?;

        // Wait until a response is accepted.
        poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            state.create_waker.register(cx.waker());
            let storage = &mut state.channels[idx.0 as usize];
            match storage.state {
                ChannelState::Disconnecting | ChannelState::PeerDisconnecting => {
                    return Poll::Ready(Err(Error::Disconnected.into()));
                }
                ChannelState::Connected => {
                    assert_eq!(storage.refcount, 0);
                    state.inc_ref(idx);
                    return Poll::Ready(Ok(L2capChannel::new(idx, self)));
                }
                _ => {}
            }
            Poll::Pending
        })
        .await
    }

    /// Dispatch an incoming L2CAP packet to the appropriate channel.
    pub(crate) fn dispatch(&self, header: L2capHeader, packet: Packet) -> Result<(), Error> {
        if header.channel < BASE_ID {
            return Err(Error::InvalidChannelId);
        }

        let chan = (header.channel - BASE_ID) as usize;
        if chan > self.inbound.len() {
            return Err(Error::InvalidChannelId);
        }

        self.with_mut(|state| {
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage.state {
                    ChannelState::Connected if header.channel == storage.cid => {
                        if storage.flow_control.available() == 0 {
                            // NOTE: This will trigger closing of the link, which might be a bit
                            // too strict. But it should be controllable via the credits given,
                            // which the remote should respect.
                            trace!("[l2cap][cid = {}] no credits available", header.channel);
                            return Err(Error::OutOfMemory);
                        }
                        storage.flow_control.confirm_received(1);
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;

        self.inbound[chan].try_send(Pdu::new(packet, header.length as usize))
    }

    /// Handle incoming L2CAP signal
    pub(crate) fn signal(&self, conn: ConnHandle, data: &[u8]) -> Result<(), Error> {
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
                self.handle_connect_request(conn, header.identifier, &req)
            }
            L2capSignalCode::LeCreditConnRes => {
                let res = LeCreditConnRes::from_hci_bytes_complete(data)?;
                self.handle_connect_response(conn, header.identifier, &res)
            }
            L2capSignalCode::LeCreditFlowInd => {
                let req = LeCreditFlowInd::from_hci_bytes_complete(data)?;
                //trace!("[l2cap] credit flow: {:?}", req);
                self.handle_credit_flow(conn, &req)?;
                Ok(())
            }
            L2capSignalCode::CommandRejectRes => {
                let (reject, _) = CommandRejectRes::from_hci_bytes(data)?;
                Ok(())
            }
            L2capSignalCode::DisconnectionReq => {
                let req = DisconnectionReq::from_hci_bytes_complete(data)?;
                trace!("[l2cap][conn = {:?}, cid = {}] disconnect request", conn, req.dcid);
                self.handle_disconnect_request(req.dcid)?;
                Ok(())
            }
            L2capSignalCode::DisconnectionRes => {
                let res = DisconnectionRes::from_hci_bytes_complete(data)?;
                trace!("[l2cap][conn = {:?}, cid = {}] disconnect response", conn, res.scid);
                self.handle_disconnect_response(res.scid)
            }
            _ => Err(Error::NotSupported),
        }
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
                trace!(
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
                    //trace!(
                    //    "[l2cap][handle_credit_flow][cid = {}] {} += {} credits",
                    //    req.cid,
                    //    storage.peer_credits,
                    //    req.credits
                    //);
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
        for storage in state.channels.iter_mut() {
            if cid == storage.cid {
                storage.state = ChannelState::PeerDisconnecting;
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

    /// Receive data on a given channel and copy it into the buffer.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub(crate) async fn receive<T: Controller>(
        &self,
        chan: ChannelIndex,
        buf: &mut [u8],
        ble: &BleHost<'d, T>,
    ) -> Result<usize, BleHostError<T::Error>> {
        let mut n_received = 1;
        let packet = self.receive_pdu(chan, ble).await?;
        let len = packet.len;

        let (first, data) = packet.as_ref().split_at(2);
        let remaining: u16 = u16::from_le_bytes([first[0], first[1]]);

        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);
        let mut pos = to_copy;

        let mut remaining = remaining as usize - data.len();

        self.flow_control(chan, ble, packet.packet).await?;

        // We have some k-frames to reassemble
        while remaining > 0 {
            let packet = self.receive_pdu(chan, ble).await?;
            n_received += 1;
            let to_copy = packet.len.min(buf.len() - pos);
            if to_copy > 0 {
                buf[pos..pos + to_copy].copy_from_slice(&packet.as_ref()[..to_copy]);
                pos += to_copy;
            }
            remaining -= packet.len;
            self.flow_control(chan, ble, packet.packet).await?;
        }

        Ok(pos)
    }

    async fn receive_pdu<T: Controller>(
        &self,
        chan: ChannelIndex,
        ble: &BleHost<'_, T>,
    ) -> Result<Pdu, BleHostError<T::Error>> {
        match self.inbound[chan.0 as usize].receive().await {
            Some(pdu) => Ok(pdu),
            None => Err(Error::ChannelClosed.into()),
        }
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
        ble: &BleHost<'d, T>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, mps, peer_cid) = self.connected_channel_params(index)?;
        // The number of packets we'll need to send for this payload
        let n_packets = 1 + ((buf.len() as u16).saturating_sub(mps - 2)).div_ceil(mps);

        let mut grant = poll_fn(|cx| self.poll_request_to_send(index, n_packets, Some(cx))).await?;
        let mut hci = ble.acl(conn, n_packets).await?;

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(mps as usize - 2));

        let len = encode(first, &mut p_buf[..], peer_cid, Some(buf.len() as u16))?;
        hci.send(&p_buf[..len]).await?;
        grant.confirm(1);

        let chunks = remaining.chunks(mps as usize);
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.enumerate() {
            let len = encode(chunk, &mut p_buf[..], peer_cid, None)?;
            hci.send(&p_buf[..len]).await?;
            grant.confirm(1);
        }
        Ok(())
    }

    /// Send the provided buffer over a given l2cap channel.
    ///
    /// The buffer will be segmented to the maximum payload size agreed in the opening handshake.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    pub(crate) fn try_send<T: Controller + blocking::Controller>(
        &self,
        index: ChannelIndex,
        buf: &[u8],
        p_buf: &mut [u8],
        ble: &BleHost<'d, T>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, mps, peer_cid) = self.connected_channel_params(index)?;

        // The number of packets we'll need to send for this payload
        let n_packets = ((buf.len() as u16).saturating_add(2)).div_ceil(mps);

        let mut grant = match self.poll_request_to_send(index, n_packets, None) {
            Poll::Ready(res) => res?,
            Poll::Pending => {
                return Err(Error::Busy.into());
            }
        };

        let mut hci = ble.try_acl(conn, n_packets)?;

        // Segment using mps
        let (first, remaining) = buf.split_at(buf.len().min(mps as usize - 2));

        let len = encode(first, &mut p_buf[..], peer_cid, Some(buf.len() as u16))?;
        hci.try_send(&p_buf[..len])?;
        grant.confirm(1);

        let chunks = remaining.chunks(mps as usize);
        let num_chunks = chunks.len();

        for (i, chunk) in chunks.enumerate() {
            let len = encode(chunk, &mut p_buf[..], peer_cid, None)?;
            hci.try_send(&p_buf[..len])?;
            grant.confirm(1);
        }
        Ok(())
    }

    fn connected_channel_params(&self, index: ChannelIndex) -> Result<(ConnHandle, u16, u16), Error> {
        let state = self.state.borrow();
        let chan = &state.channels[index.0 as usize];
        if chan.state == ChannelState::Connected {
            return Ok((chan.conn.unwrap(), chan.mps, chan.peer_cid));
        }
        //trace!("[l2cap][connected_channel_params] channel {} closed", index);
        Err(Error::ChannelClosed)
    }

    // Check the current state of flow control and send flow indications if
    // our policy says so.
    async fn flow_control<T: Controller>(
        &self,
        index: ChannelIndex,
        ble: &BleHost<'d, T>,
        mut packet: Packet,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, cid, credits) = self.with_mut(|state| {
            let chan = &mut state.channels[index.0 as usize];
            if chan.state == ChannelState::Connected {
                return Ok((chan.conn.unwrap(), chan.cid, chan.flow_control.process()));
            }
            trace!("[l2cap][flow_control_process] channel {:?} not found", index);
            Err(Error::NotFound)
        })?;

        if let Some(credits) = credits {
            let identifier = self.next_request_id();
            let signal = LeCreditFlowInd { cid, credits };

            // Reuse packet buffer for signalling data to save the extra TX buffer
            let mut hci = ble.acl(conn, 1).await?;
            hci.signal(identifier, &signal, packet.as_mut()).await?;
            self.with_mut(|state| {
                let chan = &mut state.channels[index.0 as usize];
                if chan.state == ChannelState::Connected {
                    chan.flow_control.confirm_granted(credits);
                    return Ok(());
                }
                trace!("[l2cap][flow_control_grant] channel {:?} not found", index);
                Err(Error::NotFound)
            })?;
        }
        Ok(())
    }

    fn with_mut<F: FnOnce(&mut State<'d>) -> R, R>(&self, f: F) -> R {
        let mut state = self.state.borrow_mut();
        f(&mut state)
    }

    fn poll_request_to_send(
        &self,
        index: ChannelIndex,
        credits: u16,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Result<CreditGrant<'_, 'd>, Error>> {
        let mut state = self.state.borrow_mut();
        let chan = &mut state.channels[index.0 as usize];
        if chan.state == ChannelState::Connected {
            if let Some(cx) = cx {
                chan.credit_waker.register(cx.waker());
            }
            if credits <= chan.peer_credits {
                chan.peer_credits -= credits;
                return Poll::Ready(Ok(CreditGrant::new(&self.state, index, credits)));
            } else {
                warn!(
                    "[l2cap][poll_request_to_send][cid = {}]: not enough credits, requested {} available {}",
                    chan.cid, credits, chan.peer_credits
                );
                return Poll::Pending;
            }
        }
        trace!("[l2cap][pool_request_to_send] channel index {:?} not found", index);
        Poll::Ready(Err(Error::NotFound))
    }

    pub(crate) fn poll_disconnecting<'m>(&'m self, cx: Option<&mut Context<'_>>) -> Poll<DisconnectRequest<'m, 'd>> {
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
}

pub struct DisconnectRequest<'a, 'd> {
    index: ChannelIndex,
    handle: ConnHandle,
    state: &'a RefCell<State<'d>>,
}

impl<'a, 'd> DisconnectRequest<'a, 'd> {
    pub fn handle(&self) -> ConnHandle {
        self.handle
    }

    pub async fn send<T: Controller>(&self, hci: &mut AclSender<'a, 'd, T>) -> Result<(), BleHostError<T::Error>> {
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
                hci.signal(identifier, &DisconnectionRes { dcid, scid }, &mut tx[..])
                    .await?;
            }
            ChannelState::Disconnecting => {
                assert_eq!(Some(self.handle), conn);
                hci.signal(identifier, &DisconnectionReq { dcid, scid }, &mut tx[..])
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

pub(crate) trait DynamicChannelManager {
    fn inc_ref(&self, index: ChannelIndex);
    fn dec_ref(&self, index: ChannelIndex);
    fn disconnect(&self, index: ChannelIndex);
    #[cfg(feature = "defmt")]
    fn print(&self, index: ChannelIndex, f: defmt::Formatter);
}

impl<'d, const RXQ: usize> DynamicChannelManager for ChannelManager<'d, RXQ> {
    fn inc_ref(&self, index: ChannelIndex) {
        ChannelManager::inc_ref(self, index)
    }
    fn dec_ref(&self, index: ChannelIndex) {
        ChannelManager::dec_ref(self, index)
    }
    fn disconnect(&self, index: ChannelIndex) {
        ChannelManager::disconnect(self, index)
    }
    #[cfg(feature = "defmt")]
    fn print(&self, index: ChannelIndex, f: defmt::Formatter) {
        use defmt::Format;
        self.with_mut(|state| {
            let chan = &mut state.channels[index.0 as usize];
            chan.format(f);
        })
    }
}

#[derive(Debug)]
pub struct ChannelStorage {
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
}

#[cfg(feature = "defmt")]
impl defmt::Format for ChannelStorage {
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
    }
}

impl ChannelStorage {
    pub(crate) const DISCONNECTED: ChannelStorage = ChannelStorage {
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
    };

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

pub struct CreditGrant<'reference, 'state> {
    state: &'reference RefCell<State<'state>>,
    index: ChannelIndex,
    credits: u16,
}

impl<'reference, 'state> CreditGrant<'reference, 'state> {
    fn new(state: &'reference RefCell<State<'state>>, index: ChannelIndex, credits: u16) -> Self {
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

impl<'reference, 'state> Drop for CreditGrant<'reference, 'state> {
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
