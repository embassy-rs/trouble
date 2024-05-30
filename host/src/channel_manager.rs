use core::cell::RefCell;
use core::future::poll_fn;
use core::task::{Context, Poll};

use bt_hci::controller::{blocking, Controller};
use bt_hci::param::ConnHandle;
use bt_hci::FromHciBytes;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::WakerRegistration;

use crate::cursor::{ReadCursor, WriteCursor};
use crate::host::BleHost;
use crate::packet_pool::{AllocId, GlobalPacketPool, Packet};
use crate::pdu::Pdu;
use crate::types::l2cap::{
    CommandRejectRes, DisconnectionReq, DisconnectionRes, L2capHeader, L2capSignalCode, L2capSignalHeader,
    LeCreditConnReq, LeCreditConnRes, LeCreditConnResultCode, LeCreditFlowInd,
};
use crate::{BleHostError, Error};

const BASE_ID: u16 = 0x40;

struct State<'d> {
    next_req_id: u8,
    channels: &'d mut [ChannelStorage],
    accept_waker: WakerRegistration,
    create_waker: WakerRegistration,
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

impl<const QLEN: usize> PacketChannel<QLEN> {
    pub(crate) const NEW: PacketChannel<QLEN> = PacketChannel { chan: Channel::new() };

    pub fn close(&self) -> Result<(), ()> {
        self.chan.try_send(None).map_err(|_| ())
    }

    pub async fn send(&self, pdu: Pdu) {
        self.chan.send(Some(pdu)).await;
    }

    pub async fn receive(&self) -> Option<Pdu> {
        self.chan.receive().await
    }
}

impl<'d> State<'d> {
    fn print(&self) {
        for (idx, storage) in self.channels.iter().enumerate() {
            if storage.state != ChannelState::Disconnected {
                debug!("[l2cap][idx = {}] state = {:?}", idx, storage);
            }
        }
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
            }),
            inbound,
        }
    }

    fn next_request_id(&self) -> u8 {
        let mut state = self.state.borrow_mut();
        // 0 is an invalid identifier
        if state.next_req_id == 0 {
            state.next_req_id += 1;
        }
        let next = state.next_req_id;
        state.next_req_id = state.next_req_id.wrapping_add(1);
        next
    }

    pub(crate) fn disconnect(&self, cid: u16) -> Result<ConnHandle, Error> {
        self.with_mut(|state| {
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage.state {
                    ChannelState::Disconnecting if cid == storage.cid => {
                        storage.state = ChannelState::Disconnected;
                        storage.cid = 0;
                        return Ok(ConnHandle::new(storage.conn));
                    }
                    ChannelState::PeerConnecting(_) if cid == storage.cid => {
                        storage.state = ChannelState::Disconnecting;
                        let _ = self.inbound[idx].close();
                        return Ok(ConnHandle::new(storage.conn));
                    }
                    ChannelState::Connecting(_) if cid == storage.cid => {
                        storage.state = ChannelState::Disconnecting;
                        let _ = self.inbound[idx].close();
                        return Ok(ConnHandle::new(storage.conn));
                    }
                    ChannelState::Connected if cid == storage.cid => {
                        storage.state = ChannelState::Disconnecting;
                        let _ = self.inbound[idx].close();
                        return Ok(ConnHandle::new(storage.conn));
                    }
                    _ => {}
                }
            }
            trace!("[l2cap][disconnect] channel {} not found", cid);
            Err(Error::NotFound)
        })
    }

    pub(crate) fn disconnected(&self, conn: ConnHandle) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.channels.iter_mut().enumerate() {
            match storage.state {
                ChannelState::PeerConnecting(_) if conn.raw() == storage.conn => {
                    storage.state = ChannelState::Disconnecting;
                    let _ = self.inbound[idx].close();
                }
                ChannelState::Connecting(_) if conn.raw() == storage.conn => {
                    storage.state = ChannelState::Disconnecting;
                    let _ = self.inbound[idx].close();
                }
                ChannelState::Connected if conn.raw() == storage.conn => {
                    storage.state = ChannelState::Disconnecting;
                    let _ = self.inbound[idx].close();
                }
                _ => {}
            }
            storage.credit_waker.wake();
        }
        state.accept_waker.wake();
        state.create_waker.wake();
        Ok(())
    }

    fn alloc<F: FnOnce(&mut ChannelStorage)>(&self, conn: ConnHandle, f: F) -> Result<(), Error> {
        let mut state = self.state.borrow_mut();
        for (idx, storage) in state.channels.iter_mut().enumerate() {
            if let ChannelState::Disconnected = storage.state {
                let cid: u16 = BASE_ID + idx as u16;
                storage.conn = conn.raw();
                storage.cid = cid;
                f(storage);
                return Ok(());
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
        ble: &BleHost<'d, T>,
    ) -> Result<u16, BleHostError<T::Error>> {
        // Wait until we find a channel for our connection in the connecting state matching our PSM.
        let (req_id, mps, mtu, cid, credits) = poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            for chan in state.channels.iter_mut() {
                match chan.state {
                    ChannelState::PeerConnecting(req_id) if chan.conn == conn.raw() && psm.contains(&chan.psm) => {
                        chan.mps = chan.mps.min(self.pool.mtu() as u16 - 4);
                        chan.mtu = chan.mtu.min(mtu);
                        chan.mtu = mtu;
                        chan.flow_control = CreditFlowControl::new(
                            credit_flow,
                            initial_credits.unwrap_or(self.pool.min_available(AllocId::from_channel(chan.cid)) as u16),
                        );
                        chan.state = ChannelState::Connected;

                        return Poll::Ready((req_id, chan.mps, chan.mtu, chan.cid, chan.flow_control.available()));
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

        // NOTE: This code is disabled as we send the credits in the response request. For some reason the nrf-softdevice doesn't do that,
        // so lets keep this around in case we need it.
        // Send initial credits
        //        let next_req_id = self.next_request_id();
        //        controller
        //            .signal(conn, next_req_id, &LeCreditFlowInd { cid, credits }, &mut tx[..])
        //            .await?;
        //
        Ok(cid)
    }

    pub(crate) async fn create<T: Controller>(
        &self,
        conn: ConnHandle,
        psm: u16,
        mtu: u16,
        credit_flow: CreditFlowPolicy,
        initial_credits: Option<u16>,
        ble: &BleHost<'d, T>,
    ) -> Result<u16, BleHostError<T::Error>> {
        let req_id = self.next_request_id();
        let mut credits = 0;
        let mut cid: u16 = 0;
        let mps = self.pool.mtu() as u16 - 4;

        // Allocate space for our new channel.
        self.alloc(conn, |storage| {
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
            for storage in state.channels.iter_mut() {
                match storage.state {
                    ChannelState::Disconnecting if storage.conn == conn.raw() && storage.cid == cid => {
                        return Poll::Ready(Err(Error::Disconnected));
                    }
                    ChannelState::Connected if storage.conn == conn.raw() && storage.cid == cid => {
                        return Poll::Ready(Ok(()));
                    }
                    _ => {}
                }
            }
            state.create_waker.register(cx.waker());
            Poll::Pending
        })
        .await?;

        // NOTE: This code is disabled as we send the credits in the response request. For some reason the nrf-softdevice doesn't do that,
        // so lets keep this around in case we need it.
        // Send initial credits
        // let next_req_id = self.next_request_id();
        // let req = controller
        //    .signal(conn, next_req_id, &LeCreditFlowInd { cid, credits }, &mut tx[..])
        //    .await?;
        Ok(cid)
    }

    /// Dispatch an incoming L2CAP packet to the appropriate channel.
    pub(crate) async fn dispatch(&self, header: L2capHeader, packet: Packet) -> Result<(), Error> {
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
                            trace!("[l2cap][cid = {}] no credits available", header.channel);
                            return Err(Error::OutOfMemory);
                        }
                        storage.flow_control.received(1);
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;

        self.inbound[chan].send(Pdu::new(packet, header.length as usize)).await;
        Ok(())
    }

    /// Handle incoming L2CAP signal
    pub(crate) async fn signal(&self, conn: ConnHandle, data: &[u8]) -> Result<(), Error> {
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
                warn!("Rejected: {:?}", reject);
                Ok(())
            }
            L2capSignalCode::DisconnectionReq => {
                let req = DisconnectionReq::from_hci_bytes_complete(data)?;
                trace!("[l2cap][conn = {:?}, cid = {}] disconnect request", conn, req.dcid);
                self.disconnect(req.dcid)?;
                Ok(())
            }
            L2capSignalCode::DisconnectionRes => {
                let res = DisconnectionRes::from_hci_bytes_complete(data)?;
                trace!("[l2cap][conn = {:?}, cid = {}] disconnect response", conn, res.scid);
                self.handle_disconnect_response(&res)
            }
            _ => Err(Error::NotSupported),
        }
    }

    fn handle_connect_request(&self, conn: ConnHandle, identifier: u8, req: &LeCreditConnReq) -> Result<(), Error> {
        self.alloc(conn, |storage| {
            storage.conn = conn.raw();
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
                        ChannelState::Connecting(req_id) if identifier == req_id && conn.raw() == storage.conn => {
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
                    "[l2cap][handle_connect_response] request with id {} not found",
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
                ChannelState::Connected if storage.peer_cid == req.cid && conn.raw() == storage.conn => {
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
        trace!("[l2cap][handle_credit_flow] peer channel {} not found", req.cid);
        Err(Error::NotFound)
    }

    fn handle_disconnect_response(&self, res: &DisconnectionRes) -> Result<(), Error> {
        let cid = res.scid;
        let mut state = self.state.borrow_mut();
        for storage in state.channels.iter_mut() {
            match storage.state {
                ChannelState::Disconnecting if cid == storage.cid => {
                    storage.state = ChannelState::Disconnected;
                    break;
                }
                ChannelState::PeerConnecting(_) if cid == storage.cid => {
                    storage.state = ChannelState::Disconnecting;
                    break;
                }
                ChannelState::Connecting(_) if cid == storage.cid => {
                    storage.state = ChannelState::Disconnecting;
                    break;
                }
                ChannelState::Connected if cid == storage.cid => {
                    storage.state = ChannelState::Disconnecting;
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Receive data on a given channel and copy it into the buffer.
    ///
    /// The length provided buffer slice must be equal or greater to the agreed MTU.
    pub(crate) async fn receive<T: Controller>(
        &self,
        cid: u16,
        buf: &mut [u8],
        ble: &BleHost<'d, T>,
    ) -> Result<usize, BleHostError<T::Error>> {
        let idx = self.connected_channel_index(cid)?;

        let mut n_received = 1;
        let packet = self.receive_pdu(cid, idx, ble).await?;
        let len = packet.len;

        let mut r = ReadCursor::new(packet.as_ref());
        let remaining: u16 = r.read()?;

        let data = r.remaining();
        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);
        let mut pos = to_copy;

        let mut remaining = remaining as usize - data.len();

        self.flow_control(cid, ble, packet.packet).await?;

        // We have some k-frames to reassemble
        while remaining > 0 {
            let packet = self.receive_pdu(cid, idx, ble).await?;
            n_received += 1;
            let to_copy = packet.len.min(buf.len() - pos);
            if to_copy > 0 {
                buf[pos..pos + to_copy].copy_from_slice(&packet.as_ref()[..to_copy]);
                pos += to_copy;
            }
            remaining -= packet.len;
            self.flow_control(cid, ble, packet.packet).await?;
        }

        Ok(pos)
    }

    // Return the array index for a given active channel
    fn connected_channel_index(&self, cid: u16) -> Result<usize, Error> {
        let state = self.state.borrow();
        for (idx, chan) in state.channels.iter().enumerate() {
            if chan.cid == cid && chan.state == ChannelState::Connected {
                return Ok(idx);
            }
        }
        trace!("[l2cap][connected_channel_index] channel {} closed", cid);
        Err(Error::ChannelClosed)
    }

    async fn receive_pdu<T: Controller>(
        &self,
        cid: u16,
        idx: usize,
        ble: &BleHost<'d, T>,
    ) -> Result<Pdu, BleHostError<T::Error>> {
        match self.inbound[idx].receive().await {
            Some(pdu) => Ok(pdu),
            None => {
                self.confirm_disconnected(cid, ble).await?;
                Err(Error::ChannelClosed.into())
            }
        }
    }

    /// Send the provided buffer over a given l2cap channel.
    ///
    /// The buffer will be segmented to the maximum payload size agreed in the opening handshake.
    ///
    /// If the channel has been closed or the channel id is not valid, an error is returned.
    pub(crate) async fn send<T: Controller>(
        &self,
        cid: u16,
        buf: &[u8],
        p_buf: &mut [u8],
        ble: &BleHost<'d, T>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, mps, peer_cid) = self.connected_channel_params(cid)?;
        // The number of packets we'll need to send for this payload
        let n_packets = 1 + ((buf.len() as u16).saturating_sub(mps - 2)).div_ceil(mps);

        let mut grant = poll_fn(|cx| self.poll_request_to_send(cid, n_packets, Some(cx))).await?;
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
        cid: u16,
        buf: &[u8],
        p_buf: &mut [u8],
        ble: &BleHost<'d, T>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, mps, peer_cid) = self.connected_channel_params(cid)?;

        // The number of packets we'll need to send for this payload
        let n_packets = ((buf.len() as u16).saturating_add(2)).div_ceil(mps);

        let mut grant = match self.poll_request_to_send(cid, n_packets, None) {
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

    fn connected_channel_params(&self, cid: u16) -> Result<(ConnHandle, u16, u16), Error> {
        let state = self.state.borrow();
        for chan in state.channels.iter() {
            match chan.state {
                ChannelState::Connected if chan.cid == cid => {
                    return Ok((ConnHandle::new(chan.conn), chan.mps, chan.peer_cid));
                }
                _ => {}
            }
        }
        trace!("[l2cap][connected_channel_params] channel {} closed", cid);
        Err(Error::ChannelClosed)
    }

    // Check the current state of flow control and send flow indications if
    // our policy says so.
    async fn flow_control<T: Controller>(
        &self,
        cid: u16,
        ble: &BleHost<'d, T>,
        mut packet: Packet,
    ) -> Result<(), BleHostError<T::Error>> {
        let (conn, credits) = self.with_mut(|state| {
            for storage in state.channels.iter_mut() {
                match storage.state {
                    ChannelState::Connected if cid == storage.cid => {
                        return Ok((storage.conn, storage.flow_control.process()));
                    }
                    _ => {}
                }
            }
            trace!("[l2cap][flow_control] channel {} not found", cid);
            Err(Error::NotFound)
        })?;

        if let Some(credits) = credits {
            let identifier = self.next_request_id();
            let signal = LeCreditFlowInd { cid, credits };

            // Reuse packet buffer for signalling data to save the extra TX buffer
            let mut hci = ble.acl(ConnHandle::new(conn), 1).await?;
            hci.signal(identifier, &signal, packet.as_mut()).await?;
        }
        Ok(())
    }

    fn with_mut<F: FnOnce(&mut State<'d>) -> R, R>(&self, f: F) -> R {
        let mut state = self.state.borrow_mut();
        f(&mut state)
    }

    async fn confirm_disconnected<T: Controller>(
        &self,
        cid: u16,
        ble: &BleHost<'d, T>,
    ) -> Result<(), BleHostError<T::Error>> {
        let (handle, dcid, scid) = self.with_mut(|state| {
            for storage in state.channels.iter_mut() {
                match storage.state {
                    ChannelState::Disconnecting if cid == storage.cid => {
                        storage.state = ChannelState::Disconnected;
                        let scid = storage.cid;
                        let dcid = storage.peer_cid;
                        let handle = storage.conn;
                        storage.cid = 0;
                        storage.peer_cid = 0;
                        storage.conn = 0;
                        return Ok((handle, dcid, scid));
                    }
                    _ => {}
                }
            }
            trace!("[l2cap][confirm_disconnected] channel {} not found", cid);
            Err(Error::NotFound)
        })?;

        let identifier = self.next_request_id();
        let mut tx = [0; 18];
        let mut hci = ble.acl(ConnHandle::new(handle), 1).await?;
        hci.signal(identifier, &DisconnectionRes { dcid, scid }, &mut tx[..])
            .await?;
        Ok(())
    }

    fn poll_request_to_send(
        &self,
        cid: u16,
        credits: u16,
        cx: Option<&mut Context<'_>>,
    ) -> Poll<Result<CreditGrant<'_, 'd>, Error>> {
        let mut state = self.state.borrow_mut();
        for storage in state.channels.iter_mut() {
            match storage.state {
                ChannelState::Connected if cid == storage.cid => {
                    if let Some(cx) = cx {
                        storage.credit_waker.register(cx.waker());
                    }
                    if credits <= storage.peer_credits {
                        storage.peer_credits -= credits;
                        return Poll::Ready(Ok(CreditGrant::new(&self.state, cid, credits)));
                    } else {
                        warn!(
                            "[l2cap][poll_request_to_send][cid = {}]: not enough credits, requested {} available {}",
                            cid, credits, storage.peer_credits
                        );
                        return Poll::Pending;
                    }
                }
                _ => {}
            }
        }
        trace!("[l2cap][pool_request_to_send] channel {} not found", cid);
        Poll::Ready(Err(Error::NotFound))
    }

    pub(crate) fn log_status(&self) {
        let state = self.state.borrow();
        state.print();
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

#[derive(Debug)]
pub struct ChannelStorage {
    state: ChannelState,
    conn: u16,
    cid: u16,
    psm: u16,
    mps: u16,
    mtu: u16,
    flow_control: CreditFlowControl,

    peer_cid: u16,
    peer_credits: u16,
    credit_waker: WakerRegistration,
}

#[cfg(feature = "defmt")]
impl defmt::Format for ChannelStorage {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "state = {}, conn = {}, cid = {}, peer = {}, mps = {}, mtu = {}, our credits {}, their credits = {}",
            self.state,
            self.conn,
            self.cid,
            self.peer_cid,
            self.mps,
            self.mtu,
            self.peer_credits,
            self.flow_control.available()
        );
    }
}

impl ChannelStorage {
    pub(crate) const DISCONNECTED: ChannelStorage = ChannelStorage {
        state: ChannelState::Disconnected,
        conn: 0,
        cid: 0,
        mps: 0,
        mtu: 0,
        psm: 0,

        flow_control: CreditFlowControl::new(CreditFlowPolicy::Every(1), 0),
        peer_cid: 0,
        peer_credits: 0,
        credit_waker: WakerRegistration::new(),
    };
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ChannelState {
    Disconnected,
    Connecting(u8),
    PeerConnecting(u8),
    Connected,
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

    fn received(&mut self, n: u16) {
        self.credits = self.credits.saturating_sub(n);
        self.received = self.received.saturating_add(n);
    }

    fn process(&mut self) -> Option<u16> {
        match self.policy {
            CreditFlowPolicy::Every(count) => {
                if self.received >= count {
                    let amount = self.received;
                    self.received = 0;
                    self.credits += amount;
                    Some(amount)
                } else {
                    None
                }
            }
            CreditFlowPolicy::MinThreshold(threshold) => {
                if self.credits < threshold {
                    let amount = self.received;
                    self.received = 0;
                    self.credits += amount;
                    Some(amount)
                } else {
                    None
                }
            }
        }
    }
}

pub struct CreditGrant<'reference, 'state> {
    state: &'reference RefCell<State<'state>>,
    cid: u16,
    credits: u16,
}

impl<'reference, 'state> CreditGrant<'reference, 'state> {
    fn new(state: &'reference RefCell<State<'state>>, cid: u16, credits: u16) -> Self {
        Self { state, cid, credits }
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
            for storage in state.channels.iter_mut() {
                match storage.state {
                    ChannelState::Connected if self.cid == storage.cid => {
                        storage.peer_credits += self.credits;
                        storage.credit_waker.wake();
                        return;
                    }
                    _ => {}
                }
            }
            // make it an assert?
            warn!("[l2cap][credit grant drop] channel {} not found", self.cid);
        }
    }
}
