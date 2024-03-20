use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Context, Poll},
};

use bt_hci::param::ConnHandle;
use embassy_sync::{
    blocking_mutex::{raw::RawMutex, Mutex},
    channel::{Channel, DynamicReceiver, DynamicSendFuture},
    waitqueue::WakerRegistration,
};

use crate::{
    codec,
    l2cap::L2capPacket,
    packet_pool::{AllocId, DynamicPacketPool},
    pdu::Pdu,
    types::l2cap::{
        L2capLeSignal, L2capLeSignalData, LeCreditConnReq, LeCreditConnRes, LeCreditConnResultCode, LeCreditFlowInd,
    },
};

const BASE_ID: u16 = 0x40;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    InvalidChannelId,
    NoChannelAvailable,
    ChannelNotFound,
    OutOfMemory,
    NotSupported,
    ChannelClosed,
    Codec(codec::Error),
}

impl From<codec::Error> for Error {
    fn from(e: codec::Error) -> Self {
        Self::Codec(e)
    }
}

struct State<const CHANNELS: usize> {
    channels: [ChannelState; CHANNELS],
    accept_waker: WakerRegistration,
    create_waker: WakerRegistration,
    credit_wakers: [WakerRegistration; CHANNELS],
}

/// Channel manager for L2CAP channels used directly by clients.
pub struct ChannelManager<'d, M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize> {
    pool: &'d dyn DynamicPacketPool<'d>,
    state: Mutex<M, RefCell<State<CHANNELS>>>,
    signal: Channel<M, (ConnHandle, L2capLeSignal), 1>,
    inbound: [Channel<M, Option<Pdu<'d>>, L2CAP_RXQ>; CHANNELS],
    //outbound: [Channel<M, Pdu<'d>, L2CAP_TXQ>; CHANNELS],
}

pub trait DynamicChannelManager<'d> {
    fn poll_request_to_send(&self, cid: u16, credits: usize, cx: &mut Context<'_>) -> Poll<Result<(), Error>>;
    fn confirm_received(
        &self,
        cid: u16,
        credits: usize,
    ) -> Result<DynamicSendFuture<'_, (ConnHandle, L2capLeSignal)>, Error>;
    fn confirm_disconnected(&self, cid: u16) -> Result<(), Error>;
}

impl<'d, M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize>
    ChannelManager<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>
{
    const TX_CHANNEL: Channel<M, Pdu<'d>, L2CAP_TXQ> = Channel::new();
    const RX_CHANNEL: Channel<M, Option<Pdu<'d>>, L2CAP_RXQ> = Channel::new();
    const DISCONNECTED: ChannelState = ChannelState::Disconnected;
    const CREDIT_WAKER: WakerRegistration = WakerRegistration::new();
    pub fn new(pool: &'d dyn DynamicPacketPool<'d>) -> Self {
        Self {
            pool,
            state: Mutex::new(RefCell::new(State {
                channels: [Self::DISCONNECTED; CHANNELS],
                accept_waker: WakerRegistration::new(),
                create_waker: WakerRegistration::new(),
                credit_wakers: [Self::CREDIT_WAKER; CHANNELS],
            })),
            signal: Channel::new(),
            inbound: [Self::RX_CHANNEL; CHANNELS],
            //outbound: [Self::TX_CHANNEL; CHANNELS],
        }
    }

    pub(crate) async fn signal(&self) -> (ConnHandle, L2capLeSignal) {
        self.signal.receive().await
    }

    async fn disconnect(&self, cid: u16) -> Result<(), Error> {
        let idx = self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn: state.conn, cid });
                        return Ok(idx);
                    }
                    ChannelState::Connected(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn: state.conn, cid });
                        return Ok(idx);
                    }
                    _ => {}
                }
            }
            Err(Error::ChannelNotFound)
        })?;
        self.inbound[idx].send(None).await;
        Ok(())
    }

    fn disconnected(&self, cid: u16) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.channels.iter_mut() {
                match storage {
                    ChannelState::Connecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnected;
                        break;
                    }
                    ChannelState::Connected(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnected;
                        break;
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    fn connect(&self, mut req: ConnectingState) -> Result<(usize, u16), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                if let ChannelState::Disconnected = storage {
                    let cid: u16 = BASE_ID + idx as u16;
                    req.cid = cid;
                    *storage = ChannelState::Connecting(req);
                    state.accept_waker.wake();
                    return Ok((idx, cid));
                }
            }
            Err(Error::NoChannelAvailable)
        })
    }

    fn connected<F: FnOnce(usize, &ConnectingState) -> ConnectedState>(
        &self,
        request_id: u8,
        f: F,
    ) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connecting(req) if request_id == req.request_id => {
                        let res = f(idx, req);
                        *storage = ChannelState::Connected(res);
                        state.create_waker.wake();
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Err(Error::ChannelNotFound)
        })
    }

    fn remote_credits(&self, cid: u16, credits: u16) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connected(s) if s.peer_cid == cid => {
                        s.peer_credits += credits;
                        state.credit_wakers[idx].wake();
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Err(Error::ChannelNotFound)
        })
    }

    fn poll_accept<F: FnOnce(usize, &ConnectingState) -> ConnectedState>(
        &self,
        conn: ConnHandle,
        psm: u16,
        cx: &mut Context<'_>,
        f: F,
    ) -> Poll<(usize, ConnectedState)> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connecting(req) if req.conn == conn && req.psm == psm => {
                        let state = f(idx, req);
                        let cid = state.cid;
                        *storage = ChannelState::Connected(state.clone());
                        return Poll::Ready((idx, state));
                    }
                    _ => {}
                }
            }
            state.accept_waker.register(cx.waker());
            Poll::Pending
        })
    }

    pub(crate) async fn accept(
        &self,
        conn: ConnHandle,
        psm: u16,
        mut mtu: u16,
    ) -> Result<(ConnectedState, DynamicReceiver<'_, Option<Pdu<'d>>>), Error> {
        let mut req_id = 0;
        let (idx, state) = poll_fn(|cx| {
            self.poll_accept(conn, psm, cx, |idx, req| {
                req_id = req.request_id;
                let mps = req.mps.min(self.pool.mtu() as u16 - 4);
                mtu = req.mtu.min(mtu);
                let credits = self.pool.min_available(AllocId::dynamic(idx)) as u16;
                ConnectedState {
                    conn: req.conn,
                    cid: req.cid,
                    psm: req.psm,
                    credits: self.pool.min_available(AllocId::dynamic(idx)) as u16,
                    peer_credits: req.initial_credits,
                    peer_cid: req.peer_cid,
                    pool_id: AllocId::dynamic(idx),
                    mps,
                    mtu,
                }
            })
        })
        .await;

        let response = L2capLeSignal::new(
            req_id,
            L2capLeSignalData::LeCreditConnRes(LeCreditConnRes {
                mps: state.mps,
                dcid: state.cid,
                mtu,
                credits: state.credits,
                result: LeCreditConnResultCode::Success,
            }),
        );

        self.signal.send((conn, response)).await;
        Ok((state, self.inbound[idx].receiver().into()))
    }

    pub(crate) async fn create(
        &self,
        conn: ConnHandle,
        psm: u16,
        mtu: u16,
    ) -> Result<(ConnectedState, DynamicReceiver<'_, Option<Pdu<'d>>>), Error> {
        let state = ConnectingState {
            conn,
            cid: 0,
            request_id: 0,
            psm,
            peer_cid: 0,
            initial_credits: 0,
            mps: self.pool.mtu() as u16,
            mtu,
        };
        let (idx, cid) = self.connect(state)?;

        let command = L2capLeSignal::new(
            0,
            L2capLeSignalData::LeCreditConnReq(LeCreditConnReq {
                psm,
                mps: self.pool.mtu() as u16 - 4,
                scid: cid,
                mtu,
                credits: self.pool.min_available(AllocId::dynamic(idx)) as u16,
            }),
        );
        self.signal.send((conn, command)).await;

        let (idx, state) = poll_fn(|cx| {
            self.state.lock(|state| {
                let mut state = state.borrow_mut();
                for (idx, storage) in state.channels.iter_mut().enumerate() {
                    match storage {
                        ChannelState::Connected(req) if req.conn == conn && req.cid == cid => {
                            return Poll::Ready((idx, req.clone()));
                        }
                        _ => {}
                    }
                }
                state.create_waker.register(cx.waker());
                Poll::Pending
            })
        })
        .await;

        // let tx = self.inbound[idx].sender().into();
        let rx = self.inbound[idx].receiver().into();

        Ok((state, rx))
    }

    pub async fn dispatch(&self, packet: L2capPacket<'_>) -> Result<(), Error> {
        if packet.channel < BASE_ID {
            return Err(Error::InvalidChannelId);
        }

        let chan = (packet.channel - BASE_ID) as usize;
        if chan > self.inbound.len() {
            return Err(Error::InvalidChannelId);
        }

        let chan_alloc = AllocId::dynamic(chan);
        if let Some(mut p) = self.pool.alloc(chan_alloc) {
            let len = packet.payload.len();
            p.as_mut()[..len].copy_from_slice(packet.payload);
            self.inbound[chan].send(Some(Pdu::new(p, len))).await;
            Ok(())
        } else {
            warn!("No memory for channel {}", packet.channel);
            Err(Error::OutOfMemory)
        }
    }

    pub async fn control(&self, conn: ConnHandle, signal: L2capLeSignal) -> Result<(), Error> {
        // info!("Inbound signal: {:?}", signal);
        match signal.data {
            L2capLeSignalData::LeCreditConnReq(req) => {
                self.connect(ConnectingState {
                    conn,
                    cid: 0,
                    psm: req.psm,
                    request_id: signal.id,
                    peer_cid: req.scid,
                    initial_credits: req.credits,
                    mps: req.mps,
                    mtu: req.mtu,
                })?;
                Ok(())
            }
            L2capLeSignalData::LeCreditConnRes(res) => {
                match res.result {
                    LeCreditConnResultCode::Success => {
                        // Must be a response of a previous request which should already by allocated a channel for
                        self.connected(signal.id, |idx, req| ConnectedState {
                            conn: req.conn,
                            cid: req.cid,
                            psm: req.psm,
                            credits: 0,
                            peer_credits: res.credits,
                            peer_cid: res.dcid,
                            pool_id: AllocId::dynamic(idx),
                            mps: req.mps.min(res.mps),
                            mtu: req.mtu.min(res.mtu),
                        })?;
                        Ok(())
                    }
                    other => {
                        warn!("Channel open request failed: {:?}", other);
                        Err(Error::NotSupported)
                    }
                }
            }
            L2capLeSignalData::LeCreditFlowInd(req) => {
                self.remote_credits(req.cid, req.credits)?;
                Ok(())
            }
            L2capLeSignalData::CommandRejectRes(reject) => {
                warn!("Rejected: {:?}", reject);
                Ok(())
            }
            L2capLeSignalData::DisconnectionReq(req) => {
                self.disconnect(req.dcid).await?;
                Ok(())
            }
            L2capLeSignalData::DisconnectionRes(res) => {
                warn!("Disconnection result!");
                self.disconnected(res.dcid)?;
                Ok(())
            }
        }
    }
}

impl<'d, M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize> DynamicChannelManager<'d>
    for ChannelManager<'d, M, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>
{
    fn confirm_received(
        &self,
        cid: u16,
        credits: usize,
    ) -> Result<DynamicSendFuture<'_, (ConnHandle, L2capLeSignal)>, Error> {
        let (conn, signal) = self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connected(state) if cid == state.cid => {
                        // Don't set credits higher than what we can promise
                        let increment = self.pool.min_available(AllocId::dynamic(idx)).min(credits);
                        state.credits += increment as u16;
                        return Ok((
                            state.conn,
                            L2capLeSignal::new(
                                (cid % 255) as u8,
                                L2capLeSignalData::LeCreditFlowInd(LeCreditFlowInd {
                                    cid: state.peer_cid,
                                    credits: increment as u16,
                                }),
                            ),
                        ));
                    }
                    _ => {}
                }
            }
            return Err(Error::ChannelNotFound);
        })?;
        let f = self.signal.send((conn, signal));
        Ok(f.into())
    }

    fn confirm_disconnected(&self, cid: u16) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.channels.iter_mut() {
                match storage {
                    ChannelState::Disconnecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnected;
                        return Ok(());
                    }
                    _ => {}
                }
            }
            return Err(Error::ChannelNotFound);
        })
    }

    fn poll_request_to_send(&self, cid: u16, credits: usize, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connected(s) if cid == s.cid => {
                        if credits <= s.peer_credits as usize {
                            s.peer_credits = s.peer_credits - credits as u16;
                            return Poll::Ready(Ok(()));
                        } else {
                            state.credit_wakers[idx].register(cx.waker());
                            return Poll::Pending;
                        }
                    }
                    _ => {}
                }
            }
            return Poll::Ready(Err(Error::ChannelNotFound));
        })
    }
}

pub enum ChannelState {
    Disconnected,
    Connecting(ConnectingState),
    Connected(ConnectedState),
    Disconnecting(DisconnectingState),
}

#[derive(Clone)]
pub struct ConnectingState {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
    pub(crate) request_id: u8,

    pub(crate) psm: u16,
    pub(crate) peer_cid: u16,
    pub(crate) initial_credits: u16,
    pub(crate) mps: u16,
    pub(crate) mtu: u16,
}

#[derive(Clone)]
pub struct ConnectedState {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
    pub(crate) psm: u16,
    pub(crate) mps: u16,
    pub(crate) mtu: u16,
    pub(crate) credits: u16,

    pub(crate) peer_cid: u16,
    pub(crate) peer_credits: u16,

    pub(crate) pool_id: AllocId,
}

pub struct DisconnectingState {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
}
