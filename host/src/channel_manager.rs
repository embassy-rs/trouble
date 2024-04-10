use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Context, Poll},
};

use bt_hci::{controller::Controller, param::ConnHandle};
use embassy_sync::{
    blocking_mutex::{raw::RawMutex, Mutex},
    channel::{Channel, DynamicReceiver},
    waitqueue::WakerRegistration,
};

use crate::{
    adapter::HciController,
    l2cap::L2capHeader,
    packet_pool::{AllocId, DynamicPacketPool, Packet},
    pdu::Pdu,
    types::l2cap::{
        L2capLeSignal, L2capLeSignalData, LeCreditConnReq, LeCreditConnRes, LeCreditConnResultCode, LeCreditFlowInd,
    },
    AdapterError, Error,
};

const BASE_ID: u16 = 0x40;

struct State<const CHANNELS: usize> {
    next_req_id: u8,
    channels: [ChannelState; CHANNELS],
    accept_waker: WakerRegistration,
    create_waker: WakerRegistration,
    credit_wakers: [WakerRegistration; CHANNELS],
}

/// Channel manager for L2CAP channels used directly by clients.
pub struct ChannelManager<'d, M: RawMutex, const CHANNELS: usize, const L2CAP_TXQ: usize, const L2CAP_RXQ: usize> {
    pool: &'d dyn DynamicPacketPool<'d>,
    state: Mutex<M, RefCell<State<CHANNELS>>>,
    inbound: [Channel<M, Option<Pdu<'d>>, L2CAP_RXQ>; CHANNELS],
    //outbound: [Channel<M, Pdu<'d>, L2CAP_TXQ>; CHANNELS],
}

pub trait DynamicChannelManager<'d> {
    fn poll_request_to_send(&self, cid: u16, credits: usize, cx: Option<&mut Context<'_>>) -> Poll<Result<(), Error>>;
    fn flow_control(&self, cid: u16) -> Result<Option<(ConnHandle, L2capLeSignal)>, Error>;
    fn confirm_disconnected(&self, cid: u16) -> Result<(), Error>;
    fn disconnect(&self, cid: u16) -> Result<(), Error>;
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
                next_req_id: 0,
                channels: [Self::DISCONNECTED; CHANNELS],
                accept_waker: WakerRegistration::new(),
                create_waker: WakerRegistration::new(),
                credit_wakers: [Self::CREDIT_WAKER; CHANNELS],
            })),
            inbound: [Self::RX_CHANNEL; CHANNELS],
        }
    }

    fn next_request_id(&self) -> u8 {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            let next = state.next_req_id;
            state.next_req_id = state.next_req_id.wrapping_add(1);
            next
        })
    }

    fn disconnect(&self, cid: u16) -> Result<(), Error> {
        let idx = self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Disconnecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnected;
                        return Ok(idx);
                    }
                    ChannelState::PeerConnecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn: state.conn, cid });
                        return Ok(idx);
                    }
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
            Err(Error::NotFound)
        })?;
        let _ = self.inbound[idx].try_send(None);
        Ok(())
    }

    fn disconnected(&self, cid: u16) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for storage in state.channels.iter_mut() {
                match storage {
                    ChannelState::Disconnecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnected;
                        break;
                    }
                    ChannelState::PeerConnecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn: state.conn, cid });
                        break;
                    }
                    ChannelState::Connecting(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn: state.conn, cid });
                        break;
                    }
                    ChannelState::Connected(state) if cid == state.cid => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn: state.conn, cid });
                        break;
                    }
                    _ => {}
                }
            }
            Ok(())
        })
    }

    pub fn disconnected_connection(&self, conn: ConnHandle) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::PeerConnecting(state) if conn == state.conn => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn, cid: state.cid });
                        let _ = self.inbound[idx].try_send(None);
                    }
                    ChannelState::Connecting(state) if conn == state.conn => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn, cid: state.cid });
                        let _ = self.inbound[idx].try_send(None);
                    }
                    ChannelState::Connected(state) if conn == state.conn => {
                        *storage = ChannelState::Disconnecting(DisconnectingState { conn, cid: state.cid });
                        let _ = self.inbound[idx].try_send(None);
                    }
                    _ => {}
                }
            }
            state.accept_waker.wake();
            state.create_waker.wake();
            for w in state.credit_wakers.iter_mut() {
                w.wake();
            }
        });
        Ok(())
    }

    fn peer_connect<F: FnOnce(usize, u16) -> PeerConnectingState>(&self, f: F) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                if let ChannelState::Disconnected = storage {
                    let cid: u16 = BASE_ID + idx as u16;
                    let mut req = f(idx, cid);
                    req.cid = cid;
                    *storage = ChannelState::PeerConnecting(req);
                    state.accept_waker.wake();
                    return Ok(());
                }
            }
            Err(Error::NoChannelAvailable)
        })
    }

    fn connect<F: FnOnce(usize, u16) -> ConnectingState>(&self, f: F) -> Result<(), Error> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                if let ChannelState::Disconnected = storage {
                    let cid: u16 = BASE_ID + idx as u16;
                    let mut req = f(idx, cid);
                    req.cid = cid;
                    *storage = ChannelState::Connecting(req);
                    return Ok(());
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
                        // info!("Connection created, properties: {:?}", res);
                        *storage = ChannelState::Connected(res);
                        state.create_waker.wake();
                        return Ok(());
                    }
                    _ => {}
                }
            }
            Err(Error::NotFound)
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
            Err(Error::NotFound)
        })
    }

    fn poll_accept<F: FnOnce(usize, &PeerConnectingState) -> ConnectedState>(
        &self,
        conn: ConnHandle,
        psm: &[u16],
        cx: &mut Context<'_>,
        f: F,
    ) -> Poll<(usize, ConnectedState)> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::PeerConnecting(req) if req.conn == conn && psm.contains(&req.psm) => {
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

    pub(crate) async fn accept<T: Controller>(
        &self,
        conn: ConnHandle,
        psm: &[u16],
        mut mtu: u16,
        credit_flow: CreditFlowPolicy,
        controller: &HciController<'_, T>,
    ) -> Result<(ConnectedState, DynamicReceiver<'_, Option<Pdu<'d>>>), AdapterError<T::Error>> {
        let mut req_id = 0;
        let (idx, state) = poll_fn(|cx| {
            self.poll_accept(conn, psm, cx, |idx, req| {
                req_id = req.request_id;
                let mps = req.mps.min(self.pool.mtu() as u16 - 4);
                mtu = req.mtu.min(mtu);
                let credits = self.pool.min_available(AllocId::dynamic(idx)) as u16;
                //info!("Accept, initial credits: {}", credits);
                ConnectedState {
                    conn: req.conn,
                    cid: req.cid,
                    psm: req.psm,
                    flow_control: CreditFlowControl::new(credit_flow, credits),
                    peer_credits: req.offered_credits,
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
                credits: 0,
                result: LeCreditConnResultCode::Success,
            }),
        );

        // info!("Responding to create: {:?}", response);

        controller.signal(conn, response).await?;

        // Send initial credits
        let next_req_id = self.next_request_id();
        controller
            .signal(
                conn,
                L2capLeSignal::new(
                    next_req_id,
                    L2capLeSignalData::LeCreditFlowInd(LeCreditFlowInd {
                        cid: state.cid,
                        credits: state.flow_control.available(),
                    }),
                ),
            )
            .await?;

        Ok((state, self.inbound[idx].receiver().into()))
    }

    pub(crate) async fn create<T: Controller>(
        &self,
        conn: ConnHandle,
        psm: u16,
        mtu: u16,
        credit_flow: CreditFlowPolicy,
        controller: &HciController<'_, T>,
    ) -> Result<(ConnectedState, DynamicReceiver<'_, Option<Pdu<'d>>>), AdapterError<T::Error>> {
        let req_id = self.next_request_id();
        let mut credits = 0;
        let mut cid: u16 = 0;
        self.connect(|i, c| {
            cid = c;
            credits = self.pool.min_available(AllocId::dynamic(i)) as u16;
            ConnectingState {
                conn,
                cid,
                request_id: req_id,
                psm,
                initial_credits: credits,
                flow_control_policy: credit_flow,
                mps: self.pool.mtu() as u16 - 4,
                mtu,
            }
        })?;
        //info!("Created connect state with idx cid {}", cid);

        let command = L2capLeSignal::new(
            req_id,
            L2capLeSignalData::LeCreditConnReq(LeCreditConnReq {
                psm,
                mps: self.pool.mtu() as u16 - 4,
                scid: cid,
                mtu,
                credits: 0,
            }),
        );
        //info!("Signal packet to remote: {:?}", command);
        controller.signal(conn, command).await?;
        // info!("Sent signal packet to remote, awaiting response");

        let (idx, state) = poll_fn(|cx| {
            self.state.lock(|state| {
                let mut state = state.borrow_mut();
                for (idx, storage) in state.channels.iter_mut().enumerate() {
                    match storage {
                        ChannelState::Disconnecting(req) if req.conn == conn && req.cid == cid => {
                            return Poll::Ready(Err(Error::Disconnected));
                        }
                        ChannelState::Connected(req) if req.conn == conn && req.cid == cid => {
                            return Poll::Ready(Ok((idx, req.clone())));
                        }
                        _ => {}
                    }
                }
                state.create_waker.register(cx.waker());
                Poll::Pending
            })
        })
        .await?;

        // info!("Peer setup cid {} Sending initial credits", state.peer_cid);

        // Send initial credits
        let next_req_id = self.next_request_id();
        controller
            .signal(
                conn,
                L2capLeSignal::new(
                    next_req_id,
                    L2capLeSignalData::LeCreditFlowInd(LeCreditFlowInd {
                        cid: state.cid,
                        credits,
                    }),
                ),
            )
            .await?;

        // info!("Done!");

        let rx = self.inbound[idx].receiver().into();

        Ok((state, rx))
    }

    pub async fn dispatch(&self, header: L2capHeader, packet: Packet<'d>) -> Result<(), Error> {
        if header.channel < BASE_ID {
            return Err(Error::InvalidChannelId);
        }

        let chan = (header.channel - BASE_ID) as usize;
        if chan > self.inbound.len() {
            return Err(Error::InvalidChannelId);
        }

        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connected(state) if header.channel == state.cid => {
                        if state.flow_control.available() == 0 {
                            // info!("No credits available on channel {}", state.cid);
                            return Err(Error::OutOfMemory);
                        }
                        state.flow_control.received(1);
                    }
                    _ => {}
                }
            }
            Ok(())
        })?;

        self.inbound[chan]
            .send(Some(Pdu::new(packet, header.length as usize)))
            .await;
        Ok(())
    }

    pub async fn control(&self, conn: ConnHandle, signal: L2capLeSignal) -> Result<(), Error> {
        // info!("Inbound signal: {:?}", signal);
        match signal.data {
            L2capLeSignalData::LeCreditConnReq(req) => {
                self.peer_connect(|i, c| PeerConnectingState {
                    conn,
                    cid: c,
                    psm: req.psm,
                    request_id: signal.id,
                    peer_cid: req.scid,
                    offered_credits: req.credits,
                    mps: req.mps,
                    mtu: req.mtu,
                })?;
                Ok(())
            }
            L2capLeSignalData::LeCreditConnRes(res) => {
                // info!("Got response to create request: {:?}", res);
                match res.result {
                    LeCreditConnResultCode::Success => {
                        // Must be a response of a previous request which should already by allocated a channel for
                        self.connected(signal.id, |idx, req| ConnectedState {
                            conn: req.conn,
                            cid: req.cid,
                            psm: req.psm,
                            flow_control: CreditFlowControl::new(req.flow_control_policy, req.initial_credits),
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
                info!("Disconnect request: {:?}!", req);
                self.disconnect(req.dcid)?;
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
    fn flow_control(&self, cid: u16) -> Result<Option<(ConnHandle, L2capLeSignal)>, Error> {
        let next_req_id = self.next_request_id();
        let ret = self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connected(state) if cid == state.cid => {
                        return Ok(state.flow_control.process().map(|credits| {
                            (
                                state.conn,
                                L2capLeSignal::new(
                                    next_req_id,
                                    L2capLeSignalData::LeCreditFlowInd(LeCreditFlowInd {
                                        cid: state.cid,
                                        credits,
                                    }),
                                ),
                            )
                        }));
                    }
                    _ => {}
                }
            }
            Err(Error::NotFound)
        })?;
        Ok(ret)
    }

    fn disconnect(&self, cid: u16) -> Result<(), Error> {
        ChannelManager::disconnect(self, cid)
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
            Err(Error::NotFound)
        })
    }

    fn poll_request_to_send(&self, cid: u16, credits: usize, cx: Option<&mut Context<'_>>) -> Poll<Result<(), Error>> {
        self.state.lock(|state| {
            let mut state = state.borrow_mut();
            for (idx, storage) in state.channels.iter_mut().enumerate() {
                match storage {
                    ChannelState::Connected(s) if cid == s.cid => {
                        if credits <= s.peer_credits as usize {
                            s.peer_credits -= credits as u16;
                            return Poll::Ready(Ok(()));
                        } else {
                            if let Some(cx) = cx {
                                state.credit_wakers[idx].register(cx.waker());
                            }
                            return Poll::Pending;
                        }
                    }
                    _ => {}
                }
            }
            Poll::Ready(Err(Error::NotFound))
        })
    }
}

pub enum ChannelState {
    Disconnected,
    Connecting(ConnectingState),
    PeerConnecting(PeerConnectingState),
    Connected(ConnectedState),
    Disconnecting(DisconnectingState),
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

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct CreditFlowControl {
    policy: CreditFlowPolicy,
    credits: u16,
    received: u16,
}

impl CreditFlowControl {
    fn new(policy: CreditFlowPolicy, initial_credits: u16) -> Self {
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
        let flow = match self.policy {
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
                if self.credits <= threshold {
                    let amount = self.received;
                    self.received = 0;
                    self.credits += amount;
                    Some(amount)
                } else {
                    None
                }
            }
        };
        flow
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectingState {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
    pub(crate) request_id: u8,
    pub(crate) flow_control_policy: CreditFlowPolicy,

    pub(crate) psm: u16,
    pub(crate) initial_credits: u16,
    pub(crate) mps: u16,
    pub(crate) mtu: u16,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PeerConnectingState {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
    pub(crate) request_id: u8,

    pub(crate) psm: u16,
    pub(crate) peer_cid: u16,
    pub(crate) offered_credits: u16,
    pub(crate) mps: u16,
    pub(crate) mtu: u16,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ConnectedState {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
    pub(crate) psm: u16,
    pub(crate) mps: u16,
    pub(crate) mtu: u16,
    pub(crate) flow_control: CreditFlowControl,

    pub(crate) peer_cid: u16,
    pub(crate) peer_credits: u16,

    pub(crate) pool_id: AllocId,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DisconnectingState {
    pub(crate) conn: ConnHandle,
    pub(crate) cid: u16,
}
