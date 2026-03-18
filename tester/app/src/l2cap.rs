use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;

use embassy_futures::join::join;
use embassy_futures::select::{Either3, select3};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, DynamicSender};
use embassy_sync::signal::Signal;
use trouble_host::prelude::*;

use crate::Event;
use crate::btp::protocol::l2cap::{self as proto, MAX_CHANNELS};
use crate::command_channel::{self, CommandReceiver, HasResponse};

/// Signal used by peripheral/central tasks to notify the L2CAP task
/// that a new connection has been established.
pub type ConnectionSignal<'stack, P> = Signal<NoopRawMutex, Connection<'stack, P>>;

/// Commands sent to the L2CAP task from the BTP dispatcher.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Command {
    Listen {
        psm: u16,
        mtu: u16,
        response: LeCreditConnResultCode,
    },
    Connect {
        address: Address,
        psm: u16,
        mtu: u16,
        num: u8,
    },
    Disconnect {
        chan_id: u8,
    },
    SendData {
        chan_id: u8,
        data: Box<[u8]>,
    },
}

/// Responses from the L2CAP task back to the BTP dispatcher.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Response {
    Listening,
    Connecting(proto::ConnectingResponse),
    Disconnected,
    DataSent,
    Fail,
}

impl HasResponse for Command {
    type Response = Response;
}

impl From<Response> for command_channel::Response {
    fn from(value: Response) -> Self {
        command_channel::Response::L2cap(value)
    }
}

/// Tracks the lifecycle of each L2CAP channel slot.
#[derive(Default)]
enum ChannelSlot<'stack, P: PacketPool> {
    #[default]
    Idle,
    Connecting,
    Connected {
        writer: L2capChannelWriter<'stack, P>,
    },
}

impl<P: PacketPool> ChannelSlot<'_, P> {
    fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }
}

/// Arguments for starting a new channel task.
struct ChannelArgs<'stack, P: PacketPool> {
    op: ChannelOp,
    conn: Connection<'stack, P>,
    psm: u16,
    mtu: Option<u16>,
    chan_id: u8,
    response: LeCreditConnResultCode,
}

/// A deferred listen request waiting for a connection to become available.
struct PendingListen {
    psm: u16,
    mtu: u16,
    response: LeCreditConnResultCode,
    chan_id: u8,
}

/// Whether the channel task should accept an incoming or create an outgoing channel.
enum ChannelOp {
    Accept,
    Connect,
}

/// Notification from a channel task back to the main loop.
enum ChannelNotification<'stack, P: PacketPool> {
    Connected {
        chan_id: u8,
        writer: L2capChannelWriter<'stack, P>,
    },
    Done {
        chan_id: u8,
    },
}

type NotifyChannel<'stack, P> = embassy_sync::channel::Channel<NoopRawMutex, ChannelNotification<'stack, P>, 1>;

/// Drive all L2CAP channel lifecycle futures concurrently.
///
/// Owns a stack-pinned array of channel futures. Polls a receiver for new channel
/// requests and all active channel futures. Channel futures run to completion
/// (never cancelled) — they are only removed when they return.
async fn poll_channels<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'stack, C, P>,
    rx: &embassy_sync::channel::Channel<NoopRawMutex, ChannelArgs<'stack, P>, MAX_CHANNELS>,
    notify: &NotifyChannel<'stack, P>,
    events: &DynamicSender<'_, Event>,
) {
    let mut channels = core::array::from_fn::<_, MAX_CHANNELS, _>(|_| None);

    core::future::poll_fn(|cx| {
        // Check for new channel requests.
        if let Poll::Ready(args) = rx.poll_receive(cx) {
            let idx = args.chan_id as usize;
            if idx < MAX_CHANNELS && channels[idx].is_none() {
                channels[idx] = Some(channel_task(stack, args, notify, events));
            }
        }

        // Poll all active channel futures.
        for slot in channels.iter_mut() {
            if let Some(fut) = slot {
                // SAFETY: `channels` is a local that lives across the `.await` below, so it
                // is stored in poll_channels's generated Future state. Once that Future is
                // pinned (guaranteed by Rust's async model before the first poll), `channels`
                // is at a fixed address. Each slot transitions None → Some(fut) → polled →
                // None: futures are moved in only when the slot is None (never pinned yet),
                // accessed only via &mut references from iter_mut() (no move), and dropped
                // in-place by `*slot = None` after completion. No code path moves a future
                // out of its slot between the first pin and the in-place drop.
                if unsafe { Pin::new_unchecked(fut) }.poll(cx).is_ready() {
                    *slot = None;
                }
            }
        }

        // Never completes — channels are managed for the lifetime of the task.
        Poll::Pending
    })
    .await
}

/// Run one L2CAP channel lifecycle: accept/create, receive data, exit on disconnect.
async fn channel_task<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'stack, C, P>,
    args: ChannelArgs<'stack, P>,
    notify: &NotifyChannel<'stack, P>,
    events: &DynamicSender<'_, Event>,
) {
    let ChannelArgs {
        op,
        conn,
        psm,
        mtu,
        chan_id,
        response,
    } = args;
    let config = L2capChannelConfig {
        mtu,
        ..Default::default()
    };
    let address = crate::connection::peer_address(&conn);

    let channel = match op {
        ChannelOp::Accept => {
            let psm_list = [psm];

            let pending = match L2capChannel::listen(stack, &conn, &psm_list).await {
                Ok(pending) => pending,
                Err(e) => {
                    info!("L2CAP listen ended (connection lost or error): {:?}", e);
                    return;
                }
            };

            if response != LeCreditConnResultCode::Success {
                if let Err(e) = pending.reject(stack, response).await {
                    error!("L2CAP reject failed: {:?}", e);
                }
                events.send(Event::L2capDisconnected { chan_id, psm, address }).await;
                notify.send(ChannelNotification::Done { chan_id }).await;
                return;
            }
            match pending.accept(stack, &config).await {
                Ok(ch) => ch,
                Err(e) => {
                    error!("L2CAP accept failed: {:?}", e);
                    notify.send(ChannelNotification::Done { chan_id }).await;
                    return;
                }
            }
        }
        ChannelOp::Connect => match L2capChannel::create(stack, &conn, psm, &config).await {
            Ok(ch) => ch,
            Err(e) => {
                error!("L2CAP create failed: {:?}", e);
                events.send(Event::L2capDisconnected { chan_id, psm, address }).await;
                notify.send(ChannelNotification::Done { chan_id }).await;
                return;
            }
        },
    };

    let peer_mtu = channel.peer_mtu();
    let peer_mps = channel.peer_mps();
    let our_mtu = channel.mtu();
    let our_mps = channel.mps();

    let (writer, mut reader) = channel.split();

    notify.send(ChannelNotification::Connected { chan_id, writer }).await;

    events
        .send(Event::L2capConnected {
            chan_id,
            psm,
            peer_mtu,
            peer_mps,
            our_mtu,
            our_mps,
            address,
        })
        .await;

    let mut buf = [0u8; proto::MAX_DATA_SIZE];

    loop {
        match reader.receive(stack, &mut buf).await {
            Ok(len) => {
                events
                    .send(Event::L2capDataReceived {
                        chan_id,
                        data: Box::from(&buf[..len]),
                    })
                    .await;
            }
            Err(e) => {
                error!("L2CAP receive error on chan {}: {:?}", chan_id, e);
                break;
            }
        }
    }

    events.send(Event::L2capDisconnected { chan_id, psm, address }).await;
    notify.send(ChannelNotification::Done { chan_id }).await;
}

/// L2CAP task: processes L2CAP CoC commands.
///
/// Loops forever, accepting commands and managing L2CAP connection-oriented channels.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'stack, C, P>,
    commands: CommandReceiver<'_, Command>,
    events: DynamicSender<'_, Event>,
    connection_signal: &ConnectionSignal<'stack, P>,
) -> ! {
    trace!("l2cap::run");

    let args_tx: Channel<NoopRawMutex, ChannelArgs<'stack, P>, MAX_CHANNELS> = Channel::new();
    let notify_ch: NotifyChannel<'stack, P> = Channel::new();

    let command_loop = async {
        let mut slots: [ChannelSlot<'stack, P>; MAX_CHANNELS] = Default::default();
        let mut pending_listen: Option<PendingListen> = None;

        loop {
            match select3(commands.receive(), notify_ch.receive(), connection_signal.wait()).await {
                Either3::First(cmd) => {
                    info!("l2cap command: {:?}", *cmd);
                    match &*cmd {
                        Command::Listen { psm, mtu, response } => {
                            let free_idx = match slots.iter().position(|s| s.is_idle()) {
                                Some(idx) => idx,
                                None => {
                                    error!("No free L2CAP slot for accept");
                                    cmd.reply(Response::Fail).await;
                                    continue;
                                }
                            };
                            slots[free_idx] = ChannelSlot::Connecting;

                            match stack.connections().next() {
                                Some(conn) => {
                                    args_tx
                                        .send(ChannelArgs {
                                            op: ChannelOp::Accept,
                                            conn,
                                            psm: *psm,
                                            mtu: if *mtu > 0 { Some(*mtu) } else { None },
                                            chan_id: free_idx as u8,
                                            response: *response,
                                        })
                                        .await;
                                    cmd.reply(Response::Listening).await;
                                }
                                None => {
                                    info!("No active connection, deferring listen");
                                    pending_listen = Some(PendingListen {
                                        psm: *psm,
                                        mtu: *mtu,
                                        response: *response,
                                        chan_id: free_idx as u8,
                                    });
                                    cmd.reply(Response::Listening).await;
                                }
                            }
                        }
                        Command::Connect { address, psm, mtu, num } => {
                            let conn = match stack.get_connection_by_peer_address(*address) {
                                Some(conn) => conn,
                                None => {
                                    error!("No connection found for address {:?}", address);
                                    cmd.reply(Response::Fail).await;
                                    continue;
                                }
                            };
                            let mtu_opt = if *mtu > 0 { Some(*mtu) } else { None };
                            let num = (*num as usize).min(MAX_CHANNELS);
                            let mut chan_ids = heapless::Vec::<u8, MAX_CHANNELS>::new();
                            for _ in 0..num {
                                let free_idx = match slots.iter().position(|s| s.is_idle()) {
                                    Some(idx) => idx,
                                    None => {
                                        error!("No free L2CAP slot");
                                        break;
                                    }
                                };
                                slots[free_idx] = ChannelSlot::Connecting;
                                args_tx
                                    .send(ChannelArgs {
                                        op: ChannelOp::Connect,
                                        conn: conn.clone(),
                                        psm: *psm,
                                        mtu: mtu_opt,
                                        chan_id: free_idx as u8,
                                        response: LeCreditConnResultCode::Success,
                                    })
                                    .await;
                                let _ = chan_ids.push(free_idx as u8);
                            }
                            cmd.reply(Response::Connecting(proto::ConnectingResponse {
                                num: chan_ids.len() as u8,
                                chan_ids,
                            }))
                            .await;
                        }
                        Command::Disconnect { chan_id } => {
                            let chan_id = *chan_id as usize;
                            if chan_id < MAX_CHANNELS {
                                if let ChannelSlot::Connected { writer, .. } = &mut slots[chan_id] {
                                    // Disconnect the writer; the channel_task will detect the
                                    // closed channel, send the L2capDisconnected event, and
                                    // notify Done to reset the slot to Idle.
                                    writer.disconnect();
                                    cmd.reply(Response::Disconnected).await;
                                } else {
                                    cmd.reply(Response::Fail).await;
                                }
                            } else {
                                cmd.reply(Response::Fail).await;
                            }
                        }
                        Command::SendData { chan_id, data } => {
                            let chan_id = *chan_id as usize;
                            if chan_id < MAX_CHANNELS {
                                if let ChannelSlot::Connected { writer, .. } = &mut slots[chan_id] {
                                    match writer.send(stack, data).await {
                                        Ok(()) => cmd.reply(Response::DataSent).await,
                                        Err(e) => {
                                            error!("L2CAP send failed: {:?}", e);
                                            cmd.reply(Response::Fail).await;
                                        }
                                    }
                                } else {
                                    cmd.reply(Response::Fail).await;
                                }
                            } else {
                                cmd.reply(Response::Fail).await;
                            }
                        }
                    }
                }
                Either3::Second(notification) => match notification {
                    ChannelNotification::Connected { chan_id, writer } => {
                        let idx = chan_id as usize;
                        if idx < MAX_CHANNELS {
                            slots[idx] = ChannelSlot::Connected { writer };
                        }
                    }
                    ChannelNotification::Done { chan_id } => {
                        let idx = chan_id as usize;
                        if idx < MAX_CHANNELS {
                            slots[idx] = ChannelSlot::Idle;
                        }
                    }
                },
                Either3::Third(conn) => {
                    if let Some(listen) = pending_listen.take() {
                        info!("Connection arrived, starting deferred listen on PSM {}", listen.psm);
                        args_tx
                            .send(ChannelArgs {
                                op: ChannelOp::Accept,
                                conn,
                                psm: listen.psm,
                                mtu: if listen.mtu > 0 { Some(listen.mtu) } else { None },
                                chan_id: listen.chan_id,
                                response: listen.response,
                            })
                            .await;
                    }
                }
            }
        }
    };

    join(poll_channels(stack, &args_tx, &notify_ch, &events), command_loop).await;
    unreachable!()
}
