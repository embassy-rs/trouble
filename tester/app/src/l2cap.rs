use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;

use embassy_futures::join::join3;
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, DynamicSender};
use embassy_sync::watch;
use trouble_host::prelude::*;

use crate::Event;
pub(crate) use crate::btp::L2capListenerConfig;
use crate::btp::protocol::l2cap::{self as proto, MAX_CHANNELS};
use crate::command_channel::{self, CommandReceiver, HasResponse};

/// Commands sent to the L2CAP task from the BTP dispatcher.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Command {
    Connect {
        address: Address,
        spsm: u16,
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

/// Whether the channel task should create an outgoing channel or receive on an accepted one.
enum ChannelOp<'stack, P: PacketPool> {
    Connect {
        conn: Connection<'stack, P>,
        spsm: u16,
        mtu: Option<u16>,
    },
    Accepted {
        reader: L2capChannelReader<'stack, P>,
        spsm: u16,
        address: Address,
    },
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
    Accepted {
        writer: L2capChannelWriter<'stack, P>,
        reader: L2capChannelReader<'stack, P>,
        spsm: u16,
        our_mtu: u16,
        our_mps: u16,
        peer_mtu: u16,
        peer_mps: u16,
        address: Address,
    },
    Rejected {
        spsm: u16,
        address: Address,
    },
}

type NotifyChannel<'stack, P> = embassy_sync::channel::Channel<NoopRawMutex, ChannelNotification<'stack, P>, 1>;

/// Drive all L2CAP channel lifecycle futures concurrently.
///
/// Owns a stack-pinned array of channel futures. Polls a receiver for new channel
/// requests and all active channel futures. Channel futures run to completion
/// (never cancelled) — they are only removed when they return.
async fn poll_channels<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'_, C, P>,
    rx: &embassy_sync::channel::Channel<NoopRawMutex, (ChannelOp<'stack, P>, u8), MAX_CHANNELS>,
    notify: &NotifyChannel<'stack, P>,
    events: &DynamicSender<'_, Event>,
) {
    let mut channels = core::array::from_fn::<_, MAX_CHANNELS, _>(|_| None);

    core::future::poll_fn(|cx| {
        // Check for new channel requests.
        if let Poll::Ready((op, chan_id)) = rx.poll_receive(cx) {
            let idx = chan_id as usize;
            if idx < MAX_CHANNELS && channels[idx].is_none() {
                channels[idx] = Some(channel_task(stack, op, chan_id, notify, events));
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

/// Listener task: loops over connections accepting/rejecting incoming L2CAP channels.
/// When a connection disconnects, next() returns an error and the inner loop breaks,
/// waiting for the next connection.
async fn listener_task<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'_, C, P>,
    args: L2capListenerConfig,
    conn_rx: &mut watch::DynReceiver<'_, Connection<'stack, P>>,
    notify: &NotifyChannel<'stack, P>,
) {
    let L2capListenerConfig { spsm, mtu, response } = args;

    loop {
        // Wait for a connection to become available
        let conn = conn_rx.changed().await;
        info!("listener_task: connection available, listening on SPSM {}", spsm);

        let listener = L2capChannel::listen(stack, &conn);

        // Listen on this connection until it disconnects
        loop {
            let config = L2capChannelConfig {
                mtu,
                mps: Some(64),
                ..Default::default()
            };
            let address = conn.peer_address();

            let pending = match listener.next().await {
                Ok(pending) => pending,
                Err(e) => {
                    info!("L2CAP listen ended (connection lost or error): {:?}", e);
                    break;
                }
            };

            if response != LeCreditConnResultCode::Success {
                if let Err(e) = pending.reject(stack, response).await {
                    error!("L2CAP reject failed: {:?}", e);
                }
                notify.send(ChannelNotification::Rejected { spsm, address }).await;
            } else {
                match pending.accept(stack, &config).await {
                    Ok(channel) => {
                        let our_mtu = channel.mtu();
                        let our_mps = channel.mps();
                        let peer_mtu = channel.peer_mtu();
                        let peer_mps = channel.peer_mps();
                        let (writer, reader) = channel.split();
                        notify
                            .send(ChannelNotification::Accepted {
                                writer,
                                reader,
                                spsm,
                                our_mtu,
                                our_mps,
                                peer_mtu,
                                peer_mps,
                                address,
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("L2CAP accept failed: {:?}", e);
                        notify.send(ChannelNotification::Rejected { spsm, address }).await;
                    }
                }
            }
        }
    }
}

/// Run one L2CAP channel lifecycle: create or receive data, exit on disconnect.
async fn channel_task<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'_, C, P>,
    op: ChannelOp<'stack, P>,
    chan_id: u8,
    notify: &NotifyChannel<'stack, P>,
    events: &DynamicSender<'_, Event>,
) {
    let (mut reader, spsm, address) = match op {
        ChannelOp::Connect { conn, spsm, mtu } => {
            let config = L2capChannelConfig {
                mtu,
                mps: Some(64),
                ..Default::default()
            };
            let address = conn.peer_address();

            let channel = match L2capChannel::create(stack, &conn, spsm, &config).await {
                Ok(ch) => ch,
                Err(e) => {
                    error!("L2CAP create failed: {:?}", e);
                    events.send(Event::L2capDisconnected { chan_id, spsm, address }).await;
                    notify.send(ChannelNotification::Done { chan_id }).await;
                    return;
                }
            };

            let our_mtu = channel.mtu();
            let our_mps = channel.mps();
            let peer_mtu = channel.peer_mtu();
            let peer_mps = channel.peer_mps();
            let (writer, reader) = channel.split();

            notify.send(ChannelNotification::Connected { chan_id, writer }).await;

            events
                .send(Event::L2capConnected {
                    chan_id,
                    spsm,
                    peer_mtu,
                    peer_mps,
                    our_mtu,
                    our_mps,
                    address,
                })
                .await;

            (reader, spsm, address)
        }
        ChannelOp::Accepted { reader, spsm, address } => (reader, spsm, address),
    };

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

    events.send(Event::L2capDisconnected { chan_id, spsm, address }).await;
    notify.send(ChannelNotification::Done { chan_id }).await;
}

/// L2CAP task: processes L2CAP CoC commands.
///
/// Loops forever, accepting commands and managing L2CAP connection-oriented channels.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'_, C, P>,
    commands: CommandReceiver<'_, Command>,
    events: DynamicSender<'_, Event>,
    conn_rx: &mut watch::DynReceiver<'_, Connection<'stack, P>>,
    listener_config: Option<L2capListenerConfig>,
) -> ! {
    trace!("l2cap::run");

    let args_tx: Channel<NoopRawMutex, (ChannelOp<'stack, P>, u8), MAX_CHANNELS> = Channel::new();
    let notify_ch: NotifyChannel<'stack, P> = Channel::new();

    let command_loop = async {
        let mut slots: [ChannelSlot<'stack, P>; MAX_CHANNELS] = Default::default();

        loop {
            match select(commands.receive(), notify_ch.receive()).await {
                Either::First(cmd) => {
                    info!("l2cap command: {:?}", *cmd);
                    match &*cmd {
                        Command::Connect {
                            address,
                            spsm,
                            mtu,
                            num,
                        } => {
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
                                    .send((
                                        ChannelOp::Connect {
                                            conn: conn.clone(),
                                            spsm: *spsm,
                                            mtu: mtu_opt,
                                        },
                                        free_idx as u8,
                                    ))
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
                                } else {
                                    warn!(
                                        "L2CAP Disconnect: no connected channel for {:?} (already disconnected)",
                                        chan_id
                                    );
                                }
                                cmd.reply(Response::Disconnected).await;
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
                Either::Second(notification) => match notification {
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
                    ChannelNotification::Accepted {
                        writer,
                        reader,
                        spsm,
                        our_mtu,
                        our_mps,
                        peer_mtu,
                        peer_mps,
                        address,
                    } => {
                        let free_idx = match slots.iter().position(|s| s.is_idle()) {
                            Some(idx) => idx,
                            None => {
                                error!("No free L2CAP slot for accepted channel");
                                continue;
                            }
                        };
                        let chan_id = free_idx as u8;
                        slots[free_idx] = ChannelSlot::Connected { writer };

                        events
                            .send(Event::L2capConnected {
                                chan_id,
                                spsm,
                                peer_mtu,
                                peer_mps,
                                our_mtu,
                                our_mps,
                                address,
                            })
                            .await;

                        args_tx
                            .send((ChannelOp::Accepted { reader, spsm, address }, chan_id))
                            .await;
                    }
                    ChannelNotification::Rejected { spsm, address } => {
                        events
                            .send(Event::L2capDisconnected {
                                chan_id: 0,
                                spsm,
                                address,
                            })
                            .await;
                    }
                },
            }
        }
    };

    let listener_future = async {
        if let Some(config) = listener_config {
            listener_task(stack, config, conn_rx, &notify_ch).await;
        } else {
            core::future::pending::<()>().await;
        }
    };

    join3(
        poll_channels(stack, &args_tx, &notify_ch, &events),
        listener_future,
        command_loop,
    )
    .await;
    unreachable!()
}
