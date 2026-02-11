use alloc::boxed::Box;

use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;
use trouble_host::prelude::*;

use crate::command_channel::{self, CommandReceiver, HasResponse};
use crate::{Event, Server};

/// Heap-backed mirror of `Advertisement` that owns its byte data via `Box<[u8]>`.
///
/// Constructing an `Advertisement<'_>` via `as_advertisement()` borrows from `&self`,
/// so the returned reference cannot outlive the `AdvertisementParams`.
pub enum AdvertisementParams {
    ConnectableScannableUndirected {
        adv_data: Box<[u8]>,
        scan_data: Box<[u8]>,
        bondable: bool,
    },
    ConnectableNonscannableDirected {
        peer: Address,
        bondable: bool,
    },
    ConnectableNonscannableDirectedHighDuty {
        peer: Address,
        bondable: bool,
    },
    NonconnectableScannableUndirected {
        adv_data: Box<[u8]>,
        scan_data: Box<[u8]>,
    },
    NonconnectableNonscannableUndirected {
        adv_data: Box<[u8]>,
    },
    ExtConnectableNonscannableUndirected {
        adv_data: Box<[u8]>,
        bondable: bool,
    },
    ExtConnectableNonscannableDirected {
        peer: Address,
        adv_data: Box<[u8]>,
        bondable: bool,
    },
    ExtNonconnectableScannableUndirected {
        scan_data: Box<[u8]>,
    },
    ExtNonconnectableNonscannableUndirected {
        adv_data: Box<[u8]>,
    },
}

impl AdvertisementParams {
    pub fn is_bondable(&self) -> bool {
        match self {
            AdvertisementParams::ConnectableScannableUndirected { bondable, .. }
            | AdvertisementParams::ConnectableNonscannableDirected { bondable, .. }
            | AdvertisementParams::ConnectableNonscannableDirectedHighDuty { bondable, .. }
            | AdvertisementParams::ExtConnectableNonscannableUndirected { bondable, .. }
            | AdvertisementParams::ExtConnectableNonscannableDirected { bondable, .. } => *bondable,
            _ => false,
        }
    }

    /// Construct `Advertisement<'_>` with lifetime tied to `&self`.
    pub fn as_advertisement(&self) -> Advertisement<'_> {
        match self {
            Self::ConnectableScannableUndirected {
                adv_data, scan_data, ..
            } => Advertisement::ConnectableScannableUndirected { adv_data, scan_data },
            &Self::ConnectableNonscannableDirected { peer, .. } => {
                Advertisement::ConnectableNonscannableDirected { peer }
            }
            &Self::ConnectableNonscannableDirectedHighDuty { peer, .. } => {
                Advertisement::ConnectableNonscannableDirectedHighDuty { peer }
            }
            Self::NonconnectableScannableUndirected { adv_data, scan_data } => {
                Advertisement::NonconnectableScannableUndirected { adv_data, scan_data }
            }
            Self::NonconnectableNonscannableUndirected { adv_data } => {
                Advertisement::NonconnectableNonscannableUndirected { adv_data }
            }
            Self::ExtConnectableNonscannableUndirected { adv_data, .. } => {
                Advertisement::ExtConnectableNonscannableUndirected { adv_data }
            }
            Self::ExtConnectableNonscannableDirected { peer, adv_data, .. } => {
                Advertisement::ExtConnectableNonscannableDirected { peer: *peer, adv_data }
            }
            Self::ExtNonconnectableScannableUndirected { scan_data } => {
                Advertisement::ExtNonconnectableScannableUndirected { scan_data }
            }
            Self::ExtNonconnectableNonscannableUndirected { adv_data } => {
                Advertisement::ExtNonconnectableNonscannableUndirected {
                    anonymous: false,
                    adv_data,
                }
            }
        }
    }
}

/// Commands sent to the peripheral task from the BTP dispatcher.
pub enum Command {
    StartAdvertising(AdvertisementParams),
    StopAdvertising,
}

impl core::fmt::Debug for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StartAdvertising(_) => write!(f, "StartAdvertising"),
            Self::StopAdvertising => write!(f, "StopAdvertising"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Command {
    fn format(&self, fmt: defmt::Formatter<'_>) {
        match self {
            Self::StartAdvertising(_) => defmt::write!(fmt, "StartAdvertising"),
            Self::StopAdvertising => defmt::write!(fmt, "StopAdvertising"),
        }
    }
}

/// Responses from the peripheral task back to the BTP dispatcher.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Response {
    StartedAdvertising,
    StoppedAdvertising,
    Fail,
}

impl HasResponse for Command {
    type Response = Response;
}

impl From<Response> for command_channel::Response {
    fn from(value: Response) -> Self {
        command_channel::Response::Peripheral(value)
    }
}

/// Peripheral task: processes advertising and connection commands.
///
/// Loops forever, accepting `StartAdvertising`/`StopAdvertising` commands.
/// When a connection is accepted, enters a GATT connection event loop until
/// the peer disconnects.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &Stack<'stack, C, P>,
    mut peripheral: Peripheral<'stack, C, P>,
    commands: CommandReceiver<'_, Command>,
    server: &Server<'_, P>,
    events: DynamicSender<'_, Event>,
) -> ! {
    trace!("peripheral::run");
    let mut cmd = commands.receive().await;

    loop {
        info!("peripheral command: {:?}", *cmd);
        match &*cmd {
            Command::StopAdvertising => cmd.reply(Response::StoppedAdvertising).await,
            Command::StartAdvertising(params) => {
                let bondable = params.is_bondable();
                let advertiser = match peripheral
                    .advertise(&AdvertisementParameters::default(), params.as_advertisement())
                    .await
                {
                    Ok(advertiser) => {
                        info!("Advertising started");
                        cmd.reply(Response::StartedAdvertising).await;
                        advertiser
                    }
                    Err(e) => {
                        error!("Failed to start advertising: {:?}", e);
                        cmd.reply(Response::Fail).await;
                        cmd = commands.receive().await;
                        continue;
                    }
                };

                let conn = match select(advertiser.accept(), async {
                    loop {
                        let cmd = commands.receive().await;
                        match &*cmd {
                            Command::StartAdvertising(_) => {
                                warn!("StartAdvertising during active advertising");
                                cmd.reply(Response::Fail).await;
                            }
                            Command::StopAdvertising => {
                                info!("Advertising stopped");
                                cmd.reply(Response::StoppedAdvertising).await;
                                break;
                            }
                        }
                    }
                })
                .await
                {
                    Either::First(Ok(conn)) => conn,
                    Either::First(Err(e)) => {
                        error!("Failed to accept connection: {:?}", e);
                        cmd = commands.receive().await;
                        continue;
                    }
                    Either::Second(()) => {
                        // StopAdvertising was received, go back to outer loop
                        cmd = commands.receive().await;
                        continue;
                    }
                };

                // Connection accepted - advertising stopped autonomously
                info!("Connection accepted");
                if let Err(err) = conn.set_bondable(bondable) {
                    error!("Failed to set bondable: {:?}", err);
                }

                events.send(Event::AdvertisingStopped).await;

                let address = crate::connection::peer_address(&conn);
                let conn_params = conn.params();

                events.send(Event::DeviceConnected { address, conn_params }).await;

                // Enter GATT connection event loop
                info!("Entering GATT connection loop");
                match conn.with_attribute_server(server) {
                    Ok(gatt_conn) => {
                        let res = crate::connection::run(stack, &gatt_conn, address, &events, async || {
                            let cmd = commands.receive().await;
                            match &*cmd {
                                Command::StartAdvertising(_) => cmd.reply(Response::Fail).await,
                                Command::StopAdvertising => {
                                    cmd.reply(Response::StoppedAdvertising).await;
                                }
                            }
                        })
                        .await;
                        if let Err(err) = res {
                            error!("Connection terminated with error: {:?}", err);
                        }
                    }
                    Err(e) => {
                        error!("Failed to create GATT connection: {:?}", e);
                    }
                }
            }
        }

        cmd = commands.receive().await;
    }
}
