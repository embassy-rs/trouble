use embassy_sync::channel::DynamicSender;
use embassy_sync::watch;
use embassy_time::{Duration, with_timeout};
use trouble_host::Address;
use trouble_host::connection::{ConnectConfig, ScanConfig};
use trouble_host::prelude::*;
use trouble_host::scan::Scanner;

use crate::command_channel::{self, CommandReceiver, HasResponse};
use crate::{Event, OobState, Server};

/// Commands sent to the central task from the BTP dispatcher.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Command {
    StartDiscovery {
        active: bool,
        filter_accept_list: heapless::Vec<Address, 1>,
    },
    StopDiscovery,
    Connect {
        filter_accept_list: heapless::Vec<Address, 1>,
        bondable: bool,
    },
}

/// Responses from the central task back to the BTP dispatcher.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Response {
    DiscoveryStarted,
    DiscoveryStopped,
    Connecting,
    Fail,
}

impl HasResponse for Command {
    type Response = Response;
}

impl From<Response> for command_channel::Response {
    fn from(value: Response) -> Self {
        command_channel::Response::Central(value)
    }
}

/// Central task: processes discovery and connection commands.
///
/// Loops forever, accepting `StartDiscovery`/`StopDiscovery`/`Connect` commands.
/// When a connection is established, enters a GATT connection event loop until
/// the peer disconnects.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &Stack<'_, C, P>,
    mut central: Central<'stack, C, P>,
    commands: CommandReceiver<'_, Command>,
    server: &Server<'_, P>,
    events: DynamicSender<'_, Event>,
    conn_watch: &watch::DynSender<'_, Connection<'stack, P>>,
    oob: &OobState,
) -> ! {
    trace!("central::run");

    loop {
        let cmd = commands.receive().await;
        info!("central command: {:?}", *cmd);
        match &*cmd {
            Command::StartDiscovery {
                active,
                filter_accept_list,
            } => {
                // TODO: Use a proper device discovery procedure when Trouble supports it
                let config = ScanConfig {
                    active: *active,
                    filter_accept_list,
                    interval: Duration::from_millis(100),
                    window: Duration::from_millis(50),
                    ..Default::default()
                };
                let mut scanner = Scanner::new(central);
                match scanner.scan_ext(&config).await {
                    Ok(session) => {
                        info!("Scan started");
                        cmd.reply(Response::DiscoveryStarted).await;

                        // Hold scan session alive until StopDiscovery
                        let _session = session;
                        loop {
                            let inner_cmd = commands.receive().await;
                            match &*inner_cmd {
                                Command::StopDiscovery => {
                                    // Dropping _session will stop scanning
                                    info!("Scan stopped");
                                    inner_cmd.reply(Response::DiscoveryStopped).await;
                                    break;
                                }
                                Command::StartDiscovery { .. } | Command::Connect { .. } => {
                                    warn!("Command {:?} while scanning", *inner_cmd);
                                    inner_cmd.reply(Response::Fail).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to start scanning: {:?}", e);
                        cmd.reply(Response::Fail).await;
                    }
                }
                central = scanner.into_inner();
            }
            Command::StopDiscovery => {
                // Not currently scanning, treat as idempotent success
                cmd.reply(Response::DiscoveryStopped).await;
            }
            Command::Connect {
                filter_accept_list,
                bondable,
            } => {
                let filter_accept_list = filter_accept_list.clone();
                let bondable = *bondable;
                cmd.reply(Response::Connecting).await;

                let config = ConnectConfig {
                    scan_config: ScanConfig {
                        filter_accept_list: &filter_accept_list,
                        interval: Duration::from_millis(60),
                        window: Duration::from_millis(60),
                        ..Default::default()
                    },
                    connect_params: Default::default(),
                };

                // Dropping the connect future cancels the pending LeCreateConn
                let connect_result = match with_timeout(Duration::from_secs(30), central.connect_ext(&config)).await {
                    Ok(Ok(conn)) => Some(conn),
                    Ok(Err(e)) => {
                        error!("Failed to connect: {:?}", e);
                        None
                    }
                    Err(_) => {
                        warn!("Connect timed out after 30s");
                        None
                    }
                };

                match connect_result {
                    Some(conn) => {
                        info!("Connect success: {:?}", filter_accept_list);
                        if let Err(err) = conn.set_bondable(bondable) {
                            error!("Failed to set bondable: {:?}", err);
                        }

                        let conn_address = conn.peer_address();
                        let conn_params = conn.params();

                        events
                            .send(Event::DeviceConnected {
                                address: conn_address,
                                conn_params,
                            })
                            .await;

                        match conn.with_attribute_server(server) {
                            Ok(gatt_conn) => {
                                info!("Entering GATT connection loop");
                                let res = crate::connection::run(
                                    stack,
                                    &gatt_conn,
                                    conn_address,
                                    &events,
                                    conn_watch,
                                    oob,
                                    async || {
                                        let inner_cmd = commands.receive().await;
                                        match &*inner_cmd {
                                            Command::StartDiscovery { .. } | Command::Connect { .. } => {
                                                warn!("Command {:?} while connected", *inner_cmd);
                                                inner_cmd.reply(Response::Fail).await;
                                            }
                                            Command::StopDiscovery => {
                                                inner_cmd.reply(Response::DiscoveryStopped).await;
                                            }
                                        }
                                    },
                                )
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
                    None => {
                        // Send disconnected for whichever peer we were trying to reach
                        for peer in filter_accept_list.iter() {
                            events.send(Event::DeviceDisconnected { address: *peer }).await;
                        }
                    }
                }
            }
        }
    }
}
