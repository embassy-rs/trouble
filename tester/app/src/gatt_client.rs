use alloc::boxed::Box;
use core::ops::ControlFlow;

use bt_hci::param::{AddrKind, BdAddr};
use embassy_futures::select::{Either, select};
use embassy_sync::channel::DynamicSender;
use embassy_sync::watch;
use trouble_host::prelude::*;

use crate::Event;
use crate::btp::protocol::gatt;
use crate::command_channel::{self, CommandReceiver, HasResponse};

/// Maximum number of discovered services cached per connection.
const MAX_SERVICES: usize = 32;
/// Maximum number of discovered characteristics cached per connection.
const MAX_CHARACTERISTICS: usize = 64;

/// Commands forwarded from btp::run to the gatt_client task.
///
/// Each variant carries the parsed BTP command data needed to execute
/// the operation on a `GattClient`.
pub enum Command {
    ExchangeMtu {
        addr_type: AddrKind,
        address: BdAddr,
    },
    DiscoverPrimaryUuid {
        addr_type: AddrKind,
        address: BdAddr,
        uuid: Uuid,
    },
    DiscoverChrcUuid {
        addr_type: AddrKind,
        address: BdAddr,
        start_handle: u16,
        end_handle: u16,
        uuid: Uuid,
    },
    Read {
        addr_type: AddrKind,
        address: BdAddr,
        handle: u16,
    },
    ReadLong {
        addr_type: AddrKind,
        address: BdAddr,
        handle: u16,
        offset: u16,
    },
    ReadUuid {
        addr_type: AddrKind,
        address: BdAddr,
        start_handle: u16,
        end_handle: u16,
        uuid: Uuid,
    },
    Write {
        addr_type: AddrKind,
        address: BdAddr,
        handle: u16,
        data: Box<[u8]>,
    },
    WriteWithoutRsp {
        addr_type: AddrKind,
        address: BdAddr,
        handle: u16,
        data: Box<[u8]>,
    },
    CfgNotify {
        addr_type: AddrKind,
        address: BdAddr,
        enable: bool,
        ccc_handle: u16,
    },
    CfgIndicate {
        addr_type: AddrKind,
        address: BdAddr,
        enable: bool,
        ccc_handle: u16,
    },
    DiscoverAllPrimary {
        addr_type: AddrKind,
        address: BdAddr,
    },
    DiscoverAllChrc {
        addr_type: AddrKind,
        address: BdAddr,
        start_handle: u16,
        end_handle: u16,
    },
    DiscoverAllDesc {
        addr_type: AddrKind,
        address: BdAddr,
        start_handle: u16,
        end_handle: u16,
    },
}

impl Command {
    /// Get the address from any command variant.
    fn address(&self) -> Address {
        let (kind, addr) = match self {
            Command::ExchangeMtu { addr_type, address, .. }
            | Command::DiscoverPrimaryUuid { addr_type, address, .. }
            | Command::DiscoverChrcUuid { addr_type, address, .. }
            | Command::Read { addr_type, address, .. }
            | Command::ReadLong { addr_type, address, .. }
            | Command::ReadUuid { addr_type, address, .. }
            | Command::Write { addr_type, address, .. }
            | Command::WriteWithoutRsp { addr_type, address, .. }
            | Command::CfgNotify { addr_type, address, .. }
            | Command::CfgIndicate { addr_type, address, .. }
            | Command::DiscoverAllPrimary { addr_type, address, .. }
            | Command::DiscoverAllChrc { addr_type, address, .. }
            | Command::DiscoverAllDesc { addr_type, address, .. } => (addr_type, address),
        };
        Address {
            kind: *kind,
            addr: *addr,
        }
    }
}

impl core::fmt::Debug for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ExchangeMtu { .. } => write!(f, "ExchangeMtu"),
            Self::DiscoverPrimaryUuid { .. } => write!(f, "DiscoverPrimaryUuid"),
            Self::DiscoverChrcUuid { .. } => write!(f, "DiscoverChrcUuid"),
            Self::Read { .. } => write!(f, "Read"),
            Self::ReadLong { .. } => write!(f, "ReadLong"),
            Self::ReadUuid { .. } => write!(f, "ReadUuid"),
            Self::Write { .. } => write!(f, "Write"),
            Self::WriteWithoutRsp { .. } => write!(f, "WriteWithoutRsp"),
            Self::CfgNotify { .. } => write!(f, "CfgNotify"),
            Self::CfgIndicate { .. } => write!(f, "CfgIndicate"),
            Self::DiscoverAllPrimary { .. } => write!(f, "DiscoverAllPrimary"),
            Self::DiscoverAllChrc { .. } => write!(f, "DiscoverAllChrc"),
            Self::DiscoverAllDesc { .. } => write!(f, "DiscoverAllDesc"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Command {
    fn format(&self, fmt: defmt::Formatter<'_>) {
        match self {
            Self::ExchangeMtu { .. } => defmt::write!(fmt, "ExchangeMtu"),
            Self::DiscoverPrimaryUuid { .. } => defmt::write!(fmt, "DiscoverPrimaryUuid"),
            Self::DiscoverChrcUuid { .. } => defmt::write!(fmt, "DiscoverChrcUuid"),
            Self::Read { .. } => defmt::write!(fmt, "Read"),
            Self::ReadLong { .. } => defmt::write!(fmt, "ReadLong"),
            Self::ReadUuid { .. } => defmt::write!(fmt, "ReadUuid"),
            Self::Write { .. } => defmt::write!(fmt, "Write"),
            Self::WriteWithoutRsp { .. } => defmt::write!(fmt, "WriteWithoutRsp"),
            Self::CfgNotify { .. } => defmt::write!(fmt, "CfgNotify"),
            Self::CfgIndicate { .. } => defmt::write!(fmt, "CfgIndicate"),
            Self::DiscoverAllPrimary { .. } => defmt::write!(fmt, "DiscoverAllPrimary"),
            Self::DiscoverAllChrc { .. } => defmt::write!(fmt, "DiscoverAllChrc"),
            Self::DiscoverAllDesc { .. } => defmt::write!(fmt, "DiscoverAllDesc"),
        }
    }
}

/// Responses from the GATT client task back to the BTP dispatcher.
#[derive(Debug)]
pub enum Response {
    MtuExchanged,
    Services(Box<[gatt::ServiceInfo]>),
    Characteristics(Box<[gatt::CharacteristicInfo]>),
    Descriptors(Box<[gatt::DescriptorInfo]>),
    ReadData(gatt::ReadDataResponse),
    ReadUuidData(gatt::ReadUuidDataResponse),
    WriteResult(u8),
    WriteWithoutRspDone,
    CfgDone,
    Fail,
}

#[cfg(feature = "defmt")]
impl defmt::Format for Response {
    fn format(&self, fmt: defmt::Formatter<'_>) {
        match self {
            Self::MtuExchanged => defmt::write!(fmt, "MtuExchanged"),
            Self::Services(s) => defmt::write!(fmt, "Services(count={})", s.len()),
            Self::Characteristics(c) => defmt::write!(fmt, "Characteristics(count={})", c.len()),
            Self::Descriptors(d) => defmt::write!(fmt, "Descriptors(count={})", d.len()),
            Self::ReadData(r) => {
                defmt::write!(fmt, "ReadData(att_rsp={}, len={})", r.att_response, r.data.len())
            }
            Self::ReadUuidData(r) => {
                defmt::write!(
                    fmt,
                    "ReadUuidData(att_rsp={}, count={})",
                    r.att_response,
                    r.values.len()
                )
            }
            Self::WriteResult(r) => defmt::write!(fmt, "WriteResult({})", r),
            Self::WriteWithoutRspDone => defmt::write!(fmt, "WriteWithoutRspDone"),
            Self::CfgDone => defmt::write!(fmt, "CfgDone"),
            Self::Fail => defmt::write!(fmt, "Fail"),
        }
    }
}

impl HasResponse for Command {
    type Response = Response;
}

impl From<Response> for command_channel::Response {
    fn from(value: Response) -> Self {
        command_channel::Response::GattClient(value)
    }
}

/// GATT client task: processes client-side GATT operations (discovery, read, write, subscribe).
///
/// Idles until a command arrives targeting a connected peer (or a bonded peer reconnects
/// after subscriptions were previously established), then creates a `GattClient`
/// and processes commands until the connection drops, at which point it returns to idle.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'stack, C, P>,
    commands: CommandReceiver<'_, Command>,
    events: DynamicSender<'_, Event>,
    conn_rx: &mut watch::DynReceiver<'_, Connection<'stack, P>>,
) -> ! {
    trace!("gatt_client::run");
    let mut had_subscriptions = false;
    loop {
        // === Phase 1: Idle — wait for a command or a connection via Watch ===
        let (connection, mut cmd) = loop {
            match select(commands.receive(), conn_rx.changed()).await {
                Either::First(cmd) => {
                    let addr = cmd.address();
                    if let Some(conn) = stack.get_connection_by_peer_address(addr) {
                        break (conn, Some(cmd));
                    }
                    warn!("No connection for address {:?}", addr);
                    cmd.reply(Response::Fail).await;
                }
                Either::Second(conn) => {
                    if had_subscriptions && conn.is_bonded_peer() {
                        info!("Connection signal received for gatt_client");
                        break (conn, None);
                    }
                }
            }
        };

        // === Phase 2: Connected — create GattClient and process commands ===
        let client: GattClient<'_, C, P, MAX_SERVICES> = match GattClient::new(stack, &connection).await {
            Ok(client) => client,
            Err(e) => {
                error!("Failed to create GattClient: {:?}", e);
                if let Some(cmd) = cmd {
                    cmd.reply(Response::Fail).await;
                }
                continue;
            }
        };

        // Run client.task() concurrently with command processing.
        // When client.task() completes (connection dropped), we return to Phase 1.
        let conn_address = Address {
            kind: connection.peer_addr_kind(),
            addr: connection.peer_address(),
        };
        info!("GattClient created for {:?}", conn_address);
        let mut cache = DiscoveryCache::new();
        let mut listener = match client.listen_all() {
            Ok(l) => l,
            Err(e) => {
                error!("Failed to create listen_all listener: {:?}", e);
                if let Some(cmd) = cmd.take() {
                    cmd.reply(Response::Fail).await;
                }
                continue;
            }
        };

        let mut c = cmd.take();
        loop {
            let command = match c.take() {
                Some(c) => c,
                None => {
                    match select(
                        client.task(),
                        next_command(&commands, &mut listener, &conn_address, &events),
                    )
                    .await
                    {
                        Either::First(_) => {
                            info!("GattClient disconnected");
                            break;
                        }
                        Either::Second(c) => c,
                    }
                }
            };

            if command.address() != conn_address {
                warn!("Command address doesn't match connection");
                command.reply(Response::Fail).await;
                continue;
            }

            match select(
                client.task(),
                execute_command(&client, &command, &mut cache, &mut had_subscriptions),
            )
            .await
            {
                Either::First(_) => {
                    info!("GattClient disconnected during command");
                    let response = disconnect_response(&command);
                    command.reply(response).await;
                    break;
                }
                Either::Second(response) => {
                    command.reply(response).await;
                }
            }
        }
    }
}

/// Wait for the next command, polling the catch-all notification listener concurrently.
///
/// When a notification fires, it is forwarded as an event and we continue
/// waiting. Returns only when a command is received.
async fn next_command<'a>(
    commands: &CommandReceiver<'a, Command>,
    listener: &mut NotificationListener<'_, 512>,
    conn_address: &Address,
    events: &DynamicSender<'_, Event>,
) -> command_channel::Command<'a, Command> {
    loop {
        match select(commands.receive(), listener.next()).await {
            Either::First(c) => return c,
            Either::Second(notification) => {
                let handle = notification.handle();
                let is_indication = notification.is_indication();
                trace!("Notification received: handle={} indication={}", handle, is_indication);
                if let Err(e) = events.try_send(Event::NotificationReceived {
                    address: *conn_address,
                    is_indication,
                    handle,
                    data: Box::from(notification.as_ref()),
                }) {
                    error!("Failed to send notification event: {:?}", e);
                }
            }
        }
    }
}

/// Cached discovery state for the current connection.
///
/// Populated by DiscoverPrimaryUuid, consumed by subsequent commands
/// that need a ServiceHandle.
struct DiscoveryCache {
    services: heapless::Vec<ServiceHandle, MAX_SERVICES>,
}

impl DiscoveryCache {
    fn new() -> Self {
        Self {
            services: heapless::Vec::new(),
        }
    }

    /// Find indices of all cached services whose handle ranges overlap with the given range.
    async fn find_services_overlapping<C: crate::Controller, P: PacketPool>(
        &mut self,
        start: u16,
        end: u16,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) -> heapless::Vec<usize, MAX_SERVICES> {
        // Ensure services are discovered
        if self.services.is_empty() {
            debug!("Cached service not found, starting discovery");
            match client.services().await {
                Ok(services) => {
                    debug!("Found {} services", services.len());
                    for svc in services.iter() {
                        debug!(
                            "  service: start={}, end={}, uuid={:?}",
                            svc.handle_range().start(),
                            svc.handle_range().end(),
                            svc.uuid(),
                        );
                    }
                    self.services = services;
                }
                Err(e) => {
                    error!("Auto-discover services failed: {:?}", e);
                }
            }
        }
        let mut result = heapless::Vec::new();
        for (i, svc) in self.services.iter().enumerate() {
            let svc_start = *svc.handle_range().start();
            let svc_end = *svc.handle_range().end();
            // Ranges overlap if one starts before the other ends
            if svc_start <= end && svc_end >= start {
                let _ = result.push(i);
            }
        }
        result
    }

    /// Find a cached service by its handle range.
    async fn find_service<C: crate::Controller, P: PacketPool>(
        &mut self,
        start: u16,
        end: u16,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) -> Option<&ServiceHandle> {
        let service = self.find_service_containing(start, client).await?;
        (service.handle_range() == (start..=end)).then_some(service)
    }

    /// Find the cached service whose handle range contains the given handle.
    async fn find_service_containing<C: crate::Controller, P: PacketPool>(
        &mut self,
        handle: u16,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) -> Option<&ServiceHandle> {
        if let Some(i) = self.services.iter().position(|s| s.handle_range().contains(&handle)) {
            return Some(&self.services[i]);
        }

        debug!("Cached service not found, starting discovery");
        match client.services().await {
            Ok(services) => {
                debug!("Found {} services", services.len());
                for svc in services.iter() {
                    debug!(
                        "  service: start={}, end={}, uuid={:?}",
                        svc.handle_range().start(),
                        svc.handle_range().end(),
                        svc.uuid(),
                    );
                }
                self.services = services;
                self.services.iter().find(|s| s.handle_range().contains(&handle))
            }
            Err(e) => {
                error!("Auto-discover services failed: {:?}", e);
                None
            }
        }
    }
}

/// Extract a BTP-suitable ATT response code from a `BleHostError`.
///
/// Returns the ATT error code for ATT errors, or maps Timeout/Disconnected
/// to a non-zero code so BTP responses carry a valid ATT_Response value
/// instead of falling through to a generic Fail.
fn att_error_code<E>(err: &BleHostError<E>) -> Option<u8> {
    match err {
        BleHostError::BleHost(Error::Att(code)) => Some(code.to_u8()),
        BleHostError::BleHost(Error::Timeout) | BleHostError::BleHost(Error::Disconnected) => Some(0x0e),
        _ => None,
    }
}

/// Response to send when disconnection interrupts a command.
///
/// Uses ATT Unlikely Error (0x0e) for commands that carry an ATT response code,
/// matching what `att_error_code()` returns for `Error::Disconnected`.
fn disconnect_response(cmd: &command_channel::Command<'_, Command>) -> Response {
    const UNLIKELY_ERROR: u8 = 0x0e;
    match &**cmd {
        Command::Read { .. } | Command::ReadLong { .. } => Response::ReadData(gatt::ReadDataResponse {
            att_response: UNLIKELY_ERROR,
            data: Box::from([]),
        }),
        Command::ReadUuid { .. } => Response::ReadUuidData(gatt::ReadUuidDataResponse {
            att_response: UNLIKELY_ERROR,
            values: Box::from([]),
        }),
        Command::Write { .. } => Response::WriteResult(UNLIKELY_ERROR),
        _ => Response::Fail,
    }
}

/// Execute a single GATT client command, returning the response.
async fn execute_command<C: crate::Controller, P: PacketPool>(
    client: &GattClient<'_, C, P, MAX_SERVICES>,
    cmd: &command_channel::Command<'_, Command>,
    cache: &mut DiscoveryCache,
    had_subscriptions: &mut bool,
) -> Response {
    trace!("execute_command: {:?}", **cmd);
    match &**cmd {
        Command::ExchangeMtu { .. } => {
            // MTU exchange happens automatically in GattClient::new()
            Response::MtuExchanged
        }
        Command::DiscoverPrimaryUuid { uuid, .. } => {
            match client.services_by_uuid(uuid).await {
                Ok(discovered) => {
                    let available = cache.services.capacity() - cache.services.len();
                    if discovered.len() > available {
                        warn!(
                            "Service cache full: need {} slots but only {} available (max {})",
                            discovered.len(),
                            available,
                            MAX_SERVICES
                        );
                        return Response::Fail;
                    }
                    let infos: alloc::vec::Vec<gatt::ServiceInfo> = discovered
                        .iter()
                        .map(|s| {
                            let range = s.handle_range();
                            gatt::ServiceInfo {
                                start_handle: *range.start(),
                                end_handle: *range.end(),
                                uuid: s.uuid(),
                            }
                        })
                        .collect();
                    // Cache for later DiscoverChrcUuid / ReadUuid lookups
                    cache.services.extend(discovered.into_iter());
                    Response::Services(infos.into_boxed_slice())
                }
                Err(e) => {
                    error!("DiscoverPrimaryUuid failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::DiscoverChrcUuid {
            start_handle,
            end_handle,
            uuid,
            ..
        } => {
            let service_indices = cache
                .find_services_overlapping(*start_handle, *end_handle, client)
                .await;
            if service_indices.is_empty() {
                return Response::Characteristics(alloc::vec![].into_boxed_slice());
            }
            for idx in service_indices {
                match client.characteristic_by_uuid::<[u8]>(&cache.services[idx], uuid).await {
                    Ok(chrc) => {
                        // Filter: only return characteristics within the requested range
                        if chrc.handle < *start_handle || chrc.handle > *end_handle {
                            continue;
                        }
                        let info = gatt::CharacteristicInfo {
                            char_handle: chrc.handle,
                            value_handle: chrc.handle,
                            properties: chrc.props.to_raw(),
                            uuid: *uuid,
                        };
                        return Response::Characteristics(alloc::vec![info].into_boxed_slice());
                    }
                    Err(BleHostError::BleHost(Error::NotFound)) => continue,
                    Err(e) => {
                        error!("DiscoverChrcUuid failed: {:?}", e);
                        return Response::Fail;
                    }
                }
            }
            Response::Characteristics(alloc::vec![].into_boxed_slice())
        }
        Command::Read { handle, .. } => {
            let mut buf = alloc::vec![0u8; 512];
            let result = client.read_handle(*handle, &mut buf).await;
            match result {
                Ok(len) => {
                    buf.truncate(len);
                    Response::ReadData(gatt::ReadDataResponse {
                        att_response: 0x00,
                        data: buf.into_boxed_slice(),
                    })
                }
                Err(ref e) if att_error_code(e).is_some() => {
                    let code = att_error_code(e).unwrap();
                    warn!("Read returned ATT error: {:#x}", code);
                    Response::ReadData(gatt::ReadDataResponse {
                        att_response: code,
                        data: Box::from([]),
                    })
                }
                Err(e) => {
                    error!("Read failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::ReadLong { handle, offset, .. } => {
            let mut buf = alloc::vec![0u8; 512];
            let result = client.read_handle_blob(*handle, *offset, &mut buf).await;
            match result {
                Ok(len) => {
                    buf.truncate(len);
                    Response::ReadData(gatt::ReadDataResponse {
                        att_response: 0x00,
                        data: buf.into_boxed_slice(),
                    })
                }
                Err(ref e) if att_error_code(e).is_some() => {
                    let code = att_error_code(e).unwrap();
                    warn!("ReadLong returned ATT error: {:#x}", code);
                    Response::ReadData(gatt::ReadDataResponse {
                        att_response: code,
                        data: Box::from([]),
                    })
                }
                Err(e) => {
                    error!("ReadLong failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::ReadUuid {
            start_handle,
            end_handle,
            uuid,
            ..
        } => {
            let mut values: alloc::vec::Vec<gatt::CharacteristicValue> = alloc::vec::Vec::new();

            let result = client
                .read_by_type(*start_handle, *end_handle, uuid, |handle, data| {
                    values.push(gatt::CharacteristicValue {
                        handle,
                        data: data.into(),
                    });
                    ControlFlow::<()>::Continue(())
                })
                .await;

            match result {
                Ok(_) if !values.is_empty() => Response::ReadUuidData(gatt::ReadUuidDataResponse {
                    att_response: 0x00,
                    values: values.into_boxed_slice(),
                }),
                Ok(_) => {
                    // No values found and no ATT error — shouldn't normally happen
                    // since ATTRIBUTE_NOT_FOUND would be returned, but handle gracefully.
                    Response::ReadUuidData(gatt::ReadUuidDataResponse {
                        att_response: 0x0a, // ATTRIBUTE_NOT_FOUND
                        values: Box::from([]),
                    })
                }
                Err(ref e) if att_error_code(e).is_some() => {
                    let code = att_error_code(e).unwrap();
                    warn!("ReadUuid returned ATT error: {:#x}", code);
                    Response::ReadUuidData(gatt::ReadUuidDataResponse {
                        att_response: code,
                        values: Box::from([]),
                    })
                }
                Err(e) => {
                    error!("ReadUuid failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::Write { handle, data, .. } => {
            let result = client.write_handle(*handle, data).await;
            match result {
                Ok(()) => Response::WriteResult(0x00),
                Err(ref e) if att_error_code(e).is_some() => {
                    let code = att_error_code(e).unwrap();
                    warn!("Write returned ATT error: {:#x}", code);
                    Response::WriteResult(code)
                }
                Err(e) => {
                    error!("Write failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::WriteWithoutRsp { handle, data, .. } => {
            let result = client.write_handle_without_response(*handle, data).await;
            match result {
                Ok(()) => Response::WriteWithoutRspDone,
                Err(e) => {
                    error!("WriteWithoutRsp failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::DiscoverAllPrimary { .. } => match client.services().await {
            Ok(discovered) => {
                let infos: alloc::vec::Vec<gatt::ServiceInfo> = discovered
                    .iter()
                    .map(|s| {
                        let range = s.handle_range();
                        gatt::ServiceInfo {
                            start_handle: *range.start(),
                            end_handle: *range.end(),
                            uuid: s.uuid(),
                        }
                    })
                    .collect();
                cache.services = discovered;
                Response::Services(infos.into_boxed_slice())
            }
            Err(e) => {
                error!("DiscoverAllPrimary failed: {:?}", e);
                Response::Fail
            }
        },
        Command::DiscoverAllChrc {
            start_handle,
            end_handle,
            ..
        } => {
            let Some(service) = cache.find_service(*start_handle, *end_handle, client).await else {
                error!("No cached service for handle range {}..={}", start_handle, end_handle);
                return Response::Fail;
            };
            match client.characteristics::<MAX_CHARACTERISTICS>(service).await {
                Ok(chars) => {
                    let infos: alloc::vec::Vec<gatt::CharacteristicInfo> = chars
                        .iter()
                        .map(|c| gatt::CharacteristicInfo {
                            char_handle: c.handle - 1,
                            value_handle: c.handle,
                            properties: c.props.to_raw(),
                            uuid: c.uuid,
                        })
                        .collect();
                    Response::Characteristics(infos.into_boxed_slice())
                }
                Err(e) => {
                    error!("DiscoverAllChrc failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::DiscoverAllDesc {
            start_handle,
            end_handle,
            ..
        } => {
            let mut infos: alloc::vec::Vec<gatt::DescriptorInfo> = alloc::vec::Vec::new();
            let result = client
                .find_information(*start_handle, *end_handle, |handle, uuid| {
                    infos.push(gatt::DescriptorInfo { handle, uuid });
                    ControlFlow::<()>::Continue(())
                })
                .await;
            match result {
                Ok(_) => Response::Descriptors(infos.into_boxed_slice()),
                Err(e) => {
                    error!("DiscoverAllDesc failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::CfgNotify { enable, ccc_handle, .. } => {
            subscribe_cfg(client, *ccc_handle, *enable, false, had_subscriptions).await
        }
        Command::CfgIndicate { enable, ccc_handle, .. } => {
            subscribe_cfg(client, *ccc_handle, *enable, true, had_subscriptions).await
        }
    }
}

/// Handle CfgNotify/CfgIndicate: write the CCCD to enable or disable.
///
/// Uses a raw handle write since the BTP command provides the CCCD handle directly.
async fn subscribe_cfg<C: crate::Controller, P: PacketPool>(
    client: &GattClient<'_, C, P, MAX_SERVICES>,
    ccc_handle: u16,
    enable: bool,
    is_indication: bool,
    had_subscriptions: &mut bool,
) -> Response {
    trace!(
        "subscribe_cfg: ccc_handle={} enable={} indication={}",
        ccc_handle, enable, is_indication
    );

    let value: u16 = if enable {
        if is_indication { 0x02 } else { 0x01 }
    } else {
        0x00
    };

    match client.write_handle(ccc_handle, &value.to_le_bytes()).await {
        Ok(()) => {
            info!("CCCD write handle={} value={:#04x}", ccc_handle, value);
            if enable {
                *had_subscriptions = true;
            }
            Response::CfgDone
        }
        Err(e) => {
            error!("CCCD write failed: {:?}", e);
            Response::Fail
        }
    }
}
