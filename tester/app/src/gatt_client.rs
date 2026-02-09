use alloc::boxed::Box;
use core::pin::Pin;

use bt_hci::param::{AddrKind, BdAddr};
use embassy_futures::select::{Either, select, select_slice};
use embassy_sync::channel::DynamicSender;
use trouble_host::prelude::*;

use crate::Event;
use crate::btp::protocol::gatt;
use crate::command_channel::{self, CommandReceiver, HasResponse};

/// Maximum number of discovered services cached per connection.
const MAX_SERVICES: usize = 16;
/// Maximum number of discovered characteristics cached per connection.
const MAX_CHARACTERISTICS: usize = 64;
/// Maximum number of concurrent notification/indication listeners.
const MAX_LISTENERS: usize = 16;

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
            | Command::CfgIndicate { addr_type, address, .. } => (addr_type, address),
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
        }
    }
}

/// Responses from the GATT client task back to the BTP dispatcher.
#[derive(Debug)]
#[allow(dead_code)] // Variants used once trouble-host API additions are made
pub enum Response {
    MtuExchanged,
    Services(Box<[gatt::ServiceInfo]>),
    Characteristics(Box<[gatt::CharacteristicInfo]>),
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

/// An active notification/indication listener with its metadata.
struct ActiveListener<'lst> {
    handle: u16,
    is_indication: bool,
    listener: NotificationListener<'lst, 512>,
}

/// GATT client task: processes client-side GATT operations (discovery, read, write, subscribe).
///
/// Idles until a command arrives targeting a connected peer, then creates a `GattClient`
/// and processes commands until the connection drops, at which point it returns to idle.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'stack, C, P>,
    commands: CommandReceiver<'_, Command>,
    events: DynamicSender<'_, Event>,
) -> ! {
    trace!("gatt_client::run");
    loop {
        // === Phase 1: Idle — wait for a command that requires a GattClient ===
        let (connection, first_cmd) = loop {
            let cmd = commands.receive().await;
            let addr = cmd.address();
            if let Some(conn) = stack.get_connection_by_peer_address(addr) {
                break (conn, cmd);
            }
            warn!("No connection for address {:?}", addr);
            cmd.reply(Response::Fail).await;
        };

        // === Phase 2: Connected — create GattClient and process commands ===
        let client: GattClient<'_, C, P, MAX_SERVICES> = match GattClient::new(stack, &connection).await {
            Ok(client) => client,
            Err(e) => {
                error!("Failed to create GattClient: {:?}", e);
                first_cmd.reply(Response::Fail).await;
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
        let mut cmd = Some(first_cmd);
        let mut cache = DiscoveryCache::new();
        let mut listeners: heapless::Vec<ActiveListener<'_>, MAX_LISTENERS> = heapless::Vec::new();
        let _result = select(client.task(), async {
            loop {
                let c = match cmd.take() {
                    Some(c) => c,
                    None => next_command(&commands, &mut listeners, &conn_address, &events).await,
                };
                if c.address() != conn_address {
                    warn!("Command address doesn't match connection");
                    c.reply(Response::Fail).await;
                    continue;
                }
                let response = execute_command(&client, &c, &mut cache, &mut listeners).await;
                c.reply(response).await;
            }
        })
        .await;
        // Connection dropped — client is dropped, return to idle
    }
}

/// Wait for the next command, polling active notification listeners concurrently.
///
/// When a notification fires, it is forwarded as an event and we continue
/// waiting. Returns only when a command is received.
async fn next_command<'a>(
    commands: &CommandReceiver<'a, Command>,
    listeners: &mut heapless::Vec<ActiveListener<'_>, MAX_LISTENERS>,
    conn_address: &Address,
    events: &DynamicSender<'_, Event>,
) -> command_channel::Command<'a, Command> {
    loop {
        if listeners.is_empty() {
            return commands.receive().await;
        }

        // Build notification futures that capture metadata by value, so we
        // don't need to re-borrow listeners after select resolves.
        let notification_futs: alloc::vec::Vec<_> = listeners
            .iter_mut()
            .map(|l| {
                let handle = l.handle;
                let is_indication = l.is_indication;
                async move {
                    let notification = l.listener.next().await;
                    (handle, is_indication, notification)
                }
            })
            .collect();
        let mut pinned: Pin<Box<[_]>> = Pin::from(notification_futs.into_boxed_slice());

        match select(commands.receive(), select_slice(pinned.as_mut())).await {
            Either::First(c) => return c,
            Either::Second(((handle, is_indication, notification), _idx)) => {
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
/// Populated by DiscoverPrimaryUuid and DiscoverChrcUuid, consumed by
/// subsequent commands that need a ServiceHandle or Characteristic.
struct DiscoveryCache {
    services: heapless::Vec<ServiceHandle, MAX_SERVICES>,
    characteristics: heapless::Vec<Characteristic<[u8]>, MAX_CHARACTERISTICS>,
}

impl DiscoveryCache {
    fn new() -> Self {
        Self {
            services: heapless::Vec::new(),
            characteristics: heapless::Vec::new(),
        }
    }

    /// Find a cached service by its handle range.
    fn find_service(&self, start: u16, end: u16) -> Option<&ServiceHandle> {
        self.services.iter().find(|s| s.handle_range() == (start..=end))
    }

    /// Find a cached characteristic by its handle.
    fn find_characteristic(&self, handle: u16) -> Option<&Characteristic<[u8]>> {
        self.characteristics.iter().find(|c| c.handle == handle)
    }

    /// Find a cached characteristic by its CCCD handle.
    fn find_characteristic_by_cccd(&self, cccd_handle: u16) -> Option<&Characteristic<[u8]>> {
        self.characteristics.iter().find(|c| c.cccd_handle == Some(cccd_handle))
    }
}

/// Execute a single GATT client command, returning the response.
async fn execute_command<'client, C: crate::Controller, P: PacketPool>(
    client: &'client GattClient<'_, C, P, MAX_SERVICES>,
    cmd: &command_channel::Command<'_, Command>,
    cache: &mut DiscoveryCache,
    listeners: &mut heapless::Vec<ActiveListener<'client>, MAX_LISTENERS>,
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
            let Some(service) = cache.find_service(*start_handle, *end_handle) else {
                error!("No cached service for handle range {}..={}", start_handle, end_handle);
                return Response::Fail;
            };
            match client.characteristic_by_uuid::<[u8]>(service, uuid).await {
                Ok(chrc) => {
                    if cache.characteristics.is_full() {
                        warn!("Characteristic cache full (max {})", MAX_CHARACTERISTICS);
                        return Response::Fail;
                    }
                    let info = gatt::CharacteristicInfo {
                        char_handle: chrc.handle,
                        value_handle: chrc.handle,
                        properties: chrc.props.to_raw(),
                        uuid: uuid.clone(),
                    };
                    // Cache for later Read/Write/CfgNotify lookups
                    let _ = cache.characteristics.push(chrc);
                    Response::Characteristics(alloc::vec![info].into_boxed_slice())
                }
                Err(e) => {
                    error!("DiscoverChrcUuid failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::Read { handle, .. } => {
            let Some(chrc) = cache.find_characteristic(*handle) else {
                error!("No cached characteristic for handle {}", handle);
                return Response::Fail;
            };
            let mut buf = alloc::vec![0u8; 512];
            match client.read_characteristic(chrc, &mut buf).await {
                Ok(len) => {
                    buf.truncate(len);
                    Response::ReadData(gatt::ReadDataResponse {
                        att_response: 0x00,
                        data: buf.into_boxed_slice(),
                    })
                }
                Err(e) => {
                    error!("Read failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::ReadLong { handle, offset, .. } => {
            let Some(chrc) = cache.find_characteristic(*handle) else {
                error!("No cached characteristic for handle {}", handle);
                return Response::Fail;
            };
            if *offset != 0 {
                error!("Trouble does not support read long with offset {}", offset);
                return Response::Fail;
            }
            let mut buf = alloc::vec![0u8; 512];
            match client.read_characteristic_long(chrc, &mut buf).await {
                Ok(len) => {
                    buf.truncate(len);
                    Response::ReadData(gatt::ReadDataResponse {
                        att_response: 0x00,
                        data: buf.into_boxed_slice(),
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
            let Some(service) = cache.find_service(*start_handle, *end_handle) else {
                error!("No cached service for handle range {}..={}", start_handle, end_handle);
                return Response::Fail;
            };
            let mut buf = alloc::vec![0u8; 512];
            match client.read_characteristic_by_uuid(service, uuid, &mut buf).await {
                Ok(len) => {
                    buf.truncate(len);
                    // TODO: This is wrong. We need to return the characteristic handle which is not exposed by trouble.
                    let value = gatt::CharacteristicValue {
                        handle: 0,
                        data: buf.into_boxed_slice(),
                    };
                    Response::ReadUuidData(gatt::ReadUuidDataResponse {
                        att_response: 0x00,
                        values: alloc::vec![value].into_boxed_slice(),
                    })
                }
                Err(e) => {
                    error!("ReadUuid failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::Write { handle, data, .. } => {
            let Some(chrc) = cache.find_characteristic(*handle) else {
                error!("No cached characteristic for handle {}", handle);
                return Response::Fail;
            };
            match client.write_characteristic(chrc, data).await {
                Ok(()) => Response::WriteResult(0x00),
                Err(e) => {
                    error!("Write failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::WriteWithoutRsp { handle, data, .. } => {
            let Some(chrc) = cache.find_characteristic(*handle) else {
                error!("No cached characteristic for handle {}", handle);
                return Response::Fail;
            };
            match client.write_characteristic_without_response(chrc, data).await {
                Ok(()) => Response::WriteWithoutRspDone,
                Err(e) => {
                    error!("WriteWithoutRsp failed: {:?}", e);
                    Response::Fail
                }
            }
        }
        Command::CfgNotify { enable, ccc_handle, .. } => {
            subscribe_cfg(client, cache, listeners, *ccc_handle, *enable, false).await
        }
        Command::CfgIndicate { enable, ccc_handle, .. } => {
            subscribe_cfg(client, cache, listeners, *ccc_handle, *enable, true).await
        }
    }
}

/// Handle CfgNotify/CfgIndicate: subscribe or unsubscribe, managing the listener list.
async fn subscribe_cfg<'client, C: crate::Controller, P: PacketPool>(
    client: &'client GattClient<'_, C, P, MAX_SERVICES>,
    cache: &DiscoveryCache,
    listeners: &mut heapless::Vec<ActiveListener<'client>, MAX_LISTENERS>,
    ccc_handle: u16,
    enable: bool,
    is_indication: bool,
) -> Response {
    trace!(
        "subscribe_cfg: ccc_handle={} enable={} indication={}",
        ccc_handle, enable, is_indication
    );
    let Some(chrc) = cache.find_characteristic_by_cccd(ccc_handle) else {
        error!("No cached characteristic for CCCD handle {}", ccc_handle);
        return Response::Fail;
    };

    if enable {
        if listeners.is_full() {
            error!("Cannot subscribe: listener limit ({}) reached", MAX_LISTENERS);
            return Response::Fail;
        }
        match client.subscribe(chrc, is_indication).await {
            Ok(listener) => {
                info!("Subscribed handle={}", chrc.handle);
                // Safety: checked is_full() above, so push cannot fail.
                let _ = listeners.push(ActiveListener {
                    handle: chrc.handle,
                    is_indication,
                    listener,
                });
                Response::CfgDone
            }
            Err(e) => {
                error!("Subscribe failed: {:?}", e);
                Response::Fail
            }
        }
    } else {
        // Remove the listener for this characteristic
        if let Some(idx) = listeners.iter().position(|l| l.handle == chrc.handle) {
            listeners.swap_remove(idx);
        }
        match client.unsubscribe(chrc).await {
            Ok(()) => {
                info!("Unsubscribed handle={}", chrc.handle);
                Response::CfgDone
            }
            Err(e) => {
                error!("Unsubscribe failed: {:?}", e);
                Response::Fail
            }
        }
    }
}
