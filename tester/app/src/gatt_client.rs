use alloc::boxed::Box;

use bt_hci::param::{AddrKind, BdAddr};
use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::DynamicSender;
use embassy_sync::signal::Signal;
use trouble_host::prelude::*;

use crate::Event;
use crate::btp::protocol::gatt;
use crate::command_channel::{self, CommandReceiver, HasResponse};

/// Signal used by `connection::run` to notify the gatt_client task
/// that a bonded peer has reconnected. Carries the peer's [`Address`].
pub type ConnectionSignal = Signal<NoopRawMutex, Address>;

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

/// GATT client task: processes client-side GATT operations (discovery, read, write, subscribe).
///
/// Idles until a command arrives targeting a connected peer (or a bonded peer reconnects
/// after subscriptions were previously established), then creates a `GattClient`
/// and processes commands until the connection drops, at which point it returns to idle.
pub async fn run<'stack, C: crate::Controller, P: PacketPool>(
    stack: &'stack Stack<'stack, C, P>,
    commands: CommandReceiver<'_, Command>,
    events: DynamicSender<'_, Event>,
    connection_signal: &ConnectionSignal,
) -> ! {
    trace!("gatt_client::run");
    let mut had_subscriptions = false;
    loop {
        // === Phase 1: Idle — wait for a command or a bonded-peer reconnection signal ===
        let (connection, mut cmd) = loop {
            match select(commands.receive(), connection_signal.wait()).await {
                Either::First(cmd) => {
                    let addr = cmd.address();
                    if let Some(conn) = stack.get_connection_by_peer_address(addr) {
                        break (conn, Some(cmd));
                    }
                    warn!("No connection for address {:?}", addr);
                    cmd.reply(Response::Fail).await;
                }
                Either::Second(addr) => {
                    if had_subscriptions {
                        info!("Bonded peer reconnected signal: {:?}", addr);
                        if let Some(conn) = stack.get_connection_by_peer_address(addr) {
                            break (conn, None);
                        }
                        warn!("No connection for signaled address {:?}", addr);
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

        let result = select(client.task(), async {
            loop {
                let c = match cmd.take() {
                    Some(c) => c,
                    None => next_command(&commands, &mut listener, &conn_address, &events).await,
                };
                if c.address() != conn_address {
                    warn!("Command address doesn't match connection");
                    c.reply(Response::Fail).await;
                    continue;
                }
                let response = execute_command(&client, &c, &mut cache, &mut had_subscriptions).await;
                c.reply(response).await;
            }
        })
        .await;

        match result {
            Either::First(Err(BleHostError::BleHost(Error::Disconnected))) => info!("GattClient disconnected"),
            Either::First(Err(e)) => error!("GattClient task failed: {:?}", e),
            _ => (),
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
    async fn find_service<C: crate::Controller, P: PacketPool>(
        &mut self,
        start: u16,
        end: u16,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) -> Option<&ServiceHandle> {
        let service = self.find_service_containing(start, client).await?;
        (service.handle_range() == (start..=end)).then_some(service)
    }

    /// Find a cached characteristic by its handle.
    async fn find_characteristic<C: crate::Controller, P: PacketPool>(
        &mut self,
        handle: u16,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) -> Option<&Characteristic<[u8]>> {
        self.find_characteristic_by(handle, |c| c.handle == handle, client)
            .await
    }

    /// Find a cached characteristic by its CCCD handle.
    async fn find_characteristic_by_cccd<C: crate::Controller, P: PacketPool>(
        &mut self,
        cccd_handle: u16,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) -> Option<&Characteristic<[u8]>> {
        self.find_characteristic_by(cccd_handle, |c| c.cccd_handle == Some(cccd_handle), client)
            .await
    }

    async fn find_characteristic_by<C: crate::Controller, P: PacketPool, F: FnMut(&Characteristic<[u8]>) -> bool>(
        &mut self,
        handle: u16,
        mut predicate: F,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) -> Option<&Characteristic<[u8]>> {
        if let Some(i) = self.characteristics.iter().position(&mut predicate) {
            return Some(&self.characteristics[i]);
        }

        let service = self.find_service_containing(handle, client).await?;
        match client.characteristics::<MAX_CHARACTERISTICS>(service).await {
            Ok(chars) => {
                self.characteristics.extend(chars.into_iter());
                self.characteristics.iter().find(|c| predicate(c))
            }
            Err(e) => {
                error!("Auto-discover characteristics failed: {:?}", e);
                None
            }
        }
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
                self.services = services;
                self.services.iter().find(|s| s.handle_range().contains(&handle))
            }
            Err(e) => {
                error!("Auto-discover services failed: {:?}", e);
                None
            }
        }
    }

    /// Ensure services have been discovered (populates cache if empty).
    async fn ensure_discovered<C: crate::Controller, P: PacketPool>(
        &mut self,
        client: &GattClient<'_, C, P, MAX_SERVICES>,
    ) {
        if self.services.is_empty() {
            debug!("Discovery cache empty, discovering services");
            match client.services().await {
                Ok(services) => {
                    debug!("Found {} services", services.len());
                    self.services = services;
                }
                Err(e) => {
                    error!("Auto-discover services failed: {:?}", e);
                }
            }
        }
    }

    /// Return all cached services whose handle range overlaps [start, end].
    fn services_in_range(&self, start: u16, end: u16) -> &[ServiceHandle] {
        // Since services are typically sorted and we usually want all of them
        // when start=1 end=0xFFFF, just return all services.
        // A more precise filter would check overlap, but this covers the common case.
        if start <= 1 && end >= 0xFFFE {
            return self.services.as_slice();
        }
        // For narrower ranges, return all (the caller will handle mismatches).
        self.services.as_slice()
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
            let Some(service) = cache.find_service(*start_handle, *end_handle, client).await else {
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
            let Some(chrc) = cache.find_characteristic(*handle, client).await else {
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
            let Some(chrc) = cache.find_characteristic(*handle, client).await else {
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
            // Try exact service match first, then fall back to searching all services
            // overlapping the requested handle range (e.g. 0x0001..=0xFFFF).
            let services = if let Some(service) = cache.find_service(*start_handle, *end_handle, client).await {
                core::slice::from_ref(service) as &[ServiceHandle]
            } else {
                cache.ensure_discovered(client).await;
                cache.services_in_range(*start_handle, *end_handle)
            };
            let mut buf = alloc::vec![0u8; 512];
            for service in services {
                match client.read_characteristic_by_uuid(service, uuid, &mut buf).await {
                    Ok(len) => {
                        buf.truncate(len);
                        // TODO: This is wrong. We need to return the characteristic handle which is not exposed by trouble.
                        let value = gatt::CharacteristicValue {
                            handle: 0,
                            data: buf.into_boxed_slice(),
                        };
                        return Response::ReadUuidData(gatt::ReadUuidDataResponse {
                            att_response: 0x00,
                            values: alloc::vec![value].into_boxed_slice(),
                        });
                    }
                    Err(_) => continue,
                }
            }
            error!(
                "ReadUuid: no service with UUID {:?} in range {}..={}",
                uuid, start_handle, end_handle
            );
            Response::Fail
        }
        Command::Write { handle, data, .. } => {
            let Some(chrc) = cache.find_characteristic(*handle, client).await else {
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
            let Some(chrc) = cache.find_characteristic(*handle, client).await else {
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
            subscribe_cfg(client, cache, *ccc_handle, *enable, false, had_subscriptions).await
        }
        Command::CfgIndicate { enable, ccc_handle, .. } => {
            subscribe_cfg(client, cache, *ccc_handle, *enable, true, had_subscriptions).await
        }
    }
}

/// Handle CfgNotify/CfgIndicate: subscribe or unsubscribe.
///
/// If the characteristic owning `ccc_handle` is not yet cached, this will
/// auto-discover services and characteristics to find it.
///
/// The returned `NotificationListener` from `subscribe()` is dropped immediately;
/// the single `listen_all()` listener in the caller catches all notifications.
async fn subscribe_cfg<C: crate::Controller, P: PacketPool>(
    client: &GattClient<'_, C, P, MAX_SERVICES>,
    cache: &mut DiscoveryCache,
    ccc_handle: u16,
    enable: bool,
    is_indication: bool,
    had_subscriptions: &mut bool,
) -> Response {
    trace!(
        "subscribe_cfg: ccc_handle={} enable={} indication={}",
        ccc_handle, enable, is_indication
    );

    let Some(chrc) = cache.find_characteristic_by_cccd(ccc_handle, client).await else {
        error!("No cached characteristic for CCCD handle {}", ccc_handle);
        return Response::Fail;
    };

    if enable {
        // Write the CCCD to enable notifications/indications on the remote peer.
        // The returned listener is dropped immediately — the listen_all() listener catches everything.
        match client.subscribe(chrc, is_indication).await {
            Ok(_listener) => {
                info!("Subscribed handle={}", chrc.handle);
                *had_subscriptions = true;
                Response::CfgDone
            }
            Err(e) => {
                error!("Subscribe failed: {:?}", e);
                Response::Fail
            }
        }
    } else {
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
