use core::cell::Cell;
use core::pin::pin;

use embassy_futures::select::{Either, select};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::DynamicReceiver;
use embassy_time::Duration;
use embedded_io_async::{Read, Write};
use static_cell::StaticCell;
use trouble_host::prelude::*;

use self::error::Error;
use self::protocol::core::{CoreCommand, CoreEvent, CoreResponse};
use self::protocol::gap::{
    ConnParamUpdateEvent, ControllerIndexListResponse, ControllerInfoResponse, DeviceConnectedEvent, DeviceFoundEvent,
    DeviceFoundFlags, GapCommand, GapEvent, GapResponse, GapSettings, LIMITED_DISCOVERABLE, MAX_SHORT_NAME_LEN,
    PairingFailedEvent, PasskeyConfirmRequestEvent, PasskeyDisplayEvent, SecLevelChangedEvent,
};
use self::protocol::gatt::{
    AttrValueChangedEvent, GattCommand, GattEvent as BtpGattEvent, GattResponse, ServerStartedResponse,
};
use self::protocol::l2cap::{L2capCommand, L2capEvent, L2capResponse};
use self::protocol::{BtpCommand, BtpEvent, BtpHeader, BtpPacket, BtpResponse, BtpStatus};
use self::service_builder::{AttValue, ServiceBuilder};
use crate::command_channel::CommandChannels;
use crate::{
    ATTRIBUTE_TABLE_SIZE, BtpConfig, Event, GAP_ATTRIBUTE_COUNT, GATT_ATTRIBUTE_COUNT, ScanMode, central,
    command_channel, gatt_client, l2cap, peripheral,
};

pub(crate) mod error;
pub(crate) mod protocol;
mod service_builder;
mod types;

/// Initial GAP current_settings at startup (powered, connectable, bondable, LE).
const DEFAULT_SETTINGS: GapSettings = GapSettings::POWERED
    .union(GapSettings::CONNECTABLE)
    .union(GapSettings::BONDABLE)
    .union(GapSettings::LE)
    .union(GapSettings::STATIC_ADDRESS)
    .union(GapSettings::SECURE_CONNECTIONS);

/// BTP packet transport holding the async reader and writer.
pub(crate) struct BtpTransport<R, W> {
    pub reader: R,
    pub writer: W,
}

/// Trait abstracting GAP operations that differ between pre-server and post-server phases.
trait GapOps {
    fn set_io_capabilities(&self, capability: IoCapabilities);
    fn set_mitm(&self, enabled: bool, real_capability: IoCapabilities);
    fn set_secure_connections_only(&self, enabled: bool);
    fn get_local_oob_data(&self) -> Result<OobData, BtpStatus>;
    fn enable_privacy(&self) -> Result<(), BtpStatus>;
    async fn set_rpa_timeout(&self, timeout: Duration) -> Result<(), BtpStatus>;
}

/// Pre-server GAP backend that stores deferred settings for later application to a StackBuilder.
pub(crate) struct PreServerGap {
    /// Whether MITM protection is enabled (determines effective IO capability).
    mitm: Cell<bool>,
    /// Deferred secure-connections-only setting.
    sc_only: Cell<bool>,
    enable_privacy: Cell<bool>,
    rpa_timeout: Cell<Duration>,
}

impl GapOps for PreServerGap {
    fn set_io_capabilities(&self, _capability: IoCapabilities) {
        self.mitm.set(true);
    }

    fn set_mitm(&self, enabled: bool, _real_capability: IoCapabilities) {
        self.mitm.set(enabled);
    }

    fn set_secure_connections_only(&self, enabled: bool) {
        self.sc_only.set(enabled);
    }

    fn get_local_oob_data(&self) -> Result<OobData, BtpStatus> {
        Err(BtpStatus::NotReady)
    }

    fn enable_privacy(&self) -> Result<(), BtpStatus> {
        self.enable_privacy.set(true);
        Ok(())
    }

    async fn set_rpa_timeout(&self, timeout: Duration) -> Result<(), BtpStatus> {
        self.rpa_timeout.set(timeout);
        Ok(())
    }
}

/// Post-server GAP backend that delegates operations to a live Stack.
pub(crate) struct StackGap<'a, 'b, C, P: PacketPool> {
    stack: &'a Stack<'b, C, P>,
}

impl<'a, 'b, C, P: PacketPool> GapOps for StackGap<'a, 'b, C, P>
where
    C: crate::Controller,
{
    fn set_io_capabilities(&self, capability: IoCapabilities) {
        self.stack.set_io_capabilities(capability);
    }

    fn set_mitm(&self, enabled: bool, real_capability: IoCapabilities) {
        if enabled {
            self.stack.set_io_capabilities(real_capability);
        } else {
            self.stack.set_io_capabilities(IoCapabilities::NoInputNoOutput);
        }
    }

    fn set_secure_connections_only(&self, enabled: bool) {
        self.stack.set_secure_connections_only(enabled);
    }

    fn get_local_oob_data(&self) -> Result<OobData, BtpStatus> {
        Ok(self.stack.get_local_oob_data())
    }

    fn enable_privacy(&self) -> Result<(), BtpStatus> {
        Err(BtpStatus::NotReady)
    }

    async fn set_rpa_timeout(&self, timeout: Duration) -> Result<(), BtpStatus> {
        self.stack.set_rpa_timeout(timeout).await.map_err(|_| BtpStatus::Fail)
    }
}

/// Mutable GAP state tracked across both BTP phases, generic over a backend.
pub(crate) struct GapState<'a, B> {
    current_settings: GapSettings,
    filter_accept_list: heapless::Vec<Address, 1>,
    scan_mode: &'a Cell<ScanMode>,
    /// Saved IO capability (for SET_MITM toggling).
    io_capability: IoCapabilities,
    /// Shared OOB state.
    oob: &'a crate::OobState,
    /// Pre-generated IRK for privacy.
    irk: IdentityResolvingKey,
    backend: B,
}

impl<'a> GapState<'a, PreServerGap> {
    /// Apply deferred settings to a StackBuilder, returning the configured builder.
    pub(crate) fn apply_to_builder<'b, C, P: PacketPool>(
        &self,
        mut builder: StackBuilder<'b, C, P>,
    ) -> StackBuilder<'b, C, P>
    where
        C: crate::Controller,
    {
        let effective_io = if self.backend.mitm.get() {
            self.io_capability
        } else {
            IoCapabilities::NoInputNoOutput
        };

        if self.backend.enable_privacy.get() {
            builder = builder.enable_privacy(self.irk);
        }

        builder
            .set_io_capabilities(effective_io)
            .set_secure_connections_only(self.backend.sc_only.get())
            .set_rpa_timeout(self.backend.rpa_timeout.get())
    }

    /// Convert this pre-server GapState into a post-server GapState backed by a Stack.
    pub(crate) fn into_stack_gap<'b, C, P: PacketPool>(
        self,
        stack: &'a Stack<'b, C, P>,
    ) -> GapState<'a, StackGap<'a, 'b, C, P>> {
        GapState {
            current_settings: self.current_settings,
            filter_accept_list: self.filter_accept_list,
            scan_mode: self.scan_mode,
            io_capability: self.io_capability,
            oob: self.oob,
            irk: self.irk,
            backend: StackGap { stack },
        }
    }
}

/// Result of a BTP command handler, supporting immediate, error, and forwarded outcomes.
enum HandlerResult<T> {
    /// Response is ready now.
    Ready(T),
    /// Error.
    Error(BtpStatus),
    /// Command was forwarded; await response on the given channel.
    Forwarded,
}

impl<T> HandlerResult<T> {
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> HandlerResult<U> {
        match self {
            HandlerResult::Ready(res) => HandlerResult::Ready(f(res)),
            HandlerResult::Forwarded => HandlerResult::Forwarded,
            HandlerResult::Error(err) => HandlerResult::Error(err),
        }
    }
}

impl<T> From<Result<T, BtpStatus>> for HandlerResult<T> {
    fn from(value: Result<T, BtpStatus>) -> Self {
        match value {
            Ok(val) => Self::Ready(val),
            Err(err) => Self::Error(err),
        }
    }
}

/// L2CAP listener configuration captured during the pre-server phase.
pub(crate) struct L2capListenerConfig {
    pub spsm: u16,
    pub mtu: Option<u16>,
    pub response: LeCreditConnResultCode,
}

/// Result of the pre-server BTP phase.
pub(crate) struct PreServerResult<'a, R, W> {
    pub transport: BtpTransport<R, W>,
    pub gap: GapState<'a, PreServerGap>,
    pub l2cap_listener: Option<L2capListenerConfig>,
}

/// Run the pre-server BTP phase.
///
/// Handles Core, GATT building, and GAP settings commands. Returns when
/// `StartServer` is received or a runtime command triggers auto-finalize.
/// The packet retains the unprocessed command for `btp::run` to handle.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_pre_server<'a, R: Read, W: Write>(
    transport: BtpTransport<R, W>,
    config: &BtpConfig<'_>,
    scan_mode: &'a Cell<ScanMode>,
    oob: &'a crate::OobState,
    irk: IdentityResolvingKey,
    table: &mut AttributeTable<'a, NoopRawMutex, ATTRIBUTE_TABLE_SIZE>,
    packet: &mut BtpPacket,
) -> Result<Option<PreServerResult<'a, R, W>>, Error> {
    let BtpTransport { mut reader, mut writer } = transport;

    static SERVICE_BUILDER: StaticCell<ServiceBuilder> = StaticCell::new();
    let service_builder = SERVICE_BUILDER.init(ServiceBuilder::new());

    let mut gap = GapState {
        current_settings: DEFAULT_SETTINGS,
        filter_accept_list: heapless::Vec::new(),
        scan_mode,
        io_capability: IoCapabilities::NoInputNoOutput,
        oob,
        irk,
        backend: PreServerGap {
            mitm: Cell::new(true),
            sc_only: Cell::new(false),
            enable_privacy: Cell::new(false),
            rpa_timeout: Cell::new(Duration::from_secs(900)),
        },
    };

    let mut l2cap_listener: Option<L2capListenerConfig> = None;

    // Send IUT Ready event before entering the main loop
    info!("Sending IUT Ready event");
    BtpEvent::Core(CoreEvent::IutReady).write(&mut writer).await?;

    loop {
        packet.read(&mut reader).await?;

        let result = BtpCommand::parse(&packet.header, packet.data());
        let command = match result {
            Ok(cmd) => cmd,
            Err(e) => {
                error!(
                    "Command parse error: {:?} header={:?} data={:?}",
                    e,
                    packet.header,
                    packet.data()
                );
                packet.header.write_err(e.into(), &mut writer).await?;
                continue;
            }
        };

        info!("Pre-server command: {:?}", command);

        let response = match command {
            BtpCommand::Core(core_command) => Ok(BtpResponse::Core(handle_core(core_command))),
            BtpCommand::Gap(gap_command) => handle_gap_settings(packet.header, &gap_command, config, &mut gap)
                .await
                .map(BtpResponse::Gap),
            BtpCommand::Gatt(gatt_command) => {
                handle_gatt_pre_server(gatt_command, service_builder, table).map(BtpResponse::Gatt)
            }
            BtpCommand::L2cap(l2cap_command) => match l2cap_command {
                L2capCommand::ReadSupportedCommands => Ok(BtpResponse::L2cap(L2capResponse::SupportedCommands(
                    protocol::l2cap::SUPPORTED_COMMANDS,
                ))),
                L2capCommand::Listen(listen) => {
                    let mtu = if listen.mtu > 0 { Some(listen.mtu) } else { None };
                    l2cap_listener = Some(L2capListenerConfig {
                        spsm: listen.psm,
                        mtu,
                        response: listen.response,
                    });
                    Ok(BtpResponse::L2cap(L2capResponse::Empty))
                }
                _ => Err(BtpStatus::NotReady),
            },
        };

        match response {
            Ok(ref resp) => {
                info!("Pre-server response: {:?}", resp);
                resp.write(&packet.header, &mut writer).await?;
            }
            Err(BtpStatus::NotReady) => {
                // Runtime command — finalize the table and exit
                info!("Exiting pre-server phase (auto-finalize)");
                service_builder.finalize(table).ok();
                return Ok(Some(PreServerResult {
                    transport: BtpTransport { reader, writer },
                    gap,
                    l2cap_listener,
                }));
            }
            Err(status) => {
                info!("Pre-server error response: {:?}", status);
                packet.header.write_err(status, &mut writer).await?;
            }
        }

        if !gap.current_settings.contains(GapSettings::POWERED) {
            info!("No longer powered — shutting down");
            return Ok(None);
        }
    }
}

/// Handle GATT commands during the pre-server phase (service/characteristic building).
fn handle_gatt_pre_server<'a>(
    cmd: GattCommand<'a>,
    service_builder: &mut ServiceBuilder,
    table: &mut AttributeTable<'_, NoopRawMutex, ATTRIBUTE_TABLE_SIZE>,
) -> Result<GattResponse, BtpStatus> {
    use protocol::gatt::GattCommand::*;
    use protocol::gatt::SUPPORTED_COMMANDS;

    trace!("handle_gatt_pre_server: {:?}", cmd);

    match cmd {
        ReadSupportedCommands => Ok(GattResponse::SupportedCommands(SUPPORTED_COMMANDS)),
        AddService(cmd) => service_builder
            .add_service(table, cmd.service_type, cmd.uuid)
            .map(GattResponse::ServiceAdded),
        AddCharacteristic(cmd) => {
            if cmd.service_id != 0 {
                Err(BtpStatus::Fail)
            } else {
                service_builder
                    .add_characteristic(cmd.properties, cmd.permissions, cmd.uuid)
                    .map(GattResponse::CharacteristicAdded)
            }
        }
        AddDescriptor(cmd) => {
            if cmd.char_id != 0 {
                Err(BtpStatus::Fail)
            } else {
                service_builder
                    .add_descriptor(cmd.permissions, cmd.uuid)
                    .map(GattResponse::DescriptorAdded)
            }
        }
        AddIncludedService(service_id) => service_builder
            .add_included_service(service_id)
            .map(GattResponse::IncludedServiceAdded),

        SetValue(cmd) => {
            if cmd.attr_id != 0 {
                Err(BtpStatus::Fail)
            } else {
                let value = AttValue::from_slice(cmd.value);
                service_builder.set_value(value).map(|_| GattResponse::ValueSet)
            }
        }
        SetEncKeySize { attr_id, key_size } => service_builder
            .set_enc_key_size(attr_id, key_size)
            .map(|_| GattResponse::EncKeySizeSet),
        StartServer => Err(BtpStatus::NotReady),
        _ => Err(BtpStatus::NotReady),
    }
}

/// Read the next packet while interleaving event delivery.
async fn read_with_events<R: Read, W: Write>(
    packet: &mut BtpPacket,
    reader: &mut R,
    events: &DynamicReceiver<'_, Event>,
    current_settings: &mut GapSettings,
    writer: &mut W,
) -> Result<(), Error> {
    trace!("read_with_events");
    let mut read_fut = pin!(packet.read(&mut *reader));
    loop {
        match select(&mut read_fut, events.receive()).await {
            Either::First(result) => break result,
            Either::Second(event) => {
                let btp_event = convert_event(&event, current_settings);
                info!("BTP event (while reading): {:?}", btp_event);
                btp_event.write(&mut *writer).await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<'a, 'b, R: Read, W: Write, C, P: PacketPool>(
    transport: BtpTransport<R, W>,
    mut gap: GapState<'a, StackGap<'a, 'b, C, P>>,
    config: &BtpConfig<'_>,
    server: &crate::Server<'_, P>,
    stack: &'a Stack<'b, C, P>,
    events: DynamicReceiver<'_, Event>,
    channels: &CommandChannels<'_>,
    packet: &mut BtpPacket,
) -> Result<(), Error>
where
    C: crate::Controller,
{
    info!("btp::run");

    let BtpTransport { mut reader, mut writer } = transport;

    // Process-then-read loop: the packet already contains a command from
    // run_pre_server on the first iteration (StartServer or a runtime command
    // that triggered auto-finalize).
    loop {
        // 1. Parse + dispatch command already in packet
        let result = BtpCommand::parse(&packet.header, packet.data());
        let command = match result {
            Ok(cmd) => cmd,
            Err(e) => {
                error!(
                    "Command parse error: {:?} header={:?} data={:?}",
                    e,
                    packet.header,
                    packet.data()
                );
                packet.header.write_err(e.into(), &mut writer).await?;
                // Read next packet and continue
                read_with_events(packet, &mut reader, &events, &mut gap.current_settings, &mut writer).await?;
                continue;
            }
        };

        info!("BTP command: {:?}", command);

        let response = match command {
            BtpCommand::Core(core_command) => HandlerResult::Ready(BtpResponse::Core(handle_core(core_command))),
            BtpCommand::Gap(gap_command) => handle_gap(packet.header, &gap_command, config, &mut gap, channels)
                .await
                .map(BtpResponse::Gap),
            BtpCommand::Gatt(gatt_command) => handle_gatt(gatt_command, server, stack, channels)
                .await
                .map(BtpResponse::Gatt),
            BtpCommand::L2cap(l2cap_command) => handle_l2cap(l2cap_command, channels).await.map(BtpResponse::L2cap),
        };

        // 2. Write response
        let response =
            match response {
                HandlerResult::Ready(resp) => Ok(resp),
                HandlerResult::Error(err) => Err(err),
                HandlerResult::Forwarded => {
                    let response = loop {
                        match select(channels.response.receive(), events.receive()).await {
                            Either::First(response) => {
                                info!("Forwarded response: {:?}", response);
                                break response;
                            }
                            Either::Second(event) => {
                                let btp_event = convert_event(&event, &mut gap.current_settings);
                                info!("BTP event (while forwarded): {:?}", btp_event);
                                btp_event.write(&mut writer).await?;
                            }
                        }
                    };

                    match response {
                        command_channel::Response::Peripheral(response) => {
                            match response {
                                peripheral::Response::StartedAdvertising => Ok(BtpResponse::Gap(
                                    change_current_settings(&mut gap.current_settings, GapSettings::ADVERTISING, true),
                                )),
                                peripheral::Response::StoppedAdvertising => Ok(BtpResponse::Gap(
                                    change_current_settings(&mut gap.current_settings, GapSettings::ADVERTISING, false),
                                )),
                                peripheral::Response::Fail => Err(BtpStatus::Fail),
                            }
                        }
                        command_channel::Response::Central(response) => match response {
                            central::Response::DiscoveryStarted => Ok(BtpResponse::Gap(GapResponse::Success)),
                            central::Response::DiscoveryStopped => Ok(BtpResponse::Gap(GapResponse::Success)),
                            central::Response::Connecting => Ok(BtpResponse::Gap(GapResponse::Success)),
                            central::Response::Fail => Err(BtpStatus::Fail),
                        },
                        command_channel::Response::GattClient(response) => {
                            use gatt_client::Response as GR;
                            match response {
                                GR::MtuExchanged => Ok(BtpResponse::Gatt(GattResponse::MtuExchanged)),
                                GR::Services(s) => Ok(BtpResponse::Gatt(GattResponse::Services(s))),
                                GR::Characteristics(c) => Ok(BtpResponse::Gatt(GattResponse::Characteristics(c))),
                                GR::Descriptors(d) => Ok(BtpResponse::Gatt(GattResponse::Descriptors(d))),
                                GR::ReadData(r) => Ok(BtpResponse::Gatt(GattResponse::ReadData(r))),
                                GR::ReadUuidData(r) => Ok(BtpResponse::Gatt(GattResponse::ReadUuidData(r))),
                                GR::WriteResult(att_rsp) => Ok(BtpResponse::Gatt(GattResponse::WriteResult(att_rsp))),
                                GR::WriteWithoutRspDone => Ok(BtpResponse::Gatt(GattResponse::WriteWithoutRspDone)),
                                GR::CfgDone => Ok(BtpResponse::Gatt(GattResponse::CfgDone)),
                                GR::Fail => Err(BtpStatus::Fail),
                            }
                        }
                        command_channel::Response::L2cap(response) => {
                            use l2cap::Response as LR;
                            match response {
                                LR::Connecting(rsp) => Ok(BtpResponse::L2cap(L2capResponse::Connecting(rsp))),
                                LR::Disconnected => Ok(BtpResponse::L2cap(L2capResponse::Empty)),
                                LR::DataSent => Ok(BtpResponse::L2cap(L2capResponse::Empty)),
                                LR::Fail => Err(BtpStatus::Fail),
                            }
                        }
                        command_channel::Response::Unhandled => {
                            error!("Command packet {:?} was unhandled", packet.header);
                            Err(BtpStatus::Fail)
                        }
                    }
                }
            };

        match response {
            Ok(ref resp) => {
                info!("BTP response: {:?}", resp);
                resp.write(&packet.header, &mut writer).await?;
            }
            Err(status) => {
                info!("BTP error response: {:?}", status);
                packet.header.write_err(status, &mut writer).await?;
            }
        }

        if !gap.current_settings.contains(GapSettings::POWERED) {
            info!("No longer powered — shutting down");
            return Ok(());
        }

        // 3. Read next packet (with event interleaving)
        read_with_events(packet, &mut reader, &events, &mut gap.current_settings, &mut writer).await?;
    }
}

/// Validate the controller index for a GAP command.
/// Returns `Some(BtpStatus)` if the index is invalid, `None` if valid.
fn validate_controller_index(header: BtpHeader, expected: Option<u8>) -> Result<(), BtpStatus> {
    if header.controller_index == expected {
        Ok(())
    } else {
        Err(BtpStatus::InvalidIndex)
    }
}

/// Update `current_settings` by inserting or removing `mask`, returning a `CurrentSettings` response.
fn change_current_settings(current_settings: &mut GapSettings, mask: GapSettings, set: bool) -> GapResponse<'static> {
    trace!("change_current_settings: mask={:?} set={}", mask, set);
    if set {
        current_settings.insert(mask);
    } else {
        current_settings.remove(mask);
    }
    // Mask out any internal-only flags (like LIMITED_DISCOVERABLE at bit 31).
    // GapSettings::all() has only the known bits set.
    GapResponse::CurrentSettings(*current_settings & GapSettings::all())
}

/// Convert a Duration to a u16 in units of 1.25 ms (BTP connection interval format).
fn duration_to_1_25ms(d: Duration) -> u16 {
    (d.as_micros() / 1250).try_into().unwrap_or(u16::MAX)
}

/// Convert a Duration to a u16 in units of 10 ms (BTP supervision timeout format).
fn duration_to_10ms(d: Duration) -> u16 {
    (d.as_millis() / 10).try_into().unwrap_or(u16::MAX)
}

/// Convert a SecurityLevel to the BTP sec_level wire format.
fn security_level_to_u8(level: SecurityLevel) -> u8 {
    match level {
        SecurityLevel::NoEncryption => 0,
        SecurityLevel::Encrypted => 1,
        SecurityLevel::EncryptedAuthenticated => 2,
    }
}

/// Convert a crate-level Event into a BtpEvent, updating current_settings as needed.
fn convert_event<'a>(event: &'a Event, current_settings: &mut GapSettings) -> BtpEvent<'a> {
    info!("convert_event: {:?}", event);
    match event {
        Event::AdvertisingStopped => {
            change_current_settings(current_settings, GapSettings::ADVERTISING, false);
            BtpEvent::Gap(GapEvent::NewSettings(*current_settings & !LIMITED_DISCOVERABLE))
        }
        Event::DeviceFound {
            address,
            rssi,
            adv_data,
            scan_data,
        } => {
            let adv_data = adv_data.as_deref().unwrap_or(&[]);
            let mut flags = DeviceFoundFlags::RSSI_VALID;
            if !adv_data.is_empty() {
                flags |= DeviceFoundFlags::ADV_DATA;
            }
            if !scan_data.is_empty() {
                flags |= DeviceFoundFlags::SCAN_RSP;
            }
            BtpEvent::Gap(GapEvent::DeviceFound(DeviceFoundEvent {
                address: *address,
                rssi: *rssi,
                flags,
                adv_data,
                scan_data,
            }))
        }
        Event::DeviceConnected { address, conn_params } => {
            BtpEvent::Gap(GapEvent::DeviceConnected(DeviceConnectedEvent {
                address: *address,
                interval: duration_to_1_25ms(conn_params.conn_interval),
                latency: conn_params.peripheral_latency,
                timeout: duration_to_10ms(conn_params.supervision_timeout),
            }))
        }
        Event::DeviceDisconnected { address } => BtpEvent::Gap(GapEvent::DeviceDisconnected(*address)),
        Event::AttrValueChanged { handle, data } => {
            BtpEvent::Gatt(BtpGattEvent::AttrValueChanged(AttrValueChangedEvent {
                attr_id: *handle,
                data,
            }))
        }
        Event::PasskeyDisplay { address, passkey } => BtpEvent::Gap(GapEvent::PasskeyDisplay(PasskeyDisplayEvent {
            address: *address,
            passkey: *passkey,
        })),
        Event::PasskeyEntryRequest { address } => BtpEvent::Gap(GapEvent::PasskeyEntryRequest(*address)),
        Event::PasskeyConfirmRequest { address, passkey } => {
            BtpEvent::Gap(GapEvent::PasskeyConfirmRequest(PasskeyConfirmRequestEvent {
                address: *address,
                passkey: *passkey,
            }))
        }
        Event::SecLevelChanged { address, level } => BtpEvent::Gap(GapEvent::SecLevelChanged(SecLevelChangedEvent {
            address: *address,
            sec_level: security_level_to_u8(*level),
        })),
        Event::PairingFailed { address, error } => {
            let reason = if let trouble_host::Error::Security(reason) = error {
                (*reason).into()
            } else {
                0x08 // Unspecified
            };

            BtpEvent::Gap(GapEvent::PairingFailed(PairingFailedEvent {
                address: *address,
                reason,
            }))
        }
        Event::BondLost { address } => BtpEvent::Gap(GapEvent::BondLost(*address)),
        Event::ConnParamUpdate {
            address,
            conn_interval,
            peripheral_latency,
            supervision_timeout,
        } => BtpEvent::Gap(GapEvent::ConnParamUpdate(ConnParamUpdateEvent {
            address: *address,
            interval: duration_to_1_25ms(*conn_interval),
            latency: *peripheral_latency,
            timeout: duration_to_10ms(*supervision_timeout),
        })),
        Event::NotificationReceived {
            address,
            is_indication,
            handle,
            data,
        } => {
            use protocol::gatt::NotificationType;
            let notification_type = if *is_indication {
                NotificationType::Indication
            } else {
                NotificationType::Notification
            };
            BtpEvent::Gatt(BtpGattEvent::NotificationReceived(
                protocol::gatt::NotificationReceivedEvent {
                    addr_type: address.kind,
                    address: address.addr,
                    notification_type,
                    handle: *handle,
                    data,
                },
            ))
        }
        Event::L2capConnected {
            chan_id,
            spsm,
            peer_mtu,
            peer_mps,
            our_mtu,
            our_mps,
            address,
        } => BtpEvent::L2cap(L2capEvent::Connected(protocol::l2cap::ConnectedEvent {
            chan_id: *chan_id,
            psm: *spsm,
            peer_mtu: *peer_mtu,
            peer_mps: *peer_mps,
            our_mtu: *our_mtu,
            our_mps: *our_mps,
            address: *address,
        })),
        Event::L2capDisconnected { chan_id, spsm, address } => {
            BtpEvent::L2cap(L2capEvent::Disconnected(protocol::l2cap::DisconnectedEvent {
                result: 0,
                chan_id: *chan_id,
                psm: *spsm,
                address: *address,
            }))
        }
        Event::L2capDataReceived { chan_id, data } => {
            BtpEvent::L2cap(L2capEvent::DataReceived(protocol::l2cap::DataReceivedEvent {
                chan_id: *chan_id,
                data,
            }))
        }
    }
}

/// Handle a Core Service (ID 0) command.
fn handle_core(cmd: CoreCommand) -> CoreResponse {
    use protocol::core::CoreCommand::*;
    use protocol::core::{SUPPORTED_COMMANDS, SUPPORTED_SERVICES};

    trace!("handle_core: {:?}", cmd);

    match cmd {
        ReadSupportedCommands => CoreResponse::SupportedCommands(SUPPORTED_COMMANDS),
        ReadSupportedServices => CoreResponse::SupportedServices(SUPPORTED_SERVICES),
        RegisterService(..) => CoreResponse::ServiceRegistered,
        UnregisterService(..) => CoreResponse::ServiceUnregistered,
    }
}

/// Handle GAP settings commands shared between pre-server and post-server phases.
/// Returns `Some(result)` if the command was a settings command, `None` for runtime commands.
async fn handle_gap_settings<'a, B: GapOps>(
    header: BtpHeader,
    cmd: &GapCommand<'_>,
    config: &'a BtpConfig<'a>,
    gap: &mut GapState<'_, B>,
) -> Result<GapResponse<'a>, BtpStatus> {
    use protocol::gap::GapCommand::*;
    use protocol::gap::SUPPORTED_COMMANDS;

    trace!("handle_gap_settings: {:?}", cmd);

    validate_controller_index(header, cmd.expected_controller_index())?;

    match cmd {
        ReadSupportedCommands => Ok(GapResponse::SupportedCommands(SUPPORTED_COMMANDS)),
        ReadControllerIndexList => Ok(GapResponse::ControllerIndexList(ControllerIndexListResponse {
            count: 1,
            indices: [0],
        })),
        ReadControllerInfo => {
            let short_name_len = config.device_name.len().min(MAX_SHORT_NAME_LEN);
            Ok(GapResponse::ControllerInfo(ControllerInfoResponse {
                address: config.address.addr,
                supported_settings: GapSettings::SUPPORTED,
                current_settings: gap.current_settings & !LIMITED_DISCOVERABLE,
                class_of_device: [0; 3],
                name: config.device_name,
                short_name: &config.device_name[..short_name_len],
            }))
        }
        SetConnectable(connectable) => Ok(change_current_settings(
            &mut gap.current_settings,
            GapSettings::CONNECTABLE,
            *connectable,
        )),
        SetDiscoverable(mode) => {
            let response = match mode {
                protocol::gap::DiscoverableMode::Off => change_current_settings(
                    &mut gap.current_settings,
                    GapSettings::DISCOVERABLE | LIMITED_DISCOVERABLE,
                    false,
                ),
                protocol::gap::DiscoverableMode::General => {
                    change_current_settings(&mut gap.current_settings, LIMITED_DISCOVERABLE, false);
                    change_current_settings(&mut gap.current_settings, GapSettings::DISCOVERABLE, true)
                }
                protocol::gap::DiscoverableMode::Limited => change_current_settings(
                    &mut gap.current_settings,
                    GapSettings::DISCOVERABLE | LIMITED_DISCOVERABLE,
                    true,
                ),
            };
            Ok(response)
        }
        SetBondable(bondable) => Ok(change_current_settings(
            &mut gap.current_settings,
            GapSettings::BONDABLE,
            *bondable,
        )),
        SetIoCapability(capability) => {
            gap.io_capability = *capability;
            gap.backend.set_io_capabilities(*capability);
            Ok(GapResponse::Success)
        }
        SetMitm(mitm) => {
            gap.backend.set_mitm(*mitm, gap.io_capability);
            Ok(GapResponse::Success)
        }
        SetFilterAcceptList(cmd) => {
            gap.filter_accept_list.clear();
            for entry in cmd.iter() {
                if gap.filter_accept_list.push(entry.address).is_err() {
                    return Err(BtpStatus::Fail);
                }
            }
            Ok(GapResponse::Success)
        }
        SetScOnly(enabled) => {
            gap.backend.set_secure_connections_only(*enabled);
            Ok(change_current_settings(
                &mut gap.current_settings,
                GapSettings::SC_ONLY,
                *enabled,
            ))
        }
        OobLegacySetData(data) => {
            gap.oob.legacy_tk.set(Some(*data));
            Ok(GapResponse::Success)
        }
        OobScGetLocalData => {
            let oob_data = match gap.oob.sc_local.get() {
                Some(data) => data,
                None => {
                    let data = gap.backend.get_local_oob_data()?;
                    gap.oob.sc_local.set(Some(data));
                    data
                }
            };
            Ok(GapResponse::OobScLocalData {
                random: oob_data.random,
                confirm: oob_data.confirm,
            })
        }
        OobScSetRemoteData { random, confirm } => {
            gap.oob.sc_remote.set(Some(trouble_host::OobData {
                random: *random,
                confirm: *confirm,
            }));
            // Auto-generate local OOB data if not already present, so the OOB flag
            // is set in the pairing request.
            if gap.oob.sc_local.get().is_none() {
                let data = gap.backend.get_local_oob_data()?;
                gap.oob.sc_local.set(Some(data));
            }
            Ok(GapResponse::Success)
        }
        SetPrivacy(enabled) => {
            if *enabled {
                gap.backend.enable_privacy()?;
                Ok(change_current_settings(
                    &mut gap.current_settings,
                    GapSettings::PRIVACY,
                    true,
                ))
            } else {
                Err(BtpStatus::Fail)
            }
        }
        SetRpaTimeout(secs) => {
            gap.backend.set_rpa_timeout(Duration::from_secs(*secs as u64)).await?;
            Ok(GapResponse::Success)
        }
        _ => Err(BtpStatus::NotReady),
    }
}

/// Handle a GAP runtime command (advertising, discovery, pairing, etc.).
///
/// Settings commands are delegated to [`handle_gap_settings`]; this function
/// handles the remaining commands that require async operations or forwarding.
async fn handle_gap<'a, 'b, C, P: PacketPool>(
    header: BtpHeader,
    cmd: &GapCommand<'_>,
    config: &'a BtpConfig<'a>,
    gap: &mut GapState<'_, StackGap<'_, 'b, C, P>>,
    channels: &CommandChannels<'_>,
) -> HandlerResult<GapResponse<'a>>
where
    C: crate::Controller,
{
    use HandlerResult::*;
    use protocol::gap::GapCommand::*;

    trace!("handle_gap: {:?}", cmd);

    match handle_gap_settings(header, cmd, config, gap).await {
        Err(BtpStatus::NotReady) => (),
        result => return result.into(),
    }

    // Only runtime commands remain
    match cmd {
        StartAdvertising(..) | StartDirectedAdvertising(..) => {
            if let Some(ad) = cmd.ad(gap.current_settings) {
                // TGAP(lim_adv_timeout): auto-stop when in Limited Discoverable mode.
                // TSPX_lim_adv_timeout = 30720 milliseconds (~30 seconds).
                let timeout = if gap.current_settings.contains(LIMITED_DISCOVERABLE) {
                    Some(Duration::from_secs(30))
                } else {
                    None
                };
                channels
                    .peripheral
                    .send(peripheral::Command::StartAdvertising(
                        ad,
                        timeout,
                        gap.filter_accept_list.clone(),
                    ))
                    .await;
                Forwarded
            } else {
                Error(BtpStatus::Fail)
            }
        }
        StopAdvertising => {
            channels.peripheral.send(peripheral::Command::StopAdvertising).await;
            Forwarded
        }
        StartDiscovery(flags) => {
            let list = if flags.contains(protocol::gap::DiscoveryFlags::FILTER_ACCEPT_LIST) {
                gap.filter_accept_list.clone()
            } else {
                heapless::Vec::new()
            };
            let mode = if flags.contains(protocol::gap::DiscoveryFlags::OBSERVATION) {
                ScanMode::Observer
            } else if flags.contains(protocol::gap::DiscoveryFlags::LIMITED) {
                ScanMode::LimitedDiscovery
            } else {
                ScanMode::GeneralDiscovery
            };
            gap.scan_mode.set(mode);
            channels
                .central
                .send(central::Command::StartDiscovery {
                    active: flags.contains(protocol::gap::DiscoveryFlags::ACTIVE),
                    filter_accept_list: list,
                })
                .await;
            Forwarded
        }
        StopDiscovery => {
            gap.scan_mode.set(ScanMode::Disabled);
            channels.central.send(central::Command::StopDiscovery).await;
            Forwarded
        }
        Connect(cmd) => {
            // All-zeros address means "use the filter accept list" (Auto Connection Establishment)
            let filter_accept_list = if cmd.address.addr == BdAddr::default() {
                gap.filter_accept_list.clone()
            } else {
                let mut list = heapless::Vec::new();
                let _ = list.push(cmd.address);
                list
            };
            channels
                .central
                .send(central::Command::Connect {
                    filter_accept_list,
                    bondable: gap.current_settings.contains(GapSettings::BONDABLE),
                })
                .await;
            Forwarded
        }
        Disconnect(address) => {
            if let Some(conn) = gap.backend.stack.get_connection_by_peer_address(*address) {
                conn.disconnect();
            } else {
                warn!("Disconnect: no connection for {:?} (already disconnected)", address);
            }
            Ready(GapResponse::Success)
        }
        Pair(address) => {
            if let Some(conn) = gap.backend.stack.get_connection_by_peer_address(*address) {
                if let Err(err) = conn.set_bondable(gap.current_settings.contains(GapSettings::BONDABLE)) {
                    warn!("Pair: failed to set bondable flag for {:?}: {:?}", address, err);
                }
                match conn.request_security() {
                    Ok(()) => Ready(GapResponse::Success),
                    Err(_) => {
                        warn!("Pair: request_security failed for {:?}", address);
                        Error(BtpStatus::Fail)
                    }
                }
            } else {
                warn!("Pair: no connection for {:?}", address);
                Error(BtpStatus::Fail)
            }
        }
        Unpair(address) => {
            let identity = if let Some(conn) = gap.backend.stack.get_connection_by_peer_address(*address) {
                conn.disconnect();
                conn.peer_identity()
            } else {
                Identity {
                    addr: *address,
                    irk: None,
                }
            };
            // Treat "not found" as success — the intent is to ensure no bond exists.
            let _ = gap.backend.stack.remove_bond_information(identity);
            Ready(GapResponse::Success)
        }
        PasskeyEntry(cmd) => {
            if let Some(conn) = gap.backend.stack.get_connection_by_peer_address(cmd.address) {
                match conn.pass_key_input(cmd.passkey) {
                    Ok(()) => Ready(GapResponse::Success),
                    Err(_) => Error(BtpStatus::Fail),
                }
            } else {
                Error(BtpStatus::Fail)
            }
        }
        PasskeyConfirm(cmd) => {
            if let Some(conn) = gap.backend.stack.get_connection_by_peer_address(cmd.address) {
                let res = if cmd.confirmed {
                    conn.pass_key_confirm()
                } else {
                    conn.pass_key_cancel()
                };

                match res {
                    Ok(()) => Ready(GapResponse::Success),
                    Err(_) => Error(BtpStatus::Fail),
                }
            } else {
                Error(BtpStatus::Fail)
            }
        }
        ConnParamUpdate(cmd) => {
            if let Some(conn) = gap.backend.stack.get_connection_by_peer_address(cmd.address) {
                match conn.update_connection_params(gap.backend.stack, &cmd.params()).await {
                    Ok(()) => Ready(GapResponse::Success),
                    Err(_) => Error(BtpStatus::Fail),
                }
            } else {
                Error(BtpStatus::Fail)
            }
        }
        // Settings commands handled by handle_gap_settings above
        ReadSupportedCommands
        | ReadControllerIndexList
        | ReadControllerInfo
        | SetConnectable(_)
        | SetDiscoverable(_)
        | SetBondable(_)
        | SetIoCapability(_)
        | SetMitm(_)
        | SetFilterAcceptList(_)
        | SetPrivacy(_)
        | SetScOnly(_)
        | SetRpaTimeout(_)
        | OobLegacySetData(_)
        | OobScGetLocalData
        | OobScSetRemoteData { .. } => unreachable!(),
    }
}

/// Handle GATT commands after the server has started.
///
/// Building commands return errors; StartServer returns the cached table_len.
/// Client commands are forwarded to the gatt_client task.
async fn handle_gatt<'a, C: crate::Controller, P: PacketPool>(
    cmd: GattCommand<'a>,
    server: &crate::Server<'_, P>,
    stack: &Stack<'_, C, P>,
    channels: &CommandChannels<'_>,
) -> HandlerResult<GattResponse> {
    use HandlerResult::*;
    use protocol::gatt::GattCommand::*;
    use protocol::gatt::{AttPermission, AttributeInfo, SUPPORTED_COMMANDS};

    trace!("handle_gatt: {:?}", cmd);

    match cmd {
        ReadSupportedCommands => Ready(GattResponse::SupportedCommands(SUPPORTED_COMMANDS)),
        StartServer => Ready(GattResponse::ServerStarted(ServerStartedResponse {
            db_attr_offset: (GAP_ATTRIBUTE_COUNT + GATT_ATTRIBUTE_COUNT + 1) as u16,
            db_attr_count: server.table().len() as u8,
        })),
        // Building commands not available after server started
        AddService(..) | AddCharacteristic(..) | AddDescriptor(..) | AddIncludedService(..) => Error(BtpStatus::Fail),
        SetValue(cmd) => match server.write_and_notify(stack, cmd.attr_id, cmd.value).await {
            Ok(()) => Ready(GattResponse::ValueSet),
            Err(_) => Error(BtpStatus::Fail),
        },
        SetEncKeySize { .. } => Ready(GattResponse::EncKeySizeSet),
        GetAttrs(cmd) => {
            let mut attrs = alloc::vec::Vec::new();
            for h in cmd.start_handle..=cmd.end_handle {
                if let (Some(uuid), Some(perms)) = (server.table().uuid(h), server.table().permissions(h))
                    && (cmd.type_uuid.is_none() || cmd.type_uuid.as_ref() == Some(&uuid))
                {
                    attrs.push(AttributeInfo {
                        handle: h,
                        permission: AttPermission::from(perms),
                        type_uuid: uuid,
                    });
                }
            }
            let attrs = attrs.into_boxed_slice();
            Ready(GattResponse::Attrs(attrs))
        }
        GetAttrValue(cmd) => {
            let address = Address {
                kind: cmd.addr_type,
                addr: cmd.address,
            };
            let mut buf = alloc::vec![0u8; 512];
            let result = match stack.get_connection_by_peer_address(address) {
                Some(conn) => server.read(&conn, cmd.handle, 0, &mut buf),
                None => server
                    .table()
                    .read(cmd.handle, 0, &mut buf)
                    .map_err(|_| AttErrorCode::INVALID_HANDLE),
            };
            match result {
                Ok(len) => {
                    buf.truncate(len);
                    Ready(GattResponse::AttrValue(protocol::gatt::AttrValueResponse {
                        att_response: 0x00,
                        value: buf.into_boxed_slice(),
                    }))
                }
                Err(e) => Ready(GattResponse::AttrValue(protocol::gatt::AttrValueResponse {
                    att_response: e.to_u8(),
                    value: alloc::boxed::Box::default(),
                })),
            }
        }

        // === Client commands — forward to gatt_client task ===
        ExchangeMtu(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::ExchangeMtu {
                    addr_type: c.addr_type,
                    address: c.address,
                })
                .await;
            Forwarded
        }
        DiscoverPrimaryUuid(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::DiscoverPrimaryUuid {
                    addr_type: c.addr_type,
                    address: c.address,
                    uuid: c.uuid,
                })
                .await;
            Forwarded
        }
        DiscoverChrcUuid(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::DiscoverChrcUuid {
                    addr_type: c.addr_type,
                    address: c.address,
                    start_handle: c.start_handle,
                    end_handle: c.end_handle,
                    uuid: c.uuid,
                })
                .await;
            Forwarded
        }
        Read(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::Read {
                    addr_type: c.addr_type,
                    address: c.address,
                    handle: c.handle,
                })
                .await;
            Forwarded
        }
        ReadLong(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::ReadLong {
                    addr_type: c.addr_type,
                    address: c.address,
                    handle: c.handle,
                    offset: c.offset,
                })
                .await;
            Forwarded
        }
        ReadUuid(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::ReadUuid {
                    addr_type: c.addr_type,
                    address: c.address,
                    start_handle: c.start_handle,
                    end_handle: c.end_handle,
                    uuid: c.uuid,
                })
                .await;
            Forwarded
        }
        Write(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::Write {
                    addr_type: c.addr_type,
                    address: c.address,
                    handle: c.handle,
                    data: alloc::boxed::Box::from(c.data),
                })
                .await;
            Forwarded
        }
        WriteWithoutRsp(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::WriteWithoutRsp {
                    addr_type: c.addr_type,
                    address: c.address,
                    handle: c.handle,
                    data: alloc::boxed::Box::from(c.data),
                })
                .await;
            Forwarded
        }
        CfgNotify(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::CfgNotify {
                    addr_type: c.addr_type,
                    address: c.address,
                    enable: c.enable,
                    ccc_handle: c.ccc_handle,
                })
                .await;
            Forwarded
        }
        CfgIndicate(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::CfgIndicate {
                    addr_type: c.addr_type,
                    address: c.address,
                    enable: c.enable,
                    ccc_handle: c.ccc_handle,
                })
                .await;
            Forwarded
        }

        DiscoverAllPrimary(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::DiscoverAllPrimary {
                    addr_type: c.addr_type,
                    address: c.address,
                })
                .await;
            Forwarded
        }
        DiscoverAllChrc(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::DiscoverAllChrc {
                    addr_type: c.addr_type,
                    address: c.address,
                    start_handle: c.start_handle,
                    end_handle: c.end_handle,
                })
                .await;
            Forwarded
        }
        DiscoverAllDesc(c) => {
            channels
                .gatt_client
                .send(gatt_client::Command::DiscoverAllDesc {
                    addr_type: c.addr_type,
                    address: c.address,
                    start_handle: c.start_handle,
                    end_handle: c.end_handle,
                })
                .await;
            Forwarded
        }

        // Tier 2/3 commands — not supported by trouble-host
        FindIncluded(..)
        | ReadMultiple(..)
        | ReadMultipleVar(..)
        | WriteLong(..)
        | ReliableWrite(..)
        | SignedWriteWithoutRsp(..) => Error(BtpStatus::Fail),
    }
}

/// Handle an L2CAP Service (ID 3) command. Currently all commands are unimplemented.
async fn handle_l2cap(cmd: L2capCommand<'_>, channels: &CommandChannels<'_>) -> HandlerResult<L2capResponse> {
    use protocol::l2cap::SUPPORTED_COMMANDS;

    trace!("handle_l2cap: {:?}", cmd);

    match cmd {
        L2capCommand::ReadSupportedCommands => {
            HandlerResult::Ready(L2capResponse::SupportedCommands(SUPPORTED_COMMANDS))
        }
        L2capCommand::Listen(_) => {
            // Listen must be configured in the pre-server phase
            HandlerResult::Error(BtpStatus::Fail)
        }
        L2capCommand::Connect(connect) => {
            channels
                .l2cap
                .send(l2cap::Command::Connect {
                    address: connect.address,
                    spsm: connect.psm,
                    mtu: connect.mtu,
                    num: connect.num,
                })
                .await;
            HandlerResult::Forwarded
        }
        L2capCommand::Disconnect(chan_id) => {
            channels.l2cap.send(l2cap::Command::Disconnect { chan_id }).await;
            HandlerResult::Forwarded
        }
        L2capCommand::SendData(send_data) => {
            channels
                .l2cap
                .send(l2cap::Command::SendData {
                    chan_id: send_data.chan_id,
                    data: alloc::boxed::Box::from(send_data.data),
                })
                .await;
            HandlerResult::Forwarded
        }
        L2capCommand::Credits(_) | L2capCommand::Reconfigure(_) | L2capCommand::DisconnectEattChans(_) => {
            HandlerResult::Error(BtpStatus::Fail)
        }
    }
}

#[cfg(test)]
mod tests {
    use bt_hci::param::{AddrKind, BdAddr};
    use embassy_time::Duration;
    use trouble_host::Address;
    use trouble_host::connection::{ConnParams, SecurityLevel};

    use super::*;

    fn test_address() -> Address {
        Address {
            kind: AddrKind::RANDOM,
            addr: BdAddr::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
        }
    }

    // --- duration_to_1_25ms tests ---

    #[test]
    fn duration_1_25ms_zero() {
        assert_eq!(duration_to_1_25ms(Duration::from_micros(0)), 0);
    }

    #[test]
    fn duration_1_25ms_one_unit() {
        assert_eq!(duration_to_1_25ms(Duration::from_micros(1250)), 1);
    }

    #[test]
    fn duration_1_25ms_100ms() {
        // 100ms = 100_000us / 1250 = 80
        assert_eq!(duration_to_1_25ms(Duration::from_millis(100)), 80);
    }

    // --- duration_to_10ms tests ---

    #[test]
    fn duration_10ms_zero() {
        assert_eq!(duration_to_10ms(Duration::from_millis(0)), 0);
    }

    #[test]
    fn duration_10ms_one_unit() {
        assert_eq!(duration_to_10ms(Duration::from_millis(10)), 1);
    }

    #[test]
    fn duration_10ms_1000ms() {
        assert_eq!(duration_to_10ms(Duration::from_millis(1000)), 100);
    }

    // --- security_level_to_u8 tests ---

    #[test]
    fn security_level_no_encryption() {
        assert_eq!(security_level_to_u8(SecurityLevel::NoEncryption), 0);
    }

    #[test]
    fn security_level_encrypted() {
        assert_eq!(security_level_to_u8(SecurityLevel::Encrypted), 1);
    }

    #[test]
    fn security_level_encrypted_authenticated() {
        assert_eq!(security_level_to_u8(SecurityLevel::EncryptedAuthenticated), 2);
    }

    // --- change_current_settings tests ---

    #[test]
    fn change_settings_set_flag() {
        let mut settings = GapSettings::POWERED;
        let resp = change_current_settings(&mut settings, GapSettings::ADVERTISING, true);
        assert!(settings.contains(GapSettings::ADVERTISING));
        if let GapResponse::CurrentSettings(s) = resp {
            assert!(s.contains(GapSettings::ADVERTISING));
        } else {
            panic!("Expected CurrentSettings");
        }
    }

    #[test]
    fn change_settings_remove_flag() {
        let mut settings = GapSettings::POWERED | GapSettings::ADVERTISING;
        let resp = change_current_settings(&mut settings, GapSettings::ADVERTISING, false);
        assert!(!settings.contains(GapSettings::ADVERTISING));
        if let GapResponse::CurrentSettings(s) = resp {
            assert!(!s.contains(GapSettings::ADVERTISING));
        } else {
            panic!("Expected CurrentSettings");
        }
    }

    #[test]
    fn change_settings_masks_internal_flags() {
        let mut settings = GapSettings::POWERED | LIMITED_DISCOVERABLE;
        let resp = change_current_settings(&mut settings, GapSettings::LE, true);
        // Internal flag should be stripped from response
        if let GapResponse::CurrentSettings(s) = resp {
            assert!(!s.intersects(LIMITED_DISCOVERABLE));
            assert!(s.contains(GapSettings::LE));
        } else {
            panic!("Expected CurrentSettings");
        }
    }

    // --- convert_event tests ---

    #[test]
    fn convert_advertising_stopped() {
        let mut settings = GapSettings::POWERED | GapSettings::ADVERTISING;
        let event = Event::AdvertisingStopped;
        let btp = convert_event(&event, &mut settings);
        assert!(!settings.contains(GapSettings::ADVERTISING));
        assert!(matches!(btp, BtpEvent::Gap(GapEvent::NewSettings(s)) if !s.contains(GapSettings::ADVERTISING)));
    }

    #[test]
    fn convert_device_found_with_adv_data() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::DeviceFound {
            address: test_address(),
            rssi: -50,
            adv_data: Some(alloc::rc::Rc::from([0x01u8, 0x02].as_slice())),
            scan_data: alloc::boxed::Box::from([].as_slice()),
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::DeviceFound(evt)) = btp {
            assert!(evt.flags.contains(DeviceFoundFlags::RSSI_VALID));
            assert!(evt.flags.contains(DeviceFoundFlags::ADV_DATA));
            assert!(!evt.flags.contains(DeviceFoundFlags::SCAN_RSP));
            assert_eq!(evt.rssi, -50);
            assert_eq!(evt.adv_data, &[0x01, 0x02]);
        } else {
            panic!("Expected DeviceFound");
        }
    }

    #[test]
    fn convert_device_found_scan_response() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::DeviceFound {
            address: test_address(),
            rssi: -30,
            adv_data: Some(alloc::rc::Rc::from([0x01u8, 0x02].as_slice())),
            scan_data: alloc::boxed::Box::from([0x03u8].as_slice()),
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::DeviceFound(evt)) = btp {
            assert!(evt.flags.contains(DeviceFoundFlags::SCAN_RSP));
            assert!(evt.flags.contains(DeviceFoundFlags::ADV_DATA));
            assert_eq!(evt.adv_data, &[0x01, 0x02]);
            assert_eq!(evt.scan_data, &[0x03]);
        } else {
            panic!("Expected DeviceFound");
        }
    }

    #[test]
    fn convert_device_found_empty_adv_data() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::DeviceFound {
            address: test_address(),
            rssi: -70,
            adv_data: None,
            scan_data: alloc::boxed::Box::from([].as_slice()),
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::DeviceFound(evt)) = btp {
            assert!(evt.flags.contains(DeviceFoundFlags::RSSI_VALID));
            assert!(!evt.flags.contains(DeviceFoundFlags::ADV_DATA));
            assert!(!evt.flags.contains(DeviceFoundFlags::SCAN_RSP));
        } else {
            panic!("Expected DeviceFound");
        }
    }

    #[test]
    fn convert_device_connected() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::DeviceConnected {
            address: test_address(),
            conn_params: ConnParams {
                conn_interval: Duration::from_micros(30 * 1250), // 30 units of 1.25ms
                peripheral_latency: 5,
                supervision_timeout: Duration::from_millis(200 * 10), // 200 units of 10ms
            },
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::DeviceConnected(evt)) = btp {
            assert_eq!(evt.interval, 30);
            assert_eq!(evt.latency, 5);
            assert_eq!(evt.timeout, 200);
        } else {
            panic!("Expected DeviceConnected");
        }
    }

    #[test]
    fn convert_device_disconnected() {
        let mut settings = DEFAULT_SETTINGS;
        let addr = test_address();
        let event = Event::DeviceDisconnected { address: addr };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::DeviceDisconnected(a)) = btp {
            assert_eq!(a.addr.raw(), &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        } else {
            panic!("Expected DeviceDisconnected");
        }
    }

    #[test]
    fn convert_attr_value_changed() {
        let mut settings = DEFAULT_SETTINGS;
        let data = alloc::boxed::Box::from([0xAA, 0xBB]);
        let event = Event::AttrValueChanged { handle: 42, data };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gatt(protocol::gatt::GattEvent::AttrValueChanged(evt)) = btp {
            assert_eq!(evt.attr_id, 42);
            assert_eq!(evt.data, &[0xAA, 0xBB]);
        } else {
            panic!("Expected AttrValueChanged");
        }
    }

    #[test]
    fn convert_passkey_display() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::PasskeyDisplay {
            address: test_address(),
            passkey: 123456,
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::PasskeyDisplay(evt)) = btp {
            assert_eq!(evt.passkey, 123456);
        } else {
            panic!("Expected PasskeyDisplay");
        }
    }

    #[test]
    fn convert_passkey_entry_request() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::PasskeyEntryRequest {
            address: test_address(),
        };
        let btp = convert_event(&event, &mut settings);
        assert!(matches!(btp, BtpEvent::Gap(GapEvent::PasskeyEntryRequest(..))));
    }

    #[test]
    fn convert_passkey_confirm_request() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::PasskeyConfirmRequest {
            address: test_address(),
            passkey: 654321,
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::PasskeyConfirmRequest(evt)) = btp {
            assert_eq!(evt.passkey, 654321);
        } else {
            panic!("Expected PasskeyConfirmRequest");
        }
    }

    #[test]
    fn convert_sec_level_changed() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::SecLevelChanged {
            address: test_address(),
            level: SecurityLevel::Encrypted,
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::SecLevelChanged(evt)) = btp {
            assert_eq!(evt.sec_level, 1);
        } else {
            panic!("Expected SecLevelChanged");
        }
    }

    #[test]
    fn convert_pairing_failed_non_security_error() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::PairingFailed {
            address: test_address(),
            error: trouble_host::Error::InvalidValue,
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::PairingFailed(evt)) = btp {
            assert_eq!(evt.reason, 0x08); // Unspecified
        } else {
            panic!("Expected PairingFailed");
        }
    }

    #[test]
    fn convert_conn_param_update() {
        let mut settings = DEFAULT_SETTINGS;
        let event = Event::ConnParamUpdate {
            address: test_address(),
            conn_interval: Duration::from_micros(24 * 1250),
            peripheral_latency: 0,
            supervision_timeout: Duration::from_millis(42 * 10),
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gap(GapEvent::ConnParamUpdate(evt)) = btp {
            assert_eq!(evt.interval, 24);
            assert_eq!(evt.latency, 0);
            assert_eq!(evt.timeout, 42);
        } else {
            panic!("Expected ConnParamUpdate");
        }
    }

    #[test]
    fn convert_notification_received() {
        let mut settings = DEFAULT_SETTINGS;
        let data = alloc::boxed::Box::from([0x01, 0x02, 0x03]);
        let event = Event::NotificationReceived {
            address: test_address(),
            is_indication: false,
            handle: 10,
            data,
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gatt(protocol::gatt::GattEvent::NotificationReceived(evt)) = btp {
            assert!(matches!(
                evt.notification_type,
                protocol::gatt::NotificationType::Notification
            ));
            assert_eq!(evt.handle, 10);
            assert_eq!(evt.data, &[0x01, 0x02, 0x03]);
            assert_eq!(evt.addr_type, AddrKind::RANDOM);
        } else {
            panic!("Expected NotificationReceived");
        }
    }

    #[test]
    fn convert_indication_received() {
        let mut settings = DEFAULT_SETTINGS;
        let data = alloc::boxed::Box::from([0xFF]);
        let event = Event::NotificationReceived {
            address: test_address(),
            is_indication: true,
            handle: 20,
            data,
        };
        let btp = convert_event(&event, &mut settings);
        if let BtpEvent::Gatt(protocol::gatt::GattEvent::NotificationReceived(evt)) = btp {
            assert!(matches!(
                evt.notification_type,
                protocol::gatt::NotificationType::Indication
            ));
            assert_eq!(evt.handle, 20);
        } else {
            panic!("Expected NotificationReceived (indication)");
        }
    }
}
