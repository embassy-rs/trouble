//! BTP (Bluetooth Test Protocol) implementation for trouble-host.
//!
//! This crate provides a platform-independent implementation of the BTP protocol
//! used by the Bluetooth SIG's Profile Tuning Suite (PTS) via auto-pts for
//! automated Bluetooth conformance testing.
//!
//! # Single-use
//!
//! [`run()`] uses internal `StaticCell` storage for the GATT service builder and
//! database hash, so it can only be called **once** per program execution.
//! A second call panics immediately with a clear message.
//!
//! # Architecture
//!
//! The crate is split into internal modules:
//!
//! - `btp` — BTP protocol loop, command dispatch, and handler functions
//!   - `btp::protocol` — Packet envelope types, header parsing, and per-service
//!     command/response/event definitions (core, gap, gatt, l2cap)
//!   - `btp::service_builder` — Dynamic GATT service/characteristic/descriptor builder
//! - `peripheral` — Peripheral role task (advertising, connections)
//! - `central` — Central role task (scanning, connections)
//! - `gatt_client` — GATT client task (discovery, read/write, notifications)
//! - `command_channel` — Typed command/response channel with enforced-reply `Command` wrapper
//! - `connection` — Shared GATT connection event loop
//!
//! The public API surface is intentionally small: [`run()`], [`BtpConfig`], and [`Controller`].
//!
//! # Example
//!
//! ```no_run
//! use embedded_io_async::{Read, Write};
//! use rand_core::{CryptoRng, RngCore};
//! use trouble_tester_app::{run, BtpConfig, Controller};
//!
//! async fn run_btp<C, R, W, RNG>(controller: C, reader: R, writer: W, rng: RNG)
//! where
//!     C: Controller,
//!     R: Read,
//!     W: Write,
//!     RNG: RngCore + CryptoRng,
//! {
//!     let _ = run(controller, reader, writer, BtpConfig::default(), rng).await;
//! }
//! ```

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

use core::cell::{Cell, RefCell};

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearAdvSets, LeClearFilterAcceptList, LeConnUpdate, LeCreateConn,
    LeExtCreateConn, LeReadLocalSupportedFeatures, LeReadNumberOfSupportedAdvSets, LeSetAdvSetRandomAddr,
    LeSetExtAdvData, LeSetExtAdvParams, LeSetExtScanEnable, LeSetExtScanParams, LeSetExtScanResponseData,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::LeAdvEventKind;
use embassy_futures::select::{Either, Either5, select, select5};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, DynamicSender};
use embassy_sync::watch::Watch;
use embedded_io_async::{Read, Write};
use rand_core::{CryptoRng, RngCore};
use static_cell::StaticCell;
use trouble_host::OobData;
use trouble_host::prelude::*;

use crate::command_channel::CommandReceiver;

#[cfg(feature = "std")]
extern crate std;

mod fmt;

mod btp;
mod central;
mod command_channel;
mod connection;
mod gatt_client;
mod l2cap;
mod peripheral;

/// Conditional error formatting bound: requires `defmt::Format` under `defmt`,
/// `core::fmt::Debug` otherwise.
#[cfg(not(feature = "defmt"))]
pub trait ErrorFormat: core::fmt::Debug {}
#[cfg(not(feature = "defmt"))]
impl<T: core::fmt::Debug> ErrorFormat for T {}

/// Conditional error formatting bound: requires `defmt::Format` under `defmt`,
/// `core::fmt::Debug` otherwise.
#[cfg(feature = "defmt")]
pub trait ErrorFormat: defmt::Format {}
#[cfg(feature = "defmt")]
impl<T: defmt::Format> ErrorFormat for T {}

/// Controller sub-trait bundling all HCI command bounds needed by this crate.
pub trait Controller:
    trouble_host::prelude::Controller
    + ControllerCmdSync<LeReadLocalSupportedFeatures>
    + ControllerCmdSync<LeSetScanParams>
    + ControllerCmdSync<LeClearFilterAcceptList>
    + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
    + for<'t> ControllerCmdSync<LeSetExtAdvData<'t>>
    + ControllerCmdSync<LeClearAdvSets>
    + ControllerCmdSync<LeSetExtAdvParams>
    + ControllerCmdSync<LeSetAdvSetRandomAddr>
    + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
    + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>
    + ControllerCmdSync<LeSetExtScanParams>
    + ControllerCmdSync<LeSetExtScanEnable>
    + ControllerCmdAsync<LeCreateConn>
    + ControllerCmdAsync<LeExtCreateConn>
    + ControllerCmdAsync<LeConnUpdate>
    + trouble_host::SecurityCmds
    + embedded_io::ErrorType<Error: ErrorFormat>
{
}

impl<T> Controller for T where
    T: trouble_host::prelude::Controller
        + ControllerCmdSync<LeReadLocalSupportedFeatures>
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + for<'t> ControllerCmdSync<LeSetExtAdvData<'t>>
        + ControllerCmdSync<LeClearAdvSets>
        + ControllerCmdSync<LeSetExtAdvParams>
        + ControllerCmdSync<LeSetAdvSetRandomAddr>
        + ControllerCmdSync<LeReadNumberOfSupportedAdvSets>
        + for<'t> ControllerCmdSync<LeSetExtScanResponseData<'t>>
        + ControllerCmdSync<LeSetExtScanParams>
        + ControllerCmdSync<LeSetExtScanEnable>
        + ControllerCmdAsync<LeCreateConn>
        + ControllerCmdAsync<LeExtCreateConn>
        + ControllerCmdAsync<LeConnUpdate>
        + trouble_host::SecurityCmds
        + embedded_io::ErrorType<Error: ErrorFormat>
{
}

/// Crate-level event enum for routing domain events to btp::run.
///
/// Field types use trouble-host native types (Duration, SecurityLevel, etc.)
/// rather than BTP wire-format types. Conversion to BTP format happens in
/// `btp::convert_event`.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Event {
    AdvertisingStopped,
    DeviceFound {
        address: Address,
        rssi: i8,
        adv_data: Option<alloc::rc::Rc<[u8]>>,
        scan_data: alloc::boxed::Box<[u8]>,
    },
    DeviceConnected {
        address: Address,
        conn_params: ConnParams,
    },
    DeviceDisconnected {
        address: Address,
    },
    AttrValueChanged {
        handle: u16,
        data: alloc::boxed::Box<[u8]>,
    },
    PasskeyDisplay {
        address: Address,
        passkey: u32,
    },
    PasskeyEntryRequest {
        address: Address,
    },
    PasskeyConfirmRequest {
        address: Address,
        passkey: u32,
    },
    SecLevelChanged {
        address: Address,
        level: SecurityLevel,
    },
    PairingFailed {
        address: Address,
        error: trouble_host::Error,
    },
    BondLost {
        address: Address,
    },
    ConnParamUpdate {
        address: Address,
        conn_interval: embassy_time::Duration,
        peripheral_latency: u16,
        supervision_timeout: embassy_time::Duration,
    },
    NotificationReceived {
        address: Address,
        is_indication: bool,
        handle: u16,
        data: alloc::boxed::Box<[u8]>,
    },
    L2capConnected {
        chan_id: u8,
        psm: u16,
        peer_mtu: u16,
        peer_mps: u16,
        our_mtu: u16,
        our_mps: u16,
        address: Address,
    },
    L2capDisconnected {
        chan_id: u8,
        psm: u16,
        address: Address,
    },
    L2capDataReceived {
        chan_id: u8,
        data: alloc::boxed::Box<[u8]>,
    },
}

/// Maximum number of concurrent BLE connections.
const CONNECTIONS_MAX: usize = 3;
/// Maximum number of L2CAP channels (Signal + ATT + SMP + 5 CoC).
const L2CAP_CHANNELS_MAX: usize = 14;
/// Maximum number of attributes in the GATT attribute table.
const ATTRIBUTE_TABLE_SIZE: usize = 64;
/// Maximum number of CCCD (Client Characteristic Configuration Descriptor) entries.
const CCCD_TABLE_SIZE: usize = 10;
/// Number of attributes used by the GAP service (service + device name + appearance + central address resolution).
const GAP_ATTRIBUTE_COUNT: usize = 7;
/// Number of attributes used by the GATT service (service + service_changed + client_supported_features + database_hash).
const GATT_ATTRIBUTE_COUNT: usize = 8;

/// Type alias for the GATT attribute server used throughout this crate.
pub(crate) type Server<'a, P> =
    AttributeServer<'a, NoopRawMutex, P, ATTRIBUTE_TABLE_SIZE, CCCD_TABLE_SIZE, CONNECTIONS_MAX>;

/// Errors from the BTP runner.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error<E: ErrorFormat> {
    /// The BLE host task failed.
    Ble(BleHostError<E>),
    /// The BTP protocol task failed.
    Btp(btp::error::Error),
}

impl<E: ErrorFormat> From<btp::error::Error> for Error<E> {
    fn from(e: btp::error::Error) -> Self {
        Self::Btp(e)
    }
}

impl<E: ErrorFormat> From<BleHostError<E>> for Error<E> {
    fn from(e: BleHostError<E>) -> Self {
        Self::Ble(e)
    }
}

/// Configuration for BTP runner.
#[derive(Clone)]
pub struct BtpConfig<'a> {
    /// The device address.
    pub address: Address,
    /// The device name for GAP service.
    pub device_name: &'a str,
    /// The device appearance (GAP characteristic).
    pub appearance: BluetoothUuid16,
}

impl Default for BtpConfig<'_> {
    fn default() -> Self {
        Self {
            address: Address::random([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            device_name: "TrouBLE-Tester",
            appearance: bt_hci::uuid::appearance::UNKNOWN,
        }
    }
}

/// Run the BTP protocol with the given controller and transport.
///
/// This function:
/// 1. Creates host resources and GATT storage
/// 2. Runs a pre-server BTP loop handling Core, GATT building, and GAP settings
/// 3. Creates the AttributeServer after GATT StartServer
/// 4. Runs BTP protocol loop and command processors concurrently
///
/// # Panics
///
/// Panics if called more than once per program execution (uses internal
/// `StaticCell` storage that cannot be re-initialized).
///
/// # Type Parameters
///
/// * `C` - Controller type
/// * `R` - Reader type
/// * `W` - Writer type
pub async fn run<C, R, W, RNG>(
    controller: C,
    reader: R,
    writer: W,
    config: BtpConfig<'_>,
    mut random_generator: RNG,
) -> Result<(), Error<C::Error>>
where
    C: Controller,
    R: Read,
    W: Write,
    RNG: RngCore + CryptoRng,
{
    use core::sync::atomic::{AtomicBool, Ordering};
    static CALLED: AtomicBool = AtomicBool::new(false);
    assert!(
        !CALLED.swap(true, Ordering::Relaxed),
        "run() can only be called once per program execution"
    );
    info!("BTP run: name={:?} addr={:?}", config.device_name, config.address);

    let scan_mode = Cell::new(ScanMode::default());
    let oob = OobState::new();

    // Generate an IRK for privacy support (used when SET_PRIVACY is received)
    let mut irk_bytes = [0u8; 16];
    random_generator.fill_bytes(&mut irk_bytes);
    let irk = trouble_host::prelude::IdentityResolvingKey::from_le_bytes(irk_bytes).unwrap();

    let mut table = AttributeTable::<NoopRawMutex, ATTRIBUTE_TABLE_SIZE>::new();
    init_table(&mut table, &config);

    // Phase 1: Pre-server BTP loop (handles Core, GATT building, GAP settings)
    let transport = btp::BtpTransport { reader, writer };
    let mut packet = btp::protocol::BtpPacket::new();
    info!("Entering pre-server phase");
    let Some(pre) = btp::run_pre_server(transport, &config, &scan_mode, &oob, irk, &mut table, &mut packet).await?
    else {
        info!("Clean shutdown from pre-server phase");
        return Ok(());
    };

    info!("Pre-server phase complete, building stack and creating server");

    // Build the stack, applying deferred GAP settings to the builder
    let mut resources: HostResources<_, DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
    let mut builder = trouble_host::new(controller, &mut resources)
        .set_random_address(config.address)
        .set_random_generator_seed(&mut random_generator);

    if let Some(ref listener_config) = pre.l2cap_listener {
        builder = builder.register_l2cap_psm(listener_config.psm);
    }

    let builder = pre.gap.apply_to_builder(builder);
    let stack = builder.build();
    let runner = stack.runner();
    let gap = pre.gap.into_stack_gap(&stack);
    let peripheral = stack.peripheral();
    let central = stack.central();

    // Create server on this stack frame
    let server = Server::new(table);

    // Phase 2: Full concurrent operation
    info!("Entering phase 2: concurrent operation");
    let events = Channel::<NoopRawMutex, Event, 8>::new();
    let response = Channel::<NoopRawMutex, command_channel::Response, 1>::new();

    let peripheral_command = Channel::<NoopRawMutex, peripheral::Command, 1>::new();
    let central_command = Channel::<NoopRawMutex, central::Command, 1>::new();
    let gatt_client_command = Channel::<NoopRawMutex, gatt_client::Command, 1>::new();
    let l2cap_command = Channel::<NoopRawMutex, l2cap::Command, 1>::new();
    let conn_watch: Watch<NoopRawMutex, Connection<'_, DefaultPacketPool>, 2> = Watch::new();
    let conn_sender = conn_watch.dyn_sender();
    let mut gatt_client_rx = conn_watch.dyn_receiver().unwrap();
    let mut l2cap_rx = conn_watch.dyn_receiver().unwrap();

    let channels = command_channel::CommandChannels {
        peripheral: peripheral_command.sender(),
        central: central_command.sender(),
        gatt_client: gatt_client_command.sender(),
        l2cap: l2cap_command.sender(),
        response: response.receiver(),
    };

    match select(
        l2cap::run(
            &stack,
            CommandReceiver::new(l2cap_command.receiver(), response.sender()),
            events.dyn_sender(),
            &mut l2cap_rx,
            pre.l2cap_listener,
        ),
        select5(
            ble_task(runner, events.dyn_sender(), &scan_mode),
            peripheral::run(
                &stack,
                peripheral,
                CommandReceiver::new(peripheral_command.receiver(), response.sender()),
                &server,
                events.dyn_sender(),
                &conn_sender,
                &oob,
            ),
            central::run(
                &stack,
                central,
                CommandReceiver::new(central_command.receiver(), response.sender()),
                &server,
                events.dyn_sender(),
                &conn_sender,
                &oob,
            ),
            gatt_client::run(
                &stack,
                CommandReceiver::new(gatt_client_command.receiver(), response.sender()),
                events.dyn_sender(),
                &mut gatt_client_rx,
            ),
            btp::run(
                pre.transport,
                gap,
                &config,
                &server,
                &stack,
                events.dyn_receiver(),
                &channels,
                &mut packet,
            ),
        ),
    )
    .await
    {
        Either::First(never) => match never {},
        Either::Second(Either5::First(result)) => result?,
        Either::Second(Either5::Second(never)) => match never {},
        Either::Second(Either5::Third(never)) => match never {},
        Either::Second(Either5::Fourth(never)) => match never {},
        Either::Second(Either5::Fifth(result)) => result?,
    }

    Ok(())
}

/// Initialize the attribute table with mandatory GAP and GATT services.
fn init_table<'d>(table: &mut AttributeTable<'d, NoopRawMutex, ATTRIBUTE_TABLE_SIZE>, config: &'d BtpConfig<'_>) {
    trace!("init_table");
    let mut gap_builder = table.add_service(Service::new(service::GAP));
    gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, config.device_name);
    gap_builder.add_characteristic_ro(characteristic::APPEARANCE, &config.appearance);
    gap_builder.add_characteristic_small(
        characteristic::CENTRAL_ADDRESS_RESOLUTION,
        [CharacteristicProp::Read],
        1u8,
    );
    gap_builder.build();

    let mut gatt_builder = table.add_service(Service::new(service::GATT));

    let _service_changed = gatt_builder
        .add_characteristic_small(characteristic::SERVICE_CHANGED, [CharacteristicProp::Indicate], [])
        .build();

    let _client_supported_features = gatt_builder
        .add_characteristic_small(
            characteristic::CLIENT_SUPPORTED_FEATURES,
            [CharacteristicProp::Read, CharacteristicProp::Write],
            0u8,
        )
        .build();

    static DATABASE_HASH_STORE: StaticCell<[u8; 16]> = StaticCell::new();
    let database_hash_store = DATABASE_HASH_STORE.init(0u128.to_le_bytes());
    let _database_hash = gatt_builder
        .add_characteristic(
            characteristic::DATABASE_HASH,
            [CharacteristicProp::Read],
            0u128,
            database_hash_store,
        )
        .build();

    gatt_builder.build();

    assert_eq!(table.len(), GAP_ATTRIBUTE_COUNT + GATT_ATTRIBUTE_COUNT);
}

/// Scan filter mode set by the BTP layer and read by the HCI event handler to decide
/// which advertising reports to forward as `DeviceFound` events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum ScanMode {
    /// Not scanning — drop all advertising reports.
    #[default]
    Disabled,
    /// Limited discovery — forward only reports with LE Limited Discoverable flag.
    LimitedDiscovery,
    /// General discovery — forward only reports with LE General or Limited Discoverable flags.
    GeneralDiscovery,
    /// Observation — forward all advertising reports.
    Observer,
}

/// Shared OOB (Out of Band) pairing state, written by BTP commands and read by connection tasks.
pub(crate) struct OobState {
    /// Legacy OOB TK value (16 bytes), set via `OobLegacySetData`.
    pub legacy_tk: Cell<Option<[u8; 16]>>,
    /// Local SC OOB data, generated via `OobScGetLocalData`.
    pub sc_local: Cell<Option<OobData>>,
    /// Remote SC OOB data, set via `OobScSetRemoteData`.
    pub sc_remote: Cell<Option<OobData>>,
}

impl OobState {
    fn new() -> Self {
        Self {
            legacy_tk: Cell::new(None),
            sc_local: Cell::new(None),
            sc_remote: Cell::new(None),
        }
    }

    /// Whether any OOB data has been configured.
    pub fn has_oob(&self) -> bool {
        self.legacy_tk.get().is_some() || (self.sc_local.get().is_some() && self.sc_remote.get().is_some())
    }
}

/// HCI event handler that forwards advertising reports to the event channel.
///
/// During active scanning the controller reports advertising data and scan response data as
/// separate HCI events. This handler caches advertising data so that when the subsequent scan
/// response arrives, a combined `DeviceFound` event is emitted with both `adv_data` and
/// `scan_data` populated.
struct BleEventHandler<'a> {
    events: DynamicSender<'a, Event>,
    scan_mode: &'a Cell<ScanMode>,
    /// Cached advertising data from the most recent non-scan-response report.
    last_adv: RefCell<Option<(Address, alloc::rc::Rc<[u8]>)>>,
}

impl BleEventHandler<'_> {
    /// Check whether an advertising report passes the current scan filter.
    fn passes_filter(&self, data: &[u8]) -> bool {
        match self.scan_mode.get() {
            ScanMode::Disabled => false,
            ScanMode::Observer => true,
            mode @ (ScanMode::GeneralDiscovery | ScanMode::LimitedDiscovery) => {
                // Extract discoverable flags from the first AD structure if it's a Flags type.
                let disc_flags = if data.len() >= 3 && data[0] == 2 && data[1] == 0x01 {
                    data[2]
                } else {
                    0
                };
                let required = if mode == ScanMode::LimitedDiscovery {
                    0x01 // LE Limited Discoverable only
                } else {
                    0x03 // LE Limited or General Discoverable
                };
                (disc_flags & required) != 0
            }
        }
    }
}

impl BleEventHandler<'_> {
    fn handle_report(&self, address: Address, rssi: i8, scan_response: bool, data: &[u8]) {
        let (adv_data, scan_data) = if scan_response {
            // Check if we have cached advertising data for this address.
            let cached = self.last_adv.borrow_mut().take();
            match cached {
                Some((cached_addr, cached_data)) if cached_addr == address => {
                    // Filter scan responses based on cached adv data when in a discovery mode.
                    if !self.passes_filter(&cached_data) {
                        return;
                    }
                    (Some(cached_data), alloc::boxed::Box::<[u8]>::from(data))
                }
                _ => return, // No cached adv data for this address; ignore the scan response.
            }
        } else {
            // Always cache adv data so scan responses can be filtered against it.
            let rc: alloc::rc::Rc<[u8]> = alloc::rc::Rc::from(data);
            *self.last_adv.borrow_mut() = Some((address, rc.clone()));
            if !self.passes_filter(data) {
                return;
            }
            (Some(rc), alloc::boxed::Box::from(&[] as &[u8]))
        };

        if let Err(e) = self.events.try_send(Event::DeviceFound {
            address,
            rssi,
            adv_data,
            scan_data,
        }) {
            error!("Failed to send DeviceFound event: {:?}", e);
        }
    }
}

impl EventHandler for BleEventHandler<'_> {
    fn on_adv_reports(&self, reports: bt_hci::param::LeAdvReportsIter) {
        for report in reports {
            let Ok(report) = report else { continue };
            trace!("adv report: addr={:?}", report.addr);
            self.handle_report(
                Address {
                    kind: report.addr_kind,
                    addr: report.addr,
                },
                report.rssi,
                report.event_kind == LeAdvEventKind::ScanRsp,
                report.data,
            );
        }
    }

    fn on_ext_adv_reports(&self, reports: bt_hci::param::LeExtAdvReportsIter) {
        for report in reports {
            let Ok(report) = report else { continue };
            trace!("ext adv report: addr={:?}", report.addr);
            self.handle_report(
                Address {
                    kind: report.addr_kind,
                    addr: report.addr,
                },
                report.rssi,
                report.event_kind.scan_response(),
                report.data,
            );
        }
    }
}

/// Run the trouble-host HCI event loop, forwarding advertising reports via [`BleEventHandler`].
async fn ble_task<C: Controller, P: PacketPool>(
    mut runner: Runner<'_, C, P>,
    events: DynamicSender<'_, Event>,
    scan_mode: &Cell<ScanMode>,
) -> Result<(), BleHostError<C::Error>> {
    trace!("ble_task");
    let handler = BleEventHandler {
        events,
        scan_mode,
        last_adv: RefCell::new(None),
    };
    loop {
        runner.run_with_handler(&handler).await?;
    }
}
