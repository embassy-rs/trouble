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

use bt_hci::cmd::le::{
    LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeConnUpdate, LeCreateConn, LeReadLocalSupportedFeatures,
    LeSetScanParams,
};
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::LeAdvEventKind;
use embassy_futures::select::{Either5, select5};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, DynamicSender};
use embedded_io_async::{Read, Write};
use rand_core::{CryptoRng, RngCore};
use static_cell::StaticCell;
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
    + ControllerCmdAsync<LeCreateConn>
    + ControllerCmdAsync<LeConnUpdate>
    + embedded_io::ErrorType<Error: ErrorFormat>
{
}

impl<T> Controller for T where
    T: trouble_host::prelude::Controller
        + ControllerCmdSync<LeReadLocalSupportedFeatures>
        + ControllerCmdSync<LeSetScanParams>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdAsync<LeCreateConn>
        + ControllerCmdAsync<LeConnUpdate>
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
        scan_response: bool,
        adv_data: alloc::boxed::Box<[u8]>,
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
}

/// Maximum number of concurrent BLE connections.
const CONNECTIONS_MAX: usize = 1;
/// Maximum number of L2CAP channels (Signal + ATT + SMP).
const L2CAP_CHANNELS_MAX: usize = 3;
/// Maximum number of attributes in the GATT attribute table.
const ATTRIBUTE_TABLE_SIZE: usize = 64;
/// Maximum number of CCCD (Client Characteristic Configuration Descriptor) entries.
const CCCD_TABLE_SIZE: usize = 10;
/// Number of attributes used by the GAP service (service + device name + appearance).
const GAP_ATTRIBUTE_COUNT: usize = 5;
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
    let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();

    let stack = trouble_host::new(controller, &mut resources)
        .set_random_address(config.address)
        .set_random_generator_seed(&mut random_generator);

    let Host {
        peripheral,
        central,
        runner,
        ..
    } = stack.build();

    let mut table = AttributeTable::<NoopRawMutex, ATTRIBUTE_TABLE_SIZE>::new();
    init_table(&mut table, &config);

    // Phase 1: Pre-server BTP loop (handles Core, GATT building, GAP settings)
    let transport = btp::BtpTransport { reader, writer };
    let mut packet = btp::protocol::BtpPacket::new();
    info!("Entering pre-server phase");
    let Some(pre) = btp::run_pre_server(transport, &config, &stack, &mut table, &mut packet).await? else {
        info!("Clean shutdown from pre-server phase");
        return Ok(());
    };

    info!("Pre-server phase complete, creating server");

    // Between phases: Create server on this stack frame
    let server = Server::new(table);

    // Phase 2: Full concurrent operation
    info!("Entering phase 2: concurrent operation");
    let events = Channel::<NoopRawMutex, Event, 8>::new();
    let response = Channel::<NoopRawMutex, command_channel::Response, 1>::new();

    let peripheral_command = Channel::<NoopRawMutex, peripheral::Command, 1>::new();
    let central_command = Channel::<NoopRawMutex, central::Command, 1>::new();
    let gatt_client_command = Channel::<NoopRawMutex, gatt_client::Command, 1>::new();

    let channels = command_channel::CommandChannels {
        peripheral: peripheral_command.sender(),
        central: central_command.sender(),
        gatt_client: gatt_client_command.sender(),
        response: response.receiver(),
    };

    match select5(
        ble_task(runner, events.dyn_sender()),
        peripheral::run(
            &stack,
            peripheral,
            CommandReceiver::new(peripheral_command.receiver(), response.sender()),
            &server,
            events.dyn_sender(),
        ),
        central::run(
            &stack,
            central,
            CommandReceiver::new(central_command.receiver(), response.sender()),
            &server,
            events.dyn_sender(),
        ),
        gatt_client::run(
            &stack,
            CommandReceiver::new(gatt_client_command.receiver(), response.sender()),
            events.dyn_sender(),
        ),
        btp::run(
            pre,
            &config,
            server.table(),
            events.dyn_receiver(),
            &channels,
            &mut packet,
        ),
    )
    .await
    {
        Either5::First(result) => result?,
        Either5::Second(never) => match never {},
        Either5::Third(never) => match never {},
        Either5::Fourth(never) => match never {},
        Either5::Fifth(result) => result?,
    }

    Ok(())
}

/// Initialize the attribute table with mandatory GAP and GATT services.
fn init_table<'d>(table: &mut AttributeTable<'d, NoopRawMutex, ATTRIBUTE_TABLE_SIZE>, config: &'d BtpConfig<'_>) {
    trace!("init_table");
    let mut gap_builder = table.add_service(Service::new(service::GAP));
    gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, config.device_name);
    gap_builder.add_characteristic_ro(characteristic::APPEARANCE, &config.appearance);
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

/// HCI event handler that forwards advertising reports to the event channel.
struct BleEventHandler<'a> {
    events: DynamicSender<'a, Event>,
}

impl EventHandler for BleEventHandler<'_> {
    fn on_adv_reports(&self, reports: bt_hci::param::LeAdvReportsIter) {
        for report in reports {
            let Ok(report) = report else { continue };
            trace!("adv report: addr={:?}", report.addr);
            if report.data.len() >= 3
                && report.data[0] == 2
                && report.data[1] == 1
                && (report.data[2] & 0x03) != 0
                && let Err(e) = self.events.try_send(Event::DeviceFound {
                    address: Address {
                        kind: report.addr_kind,
                        addr: report.addr,
                    },
                    rssi: report.rssi,
                    scan_response: report.event_kind == LeAdvEventKind::ScanRsp,
                    adv_data: alloc::boxed::Box::from(report.data),
                })
            {
                // If reports are received faster than they can be sent via BTP
                // we drop the excess reports.
                error!("Failed to send DeviceFound event: {:?}", e);
            }
        }
    }

    fn on_ext_adv_reports(&self, reports: bt_hci::param::LeExtAdvReportsIter) {
        for report in reports {
            let Ok(report) = report else { continue };
            trace!("ext adv report: addr={:?}", report.addr);
            if report.data.len() >= 3
                && report.data[0] == 2
                && report.data[1] == 1
                && (report.data[2] & 0x03) != 0
                && let Err(e) = self.events.try_send(Event::DeviceFound {
                    address: Address {
                        kind: report.addr_kind,
                        addr: report.addr,
                    },
                    rssi: report.rssi,
                    scan_response: report.event_kind.scan_response(),
                    adv_data: alloc::boxed::Box::from(report.data),
                })
            {
                // If reports are received faster than they can be sent via BTP
                // we drop the excess reports.
                error!("Failed to send DeviceFound event: {:?}", e);
            }
        }
    }
}

/// Run the trouble-host HCI event loop, forwarding advertising reports via [`BleEventHandler`].
async fn ble_task<C: Controller, P: PacketPool>(
    mut runner: Runner<'_, C, P>,
    events: DynamicSender<'_, Event>,
) -> Result<(), BleHostError<C::Error>> {
    trace!("ble_task");
    let handler = BleEventHandler { events };
    loop {
        runner.run_with_handler(&handler).await?;
    }
}
