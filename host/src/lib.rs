//! Trouble is a Bluetooth Low Energy (BLE) Host implementation that communicates
//! with a controller over any transport implementing the traits from the `bt-hci`
//! crate.
//!
//! Trouble can run on embedded devices (`no_std`) and be configured to consume
//! as little resources are needed depending on your required configuration.
#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::needless_lifetimes)]
#![warn(missing_docs)]

use core::mem::MaybeUninit;

use advertise::AdvertisementDataError;
use bt_hci::FromHciBytesError;
use bt_hci::cmd::status::ReadRssi;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::param::{AddrKind, BdAddr};

use crate::att::AttErrorCode;
use crate::channel_manager::{ChannelStorage, PacketChannel};
use crate::connection_manager::{ConnectionStorage, EventChannel};
use crate::l2cap::sar::SarType;
use crate::packet_pool::PacketPool;

mod fmt;

#[cfg(not(any(feature = "central", feature = "peripheral")))]
compile_error!("Must enable at least one of the `central` or `peripheral` features");

pub mod att;
#[cfg(feature = "central")]
pub mod central;
mod channel_manager;
mod codec;
mod command;
pub mod config;
mod connection_manager;
mod cursor;
pub mod packet_pool;
mod pdu;
#[cfg(feature = "peripheral")]
pub mod peripheral;
pub mod types;

#[cfg(feature = "central")]
use central::*;
#[cfg(feature = "peripheral")]
use peripheral::*;

pub mod advertise;
pub mod connection;
#[cfg(feature = "gatt")]
pub mod gap;
pub mod l2cap;
#[cfg(feature = "scan")]
pub mod scan;

#[cfg(test)]
pub(crate) mod mock_controller;

pub(crate) mod host;
use host::{AdvHandleState, BleHost, HostMetrics, Runner};

#[allow(missing_docs)]
pub mod prelude {
    pub use bt_hci::param::{AddrKind, BdAddr, LeConnRole as Role};
    pub use bt_hci::uuid::*;
    #[cfg(feature = "derive")]
    pub use heapless::String as HeaplessString;
    #[cfg(feature = "derive")]
    pub use trouble_host_macros::*;

    pub use super::att::AttErrorCode;
    pub use super::{BleHostError, Controller, Error, Host, HostResources, Stack};
    pub use crate::Address;
    #[cfg(feature = "peripheral")]
    pub use crate::advertise::*;
    #[cfg(feature = "gatt")]
    pub use crate::attribute::*;
    #[cfg(feature = "gatt")]
    pub use crate::attribute_server::*;
    #[cfg(feature = "central")]
    pub use crate::central::*;
    pub use crate::connection::*;
    #[cfg(feature = "gatt")]
    pub use crate::gap::*;
    #[cfg(feature = "gatt")]
    pub use crate::gatt::*;
    pub use crate::host::{ControlRunner, EventHandler, HostMetrics, Runner, RxRunner, TxRunner};
    pub use crate::l2cap::*;
    pub use crate::packet_pool::PacketPool;
    #[cfg(feature = "peripheral")]
    pub use crate::peripheral::*;
    #[cfg(feature = "scan")]
    pub use crate::scan::*;
    #[cfg(feature = "gatt")]
    pub use crate::types::gatt_traits::{AsGatt, FixedGattValue, FromGatt};
}

#[cfg(feature = "gatt")]
pub mod attribute;
#[cfg(feature = "gatt")]
mod attribute_server;
#[cfg(feature = "gatt")]
pub mod gatt;

/// A BLE address.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Address {
    /// Address type.
    pub kind: AddrKind,
    /// Address value.
    pub addr: BdAddr,
}

impl Address {
    /// Create a new random address.
    pub fn random(val: [u8; 6]) -> Self {
        Self {
            kind: AddrKind::RANDOM,
            addr: BdAddr::new(val),
        }
    }
}

/// Errors returned by the host.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BleHostError<E> {
    /// Error from the controller.
    Controller(E),
    /// Error from the host.
    BleHost(Error),
}

/// Errors related to Host.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Error encoding parameters for HCI commands.
    Hci(bt_hci::param::Error),
    /// Error decoding responses from HCI commands.
    HciDecode(FromHciBytesError),
    /// Error from the Attribute Protocol.
    Att(AttErrorCode),
    /// Insufficient space in the buffer.
    InsufficientSpace,
    /// Invalid value.
    InvalidValue,
    /// Error decoding advertisement data.
    Advertisement(AdvertisementDataError),
    /// Invalid l2cap channel id provided.
    InvalidChannelId,
    /// No l2cap channel available.
    NoChannelAvailable,
    /// Resource not found.
    NotFound,
    /// Invalid state.
    InvalidState,
    /// Out of memory.
    OutOfMemory,
    /// Unsupported operation.
    NotSupported,
    /// L2cap channel closed.
    ChannelClosed,
    /// Operation timed out.
    Timeout,
    /// Controller is busy.
    Busy,
    /// No send permits available.
    NoPermits,
    /// Connection is disconnected.
    Disconnected,
    /// Other error.
    Other,
}

impl<E> From<Error> for BleHostError<E> {
    fn from(value: Error) -> Self {
        Self::BleHost(value)
    }
}

impl From<FromHciBytesError> for Error {
    fn from(error: FromHciBytesError) -> Self {
        Self::HciDecode(error)
    }
}

impl From<AttErrorCode> for Error {
    fn from(error: AttErrorCode) -> Self {
        Self::Att(error)
    }
}

impl<E> From<bt_hci::cmd::Error<E>> for BleHostError<E> {
    fn from(error: bt_hci::cmd::Error<E>) -> Self {
        match error {
            bt_hci::cmd::Error::Hci(p) => Self::BleHost(Error::Hci(p)),
            bt_hci::cmd::Error::Io(p) => Self::Controller(p),
        }
    }
}

impl<E> From<bt_hci::param::Error> for BleHostError<E> {
    fn from(error: bt_hci::param::Error) -> Self {
        Self::BleHost(Error::Hci(error))
    }
}

impl From<codec::Error> for Error {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => Error::InsufficientSpace,
            codec::Error::InvalidValue => Error::InvalidValue,
        }
    }
}

impl<E> From<codec::Error> for BleHostError<E> {
    fn from(error: codec::Error) -> Self {
        match error {
            codec::Error::InsufficientSpace => BleHostError::BleHost(Error::InsufficientSpace),
            codec::Error::InvalidValue => BleHostError::BleHost(Error::InvalidValue),
        }
    }
}

use bt_hci::cmd::controller_baseband::*;
use bt_hci::cmd::le::*;
use bt_hci::cmd::link_control::*;
use bt_hci::controller::{ControllerCmdAsync, ControllerCmdSync};

/// Trait that defines the controller implementation required by the host.
///
/// The controller must implement the required commands and events to be able to be used with Trouble.
pub trait Controller:
    bt_hci::controller::Controller
    + embedded_io::ErrorType
    + ControllerCmdSync<LeReadBufferSize>
    + ControllerCmdSync<Disconnect>
    + ControllerCmdSync<SetEventMask>
    + ControllerCmdSync<LeSetEventMask>
    + ControllerCmdSync<LeSetRandomAddr>
    + ControllerCmdSync<HostBufferSize>
    + ControllerCmdAsync<LeConnUpdate>
    + ControllerCmdSync<LeReadFilterAcceptListSize>
    + ControllerCmdSync<SetControllerToHostFlowControl>
    + ControllerCmdSync<Reset>
    + ControllerCmdSync<ReadRssi>
    + ControllerCmdSync<LeCreateConnCancel>
    + ControllerCmdSync<LeSetScanEnable>
    + ControllerCmdSync<LeSetExtScanEnable>
    + ControllerCmdAsync<LeCreateConn>
    + ControllerCmdSync<LeClearFilterAcceptList>
    + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
    + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
    + ControllerCmdSync<LeReadBufferSize>
    + for<'t> ControllerCmdSync<LeSetAdvData>
    + ControllerCmdSync<LeSetAdvParams>
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetScanResponseData>
{
}

impl<
    C: bt_hci::controller::Controller
        + embedded_io::ErrorType
        + ControllerCmdSync<LeReadBufferSize>
        + ControllerCmdSync<Disconnect>
        + ControllerCmdSync<SetEventMask>
        + ControllerCmdSync<LeSetEventMask>
        + ControllerCmdSync<LeSetRandomAddr>
        + ControllerCmdSync<HostBufferSize>
        + ControllerCmdAsync<LeConnUpdate>
        + ControllerCmdSync<LeReadFilterAcceptListSize>
        + ControllerCmdSync<LeClearFilterAcceptList>
        + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
        + ControllerCmdSync<SetControllerToHostFlowControl>
        + ControllerCmdSync<Reset>
        + ControllerCmdSync<ReadRssi>
        + ControllerCmdSync<LeSetScanEnable>
        + ControllerCmdSync<LeSetExtScanEnable>
        + ControllerCmdSync<LeCreateConnCancel>
        + ControllerCmdAsync<LeCreateConn>
        + for<'t> ControllerCmdSync<LeSetAdvEnable>
        + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
        + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
        + ControllerCmdSync<LeReadBufferSize>
        + for<'t> ControllerCmdSync<LeSetAdvData>
        + ControllerCmdSync<LeSetAdvParams>
        + for<'t> ControllerCmdSync<LeSetAdvEnable>
        + for<'t> ControllerCmdSync<LeSetScanResponseData>,
> Controller for C
{
}

/// HostResources holds the resources used by the host.
///
/// The l2cap packet pool is used by the host to handle inbound data, by allocating space for
/// incoming packets and dispatching to the appropriate connection and channel.
pub struct HostResources<const CONNS: usize, const CHANNELS: usize, const L2CAP_MTU: usize, const ADV_SETS: usize = 1> {
    rx_pool: MaybeUninit<PacketPool<L2CAP_MTU, { config::L2CAP_RX_PACKET_POOL_SIZE }>>,
    #[cfg(feature = "gatt")]
    tx_pool: MaybeUninit<PacketPool<L2CAP_MTU, { config::L2CAP_TX_PACKET_POOL_SIZE }>>,
    connections: MaybeUninit<[ConnectionStorage; CONNS]>,
    events: MaybeUninit<[EventChannel; CONNS]>,
    channels: MaybeUninit<[ChannelStorage; CHANNELS]>,
    channels_rx: MaybeUninit<[PacketChannel<{ config::L2CAP_RX_QUEUE_SIZE }>; CHANNELS]>,
    sar: MaybeUninit<[SarType; CONNS]>,
    advertise_handles: MaybeUninit<[AdvHandleState; ADV_SETS]>,
}

impl<const CONNS: usize, const CHANNELS: usize, const L2CAP_MTU: usize, const ADV_SETS: usize> Default
    for HostResources<CONNS, CHANNELS, L2CAP_MTU, ADV_SETS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const CONNS: usize, const CHANNELS: usize, const L2CAP_MTU: usize, const ADV_SETS: usize>
    HostResources<CONNS, CHANNELS, L2CAP_MTU, ADV_SETS>
{
    /// Create a new instance of host resources.
    pub const fn new() -> Self {
        Self {
            rx_pool: MaybeUninit::uninit(),
            #[cfg(feature = "gatt")]
            tx_pool: MaybeUninit::uninit(),
            connections: MaybeUninit::uninit(),
            events: MaybeUninit::uninit(),
            sar: MaybeUninit::uninit(),
            channels: MaybeUninit::uninit(),
            channels_rx: MaybeUninit::uninit(),
            advertise_handles: MaybeUninit::uninit(),
        }
    }
}

/// Create a new instance of the BLE host using the provided controller implementation and
/// the resource configuration
pub fn new<
    'resources,
    C: Controller,
    const CONNS: usize,
    const CHANNELS: usize,
    const L2CAP_MTU: usize,
    const ADV_SETS: usize,
>(
    controller: C,
    resources: &'resources mut HostResources<CONNS, CHANNELS, L2CAP_MTU, ADV_SETS>,
) -> Stack<'resources, C> {
    unsafe fn transmute_slice<T>(x: &mut [T]) -> &'static mut [T] {
        unsafe { core::mem::transmute(x) }
    }

    // Safety:
    // - HostResources has the exceeding lifetime as the returned Stack.
    // - Internal lifetimes are elided (made 'static) to simplify API usage
    // - This _should_ be OK, because there are no references held to the resources
    //   when the stack is shut down.
    use crate::packet_pool::Pool;
    let rx_pool: &'resources dyn Pool = &*resources.rx_pool.write(PacketPool::new());
    let rx_pool = unsafe { core::mem::transmute::<&'resources dyn Pool, &'static dyn Pool>(rx_pool) };

    #[cfg(feature = "gatt")]
    let tx_pool: &'resources dyn Pool = &*resources.tx_pool.write(PacketPool::new());
    #[cfg(feature = "gatt")]
    let tx_pool = unsafe { core::mem::transmute::<&'resources dyn Pool, &'static dyn Pool>(tx_pool) };

    use bt_hci::param::ConnHandle;

    use crate::l2cap::sar::AssembledPacket;
    use crate::types::l2cap::L2capHeader;
    let connections: &mut [ConnectionStorage] =
        &mut *resources.connections.write([ConnectionStorage::DISCONNECTED; CONNS]);
    let connections: &'resources mut [ConnectionStorage] = unsafe { transmute_slice(connections) };

    let events: &mut [EventChannel] = &mut *resources.events.write([EventChannel::NEW; CONNS]);
    let events: &'resources mut [EventChannel] = unsafe { transmute_slice(events) };

    let channels = &mut *resources.channels.write([ChannelStorage::DISCONNECTED; CHANNELS]);
    let channels: &'static mut [ChannelStorage] = unsafe { transmute_slice(channels) };

    let channels_rx: &mut [PacketChannel<{ config::L2CAP_RX_QUEUE_SIZE }>] =
        &mut *resources.channels_rx.write([PacketChannel::NEW; CHANNELS]);
    let channels_rx: &'static mut [PacketChannel<{ config::L2CAP_RX_QUEUE_SIZE }>] =
        unsafe { transmute_slice(channels_rx) };
    let sar = &mut *resources.sar.write([const { None }; CONNS]);
    let sar: &'static mut [Option<(ConnHandle, L2capHeader, AssembledPacket)>] = unsafe { transmute_slice(sar) };
    let advertise_handles = &mut *resources.advertise_handles.write([AdvHandleState::None; ADV_SETS]);
    let advertise_handles: &'static mut [AdvHandleState] = unsafe { transmute_slice(advertise_handles) };
    let host: BleHost<'_, C> = BleHost::new(
        controller,
        rx_pool,
        #[cfg(feature = "gatt")]
        tx_pool,
        connections,
        events,
        channels,
        channels_rx,
        sar,
        advertise_handles,
    );

    Stack { host }
}

/// Contains the host stack
pub struct Stack<'stack, C> {
    host: BleHost<'stack, C>,
}

/// Host components.
#[non_exhaustive]
pub struct Host<'stack, C> {
    /// Central role
    #[cfg(feature = "central")]
    pub central: Central<'stack, C>,
    /// Peripheral role
    #[cfg(feature = "peripheral")]
    pub peripheral: Peripheral<'stack, C>,
    /// Host runner
    pub runner: Runner<'stack, C>,
}

impl<'stack, C: Controller> Stack<'stack, C> {
    /// Set the random address used by this host.
    pub fn set_random_address(mut self, address: Address) -> Self {
        self.host.address.replace(address);
        self
    }

    /// Build the stack.
    pub fn build(&'stack self) -> Host<'stack, C> {
        Host {
            #[cfg(feature = "central")]
            central: Central::new(self),
            #[cfg(feature = "peripheral")]
            peripheral: Peripheral::new(self),
            runner: Runner::new(self),
        }
    }

    /// Run a HCI command and return the response.
    pub async fn command<T>(&self, cmd: T) -> Result<T::Return, BleHostError<C::Error>>
    where
        T: SyncCmd,
        C: ControllerCmdSync<T>,
    {
        self.host.command(cmd).await
    }

    /// Run an async HCI command where the response will generate an event later.
    pub async fn async_command<T>(&self, cmd: T) -> Result<(), BleHostError<C::Error>>
    where
        T: AsyncCmd,
        C: ControllerCmdAsync<T>,
    {
        self.host.async_command(cmd).await
    }

    /// Read current host metrics
    pub fn metrics(&self) -> HostMetrics {
        self.host.metrics()
    }

    /// Log status information of the host
    pub fn log_status(&self, verbose: bool) {
        self.host.log_status(verbose);
    }
}
