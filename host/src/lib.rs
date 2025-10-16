#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::needless_lifetimes)]
#![doc = include_str!(concat!("../", env!("CARGO_PKG_README")))]
#![warn(missing_docs)]

use core::mem::MaybeUninit;

use advertise::AdvertisementDataError;
use bt_hci::cmd::status::ReadRssi;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::param::{AddrKind, BdAddr};
use bt_hci::FromHciBytesError;
use embassy_time::Duration;
#[cfg(feature = "security")]
use heapless::Vec;
use rand_core::{CryptoRng, RngCore};

use crate::att::AttErrorCode;
use crate::channel_manager::ChannelStorage;
use crate::connection_manager::ConnectionStorage;
#[cfg(feature = "security")]
pub use crate::security_manager::{BondInformation, IdentityResolvingKey, LongTermKey};
pub use crate::types::capabilities::IoCapabilities;

/// Number of bonding information stored
pub(crate) const BI_COUNT: usize = 10; // Should be configurable

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
#[cfg(feature = "default-packet-pool")]
mod packet_pool;
mod pdu;
#[cfg(feature = "peripheral")]
pub mod peripheral;
#[cfg(feature = "security")]
mod security_manager;
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

pub mod prelude {
    //! Convenience include of most commonly used types.
    pub use bt_hci::controller::ExternalController;
    pub use bt_hci::param::{AddrKind, BdAddr, LeConnRole as Role, PhyKind, PhyMask};
    pub use bt_hci::transport::SerialTransport;
    pub use bt_hci::uuid::*;
    #[cfg(feature = "derive")]
    pub use trouble_host_macros::*;

    pub use super::att::AttErrorCode;
    pub use super::{BleHostError, Controller, Error, Host, HostResources, Packet, PacketPool, Stack};
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
    #[cfg(feature = "default-packet-pool")]
    pub use crate::packet_pool::DefaultPacketPool;
    pub use crate::pdu::Sdu;
    #[cfg(feature = "peripheral")]
    pub use crate::peripheral::*;
    #[cfg(feature = "scan")]
    pub use crate::scan::*;
    #[cfg(feature = "security")]
    pub use crate::security_manager::{BondInformation, IdentityResolvingKey, LongTermKey};
    pub use crate::types::capabilities::IoCapabilities;
    #[cfg(feature = "gatt")]
    pub use crate::types::gatt_traits::{AsGatt, FixedGattValue, FromGatt};
    pub use crate::{Address, Identity};
}

#[cfg(feature = "gatt")]
pub mod attribute;
#[cfg(feature = "gatt")]
mod attribute_server;
#[cfg(feature = "gatt")]
pub mod gatt;

/// A BLE address.
/// Every BLE device is identified by a unique *Bluetooth Device Address*, which is a 48-bit identifier similar to a MAC address. BLE addresses are categorized into two main types: *Public* and *Random*.
///
/// A Public Address is globally unique and assigned by the IEEE. It remains constant and is typically used by devices requiring a stable identifier.
///
/// A Random Address can be *static* or *dynamic*:
///
/// - *Static Random Address*: Remains fixed until the device restarts or resets.
/// - *Private Random Address*: Changes periodically for privacy purposes. It can be *Resolvable* (can be linked to the original device using an Identity Resolving Key) or *Non-Resolvable* (completely anonymous).
///
/// Random addresses enhance privacy by preventing device tracking.
#[derive(Debug, Clone, Copy, PartialEq)]
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

    /// To bytes
    pub fn to_bytes(&self) -> [u8; 7] {
        let mut bytes = [0; 7];
        bytes[0] = self.kind.into_inner();
        let mut addr_bytes = self.addr.into_inner();
        addr_bytes.reverse();
        bytes[1..].copy_from_slice(&addr_bytes);
        bytes
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let a = self.addr.into_inner();
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            a[5], a[4], a[3], a[2], a[1], a[0]
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Address {
    fn format(&self, fmt: defmt::Formatter) {
        let a = self.addr.into_inner();
        defmt::write!(
            fmt,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            a[5],
            a[4],
            a[3],
            a[2],
            a[1],
            a[0]
        )
    }
}

/// Identity of a peer device
///
/// Sometimes we have to save both the address and the IRK.
/// Because sometimes the peer uses the static or public address even though the IRK is sent.
/// In this case, the IRK exists but the used address is not RPA.
/// Should `Address` be used instead?
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// Random static or public address
    pub bd_addr: BdAddr,

    /// Identity Resolving Key
    #[cfg(feature = "security")]
    pub irk: Option<IdentityResolvingKey>,
}

#[cfg(feature = "defmt")]
impl defmt::Format for Identity {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "BdAddr({:X}) ", self.bd_addr);
        #[cfg(feature = "security")]
        defmt::write!(fmt, "Irk({:X})", self.irk);
    }
}

impl Identity {
    /// Check whether the address matches the identity
    pub fn match_address(&self, address: &BdAddr) -> bool {
        if self.bd_addr == *address {
            return true;
        }
        #[cfg(feature = "security")]
        if let Some(irk) = self.irk {
            return irk.resolve_address(address);
        }
        false
    }

    /// Check whether the given identity matches current identity
    pub fn match_identity(&self, identity: &Identity) -> bool {
        if self.match_address(&identity.bd_addr) {
            return true;
        }
        #[cfg(feature = "security")]
        if let Some(irk) = identity.irk {
            if let Some(current_irk) = self.irk {
                return irk == current_irk;
            } else {
                return irk.resolve_address(&self.bd_addr);
            }
        }
        false
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

/// How many bytes of invalid data to capture in the error variants before truncating.
pub const MAX_INVALID_DATA_LEN: usize = 16;

/// Errors related to Host.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// Error encoding parameters for HCI commands.
    Hci(bt_hci::param::Error),
    /// Error decoding responses from HCI commands.
    HciDecode(FromHciBytesError),
    /// Error from the Attribute Protocol.
    Att(AttErrorCode),
    #[cfg(feature = "security")]
    /// Error from the security manager
    Security(crate::security_manager::Reason),
    /// Insufficient space in the buffer.
    InsufficientSpace,
    /// Invalid value.
    InvalidValue,

    /// Unexpected data length.
    ///
    /// This happens if the attribute data length doesn't match the input length size,
    /// and the attribute is deemed as *not* having variable length due to the characteristic's
    /// `MAX_SIZE` and `MIN_SIZE` being defined as equal.
    UnexpectedDataLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Error converting from GATT value.
    CannotConstructGattValue([u8; MAX_INVALID_DATA_LEN]),

    /// Scan config filter accept list is empty.
    ConfigFilterAcceptListIsEmpty,

    /// Unexpected GATT response.
    UnexpectedGattResponse,

    /// Received characteristic declaration data shorter than the minimum required length (5 bytes).
    MalformedCharacteristicDeclaration {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Failed to decode the data structure within a characteristic declaration attribute value.
    InvalidCharacteristicDeclarationData,

    /// Failed to finalize the packet.
    FailedToFinalize {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },

    /// Codec error.
    CodecError(codec::Error),

    /// Extended advertising not supported.
    ExtendedAdvertisingNotSupported,

    /// Invalid UUID length.
    InvalidUuidLength(usize),

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
    /// Connection limit has been reached.
    ConnectionLimitReached,
    /// GATT subscriber limit has been reached.
    ///
    /// The limit can be modified using the `gatt-client-notification-max-subscribers-N` features.
    GattSubscriberLimitReached,
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
            codec::Error::InvalidValue => Error::CodecError(error),
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
use bt_hci::cmd::info::*;
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
    + ControllerCmdSync<SetEventMaskPage2>
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
    + ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
    + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
    + ControllerCmdSync<LeReadBufferSize>
    + ControllerCmdSync<LeSetAdvData>
    + ControllerCmdSync<LeSetAdvParams>
    + ControllerCmdSync<LeSetAdvEnable>
    + ControllerCmdSync<LeSetScanResponseData>
    + ControllerCmdSync<LeLongTermKeyRequestReply>
    + ControllerCmdAsync<LeEnableEncryption>
    + ControllerCmdSync<ReadBdAddr>
{
}

impl<
        C: bt_hci::controller::Controller
            + embedded_io::ErrorType
            + ControllerCmdSync<LeReadBufferSize>
            + ControllerCmdSync<Disconnect>
            + ControllerCmdSync<SetEventMask>
            + ControllerCmdSync<SetEventMaskPage2>
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
            + ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeReadBufferSize>
            + ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + ControllerCmdSync<LeSetAdvEnable>
            + ControllerCmdSync<LeSetScanResponseData>
            + ControllerCmdSync<LeLongTermKeyRequestReply>
            + ControllerCmdAsync<LeEnableEncryption>
            + ControllerCmdSync<ReadBdAddr>,
    > Controller for C
{
}

/// A Packet is a byte buffer for packet data.
/// Similar to a `Vec<u8>` it has a length and a capacity.
pub trait Packet: Sized + AsRef<[u8]> + AsMut<[u8]> {}

/// A Packet Pool that can allocate packets of the desired size.
///
/// The MTU is usually related to the MTU of l2cap payloads.
pub trait PacketPool: 'static {
    /// Packet type provided by this pool.
    type Packet: Packet;

    /// The maximum size a packet can have.
    const MTU: usize;

    /// Allocate a new buffer with space for `MTU` bytes.
    /// Return `None` when the allocation can't be fulfilled.
    ///
    /// This function is called by the L2CAP driver when it needs
    /// space to receive a packet into.
    /// It will later call `from_raw_parts` with the buffer and the
    /// amount of bytes it has received.
    fn allocate() -> Option<Self::Packet>;

    /// Capacity of this pool in the number of packets.
    fn capacity() -> usize;
}

/// HostResources holds the resources used by the host.
///
/// The l2cap packet pool is used by the host to handle inbound data, by allocating space for
/// incoming packets and dispatching to the appropriate connection and channel.
pub struct HostResources<P: PacketPool, const CONNS: usize, const CHANNELS: usize, const ADV_SETS: usize = 1> {
    connections: MaybeUninit<[ConnectionStorage<P::Packet>; CONNS]>,
    channels: MaybeUninit<[ChannelStorage<P::Packet>; CHANNELS]>,
    advertise_handles: MaybeUninit<[AdvHandleState; ADV_SETS]>,
}

impl<P: PacketPool, const CONNS: usize, const CHANNELS: usize, const ADV_SETS: usize> Default
    for HostResources<P, CONNS, CHANNELS, ADV_SETS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<P: PacketPool, const CONNS: usize, const CHANNELS: usize, const ADV_SETS: usize>
    HostResources<P, CONNS, CHANNELS, ADV_SETS>
{
    /// Create a new instance of host resources.
    pub const fn new() -> Self {
        Self {
            connections: MaybeUninit::uninit(),
            channels: MaybeUninit::uninit(),
            advertise_handles: MaybeUninit::uninit(),
        }
    }
}

/// Create a new instance of the BLE host using the provided controller implementation and
/// the resource configuration
pub fn new<
    'resources,
    C: Controller,
    P: PacketPool,
    const CONNS: usize,
    const CHANNELS: usize,
    const ADV_SETS: usize,
>(
    controller: C,
    resources: &'resources mut HostResources<P, CONNS, CHANNELS, ADV_SETS>,
) -> Stack<'resources, C, P> {
    unsafe fn transmute_slice<T>(x: &mut [T]) -> &'static mut [T] {
        unsafe { core::mem::transmute(x) }
    }

    // Safety:
    // - HostResources has the exceeding lifetime as the returned Stack.
    // - Internal lifetimes are elided (made 'static) to simplify API usage
    // - This _should_ be OK, because there are no references held to the resources
    //   when the stack is shut down.

    let connections: &mut [ConnectionStorage<P::Packet>] =
        &mut *resources.connections.write([const { ConnectionStorage::new() }; CONNS]);
    let connections: &'resources mut [ConnectionStorage<P::Packet>] = unsafe { transmute_slice(connections) };

    let channels = &mut *resources.channels.write([const { ChannelStorage::new() }; CHANNELS]);
    let channels: &'static mut [ChannelStorage<P::Packet>] = unsafe { transmute_slice(channels) };

    let advertise_handles = &mut *resources.advertise_handles.write([AdvHandleState::None; ADV_SETS]);
    let advertise_handles: &'static mut [AdvHandleState] = unsafe { transmute_slice(advertise_handles) };
    let host: BleHost<'_, C, P> = BleHost::new(controller, connections, channels, advertise_handles);

    Stack { host }
}

/// Contains the host stack
pub struct Stack<'stack, C, P: PacketPool> {
    host: BleHost<'stack, C, P>,
}

/// Host components.
#[non_exhaustive]
pub struct Host<'stack, C, P: PacketPool> {
    /// Central role
    #[cfg(feature = "central")]
    pub central: Central<'stack, C, P>,
    /// Peripheral role
    #[cfg(feature = "peripheral")]
    pub peripheral: Peripheral<'stack, C, P>,
    /// Host runner
    pub runner: Runner<'stack, C, P>,
}

impl<'stack, C: Controller, P: PacketPool> Stack<'stack, C, P> {
    /// Set the random address used by this host.
    pub fn set_random_address(mut self, address: Address) -> Self {
        self.host.address.replace(address);
        #[cfg(feature = "security")]
        self.host.connections.security_manager.set_local_address(address);
        self
    }
    /// Set the random generator seed for random generator used by security manager
    pub fn set_random_generator_seed<RNG: RngCore + CryptoRng>(self, _random_generator: &mut RNG) -> Self {
        #[cfg(feature = "security")]
        {
            let mut random_seed = [0u8; 32];
            _random_generator.fill_bytes(&mut random_seed);
            self.host
                .connections
                .security_manager
                .set_random_generator_seed(random_seed);
        }
        self
    }
    /// Set the IO capabilities used by the security manager.
    ///
    /// Only relevant if the feature `security` is enabled.
    pub fn set_io_capabilities(self, io_capabilities: IoCapabilities) -> Self {
        #[cfg(feature = "security")]
        {
            self.host
                .connections
                .security_manager
                .set_io_capabilities(io_capabilities);
        }
        self
    }

    /// Build the stack.
    pub fn build(&'stack self) -> Host<'stack, C, P> {
        #[cfg(all(feature = "security", not(feature = "dev-disable-csprng-seed-requirement")))]
        {
            if !self.host.connections.security_manager.get_random_generator_seeded() {
                panic!(
                    "The security manager random number generator has not been seeded from a cryptographically secure random number generator"
                )
            }
        }
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
    pub fn metrics<F: FnOnce(&HostMetrics) -> R, R>(&self, f: F) -> R {
        self.host.metrics(f)
    }

    /// Log status information of the host
    pub fn log_status(&self, verbose: bool) {
        self.host.log_status(verbose);
    }

    #[cfg(feature = "security")]
    /// Get bonded devices
    pub fn add_bond_information(&self, bond_information: BondInformation) -> Result<(), Error> {
        self.host
            .connections
            .security_manager
            .add_bond_information(bond_information)
    }

    #[cfg(feature = "security")]
    /// Remove a bonded device
    pub fn remove_bond_information(&self, identity: Identity) -> Result<(), Error> {
        self.host.connections.security_manager.remove_bond_information(identity)
    }

    #[cfg(feature = "security")]
    /// Get bonded devices
    pub fn get_bond_information(&self) -> Vec<BondInformation, BI_COUNT> {
        self.host.connections.security_manager.get_bond_information()
    }
}

pub(crate) fn bt_hci_duration<const US: u32>(d: Duration) -> bt_hci::param::Duration<US> {
    bt_hci::param::Duration::from_micros(d.as_micros())
}

pub(crate) fn bt_hci_ext_duration<const US: u16>(d: Duration) -> bt_hci::param::ExtDuration<US> {
    bt_hci::param::ExtDuration::from_micros(d.as_micros())
}
