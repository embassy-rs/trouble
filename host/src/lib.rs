#![no_std]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::needless_lifetimes)]
#![doc = include_str!(concat!("../", env!("CARGO_PKG_README")))]
#![warn(missing_docs)]

use core::cell::{Cell, RefCell};
use core::mem::{ManuallyDrop, MaybeUninit};

use advertise::AdvertisementDataError;
use bt_hci::cmd::le::LeReadMinimumSupportedConnectionInterval;
use bt_hci::cmd::status::ReadRssi;
use bt_hci::cmd::{AsyncCmd, SyncCmd};
use bt_hci::param::{AddrKind, BdAddr, ConnHandle};
use bt_hci::FromHciBytesError;
use embassy_time::Duration;
#[cfg(feature = "security")]
use heapless::{Vec, VecView};
#[cfg(feature = "security")]
use rand_core::{CryptoRng, RngCore};

use crate::att::AttErrorCode;
use crate::channel_manager::ChannelStorage;
use crate::connection::Connection;
use crate::connection_manager::ConnectionStorage;
#[cfg(feature = "security")]
pub use crate::security_manager::{
    BondInformation, IdentityResolvingKey, LongTermKey, OobData, Reason as PairingFailedReason,
};
pub use crate::types::capabilities::IoCapabilities;

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
    pub use heapless::String as HeaplessString;
    #[cfg(feature = "derive")]
    pub use trouble_host_macros::*;

    pub use super::att::AttErrorCode;
    pub use super::{BleHostError, Controller, Error, HostResources, Packet, PacketPool, Stack, StackBuilder};
    #[cfg(feature = "peripheral")]
    pub use crate::advertise::*;
    #[cfg(feature = "gatt")]
    pub use crate::attribute::*;
    #[cfg(feature = "gatt")]
    pub use crate::attribute_server::*;
    #[cfg(feature = "central")]
    pub use crate::central::*;
    pub use crate::connection::{ConnectRateParams, *};
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
    pub use crate::security_manager::{
        BondInformation, IdentityResolvingKey, LongTermKey, OobData, Reason as PairingFailedReason,
    };
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
#[derive(Debug, Clone, Copy, Default, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Address {
    /// Address type.
    pub kind: AddrKind,
    /// Address value.
    pub addr: BdAddr,
}

impl PartialEq for Address {
    /// Compare two addresses, normalizing HCI identity address types.
    ///
    /// In HCI events the controller may report a peer's address type as 0x02 (Public Identity) or
    /// 0x03 (Random Static Identity) when it resolved the peer's RPA via the resolving list. These
    /// are semantically equivalent to 0x00 (Public) and 0x01 (Random) respectively, so this
    /// implementation treats them as equal when comparing.
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.kind.as_raw() & 1 == other.kind.as_raw() & 1
    }
}

impl Address {
    /// Create a new address with the given kind and value.
    pub const fn new(kind: AddrKind, addr: BdAddr) -> Self {
        Self { kind, addr }
    }

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// Identity address (random static or public)
    pub addr: Address,

    /// Identity Resolving Key
    #[cfg(feature = "security")]
    pub irk: Option<IdentityResolvingKey>,
}

#[cfg(feature = "defmt")]
impl defmt::Format for Identity {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "Addr({}) ", self.addr);
        #[cfg(feature = "security")]
        defmt::write!(fmt, "Irk({:X})", self.irk);
    }
}

impl From<Address> for Identity {
    fn from(addr: Address) -> Self {
        Self {
            addr,
            #[cfg(feature = "security")]
            irk: None,
        }
    }
}

impl Identity {
    /// Check whether the address matches the identity.
    ///
    /// Matches if the address is an exact match (kind + addr) or if the IRK can resolve it.
    pub fn match_address(&self, address: &Address) -> bool {
        if self.addr == *address {
            return true;
        }
        #[cfg(feature = "security")]
        if let Some(irk) = self.irk {
            return irk.resolve_address(&address.addr);
        }
        false
    }

    /// Check whether the given identity matches current identity
    pub fn match_identity(&self, identity: &Identity) -> bool {
        if self.addr == identity.addr {
            return true;
        }
        #[cfg(feature = "security")]
        {
            if let Some(irk) = self.irk {
                if irk.resolve_address(&identity.addr.addr) {
                    return true;
                }
            }
            if let Some(irk) = identity.irk {
                if let Some(current_irk) = self.irk {
                    if irk == current_irk {
                        return true;
                    }
                }
                if irk.resolve_address(&self.addr.addr) {
                    return true;
                }
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
    Security(PairingFailedReason),
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
    /// L2CAP credit-based connection refused by the peer.
    L2capConnectError(crate::types::l2cap::LeCreditConnResultCode),
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
    /// Resource is already in use.
    AlreadyInUse,
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

/// Trait for security-related controller commands.
///
/// When the `security` feature is enabled, this requires the controller to support
/// encryption, resolving list and address resolution HCI commands. When disabled, this is
/// automatically implemented for all controllers.
#[cfg(feature = "security")]
pub trait SecurityCmds:
    bt_hci::controller::Controller
    + ControllerCmdSync<LeLongTermKeyRequestReply>
    + ControllerCmdAsync<LeEnableEncryption>
    + ControllerCmdSync<LeAddDeviceToResolvingList>
    + ControllerCmdSync<LeRemoveDeviceFromResolvingList>
    + ControllerCmdSync<LeClearResolvingList>
    + ControllerCmdSync<LeSetAddrResolutionEnable>
    + ControllerCmdSync<LeSetResolvablePrivateAddrTimeout>
    + ControllerCmdSync<LeSetPrivacyMode>
{
}

#[cfg(feature = "security")]
impl<
        C: bt_hci::controller::Controller
            + ControllerCmdSync<LeLongTermKeyRequestReply>
            + ControllerCmdAsync<LeEnableEncryption>
            + ControllerCmdSync<LeAddDeviceToResolvingList>
            + ControllerCmdSync<LeRemoveDeviceFromResolvingList>
            + ControllerCmdSync<LeClearResolvingList>
            + ControllerCmdSync<LeSetAddrResolutionEnable>
            + ControllerCmdSync<LeSetResolvablePrivateAddrTimeout>
            + ControllerCmdSync<LeSetPrivacyMode>,
    > SecurityCmds for C
{
}

/// Auto-implemented when security is not enabled.
#[cfg(not(feature = "security"))]
pub trait SecurityCmds: bt_hci::controller::Controller {}

#[cfg(not(feature = "security"))]
impl<C: bt_hci::controller::Controller> SecurityCmds for C {}

/// Trait that defines the controller implementation required by the host.
///
/// The controller must implement the required commands and events to be able to be used with Trouble.
pub trait Controller:
    bt_hci::controller::Controller
    + embedded_io::ErrorType<Error: crate::fmt::Format>
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
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
    + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
    + ControllerCmdSync<LeReadBufferSize>
    + for<'t> ControllerCmdSync<LeSetAdvData>
    + ControllerCmdSync<LeSetAdvParams>
    + for<'t> ControllerCmdSync<LeSetAdvEnable>
    + for<'t> ControllerCmdSync<LeSetScanResponseData>
    + ControllerCmdSync<ReadBdAddr>
    + SecurityCmds
{
}

impl<
        C: bt_hci::controller::Controller
            + embedded_io::ErrorType<Error: crate::fmt::Format>
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
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetExtAdvEnable<'t>>
            + for<'t> ControllerCmdSync<HostNumberOfCompletedPackets<'t>>
            + ControllerCmdSync<LeReadBufferSize>
            + for<'t> ControllerCmdSync<LeSetAdvData>
            + ControllerCmdSync<LeSetAdvParams>
            + for<'t> ControllerCmdSync<LeSetAdvEnable>
            + for<'t> ControllerCmdSync<LeSetScanResponseData>
            + ControllerCmdSync<ReadBdAddr>
            + SecurityCmds,
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
pub struct HostResources<
    C: Controller,
    P: PacketPool,
    const CONNS: usize,
    const CHANNELS: usize,
    const ADV_SETS: usize = 1,
    const BONDS: usize = 10,
> {
    host: MaybeUninit<ManuallyDrop<BleHost<'static, C, P>>>,
    connections: MaybeUninit<RefCell<[ConnectionStorage<P::Packet>; CONNS]>>,
    channels: MaybeUninit<RefCell<[ChannelStorage<P::Packet>; CHANNELS]>>,
    advertise_handles: MaybeUninit<RefCell<[AdvHandleState; ADV_SETS]>>,
    #[cfg(feature = "security")]
    bond_storage: MaybeUninit<RefCell<Vec<BondInformation, BONDS>>>,
}

impl<
        C: Controller,
        P: PacketPool,
        const CONNS: usize,
        const CHANNELS: usize,
        const ADV_SETS: usize,
        const BONDS: usize,
    > Default for HostResources<C, P, CONNS, CHANNELS, ADV_SETS, BONDS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
        C: Controller,
        P: PacketPool,
        const CONNS: usize,
        const CHANNELS: usize,
        const ADV_SETS: usize,
        const BONDS: usize,
    > HostResources<C, P, CONNS, CHANNELS, ADV_SETS, BONDS>
{
    /// Create a new instance of host resources.
    pub const fn new() -> Self {
        Self {
            host: MaybeUninit::uninit(),
            connections: MaybeUninit::uninit(),
            channels: MaybeUninit::uninit(),
            advertise_handles: MaybeUninit::uninit(),
            #[cfg(feature = "security")]
            bond_storage: MaybeUninit::uninit(),
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
    const BONDS: usize,
>(
    controller: C,
    resources: &'resources mut HostResources<C, P, CONNS, CHANNELS, ADV_SETS, BONDS>,
) -> StackBuilder<'resources, C, P> {
    let connections: &'resources RefCell<[ConnectionStorage<P::Packet>]> = resources
        .connections
        .write(RefCell::new([const { ConnectionStorage::new() }; CONNS]));

    let channels: &'resources RefCell<[ChannelStorage<P::Packet>]> = resources
        .channels
        .write(RefCell::new([const { ChannelStorage::new() }; CHANNELS]));

    let advertise_handles: &'resources RefCell<[AdvHandleState]> = resources
        .advertise_handles
        .write(RefCell::new([AdvHandleState::None; ADV_SETS]));

    #[cfg(feature = "security")]
    let bond_storage: &'resources RefCell<VecView<BondInformation>> =
        resources.bond_storage.write(RefCell::new(Vec::new()));

    // SAFETY: Narrows the host field's lifetime from `'static` to `'resources`. Sound because:
    // - BleHost is covariant in 'd so the types differ only in a lifetime (identical layout).
    // - The returned StackBuilder/Stack exclusively borrows the HostResources for 'resources,
    //   preventing re-entry into this function while the narrowed-lifetime data is live.
    // - The host field is private, MaybeUninit (no auto-drop), and only ever accessed by this
    //   function (which overwrites via write()), so the narrowed lifetime can never be observed
    //   through the original `'static` type — even if the StackBuilder/Stack is mem::forget'd.
    let host: &'resources mut MaybeUninit<ManuallyDrop<BleHost<'resources, C, P>>> =
        unsafe { core::mem::transmute(&mut resources.host) };

    let host: &'resources mut ManuallyDrop<BleHost<'resources, C, P>> = host.write(ManuallyDrop::new(BleHost::new(
        controller,
        connections,
        channels,
        advertise_handles,
        #[cfg(feature = "security")]
        bond_storage,
    )));

    StackBuilder { host: Some(host) }
}

/// Contains the host stack
pub struct Stack<'stack, C, P: PacketPool> {
    host: &'stack mut ManuallyDrop<BleHost<'stack, C, P>>,
    runner_taken: Cell<bool>,
}

impl<'stack, C, P: PacketPool> Drop for Stack<'stack, C, P> {
    fn drop(&mut self) {
        // SAFETY: host was fully initialized in new() and has not been dropped.
        // Stack is the sole owner responsible for dropping BleHost.
        // All shared &BleHost references (in Runner, Central, etc.) have already
        // been dropped (reverse drop order), so no aliasing conflict.
        unsafe { ManuallyDrop::drop(self.host) }
    }
}

/// Builder for configuring the BLE stack before use.
///
/// Call [`build()`](StackBuilder::build) to finalize configuration and obtain the [`Stack`].
pub struct StackBuilder<'stack, C, P: PacketPool> {
    host: Option<&'stack mut ManuallyDrop<BleHost<'stack, C, P>>>,
}

impl<'stack, C, P: PacketPool> Drop for StackBuilder<'stack, C, P> {
    fn drop(&mut self) {
        if let Some(host) = &mut self.host {
            // SAFETY: host was fully initialized in new() and has not been dropped.
            // `build()` was never called, leaving StackBuilder as the sole owner
            // responsible for dropping BleHost.
            unsafe { ManuallyDrop::drop(host) }
        }
    }
}

impl<'stack, C: Controller, P: PacketPool> StackBuilder<'stack, C, P> {
    fn host(&mut self) -> &mut BleHost<'stack, C, P> {
        self.host.as_mut().unwrap()
    }

    /// Register an L2CAP SPSM (Simplified Protocol/Service Multiplexer) for accepting incoming connections.
    pub fn register_l2cap_spsm(mut self, spsm: u16) -> Self {
        self.host().channels.register_spsm(spsm);
        self
    }

    /// Set the random address used by this host.
    pub fn set_random_address(mut self, address: Address) -> Self {
        self.host().address.replace(address);
        #[cfg(feature = "security")]
        self.host().connections.security_manager.set_local_address(address);
        self
    }

    /// Enable BLE address privacy with the given Identity Resolving Key (IRK).
    ///
    /// When privacy is enabled, the controller generates Resolvable Private Addresses (RPAs)
    /// that rotate periodically, preventing device tracking while allowing bonded peers to
    /// resolve the device's identity.
    ///
    /// The IRK should be persisted across reboots so bonded peers can continue to resolve
    /// our RPAs. Generate a new IRK using a CSPRNG for first-time setup.
    ///
    /// After bonds are added or removed (either directly or via pairing), the controller's
    /// resolving list is updated automatically the next time advertising, scanning, and
    /// connecting are all idle. Applications should ensure periodic idle windows to allow
    /// resolving list updates to take effect.
    #[cfg(feature = "security")]
    pub fn enable_privacy(mut self, irk: IdentityResolvingKey) -> Self {
        self.host().connections.security_manager.set_local_irk(irk);
        self
    }

    /// Set the RPA (Resolvable Private Address) rotation timeout.
    ///
    /// The controller will automatically generate a new RPA after this duration.
    /// Default is 900 seconds (15 minutes) per the BLE specification.
    #[cfg(feature = "security")]
    pub fn set_rpa_timeout(mut self, timeout: Duration) -> Self {
        self.host().rpa_timeout.set(timeout);
        self
    }

    /// Set the random generator seed for random generator used by security manager.
    #[cfg(feature = "security")]
    pub fn set_random_generator_seed<RNG: RngCore + CryptoRng>(mut self, _random_generator: &mut RNG) -> Self {
        {
            let mut random_seed = [0u8; 32];
            _random_generator.fill_bytes(&mut random_seed);
            self.host()
                .connections
                .security_manager
                .set_random_generator_seed(random_seed);
        }
        self
    }

    /// Set the IO capabilities used by the security manager.
    ///
    /// Only relevant if the feature `security` is enabled.
    #[cfg(feature = "security")]
    pub fn set_io_capabilities(mut self, io_capabilities: IoCapabilities) -> Self {
        self.host()
            .connections
            .security_manager
            .set_io_capabilities(io_capabilities);
        self
    }

    /// Enable or disable secure connections only mode.
    ///
    /// When enabled, legacy pairing is rejected even if the `legacy-pairing` feature is compiled in.
    /// This matches the BLE spec's "Secure Connections Only Mode" (Vol 3, Part C, Section 10.2.4).
    ///
    /// Only relevant if the feature `legacy-pairing` is enabled.
    #[cfg(feature = "legacy-pairing")]
    pub fn set_secure_connections_only(mut self, enabled: bool) -> Self {
        self.host()
            .connections
            .security_manager
            .set_secure_connections_only(enabled);
        self
    }

    /// Finalize configuration and return the stack.
    ///
    /// Use the returned [`Stack`] for runtime operations: obtain a [`Runner`] via
    /// [`Stack::runner()`], and [`Central`](central::Central) or
    /// [`Peripheral`](peripheral::Peripheral) handles via [`Stack::central()`] and
    /// [`Stack::peripheral()`].
    pub fn build(mut self) -> Stack<'stack, C, P> {
        #[cfg(all(feature = "security", not(feature = "dev-disable-csprng-seed-requirement")))]
        if !self.host().connections.security_manager.get_random_generator_seeded() {
            panic!(
                "The security manager random number generator has not been seeded from a cryptographically secure random number generator"
            )
        }

        Stack {
            host: self.host.take().unwrap(),
            runner_taken: Cell::new(false),
        }
    }
}

impl<'stack, C: Controller, P: PacketPool> Stack<'stack, C, P> {
    /// Obtain a [`Runner`] to drive the BLE host.
    ///
    /// The runner must be polled (e.g. via [`Runner::run()`]) to drive the BLE host.
    pub fn runner(&self) -> Runner<'_, C, P> {
        assert!(
            !self.runner_taken.replace(true),
            "runner() can only be called once per Stack"
        );
        Runner::new(self.host)
    }

    /// Obtain a [`Central`](central::Central) handle for the central BLE role.
    ///
    /// This is a lightweight handle that can be created multiple times.
    /// Concurrent connect operations are serialized internally.
    #[cfg(feature = "central")]
    pub fn central(&self) -> Central<'_, C, P> {
        Central::new(self.host)
    }

    /// Obtain a [`Peripheral`](peripheral::Peripheral) handle for the peripheral BLE role.
    ///
    /// This is a lightweight handle that can be created multiple times.
    /// Concurrent advertise operations are serialized internally.
    #[cfg(feature = "peripheral")]
    pub fn peripheral(&self) -> Peripheral<'_, C, P> {
        Peripheral::new(self.host)
    }

    /// Set the IO capabilities used by the security manager.
    ///
    /// Only relevant if the feature `security` is enabled.
    #[cfg(feature = "security")]
    pub fn set_io_capabilities(&self, io_capabilities: IoCapabilities) {
        self.host
            .connections
            .security_manager
            .set_io_capabilities(io_capabilities);
    }

    /// Enable or disable secure connections only mode.
    ///
    /// When enabled, legacy pairing is rejected even if the `legacy-pairing` feature is compiled in.
    /// This matches the BLE spec's "Secure Connections Only Mode" (Vol 3, Part C, Section 10.2.4).
    ///
    /// Only relevant if the feature `legacy-pairing` is enabled.
    #[cfg(feature = "legacy-pairing")]
    pub fn set_secure_connections_only(&self, enabled: bool) {
        self.host
            .connections
            .security_manager
            .set_secure_connections_only(enabled);
    }

    /// Set the RPA (Resolvable Private Address) rotation timeout.
    ///
    /// Updates the stored timeout. If the host is already initialized, also sends
    /// the `LeSetResolvablePrivateAddrTimeout` HCI command to the controller.
    /// If called before initialization (e.g. during pre-server setup), the value
    /// will be used when the controller is initialized.
    ///
    /// Valid range is 1s to 3600s.
    #[cfg(feature = "security")]
    pub async fn set_rpa_timeout(&self, timeout: Duration) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeSetResolvablePrivateAddrTimeout>,
    {
        self.host.rpa_timeout.set(timeout);
        if self.host.is_initialized() {
            self.host
                .command(LeSetResolvablePrivateAddrTimeout::new(
                    bt_hci::param::Duration::from_secs(timeout.as_secs() as u32),
                ))
                .await?;
        }
        Ok(())
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

    /// Read the minimum supported connection interval from the controller.
    pub async fn read_minimum_supported_connection_interval(
        &self,
    ) -> Result<<LeReadMinimumSupportedConnectionInterval as SyncCmd>::Return, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeReadMinimumSupportedConnectionInterval>,
    {
        self.host.command(LeReadMinimumSupportedConnectionInterval::new()).await
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
    /// Generate local OOB data for LESC pairing.
    ///
    /// The returned data should be transferred to the peer device via an out-of-band
    /// channel (NFC, QR code, etc.) before pairing begins.
    pub fn get_local_oob_data(&self) -> OobData {
        self.host.connections.security_manager.get_local_oob_data()
    }

    #[cfg(feature = "security")]
    /// Get the local address configured on the security manager.
    pub fn get_local_address(&self) -> Option<Address> {
        self.host.connections.security_manager.get_local_address()
    }

    /// Check whether BLE address privacy is enabled.
    #[cfg(feature = "security")]
    pub fn is_privacy_enabled(&self) -> bool {
        self.host.is_privacy_enabled()
    }

    #[cfg(feature = "security")]
    /// Add bond information for a peer device.
    ///
    /// After bonds are added or removed (either directly or via pairing), the controller's
    /// resolving list is updated automatically the next time advertising, scanning, and
    /// connecting are all idle. Applications should ensure periodic idle windows to allow
    /// resolving list updates to take effect.
    pub fn add_bond_information(&self, bond_information: BondInformation) -> Result<(), Error> {
        let identity = bond_information.identity;
        let result = self
            .host
            .connections
            .security_manager
            .add_bond_information(bond_information);
        #[cfg(feature = "security")]
        if result.is_ok() {
            self.host
                .resolving_list_state
                .borrow_mut()
                .push(crate::host::ResolvingListUpdate::Add(identity));
        }
        result
    }

    #[cfg(feature = "security")]
    /// Remove a bonded device.
    ///
    /// After bonds are added or removed (either directly or via pairing), the controller's
    /// resolving list is updated automatically the next time advertising, scanning, and
    /// connecting are all idle. Applications should ensure periodic idle windows to allow
    /// resolving list updates to take effect.
    pub fn remove_bond_information(&self, identity: Identity) -> Result<(), Error> {
        let result = self.host.connections.security_manager.remove_bond_information(identity);
        #[cfg(feature = "security")]
        if result.is_ok() {
            self.host
                .resolving_list_state
                .borrow_mut()
                .push(crate::host::ResolvingListUpdate::Remove(identity));
        }
        result
    }

    #[cfg(feature = "security")]
    /// Access bonded devices
    pub fn with_bond_information<R>(&self, f: impl FnOnce(&[BondInformation]) -> R) -> R {
        f(&self.host.connections.security_manager.get_bond_information())
    }

    /// Get a connection by its peer address
    pub fn get_connection_by_peer_address(&self, peer_address: Address) -> Option<Connection<'_, P>> {
        self.host.connections.get_connection_by_peer_address(peer_address)
    }

    /// Get a connection by its handle
    pub fn get_connected_handle(&self, handle: ConnHandle) -> Option<Connection<'_, P>> {
        self.host.connections.get_connected_handle(handle)
    }

    /// Iterate over all currently connected connections.
    pub fn connections(&self) -> connection_manager::ConnectedIter<'_, P> {
        self.host.connections.connections()
    }
}

pub(crate) fn bt_hci_duration<const US: u32>(d: Duration) -> bt_hci::param::Duration<US> {
    bt_hci::param::Duration::from_micros(d.as_micros())
}

pub(crate) fn bt_hci_ext_duration<const US: u16>(d: Duration) -> bt_hci::param::ExtDuration<US> {
    bt_hci::param::ExtDuration::from_micros(d.as_micros())
}

// Re-export our version of embassy-sync for the macros
#[doc(hidden)]
pub mod __export {
    pub use embassy_sync;
}
