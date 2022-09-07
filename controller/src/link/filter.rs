//! Link-Layer Device Filtering.

use super::DeviceAddress;
use core::{iter, slice};

pub trait AddressFilter {
    fn matches(&self, address: DeviceAddress) -> bool;
}

/// An `AddressFilter` that allows all devices (ie. no whitelist in use).
pub struct AllowAll;

impl AddressFilter for AllowAll {
    fn matches(&self, _address: DeviceAddress) -> bool {
        true
    }
}

/// An `AddressFilter` that checks device addresses against a whitelist.
///
/// This is a software filter, which allows checking against arbitrarily many device addresses, but
/// might be less efficient than a hardware-based filter.
pub struct WhitelistFilter<I: Iterator<Item = DeviceAddress> + Clone> {
    addresses: I,
}

impl<I: Iterator<Item = DeviceAddress> + Clone> WhitelistFilter<I> {
    /// Creates a device whitelist from an iterator yielding the allowed device addresses.
    ///
    /// The filter will clone and iterate over `allowed_addresses` for each incoming packet that
    /// needs to be checked against the filter.
    pub fn new(allowed_addresses: I) -> Self {
        Self {
            addresses: allowed_addresses,
        }
    }
}

pub type SliceIter<'a> = iter::Cloned<slice::Iter<'a, DeviceAddress>>;

impl<'a> WhitelistFilter<SliceIter<'a>> {
    /// Creates a device whitelist from a slice of device addresses.
    ///
    /// This is a convenience method provided to simplify using a slice as a device address
    /// whitelist.
    pub fn from_slice(addresses: &'a [DeviceAddress]) -> Self {
        Self {
            addresses: addresses.iter().cloned(),
        }
    }
}

pub type SingleIter = iter::Once<DeviceAddress>;

impl WhitelistFilter<SingleIter> {
    /// Creates a device whitelist that will allow a single device.
    pub fn from_address(address: DeviceAddress) -> Self {
        Self {
            addresses: iter::once(address),
        }
    }
}

impl<I: Iterator<Item = DeviceAddress> + Clone> AddressFilter for WhitelistFilter<I> {
    fn matches(&self, address: DeviceAddress) -> bool {
        self.addresses.clone().any(|a| a == address)
    }
}

/// Advertising filter policy. Governs which devices may scan and connect to an advertising device.
pub struct AdvFilter<S: AddressFilter, C: AddressFilter> {
    scan: S,
    connect: C,
}

impl<S: AddressFilter, C: AddressFilter> AdvFilter<S, C> {
    /// Creates a new filter policy from behaviors for scan and connect requests.
    ///
    /// # Parameters
    ///
    /// * **`scan`**: An `AddressFilter` governing which devices may scan this device.
    /// * **`connect`**: An `AddressFilter` governing which devices may connect to this device.
    pub fn new(scan: S, connect: C) -> Self {
        Self { scan, connect }
    }

    pub fn may_scan(&self, device: DeviceAddress) -> bool {
        self.scan.matches(device)
    }

    pub fn may_connect(&self, device: DeviceAddress) -> bool {
        self.connect.matches(device)
    }
}

/// Scanner filter policy. Governs which devices will be scanned by this device.
///
/// This can be used for active and passive scanning. Advertisements sent by devices not matched by
/// the filter will be ignored.
pub struct ScanFilter<S: AddressFilter> {
    scan: S,
}

impl<S: AddressFilter> ScanFilter<S> {
    /// Creates a new scanner filter policy from an `AddressFilter`.
    pub fn new(scan: S) -> Self {
        Self { scan }
    }

    pub fn should_scan(&self, device: DeviceAddress) -> bool {
        self.scan.matches(device)
    }
}
