//! ## Generic Access Profile
//!
//! This profile defines the generic procedures related to discovery of
//! Bluetooth devices (idle mode procedures) and link management aspects
//! of connecting to Bluetooth devices (connecting mode procedures).
//! It also defines procedures related to use of different security levels.
//! In addition, this profile includes common format requirements for
//! parameters accessible on the user interface level.

use embassy_sync::blocking_mutex::raw::RawMutex;

use crate::prelude::*;
use crate::types::gatt_traits::FromGattError;

/// Advertising packet is limited to 31 bytes. 9 of these are used by other GAP data, leaving 22 bytes for the Device Name characteristic
const DEVICE_NAME_MAX_LENGTH: usize = 22;

/// The number of attributes added by the GAP and GATT services
/// GAP_SERVICE:                      1
/// ├── DEVICE_NAME:                  2
/// ├── APPEARANCE:                   2
/// └── CENTRAL_ADDRESS_RESOLUTION:   2 (security+central only)
/// GATT_SERVICE:                   + 1
///                                 ---
///                                 = 6 (or 8 with security+central)
///
/// A GATT service built with [`GattServiceConfig::service_changed`] adds [`SERVICE_CHANGED_ATTRIBUTE_COUNT`] more.
#[cfg(not(feature = "security"))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 6;
/// The number of attributes added by the GAP and GATT services (with security, peripheral only)
#[cfg(all(feature = "security", not(feature = "central")))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 6;
/// The number of attributes added by the GAP and GATT services (with security)
#[cfg(all(feature = "security", feature = "central"))]
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 8;

/// The number of attributes the Service Changed characteristic adds to the GATT service
/// (declaration, value and CCCD).
pub const SERVICE_CHANGED_ATTRIBUTE_COUNT: usize = 3;

/// Value of the Service Changed characteristic: the range of attribute handles a client must rediscover.
///
/// See Core Specification Vol 3, Part G, Section 7.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServiceChanged {
    bytes: [u8; 4],
}

impl ServiceChanged {
    /// Ask the client to rediscover every attribute (handles 0x0001 to 0xFFFF).
    pub const ALL: Self = Self::new(0x0001, 0xFFFF);

    /// The affected handle range, from `start` to `end` inclusive.
    pub const fn new(start: u16, end: u16) -> Self {
        let [s0, s1] = start.to_le_bytes();
        let [e0, e1] = end.to_le_bytes();
        Self {
            bytes: [s0, s1, e0, e1],
        }
    }

    /// First affected attribute handle.
    pub const fn start(&self) -> u16 {
        u16::from_le_bytes([self.bytes[0], self.bytes[1]])
    }

    /// Last affected attribute handle.
    pub const fn end(&self) -> u16 {
        u16::from_le_bytes([self.bytes[2], self.bytes[3]])
    }
}

impl AsGatt for ServiceChanged {
    const MIN_SIZE: usize = 4;
    const MAX_SIZE: usize = 4;

    fn as_gatt(&self) -> &[u8] {
        &self.bytes
    }
}

impl FromGatt for ServiceChanged {
    fn from_gatt(data: &[u8]) -> Result<Self, FromGattError> {
        let bytes = data.try_into().map_err(|_| FromGattError::InvalidLength)?;
        Ok(Self { bytes })
    }
}

/// Configuration for the GATT Service, added together with the GAP Service.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GattServiceConfig {
    /// Add the Service Changed characteristic.
    ///
    /// Its presence lets a bonded client keep its cached attribute table across connections and rely on
    /// indications to learn about changes, so a server that enables it must indicate after any change to
    /// its attribute table, through [`AttributeTable::service_changed`].
    pub service_changed: bool,
}

impl GattServiceConfig {
    /// The number of attributes this configuration adds beyond [`GAP_SERVICE_ATTRIBUTE_COUNT`].
    pub const fn extra_attribute_count(&self) -> usize {
        if self.service_changed {
            SERVICE_CHANGED_ATTRIBUTE_COUNT
        } else {
            0
        }
    }

    fn build<M: RawMutex, const MAX: usize>(self, table: &mut AttributeTable<'_, M, MAX>) {
        let mut gatt_builder = table.add_service(Service::new(service::GATT));
        if self.service_changed {
            gatt_builder.add_characteristic_small(
                characteristic::SERVICE_CHANGED,
                [CharacteristicProp::Indicate],
                ServiceChanged::ALL,
            );
        }
        gatt_builder.build();
    }
}

/// Configuration for the GAP Service.
pub enum GapConfig<'a> {
    /// Peripheral device configuration.
    Peripheral(PeripheralConfig<'a>),
    /// Central device configuration.
    Central(CentralConfig<'a>),
}

/// Configuration for a peripheral device GAP Service.
pub struct PeripheralConfig<'a> {
    /// The name of the peripheral device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR.`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
    // pub preferred_connection_parameters: Option<ConnectionParameters>,
}

/// Configuration for a central device GAP Service.
pub struct CentralConfig<'a> {
    /// The name of the central device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::sensor::GENERIC_SENSOR`
    pub appearance: &'a BluetoothUuid16,
    // TODO: Add more GAP parameters
}

impl<'a> GapConfig<'a> {
    /// Create a default peripheral configuration.
    ///
    /// This configuration will use the `UNKNOWN` appearance.
    pub fn default(name: &'a str) -> Self {
        GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::UNKNOWN,
        })
    }

    /// Add the GAP config and a default GATT Service to the attribute table
    pub fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<(), &'static str> {
        self.build_with_gatt(table, GattServiceConfig::default())
    }

    /// Add the GAP config and a GATT Service built from `gatt` to the attribute table
    pub fn build_with_gatt<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
        gatt: GattServiceConfig,
    ) -> Result<(), &'static str> {
        match self {
            GapConfig::Peripheral(config) => config.build(table, gatt),
            GapConfig::Central(config) => config.build(table, gatt),
        }
    }
}

impl<'a> PeripheralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
        gatt: GattServiceConfig,
    ) -> Result<(), &'static str> {
        // Store the name by reference (lives for `'a`); a one-shot StaticCell
        // would panic if the server is ever built twice.
        if self.name.len() > DEVICE_NAME_MAX_LENGTH {
            return Err("Device name is too long. Max length is 22 bytes");
        }

        let mut gap_builder = table.add_service(Service::new(service::GAP));
        gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, self.name);
        gap_builder.add_characteristic_ro(characteristic::APPEARANCE, self.appearance);
        #[cfg(all(feature = "security", feature = "central"))]
        gap_builder.add_characteristic_ro(characteristic::CENTRAL_ADDRESS_RESOLUTION, &1u8);
        gap_builder.build();

        gatt.build(table);

        Ok(())
    }
}

impl<'a> CentralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
        gatt: GattServiceConfig,
    ) -> Result<(), &'static str> {
        // Store the name by reference (lives for `'a`); a one-shot StaticCell
        // would panic if the server is ever built twice.
        if self.name.len() > DEVICE_NAME_MAX_LENGTH {
            return Err("Device name is too long. Max length is 22 bytes");
        }

        let mut gap_builder = table.add_service(Service::new(service::GAP));
        gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, self.name);
        gap_builder.add_characteristic_ro(characteristic::APPEARANCE, self.appearance);
        #[cfg(all(feature = "security", feature = "central"))]
        gap_builder.add_characteristic_ro(characteristic::CENTRAL_ADDRESS_RESOLUTION, &1u8);
        gap_builder.build();

        gatt.build(table);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;

    // Building the GAP config twice must not panic. With the one-shot StaticCell
    // the second build panicked ("StaticCell already full").
    #[test]
    fn gap_config_can_be_built_twice() {
        for _ in 0..2 {
            let mut table: AttributeTable<'_, NoopRawMutex, 16> = AttributeTable::new();
            GapConfig::Peripheral(PeripheralConfig {
                name: "trouble",
                appearance: &appearance::UNKNOWN,
            })
            .build(&mut table)
            .unwrap();
        }
    }

    fn gap_configs() -> [GapConfig<'static>; 2] {
        [
            GapConfig::default("trouble"),
            GapConfig::Central(CentralConfig {
                name: "trouble",
                appearance: &appearance::UNKNOWN,
            }),
        ]
    }

    #[test]
    fn gatt_service_omits_service_changed_by_default() {
        for gap in gap_configs() {
            let mut table: AttributeTable<'_, NoopRawMutex, GAP_SERVICE_ATTRIBUTE_COUNT> = AttributeTable::new();
            gap.build(&mut table).unwrap();
            assert_eq!(table.len(), GAP_SERVICE_ATTRIBUTE_COUNT);
            assert!(matches!(table.service_changed(), Err(Error::NotFound)));
        }
    }

    #[test]
    fn gatt_service_offers_service_changed_when_configured() {
        const SIZE: usize = GAP_SERVICE_ATTRIBUTE_COUNT + SERVICE_CHANGED_ATTRIBUTE_COUNT;
        let gatt = GattServiceConfig { service_changed: true };
        assert_eq!(gatt.extra_attribute_count(), SERVICE_CHANGED_ATTRIBUTE_COUNT);
        for gap in gap_configs() {
            let mut table: AttributeTable<'_, NoopRawMutex, SIZE> = AttributeTable::new();
            gap.build_with_gatt(&mut table, gatt).unwrap();
            assert_eq!(table.len(), SIZE);

            let service_changed = table.service_changed().unwrap();
            assert!(service_changed.props.any(&[CharacteristicProp::Indicate]));
            assert!(service_changed.cccd_handle.is_some());
            assert_eq!(table.get(&service_changed).unwrap(), ServiceChanged::ALL);
        }
    }

    #[test]
    fn service_changed_encodes_the_handle_range_little_endian() {
        assert_eq!(ServiceChanged::ALL.as_gatt(), &[0x01, 0x00, 0xFF, 0xFF]);
        let range = ServiceChanged::new(0x0010, 0x0123);
        assert_eq!((range.start(), range.end()), (0x0010, 0x0123));
        assert_eq!(ServiceChanged::from_gatt(range.as_gatt()), Ok(range));
        assert_eq!(
            ServiceChanged::from_gatt(&[0x01, 0x00, 0xFF]),
            Err(FromGattError::InvalidLength)
        );
    }
}
