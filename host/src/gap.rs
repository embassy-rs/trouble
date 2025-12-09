//! ## Generic Access Profile
//!
//! This profile defines the generic procedures related to discovery of
//! Bluetooth devices (idle mode procedures) and link management aspects
//! of connecting to Bluetooth devices (connecting mode procedures).
//! It also defines procedures related to use of different security levels.
//! In addition, this profile includes common format requirements for
//! parameters accessible on the user interface level.

use crate::prelude::*;

/// Advertising packet is limited to 31 bytes. 9 of these are used by other GAP data, leaving 22 bytes for the Device Name characteristic
const DEVICE_NAME_MAX_LENGTH: usize = 22;

/// The number of attributes added by the GAP and GATT services
/// GAP_SERVICE:       1
/// ├── DEVICE_NAME:   2
/// └── APPEARANCE:    2
/// GATT_SERVICE:    + 1
///                  ---
///                  = 6
pub const GAP_SERVICE_ATTRIBUTE_COUNT: usize = 6;

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

    /*
    /// Add the GAP config to the attribute table
    pub fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<(), &'static str> {
        match self {
            GapConfig::Peripheral(config) => config.build(table),
            GapConfig::Central(config) => config.build(table),
        }
    }*/
}

/*
impl<'a> PeripheralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(self, table: &mut AttributeTable<'a, M, MAX>) -> Result<(), &'static str> {
        static PERIPHERAL_NAME: StaticCell<String<DEVICE_NAME_MAX_LENGTH>> = StaticCell::new();
        let peripheral_name = PERIPHERAL_NAME.init(String::new());
        peripheral_name
            .push_str(self.name)
            .map_err(|_| "Device name is too long. Max length is 22 bytes")?;

        let mut gap_builder = table.add_service(Service::new(service::GAP));
        gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, peripheral_name);
        gap_builder.add_characteristic_ro(characteristic::APPEARANCE, self.appearance);
        gap_builder.build();

        table.add_service(Service::new(service::GATT));

        Ok(())
    }
}

impl<'a> CentralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(self, table: &mut AttributeTable<'a, M, MAX>) -> Result<(), &'static str> {
        static CENTRAL_NAME: StaticCell<String<DEVICE_NAME_MAX_LENGTH>> = StaticCell::new();
        let central_name = CENTRAL_NAME.init(String::new());
        central_name
            .push_str(self.name)
            .map_err(|_| "Device name is too long. Max length is 22 bytes")?;

        let mut gap_builder = table.add_service(Service::new(service::GAP));
        gap_builder.add_characteristic_ro(characteristic::DEVICE_NAME, central_name);
        gap_builder.add_characteristic_ro(characteristic::APPEARANCE, self.appearance);
        gap_builder.build();

        table.add_service(Service::new(service::GATT));

        Ok(())
    }
}
*/
