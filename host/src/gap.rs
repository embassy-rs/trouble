//! ## Generic Access Profile
//!
//! This profile defines the generic procedures related to discovery of
//! Bluetooth devices (idle mode procedures) and link management aspects
//! of connecting to Bluetooth devices (connecting mode procedures).
//! It also defines procedures related to use of different security levels.
//! In addition, this profile includes common format requirements for
//! parameters accessible on the user interface level.

use crate::prelude::*;
use embassy_sync::blocking_mutex::raw::RawMutex;

/// Configuration for the GAP Service.
pub enum GapConfig {
    /// Peripheral device configuration.
    Peripheral(PeripheralConfig),
    /// Central device configuration.
    Central(CentralConfig),
}

/// Configuration for a peripheral device GAP Service.
pub struct PeripheralConfig {
    /// The name of the peripheral device.
    pub name: &'static str,
    /// The representation of the external appearance of the device.
    pub appearance: &'static [u8; 2],
    // pub preferred_connection_parameters: Option<ConnectionParameters>,
}

/// Configuration for a central device GAP Service.
pub struct CentralConfig {
    /// The name of the central device.
    pub name: &'static str,
    /// The representation of the external appearance of the device.
    pub appearance: &'static [u8; 2],
}

impl GapConfig {
    /// Create a default peripheral configuration.
    pub fn default(name: &'static str) -> Self {
        GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &[0x80, 0x07],
        })
    }
    /// Add the GAP service to the attribute table.
    pub fn build<M: RawMutex, const MAX: usize>(self, table: &mut AttributeTable<'_, M, MAX>) {
        let mut gap = table.add_service(Service::new(0x1800)); // GAP UUID (mandatory)
        match self {
            GapConfig::Peripheral(config) => {
                let id = config.name.as_bytes();
                let _ = gap.add_characteristic_ro(0x2a00, id);
                let _ = gap.add_characteristic_ro(0x2a01, &config.appearance[..]);
            }
            GapConfig::Central(config) => {
                let id = config.name.as_bytes();
                let _ = gap.add_characteristic_ro(0x2a00, id);
                let _ = gap.add_characteristic_ro(0x2a01, &config.appearance[..]);
            }
        };
        gap.build();

        table.add_service(Service::new(0x1801)); // GATT UUID (mandatory)
    }
}
