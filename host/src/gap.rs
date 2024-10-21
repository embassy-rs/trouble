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

pub mod appearance {
    //! The representation of the external appearance of the device.
    //!
    //! This is a list of some of the most common appearance values and demonstrates the pattern to use to define new appearance values.
    //!
    //! https://www.bluetooth.com/wp-content/uploads/Files/Specification/Assigned_Numbers.html#bookmark49

    /// Create a new appearance value.
    pub const fn new(category: u16, subcategory: u8) -> [u8; 2] {
        ((category << 6) | (subcategory as u16)).to_le_bytes()
    }
    /// Generic Unknown device appearance.
    pub const GENERIC_UNKNOWN: [u8; 2] = new(0x000, 0x00);
    /// Generic Phone device appearance.
    pub const GENERIC_PHONE: [u8; 2] = new(0x001, 0x00);
    /// Generic Computer device appearance.
    pub const GENERIC_COMPUTER: [u8; 2] = new(0x002, 0x00);
    /// Smart Watch device appearance.
    pub const SMART_WATCH: [u8; 2] = new(0x003, 0x02);
    /// Generic Power device appearance.
    pub const GENERIC_POWER: [u8; 2] = new(0x01E, 0x00);
    /// Generic Sensor device appearance.
    pub const GENERIC_SENSOR: [u8; 2] = new(0x015, 0x00);
    /// Gamepad device appearance.
    pub const GAMEPAD: [u8; 2] = new(0x00F, 0x04);
}

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
    ///
    /// This configuration will use the `GENERIC_UNKNOWN` appearance.
    pub fn default(name: &'static str) -> Self {
        GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::GENERIC_UNKNOWN,
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
