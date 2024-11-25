//! ## Generic Access Profile
//!
//! This profile defines the generic procedures related to discovery of
//! Bluetooth devices (idle mode procedures) and link management aspects
//! of connecting to Bluetooth devices (connecting mode procedures).
//! It also defines procedures related to use of different security levels.
//! In addition, this profile includes common format requirements for
//! parameters accessible on the user interface level.

use embassy_sync::blocking_mutex::raw::RawMutex;
use heapless::String;
use static_cell::StaticCell;

use crate::prelude::*;

// GAP Service UUIDs
const GAP_UUID: u16 = 0x1800;
const GATT_UUID: u16 = 0x1801;

// GAP Characteristic UUIDs
const DEVICE_NAME_UUID: u16 = 0x2a00;
const APPEARANCE_UUID: u16 = 0x2a01;

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

pub mod appearance {
    //! The representation of the external appearance of the device.
    //!
    //! This is a list of some of the most common appearance values and demonstrates the pattern to use to define new appearance values.
    //!
    //! https://www.bluetooth.com/wp-content/uploads/Files/Specification/Assigned_Numbers.html#bookmark49

    // TODO: Perhaps this should be it's own crate in future?

    /// Construct a new appearance value for the GAP Service.
    ///
    /// Follow the pattern of the examples below to create new appearance values.
    /// Use UUIDs from the [Bluetooth Assigned Numbers list](https://www.bluetooth.com/wp-content/uploads/Files/Specification/Assigned_Numbers.html#bookmark49).
    ///
    /// ## Example
    ///
    /// ```rust
    /// use trouble_host::prelude::*;
    ///
    /// const GAMEPAD: &[u8; 2] = &appearance::new(0x00F, 0x040);
    /// ```
    pub const fn new(category: u8, subcategory: u8) -> [u8; 2] {
        (((category as u16) << 6) | (subcategory as u16)).to_le_bytes()
    }

    /// Generic Unknown device appearance.
    pub const GENERIC_UNKNOWN: [u8; 2] = new(0x000, 0x000);
    /// Generic Phone device appearance.
    pub const GENERIC_PHONE: [u8; 2] = new(0x001, 0x000);
    /// Generic Computer device appearance.
    pub const GENERIC_COMPUTER: [u8; 2] = new(0x002, 0x000);
    /// Smart Watch device appearance.
    pub const SMART_WATCH: [u8; 2] = new(0x003, 0x020);
    /// Generic Power device appearance.
    pub const GENERIC_POWER: [u8; 2] = new(0x01E, 0x000);
    /// Generic Sensor device appearance.
    pub const GENERIC_SENSOR: [u8; 2] = new(0x015, 0x000);
    /// Generic HID device appearance.
    pub const GENERIC_HID: [u8; 2] = new(0x00F, 0x000);
    /// Keyboard device appearance.
    pub const KEYBOARD: [u8; 2] = new(0x00F, 0x001);
    /// Mouse device appearance.
    pub const MOUSE: [u8; 2] = new(0x00F, 0x002);
    /// Joystick device appearance.
    pub const JOYSTICK: [u8; 2] = new(0x00F, 0x003);
    /// Gamepad device appearance.
    pub const GAMEPAD: [u8; 2] = new(0x00F, 0x004);
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
    /// /// Example: `&appearance::GENERIC_SENSOR`
    pub appearance: &'a [u8; 2],
    // TODO: Add more GAP parameters
    // pub preferred_connection_parameters: Option<ConnectionParameters>,
}

/// Configuration for a central device GAP Service.
pub struct CentralConfig<'a> {
    /// The name of the central device.
    pub name: &'a str,
    /// The representation of the external appearance of the device.
    ///
    /// Example: `&appearance::GENERIC_SENSOR`
    pub appearance: &'a [u8; 2],
    // TODO: Add more GAP parameters
}

impl<'a> GapConfig<'a> {
    /// Create a default peripheral configuration.
    ///
    /// This configuration will use the `GENERIC_UNKNOWN` appearance.
    pub fn default(name: &'a str) -> Self {
        GapConfig::Peripheral(PeripheralConfig {
            name,
            appearance: &appearance::GENERIC_UNKNOWN,
        })
    }

    /// Add the GAP config to the attribute table
    pub fn build<M: RawMutex, const MAX: usize>(
        self,
        table: &mut AttributeTable<'a, M, MAX>,
    ) -> Result<(), &'static str> {
        match self {
            GapConfig::Peripheral(config) => config.build(table),
            GapConfig::Central(config) => config.build(table),
        }
    }
}

impl<'a> PeripheralConfig<'a> {
    /// Add the peripheral GAP config to the attribute table
    fn build<M: RawMutex, const MAX: usize>(self, table: &mut AttributeTable<'a, M, MAX>) -> Result<(), &'static str> {
        static PERIPHERAL_NAME: StaticCell<String<DEVICE_NAME_MAX_LENGTH>> = StaticCell::new();
        let peripheral_name = PERIPHERAL_NAME.init(String::new());
        peripheral_name
            .push_str(self.name)
            .map_err(|_| "Device name is too long. Max length is 22 bytes")?;

        let mut gap_builder = table.add_service(Service::new(GAP_UUID));
        gap_builder.add_characteristic_ro(DEVICE_NAME_UUID, peripheral_name);
        gap_builder.add_characteristic_ro(APPEARANCE_UUID, self.appearance);
        gap_builder.build();

        table.add_service(Service::new(GATT_UUID));

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

        let mut gap_builder = table.add_service(Service::new(GAP_UUID));
        gap_builder.add_characteristic_ro(DEVICE_NAME_UUID, central_name);
        gap_builder.add_characteristic_ro(APPEARANCE_UUID, self.appearance);
        gap_builder.build();

        table.add_service(Service::new(GATT_UUID));

        Ok(())
    }
}
