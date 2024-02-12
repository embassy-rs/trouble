use crate::{att::Uuid, Data};

pub const AD_FLAG_LE_LIMITED_DISCOVERABLE: u8 = 0b00000001;
pub const LE_GENERAL_DISCOVERABLE: u8 = 0b00000010;
pub const BR_EDR_NOT_SUPPORTED: u8 = 0b00000100;
pub const SIMUL_LE_BR_CONTROLLER: u8 = 0b00001000;
pub const SIMUL_LE_BR_HOST: u8 = 0b00010000;

#[derive(Debug, Copy, Clone)]
pub enum AdvertisementDataError {
    TooLong,
}

#[derive(Debug, Copy, Clone)]
pub enum AdStructure<'a> {
    /// Device flags and baseband capabilities.
    ///
    /// This should be sent if any flags apply to the device. If not (ie. the value sent would be
    /// 0), this may be omitted.
    ///
    /// Must not be used in scan response data.
    Flags(u8),

    ServiceUuids16(&'a [Uuid]),
    ServiceUuids128(&'a [Uuid]),

    /// Service data with 16-bit service UUID.
    ServiceData16 {
        /// The 16-bit service UUID.
        uuid: u16,
        /// The associated service data. May be empty.
        data: &'a [u8],
    },

    /// Sets the full (unabbreviated) device name.
    ///
    /// This will be shown to the user when this device is found.
    CompleteLocalName(&'a str),

    /// Sets the shortened device name.
    ShortenedLocalName(&'a str),

    /// Set manufacturer specific data
    ManufacturerSpecificData {
        company_identifier: u16,
        payload: &'a [u8],
    },

    /// An unknown or unimplemented AD structure stored as raw bytes.
    Unknown {
        /// Type byte.
        ty: u8,
        /// Raw data transmitted after the type.
        data: &'a [u8],
    },
}

impl Data {
    pub fn append_ad_structure(&mut self, src: &AdStructure) {
        match src {
            AdStructure::Flags(flags) => {
                self.append(&[0x02, 0x01, *flags]);
            }
            AdStructure::ServiceUuids16(uuids) => {
                self.append(&[(uuids.len() * 2 + 1) as u8, 0x02]);
                for uuid in uuids.iter() {
                    self.append_uuid(uuid);
                }
            }
            AdStructure::ServiceUuids128(uuids) => {
                self.append(&[(uuids.len() * 16 + 1) as u8, 0x07]);
                for uuid in uuids.iter() {
                    self.append_uuid(uuid);
                }
            }
            AdStructure::ShortenedLocalName(name) => {
                self.append(&[(name.len() + 1) as u8, 0x08]);
                self.append(name.as_bytes());
            }
            AdStructure::CompleteLocalName(name) => {
                self.append(&[(name.len() + 1) as u8, 0x09]);
                self.append(name.as_bytes());
            }
            AdStructure::ServiceData16 { uuid, data } => {
                self.append(&[(data.len() + 3) as u8, 0x16]);
                self.append_value(*uuid);
                self.append(data);
            }
            AdStructure::ManufacturerSpecificData {
                company_identifier,
                payload,
            } => {
                self.append(&[(payload.len() + 3) as u8, 0xff]);
                self.append_value(*company_identifier);
                self.append(payload);
            }
            AdStructure::Unknown { ty, data } => {
                self.append(&[(data.len() + 1) as u8, *ty]);
                self.append(data);
            }
        }
    }
}

pub fn create_advertising_data(ad: &[AdStructure]) -> Result<Data, AdvertisementDataError> {
    let mut data = Data::default();
    data.append(&[0]);

    for item in ad.iter() {
        data.append_ad_structure(&item);
    }

    let len = data.len - 1;
    data.set(0, len as u8);

    if len > 31 {
        return Err(AdvertisementDataError::TooLong);
    }

    for _ in 0..(31 - len) {
        data.append(&[0]);
    }

    Ok(data)
}
