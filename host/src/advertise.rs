use crate::adapter::Adapter;
use crate::connection::Connection;
use crate::Error;
use crate::{codec, cursor::WriteCursor, types::uuid::Uuid};
use bt_hci::{
    cmd::{
        le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams},
        SyncCmd,
    },
    param::BdAddr,
    ControllerCmdSync,
};
use embassy_sync::blocking_mutex::raw::RawMutex;

pub struct AdvertiseConfig<'d> {
    pub params: Option<LeSetAdvParams>,
    pub data: &'d [AdStructure<'d>],
}

pub struct Advertiser<'d> {
    config: AdvertiseConfig<'d>,
}

impl<'d> Advertiser<'d> {
    pub(crate) fn new(config: AdvertiseConfig<'d>) -> Self {
        Self { config }
    }

    pub async fn advertise<
        'm,
        M,
        T,
        const CONNS: usize,
        const CHANNELS: usize,
        const L2CAP_TXQ: usize,
        const L2CAP_RXQ: usize,
    >(
        &mut self,
        adapter: &'m Adapter<'_, M, T, CONNS, CHANNELS, L2CAP_TXQ, L2CAP_RXQ>,
    ) -> Result<Connection<'m>, Error<T::Error>>
    where
        M: RawMutex,
        T: ControllerCmdSync<LeSetAdvData> + ControllerCmdSync<LeSetAdvEnable> + ControllerCmdSync<LeSetAdvParams>,
    {
        let params = &self.config.params.unwrap_or(LeSetAdvParams::new(
            bt_hci::param::Duration::from_millis(400),
            bt_hci::param::Duration::from_millis(400),
            bt_hci::param::AdvKind::AdvInd,
            bt_hci::param::AddrKind::PUBLIC,
            bt_hci::param::AddrKind::PUBLIC,
            BdAddr::default(),
            bt_hci::param::AdvChannelMap::ALL,
            bt_hci::param::AdvFilterPolicy::default(),
        ));

        params.exec(&adapter.controller).await?;

        let mut data = [0; 31];
        let mut w = WriteCursor::new(&mut data[..]);
        for item in self.config.data.iter() {
            item.encode(&mut w)?;
        }
        let len = w.len();
        drop(w);
        LeSetAdvData::new(len as u8, data).exec(&adapter.controller).await?;
        LeSetAdvEnable::new(true).exec(&adapter.controller).await?;
        let conn = Connection::accept(adapter).await;
        LeSetAdvEnable::new(false).exec(&adapter.controller).await?;
        Ok(conn)
    }
}

pub const AD_FLAG_LE_LIMITED_DISCOVERABLE: u8 = 0b00000001;
pub const LE_GENERAL_DISCOVERABLE: u8 = 0b00000010;
pub const BR_EDR_NOT_SUPPORTED: u8 = 0b00000100;
pub const SIMUL_LE_BR_CONTROLLER: u8 = 0b00001000;
pub const SIMUL_LE_BR_HOST: u8 = 0b00010000;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

impl<'d> AdStructure<'d> {
    pub fn encode(&self, w: &mut WriteCursor<'_>) -> Result<(), codec::Error> {
        match self {
            AdStructure::Flags(flags) => {
                w.append(&[0x02, 0x01, *flags])?;
            }
            AdStructure::ServiceUuids16(uuids) => {
                w.append(&[(uuids.len() * 2 + 1) as u8, 0x02])?;
                for uuid in uuids.iter() {
                    w.write(*uuid)?;
                }
            }
            AdStructure::ServiceUuids128(uuids) => {
                w.append(&[(uuids.len() * 16 + 1) as u8, 0x07])?;
                for uuid in uuids.iter() {
                    w.write(*uuid)?;
                }
            }
            AdStructure::ShortenedLocalName(name) => {
                w.append(&[(name.len() + 1) as u8, 0x08])?;
                w.append(name.as_bytes())?;
            }
            AdStructure::CompleteLocalName(name) => {
                w.append(&[(name.len() + 1) as u8, 0x09])?;
                w.append(name.as_bytes())?;
            }
            AdStructure::ServiceData16 { uuid, data } => {
                w.append(&[(data.len() + 3) as u8, 0x16])?;
                w.write(*uuid)?;
                w.append(data)?;
            }
            AdStructure::ManufacturerSpecificData {
                company_identifier,
                payload,
            } => {
                w.append(&[(payload.len() + 3) as u8, 0xff])?;
                w.write(*company_identifier)?;
                w.append(payload)?;
            }
            AdStructure::Unknown { ty, data } => {
                w.append(&[(data.len() + 1) as u8, *ty])?;
                w.append(data)?;
            }
        }
        Ok(())
    }
}
