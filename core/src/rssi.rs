
pub struct InvalidRssi;

pub enum Rssi {
    Unknown,
    Dbm(i8),
}

impl Rssi {
    pub fn new(rssi: i8) -> Result<Self, InvalidRssi> {
        if rssi == 127 {
            return Ok(Self::Unknown);
        }

        if !(-127..=20).contains(&rssi) {
            return Err(InvalidRssi);
        }

        Ok(Self::Dbm(rssi))
    }
}