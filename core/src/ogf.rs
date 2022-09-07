
#[derive(Copy, Clone, Debug)]
pub enum Ogf {
    LinkControl = 0x01,
    LinkPolicy = 0x02,
    HciControlAndBaseband = 0x03,
    InformationalParameters = 0x04,
    StatusParameters = 0x05,
    Testing = 0x06,
    LeController = 0x08,

}