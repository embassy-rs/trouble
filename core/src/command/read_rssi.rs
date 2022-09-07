use crate::command::Command;
use crate::handle::Handle;
use crate::ogf::Ogf;
use crate::rssi::Rssi;
use crate::status::Status;

pub struct ReadRssi {
    handle: Handle,
}

impl Command for ReadRssi  {
    const OGF: Ogf = Ogf::StatusParameters;
    const OCF: u16 = 0x0005;
    type Parameters = Handle;
    type ReturnParameters = (Status, Handle, Rssi);

    fn parameters(&self) -> Self::Parameters {
        self.handle
    }
}

impl ReadRssi {
    pub fn new(handle: Handle) -> Self {
        Self {
            handle
        }
    }
}