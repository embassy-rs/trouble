pub enum State {
    Standby,
    Advertising,
    Scanning,
    Initiating,
    Connection,
    Synchronization,
    IsocronBroadcast,
}

pub enum PDU<'a> {
    AdvInd(&)

}

pub struct AdvPdu<'a> {
    data: &'a mut [u8],
}

impl<'a> AdvPdu<'a> {}

pub enum Address {
    Public([u8; 6]),
    Random([u8; 6]),
}

pub struct Channel {
    index: u8,
    freq: u32,
    r#type: ChannelType,
}

pub enum ChannelType {
    PrimaryAdv,
    Generic,
}

pub struct LinkLayer {
    state: State,
}

impl LinkLayer {
    pub fn standby(&mut self) -> Result<(), Error> {
        self.state = State::Standby;
        // Sleep radio
    }

    pub fn advertise(&mut self, pdu: &[u8]) -> impl Future<Output = Result<(), Error>> {
        self.state = State::Advertising;
        /*let on_drop = OnDrop::new(|_| {
            self.state =
        });
        async move {

        }*/
        todo!()
    }

    pub fn scan(&mut self, pdu: &mut [u8]) -> impl Future<Output = Result<usize, Error>> {
        self.state = State::Scanning;
        todo!()
    }
}
