use crate::acl::AclPacket;
use crate::command::{
    opcode, Command, CONTROLLER_OGF, LE_OGF, RESET_OCF, SET_ADVERTISE_ENABLE_OCF, SET_ADVERTISING_DATA_OCF,
    SET_ADVERTISING_PARAMETERS_OCF, SET_EVENT_MASK_OCF,
};
use crate::driver::{HciDriver, HciMessageType};
use crate::event::EventType;
use crate::{Addr, Data};
use crate::{AdvertisingParameters, Error};
use core::cell::RefCell;
use core::future::poll_fn;
use core::marker::PhantomData;
use core::task::{Poll, Waker};

pub struct AdapterResources<'d, const CONN: usize> {
    connections: [ConnectionStorage<'d>; CONN],
}

impl<'d, const CONN: usize> AdapterResources<'d, CONN> {
    pub const fn new() -> Self {
        Self {
            connections: [ConnectionStorage::EMPTY; CONN],
        }
    }
}

struct ConnectionStorage<'d> {
    state: Option<ConnectionState<'d>>,
}

impl<'d> ConnectionStorage<'d> {
    const EMPTY: Self = Self { state: None };
}

pub struct ConnectionState<'d> {
    handle: u16,
    _p: PhantomData<&'d u8>,
    status: u8,
    role: u8,
    peer_address: Addr,
    interval: u16,
    latency: u16,
    timeout: u16,
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BleConnection {
    handle: u16,
}

pub struct BleStack<'d, T>
where
    T: HciDriver,
{
    driver: T,
    connections: &'d mut [ConnectionStorage<'d>],
}

impl<E: crate::driver::Error> From<E> for Error<E> {
    fn from(e: E) -> Error<E> {
        Error::Driver(e)
    }
}

impl<'d, T> BleStack<'d, T>
where
    T: HciDriver,
{
    pub fn new(driver: T, connections: &'d mut [ConnectionStorage<'d>]) -> BleStack<'d, T> {
        Self { driver, connections }
    }

    fn try_write(&mut self, message: &HciMessage<'_>) -> Result<usize, Error<T::Error>> {
        let (buffer, t) = message.encode().map_err(|_| Error::Encode)?;
        let v = self.driver.try_write(t, buffer.as_slice())?;
        Ok(v)
    }

    fn try_read<'m>(&mut self, buffer: &'m mut [u8]) -> Result<Option<HciMessage<'m>>, Error<T::Error>> {
        if let Some(mtype) = self.driver.try_read(buffer)? {
            Ok(Some(HciMessage::decode(mtype, buffer).map_err(|_| Error::Decode)?))
        } else {
            Ok(None)
        }
    }

    fn register_read_waker(&mut self, waker: &Waker) {
        self.driver.register_read_waker(waker);
    }

    fn register_write_waker(&mut self, waker: &Waker) {
        self.driver.register_write_waker(waker);
    }

    fn do_work(&mut self) -> Result<Option<AdapterEvent>, Error<T::Error>> {
        let mut buffer: [u8; 259] = [0; 259];
        match self.try_read(&mut buffer)? {
            None => Ok(None),
            Some(message) => match message {
                HciMessage::Command(_) => Ok(None),
                HciMessage::Data(data) => {
                    for conn in self.connections.iter_mut() {
                        if let Some(state) = &conn.state {
                            if state.handle == data.handle {
                                return Ok(Some(AdapterEvent::Data {
                                    connection: BleConnection { handle: state.handle },
                                    data,
                                }));
                            }
                        }
                    }
                    Ok(None)
                }
                HciMessage::Event(etype) => match etype {
                    EventType::ConnectionComplete {
                        status,
                        handle,
                        role,
                        peer_address,
                        interval,
                        latency,
                        timeout,
                    } => {
                        for conn in self.connections.iter_mut() {
                            if conn.state.is_none() {
                                conn.state.replace(ConnectionState {
                                    _p: PhantomData,
                                    status,
                                    handle,
                                    role,
                                    peer_address,
                                    interval,
                                    latency,
                                    timeout,
                                });
                                return Ok(Some(AdapterEvent::Connected {
                                    connection: BleConnection { handle },
                                }));
                            }
                        }
                        panic!("no sockets left");
                    }
                    e => Ok(Some(AdapterEvent::Control { event: e })),
                },
            },
        }
    }
}

pub struct BleAdapter<'d, T>
where
    T: HciDriver,
{
    stack: RefCell<BleStack<'d, T>>,
}

impl<'d, T> BleAdapter<'d, T>
where
    T: HciDriver,
{
    pub fn new<const CONN: usize>(driver: T, resources: &'d mut AdapterResources<'d, CONN>) -> BleAdapter<'d, T> {
        let stack = BleStack::new(driver, &mut resources.connections);
        Self {
            stack: RefCell::new(stack),
        }
    }

    pub fn try_send(&mut self, message: &HciMessage<'_>) -> Result<Option<()>, Error<T::Error>> {
        let s = &mut *self.stack.borrow_mut();
        if s.try_write(&message)? == 0 {
            Ok(None)
        } else {
            Ok(Some(()))
        }
    }

    pub fn try_recv(&mut self) -> Result<Option<AdapterEvent>, Error<T::Error>> {
        let s = &mut *self.stack.borrow_mut();
        s.do_work()
    }

    pub async fn send(&mut self, message: HciMessage<'_>) -> Result<(), Error<T::Error>> {
        poll_fn(|cx| {
            let s = &mut *self.stack.borrow_mut();
            match s.try_write(&message) {
                Ok(0) => {
                    s.register_write_waker(cx.waker());
                    Poll::Pending
                }
                Ok(_) => Poll::Ready(Ok(())),
                Err(e) => Poll::Ready(Err(e)),
            }
        })
        .await
    }

    pub async fn recv(&mut self) -> Result<AdapterEvent, Error<T::Error>> {
        poll_fn(|cx| {
            let s = &mut *self.stack.borrow_mut();
            match s.do_work() {
                Ok(Some(event)) => Poll::Ready(Ok(event)),
                Ok(_) => {
                    s.register_read_waker(cx.waker());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
        .await
    }

    pub async fn request(&mut self, command: Command<'_>) -> Result<(), Error<T::Error>> {
        let (ogf, ocf) = command.opcode();
        self.send(HciMessage::Command(command)).await?;
        poll_fn(|cx| {
            let s = &mut *self.stack.borrow_mut();
            match s.do_work() {
                Ok(Some(AdapterEvent::Control {
                    event: EventType::CommandComplete { opcode: code, .. },
                })) if code == opcode(ogf, ocf) => Poll::Ready(Ok(())),
                Ok(_) => {
                    s.register_read_waker(cx.waker());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
        .await?;
        Ok(())
    }

    pub async fn init(&mut self) -> Result<(), Error<T::Error>> {
        self.request(Command::Reset).await?;
        self.request(Command::SetEventMask {
            events: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        })
        .await?;
        Ok(())
    }

    pub async fn start_advertise(&mut self, data: Data) -> Result<(), Error<T::Error>> {
        self.request(Command::LeSetAdvertisingParameters).await?;
        self.request(Command::LeSetAdvertisingData { data }).await?;
        self.request(Command::LeSetAdvertiseEnable(true)).await?;
        Ok(())

        /*
        let connection = poll_fn(|cx| {
            let s = &mut *self.stack.borrow_mut();
            match s.do_work() {
                Ok(Some(AdapterEvent::Connected { connection })) => Poll::Ready(Ok(connection)),
                Ok(_) => {
                    s.register_read_waker(cx.waker());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
        .await?;

        self.send(HciMessage::Command(Command::LeSetAdvertiseEnable(false)))
            .await?;
        Ok(connection)*/
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdapterEvent {
    Connected { connection: BleConnection },
    Data { connection: BleConnection, data: AclPacket },
    Disconnected { connection: BleConnection },
    Control { event: EventType },
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HciMessage<'d> {
    Command(Command<'d>),
    Data(AclPacket),
    Event(EventType),
}

impl<'d> HciMessage<'d> {
    fn encode(&self) -> Result<(Data, HciMessageType), ()> {
        match self {
            Self::Command(command) => Ok((command.encode(), HciMessageType::Command)),
            Self::Data(acl) => Ok((acl.encode(), HciMessageType::Data)),
            Self::Event(event) => unimplemented!(),
        }
    }

    fn decode(message_type: HciMessageType, buf: &'d [u8]) -> Result<HciMessage<'d>, ()> {
        match message_type {
            HciMessageType::Command => {
                unimplemented!()
            }
            HciMessageType::Data => {
                let acl_packet = AclPacket::read(buf);
                Ok(HciMessage::Data(acl_packet))
            }
            HciMessageType::Event => {
                let event = EventType::read(buf);
                Ok(HciMessage::Event(event))
            }
        }
    }
}

/*
impl<'d> HciMessage<'d> {
    fn encode(&self, dest: &mut [u8]) -> Result<(usize, HciMessageType), ()> {
        match self {
            Self::Command(command) => Ok((command.encode(dest)?, HciMessageType::Command)),
            Self::Data(acl) => Ok((acl.encode(dest)?, HciMessageType::Data)),
            Self::Event(event) => Ok((event.encode(dest)?, HciMessageType::Event)),
        }
    }

    fn decode(message_type: HciMessageType, buf: &'d [u8]) -> Result<HciMessage<'d>, ()> {
        match message_type {
            HciMessageType::Command => {
                unimplemented!()
            }
            HciMessageType::Data => {
                let acl_packet = AclPacket::read(buf);
                Ok(acl_packet)
            }
            HciMessageType::Event => {
                let event = EventType::read(buf);
                Ok(event)
            }
        }
    }
}
*/
