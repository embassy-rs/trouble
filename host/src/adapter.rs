use embassy_sync::waitqueue::WakerRegistration;

use crate::attribute::Attribute;
use crate::driver::HciDriver;
use crate::Addr;
use crate::{AdvertisingParameters, Error};
use bt_hci::cmd::Cmd;
use bt_hci::data::AclPacket;
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::ControllerToHostPacket;
use bt_hci::PacketKind;
use core::cell::RefCell;
use core::future::poll_fn;
use core::marker::PhantomData;
use core::task::{Poll, Waker};

pub struct AdapterResources<'d, const CONN: usize> {
    attributes: &'d mut [Attribute<'d>],
    connections: [ConnectionStorage<'d>; CONN],
}

impl<'d, const CONN: usize> AdapterResources<'d, CONN> {
    pub fn new(attributes: &'d mut [Attribute<'d>]) -> Self {
        Self {
            attributes,
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
    waker: WakerRegistration,
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

    fn register_read_waker(&mut self, waker: &Waker) {
        self.driver.register_read_waker(waker);
    }

    fn register_write_waker(&mut self, waker: &Waker) {
        self.driver.register_write_waker(waker);
    }

    fn do_work<'m>(&mut self, buffer: &'m mut [u8]) -> Result<Option<ControllerToHostPacket<'m>>, Error<T::Error>> {
        match self.driver.try_read(buffer)? {
            None => Ok(None),
            Some(kind) => match ControllerToHostPacket::from_hci_bytes_with_kind(kind, buffer)? {
                (p @ ControllerToHostPacket::Event(Event::Le(LeEvent::LeConnectionComplete(_))), _) => {
                    info!("Connection established!");
                    /*
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
                                waker: WakerRegistration::new(),
                            });
                            return Ok(Some(AdapterEvent::Connected {
                                connection: BleConnection { handle },
                            }));
                        }
                    }
                    panic!("no sockets left");
                    */
                    Ok(Some(p))
                }
                (packet, _) => Ok(Some(packet)),
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

    /*
    fn try_send(&self, message: &HciPacket<'_>) -> Result<Option<()>, Error<T::Error>> {
        let s = &mut *self.stack.borrow_mut();
        if s.try_write(&message)? == 0 {
            Ok(None)
        } else {
            Ok(Some(()))
        }
    }

    fn try_recv(&mut self) -> Result<Option<AdapterEvent>, Error<T::Error>> {
        let s = &mut *self.stack.borrow_mut();
        s.do_work()
    }

    pub async fn send(&self, message: HciPacket<'_>) -> Result<(), Error<T::Error>> {
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
    }*/

    pub async fn recv(&mut self) -> Result<(), Error<T::Error>> {
        poll_fn(|cx| {
            let s = &mut *self.stack.borrow_mut();
            let mut buffer = [0; 259];
            match s.do_work(&mut buffer) {
                Ok(Some(event)) => {
                    info!("Event: {:?}", event);
                    Poll::Ready(Ok(()))
                }
                Ok(_) => {
                    s.register_read_waker(cx.waker());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(e)),
            }
        })
        .await
    }

    /*
    pub async fn request(&mut self, command: Command<'_>) -> Result<(), Error<T::Error>> {
        let (ogf, ocf) = command.opcode();
        self.send(HciPacket::Command(command)).await?;
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
    }*/
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdapterEvent {
    Connected { connection: BleConnection },
    Disconnected { connection: BleConnection },
}
