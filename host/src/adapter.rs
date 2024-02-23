use bt_hci::cmd::le::{LeSetAdvData, LeSetAdvEnable, LeSetAdvParams};
use embassy_sync::waitqueue::WakerRegistration;

use crate::attribute::Attribute;
use crate::byte_writer::ByteWriter;
use crate::Addr;
use crate::{AdvertisingParameters, Error};
use bt_hci::cmd::{Cmd, SyncCmd};
use bt_hci::data::AclPacket;
use bt_hci::event::le::LeEvent;
use bt_hci::event::Event;
use bt_hci::Controller;
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
    T: Controller,
{
    connections: &'d mut [ConnectionStorage<'d>],
}

impl<E: crate::driver::Error> From<E> for Error<E> {
    fn from(e: E) -> Error<E> {
        Error::Driver(e)
    }
}

impl<'d, T> BleStack<'d, T>
where
    T: Controller,
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

use crate::ad_structure::AdStructure;

pub struct AdvertiseConfig<'d> {
    pub params: Option<LeSetAdvParams>,
    pub data: &'d [AdStructure<'d>],
}

pub struct Config<'d> {
    pub advertise: Option<AdvertiseConfig<'d>>,
}

impl Default for Config {
    fn default() -> Self {
        Self { advertise: None }
    }
}

pub struct BleAdapter<'d, T>
where
    T: Controller,
{
    controller: T,
    config: Config<'d>,
}

impl<'d, T> BleAdapter<'d, T>
where
    T: Controller,
{
    pub fn new(controller: T, config: Config<'d>) -> BleAdapter<'d, T> {
        //let stack = BleStack::new(driver, &mut resources.connections);
        Self { controller, config }
    }

    pub async fn run(&self) -> Result<(), Error<T::Error>> {
        if let Some(adv) = &self.config.advertise {
            if let Some(params) = &adv.params {
                params.exec(&self.controller).await?
            }

            let mut data = [0; 31];
            let mut w = ByteWriter::new(&mut data[..]);
            for item in adv.data.iter() {
                item.encode(&mut w);
            }
            let len = w.len();
            drop(w);
            LeSetAdvData::new(len, data).exec(&self.controller).await?;
            LeSetAdvEnable::new(true).exec(&self.controller).await?;
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AdapterEvent {
    Connected { connection: BleConnection },
    Disconnected { connection: BleConnection },
}
