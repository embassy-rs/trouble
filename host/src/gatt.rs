use core::cell::RefCell;
use core::future::Future;
use core::marker::PhantomData;

use bt_hci::controller::Controller;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::channel::{Channel, DynamicReceiver, DynamicSender};
use heapless::Vec;

use crate::att::{self, AttReq, AttRsp, ATT_HANDLE_VALUE_NTF};
use crate::attribute::{
    AttributeData, Characteristic, CharacteristicProp, Uuid, CCCD, CHARACTERISTIC_CCCD_UUID16, CHARACTERISTIC_UUID16,
    PRIMARY_SERVICE_UUID16,
};
use crate::attribute_server::AttributeServer;
use crate::connection::Connection;
use crate::connection_manager::DynamicConnectionManager;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::host::BleHost;
use crate::packet_pool::{GlobalPacketPool, Packet, ATT_ID};
use crate::pdu::Pdu;
use crate::types::l2cap::L2capHeader;
use crate::{BleHostError, Error};

pub struct GattServer<'reference, 'values, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize> {
    pub(crate) server: AttributeServer<'reference, 'values, M, MAX>,
    pub(crate) tx: DynamicSender<'reference, (ConnHandle, Pdu)>,
    pub(crate) rx: DynamicReceiver<'reference, (ConnHandle, Pdu)>,
    pub(crate) connections: &'reference dyn DynamicConnectionManager,
}

impl<'reference, 'values, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize>
    GattServer<'reference, 'values, M, MAX, L2CAP_MTU>
{
    /// Process GATT requests and update the attribute table accordingly.
    ///
    /// If attributes are written or read, an event will be returned describing the handle
    /// and the connection causing the event.
    pub async fn next(&self) -> Result<GattEvent<'reference>, Error> {
        loop {
            let (handle, pdu) = self.rx.receive().await;
            if let Some(connection) = self.connections.get_connected_handle(handle) {
                match AttReq::decode(pdu.as_ref()) {
                    Ok(att) => {
                        let mut tx = [0; L2CAP_MTU];
                        let mut w = WriteCursor::new(&mut tx);
                        let (mut header, mut data) = w.split(4)?;

                        match self.server.process(handle, &att, data.write_buf()) {
                            Ok(Some(written)) => {
                                let mtu = self.connections.get_att_mtu(handle);
                                data.commit(written)?;
                                data.truncate(mtu as usize);
                                header.write(written as u16)?;
                                header.write(4_u16)?;
                                let len = header.len() + data.len();

                                let event = match att {
                                    AttReq::Write { handle, data } => Some(GattEvent::Write {
                                        connection,
                                        handle: self.server.table.find_characteristic_by_value_handle(handle)?,
                                    }),

                                    AttReq::Read { handle } => Some(GattEvent::Read {
                                        connection,
                                        handle: self.server.table.find_characteristic_by_value_handle(handle)?,
                                    }),

                                    AttReq::ReadBlob { handle, offset } => Some(GattEvent::Read {
                                        connection,
                                        handle: self.server.table.find_characteristic_by_value_handle(handle)?,
                                    }),
                                    _ => None,
                                };

                                let mut packet = pdu.packet;
                                packet.as_mut()[..len].copy_from_slice(&tx[..len]);
                                self.tx.send((handle, Pdu::new(packet, len))).await;
                                if let Some(event) = event {
                                    return Ok(event);
                                }
                            }
                            Ok(None) => {
                                debug!("No response sent");
                            }
                            Err(e) => {
                                warn!("Error processing attribute: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error decoding attribute request: {:?}", e);
                    }
                }
            }
        }
    }

    /// Write a value to a characteristic, and notify a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be notified.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub async fn notify<T: Controller>(
        &self,
        ble: &BleHost<'_, T>,
        handle: Characteristic,
        connection: &Connection<'_>,
        value: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let conn = connection.handle();
        self.server.table.set(handle, value)?;

        let cccd_handle = handle.cccd_handle.ok_or(Error::Other)?;

        if !self.server.should_notify(conn, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        let mut tx = [0; L2CAP_MTU];
        let mut w = WriteCursor::new(&mut tx[..]);
        let (mut header, mut data) = w.split(4)?;
        data.write(ATT_HANDLE_VALUE_NTF)?;
        data.write(handle.handle)?;
        data.append(value)?;

        header.write(data.len() as u16)?;
        header.write(4_u16)?;
        let total = header.len() + data.len();
        ble.acl(conn, 1).await?.send(&tx[..total]).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub enum GattEvent<'reference> {
    Read {
        connection: Connection<'reference>,
        handle: Characteristic,
    },
    Write {
        connection: Connection<'reference>,
        handle: Characteristic,
    },
}

pub struct NotificationListener<'lst> {
    pub(crate) listener: DynamicReceiver<'lst, (u16, Packet)>,
}

impl<'lst> NotificationListener<'lst> {
    #[allow(clippy::should_implement_trait)]
    /// Get the next (len: u16, Packet) tuple from the rx queue
    pub fn next(&mut self) -> impl Future<Output = (u16, Packet)> + '_ {
        self.listener.receive()
    }
}

pub struct NotificationManager<
    'mgr,
    E,
    C: Client<E>,
    const MAX_NOTIF: usize,
    const NOTIF_QSIZE: usize,
    const ATT_MTU: usize,
> {
    pub(crate) client: &'mgr C,
    pub(crate) rx: DynamicReceiver<'mgr, (ConnHandle, Pdu)>,
    _e: PhantomData<E>,
}

pub struct GattClient<
    'reference,
    'resources,
    T: Controller,
    const MAX_SERVICES: usize,
    const MAX_NOTIF: usize,
    const NOTIF_QSIZE: usize,
    const L2CAP_MTU: usize = 27,
> {
    pub(crate) known_services: RefCell<Vec<ServiceHandle, MAX_SERVICES>>,
    pub(crate) rx: DynamicReceiver<'reference, (ConnHandle, Pdu)>,
    pub(crate) ble: &'reference BleHost<'resources, T>,
    pub(crate) connection: Connection<'reference>,
    pub(crate) request_channel: Channel<NoopRawMutex, (ConnHandle, Pdu), NOTIF_QSIZE>,

    pub(crate) notification_pool: &'static dyn GlobalPacketPool,
    pub(crate) notification_map: RefCell<[Option<u16>; MAX_NOTIF]>,
    pub(crate) notification_channels: [Channel<NoopRawMutex, (u16, Packet), NOTIF_QSIZE>; MAX_NOTIF],
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Clone)]
pub struct ServiceHandle {
    start: u16,
    end: u16,
    uuid: Uuid,
}

pub trait Client<E> {
    fn request(&self, req: AttReq<'_>) -> impl Future<Output = Result<Pdu, BleHostError<E>>>;
}

impl<
        'reference,
        'resources,
        T: Controller,
        const MAX_SERVICES: usize,
        const MAX_NOTIF: usize,
        const NOTIF_QSIZE: usize,
        const L2CAP_MTU: usize,
    > Client<T::Error> for GattClient<'reference, 'resources, T, MAX_SERVICES, MAX_NOTIF, NOTIF_QSIZE, L2CAP_MTU>
{
    async fn request(&self, req: AttReq<'_>) -> Result<Pdu, BleHostError<T::Error>> {
        let header = L2capHeader {
            channel: crate::types::l2cap::L2CAP_CID_ATT,
            length: req.size() as u16,
        };

        let mut buf = [0; L2CAP_MTU];
        let mut w = WriteCursor::new(&mut buf);
        w.write_hci(&header)?;
        w.write(req)?;

        let mut grant = self.ble.acl(self.connection.handle(), 1).await?;
        grant.send(w.finish()).await?;

        let (h, pdu) = self.request_channel.receive().await;

        assert_eq!(h, self.connection.handle());
        Ok(pdu)
    }
}

impl<
        'reference,
        'resources,
        T: Controller,
        const MAX_SERVICES: usize,
        const MAX_NOTIF: usize,
        const NOTIF_QSIZE: usize,
        const L2CAP_MTU: usize,
    > GattClient<'reference, 'resources, T, MAX_SERVICES, MAX_NOTIF, NOTIF_QSIZE, L2CAP_MTU>
{
    /// Discover primary services associated with a UUID.
    pub async fn services_by_uuid(
        &self,
        uuid: &Uuid,
    ) -> Result<Vec<ServiceHandle, MAX_SERVICES>, BleHostError<T::Error>> {
        let mut start: u16 = 0x0001;
        let mut result = Vec::new();

        loop {
            let data = att::AttReq::FindByTypeValue {
                start_handle: start,
                end_handle: 0xffff,
                att_type: PRIMARY_SERVICE_UUID16.as_short(),
                att_value: uuid.as_raw(),
            };

            let pdu = self.request(data).await?;
            match AttRsp::decode(pdu.as_ref())? {
                AttRsp::Error { request, handle, code } => {
                    if code == att::AttErrorCode::AttributeNotFound {
                        break;
                    }
                    return Err(Error::Att(code).into());
                }
                AttRsp::FindByTypeValue { mut it } => {
                    let mut end: u16 = 0;
                    while let Some(res) = it.next() {
                        let (handle, e) = res?;
                        end = e;
                        let svc = ServiceHandle {
                            start: handle,
                            end,
                            uuid: uuid.clone(),
                        };
                        result.push(svc.clone()).map_err(|_| Error::InsufficientSpace)?;
                        self.known_services
                            .borrow_mut()
                            .push(svc)
                            .map_err(|_| Error::InsufficientSpace)?;
                    }
                    if end == 0xFFFF {
                        break;
                    }
                    start = end + 1;
                }
                _ => {
                    return Err(Error::InvalidValue.into());
                }
            }
        }

        Ok(result)
    }

    /// Discover characteristics in a given service using a UUID.
    pub async fn characteristic_by_uuid(
        &self,
        service: &ServiceHandle,
        uuid: &Uuid,
    ) -> Result<Characteristic, BleHostError<T::Error>> {
        let mut start: u16 = service.start;
        loop {
            let data = att::AttReq::ReadByType {
                start,
                end: service.end,
                attribute_type: CHARACTERISTIC_UUID16,
            };
            let pdu = self.request(data).await?;

            match AttRsp::decode(pdu.as_ref())? {
                AttRsp::ReadByType { mut it } => {
                    while let Some(Ok((handle, item))) = it.next() {
                        if item.len() < 5 {
                            return Err(Error::InvalidValue.into());
                        }
                        if let AttributeData::Declaration {
                            props,
                            handle,
                            uuid: decl_uuid,
                        } = AttributeData::decode_declaration(item)?
                        {
                            if *uuid == decl_uuid {
                                // "notify" and "indicate" characteristic properties
                                let cccd_handle =
                                    if props.any(&[CharacteristicProp::Indicate, CharacteristicProp::Notify]) {
                                        Some(self.get_characteristic_cccd(handle).await?.0)
                                    } else {
                                        None
                                    };

                                return Ok(Characteristic { handle, cccd_handle });
                            }

                            if handle == 0xFFFF {
                                return Err(Error::NotFound.into());
                            }
                            start = handle + 1;
                        } else {
                            return Err(Error::InvalidValue.into());
                        }
                    }
                }
                AttRsp::Error { request, handle, code } => return Err(Error::Att(code).into()),
                _ => {
                    return Err(Error::InvalidValue.into());
                }
            }
        }
    }

    async fn get_characteristic_cccd(&self, char_handle: u16) -> Result<(u16, CCCD), BleHostError<T::Error>> {
        let data = att::AttReq::ReadByType {
            start: char_handle,
            end: char_handle + 1,
            attribute_type: CHARACTERISTIC_CCCD_UUID16,
        };

        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::ReadByType { mut it } => {
                if let Some(Ok((handle, item))) = it.next() {
                    Ok((
                        handle,
                        CCCD(u16::from_le_bytes(item.try_into().map_err(|_| Error::OutOfMemory)?)),
                    ))
                } else {
                    Err(Error::NotFound.into())
                }
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Read a characteristic described by a handle.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic(
        &self,
        characteristic: &Characteristic,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<T::Error>> {
        let data = att::AttReq::Read {
            handle: characteristic.handle,
        };

        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::Read { data } => {
                let to_copy = data.len().min(dest.len());
                dest[..to_copy].copy_from_slice(&data[..to_copy]);
                Ok(to_copy)
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Read a characteristic described by a UUID.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic_by_uuid(
        &self,
        service: &ServiceHandle,
        uuid: &Uuid,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<T::Error>> {
        let data = att::AttReq::ReadByType {
            start: service.start,
            end: service.end,
            attribute_type: uuid.clone(),
        };

        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::ReadByType { mut it } => {
                let mut to_copy = 0;
                if let Some(item) = it.next() {
                    let (_handle, data) = item?;
                    to_copy = data.len().min(dest.len());
                    dest[..to_copy].copy_from_slice(&data[..to_copy]);
                }
                Ok(to_copy)
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Write to a characteristic described by a handle.
    pub async fn write_characteristic(
        &self,
        handle: &Characteristic,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let data = att::AttReq::Write {
            handle: handle.handle,
            data: buf,
        };

        let pdu = self.request(data).await?;
        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Subscribe to indication/notification of a given Characteristic
    ///
    /// A listener is returned, which has a `next()` method
    pub async fn subscribe(
        &self,
        characteristic: &Characteristic,
        indication: bool,
    ) -> Result<NotificationListener, BleHostError<T::Error>> {
        let properties = u16::to_le_bytes(if indication { 0x02 } else { 0x01 });

        let data = att::AttReq::Write {
            handle: characteristic.cccd_handle.ok_or(Error::NotSupported)?,
            data: &properties,
        };

        // set the CCCD
        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::Write => {
                // look for a free slot in the n_channel -> handle array
                for (n, item) in self.notification_map.borrow_mut().iter_mut().enumerate() {
                    if item.is_none() {
                        item.replace(characteristic.handle);
                        return Ok(NotificationListener {
                            listener: self.notification_channels[n].dyn_receiver(),
                        });
                    }
                }
                // otherwise, there's no space left in the array
                Err(Error::InsufficientSpace.into())
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Unsubscribe from a given Characteristic
    pub async fn unsubscribe(&self, characteristic: &Characteristic) -> Result<(), BleHostError<T::Error>> {
        let mut notifications = self.notification_map.borrow_mut();
        let (item, n) = notifications
            .iter_mut()
            .enumerate()
            .find_map(|(n, item)| {
                if let Some(h) = item {
                    if *h == characteristic.handle {
                        Some((item, n))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or(Error::NotFound)?;

        // Free up the slot in the n_channel -> handle map
        item.take();
        // Clear any data queued up in the channel
        self.notification_channels[n].clear();
        Ok(())
    }

    pub async fn handle_notification_packet(&'reference self, data: &[u8]) -> Result<(), BleHostError<T::Error>> {
        let mut r = ReadCursor::new(data);
        let value_handle: u16 = r.read()?;
        let value_attr = r.remaining();

        // let's find the corresponding `n` first, to avoid retaining the borrow_mut() across an await point
        let found_n = self
            .notification_map
            .borrow_mut()
            .iter()
            .enumerate()
            .find_map(|(n, item)| {
                if let Some(handle) = item {
                    if *handle == value_handle {
                        return Some(n);
                    }
                }
                None
            });

        if let Some(n) = found_n {
            let mut packet = self.notification_pool.alloc(ATT_ID).ok_or(Error::InsufficientSpace)?;
            let len = value_attr.len();
            packet.as_mut()[..len].copy_from_slice(value_attr);
            self.notification_channels[n].send((len as u16, packet)).await;
        }
        Ok(())
    }

    /// Task which handles GATT rx data (needed for notifications to work)
    pub async fn task(&self) -> Result<(), BleHostError<T::Error>> {
        loop {
            let (handle, pdu) = self.rx.receive().await;
            let data = pdu.as_ref();

            // handle notifications
            if data[0] == ATT_HANDLE_VALUE_NTF {
                self.handle_notification_packet(&data[1..]).await?;
            } else {
                self.request_channel.send((handle, pdu)).await;
            }
        }
    }
}
