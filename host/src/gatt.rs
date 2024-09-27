//! GATT server and client implementation.
use core::cell::RefCell;
use core::future::Future;

use bt_hci::controller::Controller;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::channel::{Channel, DynamicReceiver, DynamicSender};
use embassy_sync::pubsub::{self, PubSubChannel, WaitResult};
use heapless::Vec;

use crate::att::{self, AttReq, AttRsp, ATT_HANDLE_VALUE_NTF};
use crate::attribute::{
    AttributeData, AttributeTable, Characteristic, CharacteristicProp, Uuid, CCCD, CHARACTERISTIC_CCCD_UUID16,
    CHARACTERISTIC_UUID16, PRIMARY_SERVICE_UUID16,
};
use crate::attribute_server::AttributeServer;
use crate::connection::Connection;
use crate::connection_manager::DynamicConnectionManager;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::pdu::Pdu;
use crate::types::l2cap::L2capHeader;
use crate::{config, BleHostError, Error, Stack};

/// A GATT server capable of processing the GATT protocol using the provided table of attributes.
pub struct GattServer<'reference, 'values, C: Controller, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize> {
    stack: Stack<'reference, C>,
    server: AttributeServer<'reference, 'values, M, MAX>,
    tx: DynamicSender<'reference, (ConnHandle, Pdu<'reference>)>,
    rx: DynamicReceiver<'reference, (ConnHandle, Pdu<'reference>)>,
    connections: &'reference dyn DynamicConnectionManager,
}

impl<'reference, 'values, C: Controller, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize>
    GattServer<'reference, 'values, C, M, MAX, L2CAP_MTU>
{
    /// Creates a GATT server capable of processing the GATT protocol using the provided table of attributes.
    pub fn new(stack: Stack<'reference, C>, table: &'reference AttributeTable<'values, M, MAX>) -> Self {
        stack.host.connections.set_default_att_mtu(L2CAP_MTU as u16 - 4);
        use crate::attribute_server::AttributeServer;

        Self {
            stack,
            server: AttributeServer::new(table),
            rx: stack.host.att_inbound.receiver().into(),
            tx: stack.host.outbound.sender().into(),
            connections: &stack.host.connections,
        }
    }

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
    pub async fn notify(
        &self,
        handle: Characteristic,
        connection: &Connection<'_>,
        value: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
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
        self.stack.host.acl(conn, 1).await?.send(&tx[..total]).await?;
        Ok(())
    }
}

/// An event returned while processing GATT requests.
#[derive(Clone)]
pub enum GattEvent<'reference> {
    /// A characteristic was read.
    Read {
        /// Connection that read the characteristic.
        connection: Connection<'reference>,
        /// Characteristic handle that was read.
        handle: Characteristic,
    },
    /// A characteristic was written.
    Write {
        /// Connection that wrote the characteristic.
        connection: Connection<'reference>,
        /// Characteristic handle that was written.
        handle: Characteristic,
    },
}

/// Notification listener for GATT client.
pub struct NotificationListener<'lst, const MTU: usize> {
    handle: u16,
    listener: pubsub::DynSubscriber<'lst, Notification<MTU>>,
}

impl<'lst, const MTU: usize> NotificationListener<'lst, MTU> {
    #[allow(clippy::should_implement_trait)]
    /// Get the next (len: u16, Packet) tuple from the rx queue
    pub async fn next(&mut self) -> Notification<MTU> {
        loop {
            if let WaitResult::Message(m) = self.listener.next_message().await {
                if m.handle == self.handle {
                    return m;
                }
            }
        }
    }
}

const MAX_NOTIF: usize = config::GATT_CLIENT_NOTIFICATION_MAX_SUBSCRIBERS;
const NOTIF_QSIZE: usize = config::GATT_CLIENT_NOTIFICATION_QUEUE_SIZE;

/// A GATT client capable of using the GATT protocol.
pub struct GattClient<'reference, T: Controller, const MAX_SERVICES: usize, const L2CAP_MTU: usize = 27> {
    known_services: RefCell<Vec<ServiceHandle, MAX_SERVICES>>,
    rx: DynamicReceiver<'reference, (ConnHandle, Pdu<'reference>)>,
    stack: Stack<'reference, T>,
    connection: Connection<'reference>,
    response_channel: Channel<NoopRawMutex, (ConnHandle, Pdu<'reference>), 1>,

    notifications: PubSubChannel<NoopRawMutex, Notification<L2CAP_MTU>, NOTIF_QSIZE, MAX_NOTIF, 1>,
}

/// A notification payload.
#[derive(Debug, PartialEq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Notification<const MTU: usize> {
    handle: u16,
    data: [u8; MTU],
    len: usize,
}

impl<const MTU: usize> AsRef<[u8]> for Notification<MTU> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Handle for a GATT service.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Clone)]
pub struct ServiceHandle {
    start: u16,
    end: u16,
    uuid: Uuid,
}

/// Trait with behavior for a gatt client.
pub(crate) trait Client<'d, E> {
    /// Perform a gatt request and return the response.
    fn request(&self, req: AttReq<'_>) -> impl Future<Output = Result<Pdu<'d>, BleHostError<E>>>;
}

impl<'reference, T: Controller, const MAX_SERVICES: usize, const L2CAP_MTU: usize> Client<'reference, T::Error>
    for GattClient<'reference, T, MAX_SERVICES, L2CAP_MTU>
{
    async fn request(&self, req: AttReq<'_>) -> Result<Pdu<'reference>, BleHostError<T::Error>> {
        let header = L2capHeader {
            channel: crate::types::l2cap::L2CAP_CID_ATT,
            length: req.size() as u16,
        };

        let mut buf = [0; L2CAP_MTU];
        let mut w = WriteCursor::new(&mut buf);
        w.write_hci(&header)?;
        w.write(req)?;

        let mut grant = self.stack.host.acl(self.connection.handle(), 1).await?;
        grant.send(w.finish()).await?;

        let (h, pdu) = self.response_channel.receive().await;

        assert_eq!(h, self.connection.handle());
        Ok(pdu)
    }
}

impl<'reference, T: Controller, const MAX_SERVICES: usize, const L2CAP_MTU: usize>
    GattClient<'reference, T, MAX_SERVICES, L2CAP_MTU>
{
    /// Creates a GATT client capable of processing the GATT protocol using the provided table of attributes.
    pub async fn new(
        stack: Stack<'reference, T>,
        connection: &Connection<'reference>,
    ) -> Result<GattClient<'reference, T, MAX_SERVICES, L2CAP_MTU>, BleHostError<T::Error>> {
        let l2cap = L2capHeader { channel: 4, length: 3 };
        let mut buf = [0; 7];
        let mut w = WriteCursor::new(&mut buf);
        w.write_hci(&l2cap)?;
        w.write(att::AttReq::ExchangeMtu {
            mtu: L2CAP_MTU as u16 - 4,
        })?;

        let mut grant = stack.host.acl(connection.handle(), 1).await?;

        grant.send(w.finish()).await?;

        Ok(Self {
            known_services: RefCell::new(heapless::Vec::new()),
            rx: stack.host.att_inbound.receiver().into(),
            stack,
            connection: connection.clone(),

            response_channel: Channel::new(),

            notifications: PubSubChannel::new(),
        })
    }

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
    ) -> Result<NotificationListener<'_, L2CAP_MTU>, BleHostError<T::Error>> {
        let properties = u16::to_le_bytes(if indication { 0x02 } else { 0x01 });

        let data = att::AttReq::Write {
            handle: characteristic.cccd_handle.ok_or(Error::NotSupported)?,
            data: &properties,
        };

        // set the CCCD
        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::Write => {
                let listener = self
                    .notifications
                    .dyn_subscriber()
                    .map_err(|_| Error::InsufficientSpace)?;
                Ok(NotificationListener {
                    listener,
                    handle: characteristic.handle,
                })
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Unsubscribe from a given Characteristic
    pub async fn unsubscribe(&self, characteristic: &Characteristic) -> Result<(), BleHostError<T::Error>> {
        let properties = u16::to_le_bytes(0);
        let data = att::AttReq::Write {
            handle: characteristic.cccd_handle.ok_or(Error::NotSupported)?,
            data: &[0, 0],
        };

        // set the CCCD
        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Handle a notification that was received.
    async fn handle_notification_packet(&self, data: &[u8]) -> Result<(), BleHostError<T::Error>> {
        let mut r = ReadCursor::new(data);
        let value_handle: u16 = r.read()?;
        let value_attr = r.remaining();

        let handle = value_handle;

        let mut data = [0u8; L2CAP_MTU];
        let to_copy = data.len().min(value_attr.len());
        data[..to_copy].copy_from_slice(&value_attr[..to_copy]);
        let n = Notification {
            handle,
            data,
            len: to_copy,
        };
        self.notifications.immediate_publisher().publish_immediate(n);
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
                self.response_channel.send((handle, pdu)).await;
            }
        }
    }
}
