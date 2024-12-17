//! GATT server and client implementation.
use core::cell::RefCell;
use core::future::Future;
use core::marker::PhantomData;

use bt_hci::controller::Controller;
use bt_hci::param::ConnHandle;
use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, DynamicReceiver};
use embassy_sync::pubsub::{self, PubSubChannel, WaitResult};
use heapless::Vec;

use crate::att::ATT_HANDLE_VALUE_NTF;
use crate::att::{self, AttReq, AttRsp};
use crate::attribute::{AttributeData, Characteristic, CharacteristicProp, Uuid, CCCD};
use crate::attribute_server::DynamicAttributeServer;
use crate::connection::Connection;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::packet_pool::GlobalPacketPool;
use crate::packet_pool::ATT_ID;
use crate::pdu::Pdu;
use crate::types::gatt_traits::GattValue;
use crate::types::l2cap::L2capHeader;
use crate::{config, BleHostError, Error, Stack};

/// A GATT payload ready for processing.
pub struct GattData<'d> {
    pdu: Pdu<'d>,
    tx_pool: &'d dyn GlobalPacketPool<'d>,
    connection: Connection<'d>,
}

impl<'d> GattData<'d> {
    pub(crate) fn new(pdu: Pdu<'d>, tx_pool: &'d dyn GlobalPacketPool<'d>, connection: Connection<'d>) -> Self {
        Self {
            pdu,
            tx_pool,
            connection,
        }
    }
}

/// An event returned while processing GATT requests.
pub enum GattEvent<'d, 'server> {
    /// A characteristic was read.
    Read(ReadEvent<'d, 'server>),
    /// A characteristic was written.
    Write(WriteEvent<'d, 'server>),
}

/// An event returned while processing GATT requests.
pub struct ReadEvent<'d, 'server> {
    value_handle: u16,
    connection: Connection<'d>,
    server: &'server dyn DynamicAttributeServer,
    tx_pool: &'d dyn GlobalPacketPool<'d>,
    pdu: Option<Pdu<'d>>,
}

impl<'d, 'server> ReadEvent<'d, 'server> {
    /// Characteristic handle that was read
    pub fn handle(&self) -> u16 {
        self.value_handle
    }

    /// Process and respond to event.
    pub fn try_reply(mut self) -> Result<(), Error> {
        if let Some(pdu) = self.pdu.take() {
            let att = unwrap!(AttReq::decode(pdu.as_ref()));
            if let Some(pdu) = process(&self.connection, att, self.server, self.tx_pool)? {
                self.connection.try_send(pdu)?;
            }
        }
        Ok(())
    }

    /// Process and respond to event.
    pub async fn reply(mut self) -> Result<(), Error> {
        if let Some(pdu) = self.pdu.take() {
            let att = unwrap!(AttReq::decode(pdu.as_ref()));
            if let Some(pdu) = process(&self.connection, att, self.server, self.tx_pool)? {
                self.connection.send(pdu).await;
            }
        }
        Ok(())
    }
}

impl<'d, 'server> Drop for ReadEvent<'d, 'server> {
    fn drop(&mut self) {
        if let Some(pdu) = self.pdu.take() {
            let att = unwrap!(AttReq::decode(pdu.as_ref()));
            if let Ok(Some(pdu)) = process(&self.connection, att, self.server, self.tx_pool) {
                let _ = self.connection.try_send(pdu);
            }
        }
    }
}

/// An event returned while processing GATT requests.
pub struct WriteEvent<'d, 'server> {
    /// Characteristic handle that was written.
    value_handle: u16,
    pdu: Option<Pdu<'d>>,
    connection: Connection<'d>,
    tx_pool: &'d dyn GlobalPacketPool<'d>,
    server: &'server dyn DynamicAttributeServer,
}

impl<'d, 'server> WriteEvent<'d, 'server> {
    /// Characteristic handle that was read
    pub fn handle(&self) -> u16 {
        self.value_handle
    }

    /// Characteristic data that was written
    pub fn data(&self) -> &[u8] {
        // Note: write event data is always at offset 3, right?
        &self.pdu.as_ref().unwrap().as_ref()[3..]
    }

    /// Process and respond to event.
    pub fn try_reply(mut self) -> Result<(), Error> {
        if let Some(pdu) = self.pdu.take() {
            let att = unwrap!(AttReq::decode(pdu.as_ref()));
            if let Some(pdu) = process(&self.connection, att, self.server, self.tx_pool)? {
                self.connection.try_send(pdu)?;
            }
        }
        Ok(())
    }

    /// Process and respond to event.
    pub async fn reply(mut self) -> Result<(), Error> {
        if let Some(pdu) = self.pdu.take() {
            let att = unwrap!(AttReq::decode(pdu.as_ref()));
            if let Some(pdu) = process(&self.connection, att, self.server, self.tx_pool)? {
                self.connection.send(pdu).await;
            }
        }
        Ok(())
    }
}

impl<'d, 'server> Drop for WriteEvent<'d, 'server> {
    fn drop(&mut self) {
        if let Some(pdu) = self.pdu.take() {
            let att = unwrap!(AttReq::decode(pdu.as_ref()));
            if let Ok(Some(pdu)) = process(&self.connection, att, self.server, self.tx_pool) {
                let _ = self.connection.try_send(pdu);
            }
        }
    }
}

fn process<'d, 'server>(
    conn: &Connection<'d>,
    att: AttReq<'_>,
    server: &'server dyn DynamicAttributeServer,
    tx_pool: &'d dyn GlobalPacketPool<'d>,
) -> Result<Option<Pdu<'d>>, Error> {
    let mut tx = tx_pool.alloc(ATT_ID).ok_or(Error::OutOfMemory)?;
    let mut w = WriteCursor::new(tx.as_mut());
    let (mut header, mut data) = w.split(4)?;
    if let Some(written) = server.process(conn, &att, data.write_buf())? {
        let mtu = conn.get_att_mtu();
        data.commit(written)?;
        data.truncate(mtu as usize);
        header.write(written as u16)?;
        header.write(4_u16)?;
        let len = header.len() + data.len();
        let pdu = Pdu::new(tx, len);

        Ok(Some(pdu))
    } else {
        Ok(None)
    }
}

impl<'d> GattData<'d> {
    /// Get the raw request.
    pub fn request(&self) -> AttReq<'_> {
        // We know it has been checked, therefore this cannot fail
        unwrap!(AttReq::decode(self.pdu.as_ref()))
    }

    /// Respond directly to request.
    pub async fn reply(self, rsp: AttRsp<'_>) -> Result<(), Error> {
        let mut tx = self.tx_pool.alloc(ATT_ID).ok_or(Error::OutOfMemory)?;
        let mut w = WriteCursor::new(tx.as_mut());
        let (mut header, mut data) = w.split(4)?;
        data.write(rsp)?;
        let mtu = self.connection.get_att_mtu();
        data.truncate(mtu as usize);
        header.write(data.len() as u16)?;
        header.write(4_u16)?;
        let len = header.len() + data.len();
        let pdu = Pdu::new(tx, len);
        self.connection.send(pdu).await;
        Ok(())
    }

    /// Handle the GATT data.
    ///
    /// May return an event that should be replied/processed. Uses the attribute server to
    /// handle the protocol.
    pub async fn process(self, server: &dyn DynamicAttributeServer) -> Result<Option<GattEvent<'d, '_>>, Error> {
        // We know it has been checked, therefore this cannot fail
        let att = unwrap!(AttReq::decode(self.pdu.as_ref()));
        match att {
            AttReq::Write { handle, data: _ } => Ok(Some(GattEvent::Write(WriteEvent {
                value_handle: handle,
                tx_pool: self.tx_pool,
                pdu: Some(self.pdu),
                connection: self.connection,
                server,
            }))),

            AttReq::Read { handle } => Ok(Some(GattEvent::Read(ReadEvent {
                value_handle: handle,
                tx_pool: self.tx_pool,
                pdu: Some(self.pdu),
                connection: self.connection,
                server,
            }))),

            AttReq::ReadBlob { handle, offset } => Ok(Some(GattEvent::Read(ReadEvent {
                value_handle: handle,
                tx_pool: self.tx_pool,
                pdu: Some(self.pdu),
                connection: self.connection,
                server,
            }))),
            _ => {
                // Process it now since the user will not
                if let Some(pdu) = process(&self.connection, att, server, self.tx_pool)? {
                    self.connection.send(pdu).await;
                }
                Ok(None)
            }
        }
    }
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
        grant.send(w.finish(), true).await?;

        let (h, pdu) = self.response_channel.receive().await;

        assert_eq!(h, self.connection.handle());
        Ok(pdu)
    }
}

impl<'reference, C: Controller, const MAX_SERVICES: usize, const L2CAP_MTU: usize>
    GattClient<'reference, C, MAX_SERVICES, L2CAP_MTU>
{
    /// Creates a GATT client capable of processing the GATT protocol using the provided table of attributes.
    pub async fn new(
        stack: Stack<'reference, C>,
        connection: &Connection<'reference>,
    ) -> Result<GattClient<'reference, C, MAX_SERVICES, L2CAP_MTU>, BleHostError<C::Error>> {
        let l2cap = L2capHeader { channel: 4, length: 3 };
        let mut buf = [0; 7];
        let mut w = WriteCursor::new(&mut buf);
        w.write_hci(&l2cap)?;
        w.write(att::AttReq::ExchangeMtu {
            mtu: L2CAP_MTU as u16 - 4,
        })?;

        let mut grant = stack.host.acl(connection.handle(), 1).await?;

        grant.send(w.finish(), true).await?;

        Ok(Self {
            known_services: RefCell::new(heapless::Vec::new()),
            rx: stack.host.att_client.receiver().into(),
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
    ) -> Result<Vec<ServiceHandle, MAX_SERVICES>, BleHostError<C::Error>> {
        let mut start: u16 = 0x0001;
        let mut result = Vec::new();

        loop {
            let data = att::AttReq::FindByTypeValue {
                start_handle: start,
                end_handle: 0xffff,
                att_type: PRIMARY_SERVICE.into(),
                att_value: uuid.as_raw(),
            };

            let pdu = self.request(data).await?;
            let res = AttRsp::decode(pdu.as_ref())?;
            match res {
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
                res => {
                    trace!("[gatt client] response: {:?}", res);
                    return Err(Error::InvalidValue.into());
                }
            }
        }

        Ok(result)
    }

    /// Discover characteristics in a given service using a UUID.
    pub async fn characteristic_by_uuid<T: GattValue>(
        &self,
        service: &ServiceHandle,
        uuid: &Uuid,
    ) -> Result<Characteristic<T>, BleHostError<C::Error>> {
        let mut start: u16 = service.start;
        loop {
            let data = att::AttReq::ReadByType {
                start,
                end: service.end,
                attribute_type: CHARACTERISTIC.into(),
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

                                return Ok(Characteristic {
                                    handle,
                                    cccd_handle,
                                    phantom: PhantomData,
                                });
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

    async fn get_characteristic_cccd(&self, char_handle: u16) -> Result<(u16, CCCD), BleHostError<C::Error>> {
        let data = att::AttReq::ReadByType {
            start: char_handle,
            end: char_handle + 1,
            attribute_type: CLIENT_CHARACTERISTIC_CONFIGURATION.into(),
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
    pub async fn read_characteristic<T: GattValue>(
        &self,
        characteristic: &Characteristic<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
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
    ) -> Result<usize, BleHostError<C::Error>> {
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
    pub async fn write_characteristic<T: GattValue>(
        &self,
        handle: &Characteristic<T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
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
    pub async fn subscribe<T: GattValue>(
        &self,
        characteristic: &Characteristic<T>,
        indication: bool,
    ) -> Result<NotificationListener<'_, L2CAP_MTU>, BleHostError<C::Error>> {
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
    pub async fn unsubscribe<T: GattValue>(
        &self,
        characteristic: &Characteristic<T>,
    ) -> Result<(), BleHostError<C::Error>> {
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
    async fn handle_notification_packet(&self, data: &[u8]) -> Result<(), BleHostError<C::Error>> {
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
    pub async fn task(&self) -> Result<(), BleHostError<C::Error>> {
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
