//! GATT server and client implementation.
use core::cell::RefCell;
use core::future::Future;
use core::marker::PhantomData;

use att::AttErrorCode;
use bt_hci::controller::Controller;
use bt_hci::param::{ConnHandle, PhyKind, Status};
use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::channel::{Channel, DynamicReceiver};
use embassy_sync::pubsub::{self, PubSubChannel, WaitResult};
use embassy_time::Duration;
use heapless::Vec;

use crate::att::{self, Att, AttClient, AttCmd, AttReq, AttRsp, AttServer, AttUns, ATT_HANDLE_VALUE_NTF};
use crate::attribute::{AttributeData, Characteristic, CharacteristicProp, Uuid, CCCD};
use crate::attribute_server::{AttributeServer, DynamicAttributeServer};
use crate::connection::Connection;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::pdu::Pdu;
use crate::prelude::ConnectionEvent;
#[cfg(feature = "security")]
use crate::security_manager::BondInformation;
use crate::types::gatt_traits::{AsGatt, FromGatt, FromGattError};
use crate::types::l2cap::L2capHeader;
use crate::{config, BleHostError, Error, PacketPool, Stack};

/// A GATT connection event.
pub enum GattConnectionEvent<'stack, 'server, P: PacketPool> {
    /// Connection disconnected.
    Disconnected {
        /// The reason (status code) for the disconnect.
        reason: Status,
    },
    /// The phy settings was updated for this connection.
    PhyUpdated {
        /// The TX phy.
        tx_phy: PhyKind,
        /// The RX phy.
        rx_phy: PhyKind,
    },
    /// The phy settings was updated for this connection.
    ConnectionParamsUpdated {
        /// Connection interval.
        conn_interval: Duration,
        /// Peripheral latency.
        peripheral_latency: u16,
        /// Supervision timeout.
        supervision_timeout: Duration,
    },
    #[cfg(feature = "security")]
    /// Bonded event.
    Bonded {
        /// Bond info for this connection
        bond_info: BondInformation,
    },
    /// GATT event.
    Gatt {
        /// The event that was returned
        event: Result<GattEvent<'stack, 'server, P>, Error>,
    },
}

/// Used to manage a GATT connection with a client.
pub struct GattConnection<'stack, 'server, P: PacketPool> {
    connection: Connection<'stack, P>,
    pub(crate) server: &'server dyn DynamicAttributeServer<P>,
}

impl<P: PacketPool> Drop for GattConnection<'_, '_, P> {
    fn drop(&mut self) {
        trace!("[gatt {}] disconnecting from server", self.connection.handle().raw());
        self.server.disconnect(&self.connection);
    }
}

impl<'stack, 'server, P: PacketPool> GattConnection<'stack, 'server, P> {
    /// Creates a GATT connection from the given BLE connection and `AttributeServer`:
    /// this will register the client within the server's CCCD table.
    pub(crate) fn try_new<'values, M: RawMutex, const AT: usize, const CT: usize, const CN: usize>(
        connection: Connection<'stack, P>,
        server: &'server AttributeServer<'values, M, P, AT, CT, CN>,
    ) -> Result<Self, Error> {
        trace!("[gatt {}] connecting to server", connection.handle().raw());
        server.connect(&connection)?;
        Ok(Self { connection, server })
    }

    /// Wait for the next GATT connection event.
    ///
    /// Uses the attribute server to handle the protocol.
    pub async fn next(&self) -> GattConnectionEvent<'stack, 'server, P> {
        loop {
            match select(self.connection.next(), self.connection.next_gatt()).await {
                Either::First(event) => match event {
                    ConnectionEvent::Disconnected { reason } => return GattConnectionEvent::Disconnected { reason },
                    ConnectionEvent::ConnectionParamsUpdated {
                        conn_interval,
                        peripheral_latency,
                        supervision_timeout,
                    } => {
                        return GattConnectionEvent::ConnectionParamsUpdated {
                            conn_interval,
                            peripheral_latency,
                            supervision_timeout,
                        };
                    }
                    ConnectionEvent::PhyUpdated { tx_phy, rx_phy } => {
                        return GattConnectionEvent::PhyUpdated { tx_phy, rx_phy };
                    }
                    #[cfg(feature = "security")]
                    ConnectionEvent::Bonded { bond_info } => {
                        // Update the identity of the connection
                        if let Err(e) = self.server.update_identity(bond_info.identity) {
                            error!("Failed to update identity in att server: {:?}", e);
                        }
                        return GattConnectionEvent::Bonded { bond_info };
                    }
                },
                Either::Second(data) => {
                    let data = GattData::new(data, self.connection.clone());
                    match data.process(self.server).await {
                        Ok(event) => match event {
                            Some(event) => return GattConnectionEvent::Gatt { event: Ok(event) },
                            None => continue,
                        },
                        Err(e) => return GattConnectionEvent::Gatt { event: Err(e) },
                    }
                }
            }
        }
    }

    /// Get a reference to the underlying BLE connection.
    pub fn raw(&self) -> &Connection<'stack, P> {
        &self.connection
    }
}

/// A GATT payload ready for processing.
pub struct GattData<'stack, P: PacketPool> {
    pdu: Option<Pdu<P::Packet>>,
    connection: Connection<'stack, P>,
}

impl<'stack, P: PacketPool> GattData<'stack, P> {
    pub(crate) fn new(pdu: Pdu<P::Packet>, connection: Connection<'stack, P>) -> Self {
        Self {
            pdu: Some(pdu),
            connection,
        }
    }

    /// Get the raw incoming ATT PDU.
    pub fn incoming(&self) -> AttClient<'_> {
        // We know that:
        // - The PDU is decodable, as it was already decoded once before adding it to the connection queue
        // - The PDU is of type `Att::Client` because only those types of PDUs are added to the connection queue
        let att = unwrap!(Att::decode(self.pdu.as_ref().unwrap().as_ref()));
        let Att::Client(client) = att else {
            unreachable!("Expected Att::Client, got {:?}", att)
        };

        client
    }

    /// Respond directly to request.
    pub async fn reply(self, rsp: AttRsp<'_>) -> Result<(), Error> {
        let pdu = send(&self.connection, AttServer::Response(rsp))?;
        self.connection.send(pdu).await;
        Ok(())
    }

    /// Send an unsolicited ATT PDU without having a request (e.g. notification or indication)
    pub async fn send_unsolicited(connection: &Connection<'_, P>, uns: AttUns<'_>) -> Result<(), Error> {
        let pdu = send(connection, AttServer::Unsolicited(uns))?;
        connection.send(pdu).await;
        Ok(())
    }

    /// Handle the GATT data.
    ///
    /// May return an event that should be replied/processed. Uses the provided
    /// attribute server to handle the protocol.
    pub async fn process<'m>(
        mut self,
        server: &'m dyn DynamicAttributeServer<P>,
    ) -> Result<Option<GattEvent<'stack, 'm, P>>, Error> {
        let att = self.incoming();
        match att {
            AttClient::Request(AttReq::Write { handle, data: _ }) => Ok(Some(GattEvent::Write(WriteEvent {
                value_handle: handle,
                pdu: self.pdu.take(),
                connection: self.connection.clone(),
                server,
            }))),

            AttClient::Command(AttCmd::Write { handle, data: _ }) => Ok(Some(GattEvent::Write(WriteEvent {
                value_handle: handle,
                pdu: self.pdu.take(),
                connection: self.connection.clone(),
                server,
            }))),

            AttClient::Request(AttReq::Read { handle }) => Ok(Some(GattEvent::Read(ReadEvent {
                value_handle: handle,
                pdu: self.pdu.take(),
                connection: self.connection.clone(),
                server,
            }))),

            AttClient::Request(AttReq::ReadBlob { handle, offset }) => Ok(Some(GattEvent::Read(ReadEvent {
                value_handle: handle,
                pdu: self.pdu.take(),
                connection: self.connection.clone(),
                server,
            }))),
            _ => {
                // Process it now since the user will not
                if let Some(pdu) = self.pdu.as_ref() {
                    let reply = process_accept(pdu, &self.connection, server)?;
                    reply.send().await;
                }
                Ok(None)
            }
        }
    }
}

/// An event returned while processing GATT requests.
pub enum GattEvent<'stack, 'server, P: PacketPool> {
    /// A characteristic was read.
    Read(ReadEvent<'stack, 'server, P>),
    /// A characteristic was written.
    Write(WriteEvent<'stack, 'server, P>),
}

impl<'stack, 'server, P: PacketPool> GattEvent<'stack, 'server, P> {
    /// Accept the event, making it processed by the server.
    pub fn accept(self) -> Result<Reply<'stack, P>, Error> {
        match self {
            Self::Read(e) => e.accept(),
            Self::Write(e) => e.accept(),
        }
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        match self {
            Self::Read(e) => e.reject(err),
            Self::Write(e) => e.reject(err),
        }
    }
}

/// An event returned while processing GATT requests.
pub struct ReadEvent<'stack, 'server, P: PacketPool> {
    value_handle: u16,
    connection: Connection<'stack, P>,
    server: &'server dyn DynamicAttributeServer<P>,
    pdu: Option<Pdu<P::Packet>>,
}

impl<'stack, P: PacketPool> ReadEvent<'stack, '_, P> {
    /// Characteristic handle that was read
    pub fn handle(&self) -> u16 {
        self.value_handle
    }

    /// Accept the event, making it processed by the server.
    ///
    /// Automatically called if drop() is invoked.
    pub fn accept(mut self) -> Result<Reply<'stack, P>, Error> {
        let handle = self.handle();
        process(&mut self.pdu, handle, &self.connection, self.server, Ok(()))
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(mut self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        let handle = self.handle();
        process(&mut self.pdu, handle, &self.connection, self.server, Err(err))
    }
}

impl<P: PacketPool> Drop for ReadEvent<'_, '_, P> {
    fn drop(&mut self) {
        let handle = self.handle();
        let _ = process(&mut self.pdu, handle, &self.connection, self.server, Ok(()));
    }
}

/// An event returned while processing GATT requests.
pub struct WriteEvent<'stack, 'server, P: PacketPool> {
    /// Characteristic handle that was written.
    value_handle: u16,
    pdu: Option<Pdu<P::Packet>>,
    connection: Connection<'stack, P>,
    server: &'server dyn DynamicAttributeServer<P>,
}

impl<'stack, P: PacketPool> WriteEvent<'stack, '_, P> {
    /// Characteristic handle that was read
    pub fn handle(&self) -> u16 {
        self.value_handle
    }

    /// Raw data to be written
    pub fn data(&self) -> &[u8] {
        // Note: write event data is always at offset 3, right?
        &self.pdu.as_ref().unwrap().as_ref()[3..]
    }

    /// Characteristic data to be written
    pub fn value<T: FromGatt>(&self, _c: &Characteristic<T>) -> Result<T, FromGattError> {
        T::from_gatt(self.data())
    }

    /// Accept the event, making it processed by the server.
    ///
    /// Automatically called if drop() is invoked.
    pub fn accept(mut self) -> Result<Reply<'stack, P>, Error> {
        let handle = self.handle();
        process(&mut self.pdu, handle, &self.connection, self.server, Ok(()))
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(mut self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        let handle = self.handle();
        process(&mut self.pdu, handle, &self.connection, self.server, Err(err))
    }
}

impl<P: PacketPool> Drop for WriteEvent<'_, '_, P> {
    fn drop(&mut self) {
        let handle = self.handle();
        let _ = process(&mut self.pdu, handle, &self.connection, self.server, Ok(()));
    }
}

fn process<'stack, P>(
    pdu: &mut Option<Pdu<P::Packet>>,
    handle: u16,
    connection: &Connection<'stack, P>,
    server: &dyn DynamicAttributeServer<P>,
    result: Result<(), AttErrorCode>,
) -> Result<Reply<'stack, P>, Error>
where
    P: PacketPool,
{
    if let Some(pdu) = pdu.take() {
        let res = match result {
            Ok(_) => process_accept(&pdu, connection, server),
            Err(code) => process_reject(&pdu, handle, connection, code),
        };
        res
    } else {
        Ok(Reply::new(connection.clone(), None))
    }
}

fn process_accept<'stack, P>(
    pdu: &Pdu<P::Packet>,
    connection: &Connection<'stack, P>,
    server: &dyn DynamicAttributeServer<P>,
) -> Result<Reply<'stack, P>, Error>
where
    P: PacketPool,
{
    // - The PDU is decodable, as it was already decoded once before adding it to the connection queue
    // - The PDU is of type `Att::Client` because only those types of PDUs are added to the connection queue
    let att = unwrap!(Att::decode(pdu.as_ref()));
    let Att::Client(att) = att else {
        unreachable!("Expected Att::Client, got {:?}", att)
    };
    let mut tx = P::allocate().ok_or(Error::OutOfMemory)?;
    let mut w = WriteCursor::new(tx.as_mut());
    let (mut header, mut data) = w.split(4)?;
    if let Some(written) = server.process(connection, &att, data.write_buf())? {
        let mtu = connection.get_att_mtu();
        data.commit(written)?;
        data.truncate(mtu as usize);
        header.write(data.len() as u16)?;
        header.write(4_u16)?;
        let len = header.len() + data.len();
        let pdu = Pdu::new(tx, len);
        Ok(Reply::new(connection.clone(), Some(pdu)))
    } else {
        Ok(Reply::new(connection.clone(), None))
    }
}

fn process_reject<'stack, P: PacketPool>(
    pdu: &Pdu<P::Packet>,
    handle: u16,
    connection: &Connection<'stack, P>,
    code: AttErrorCode,
) -> Result<Reply<'stack, P>, Error> {
    // We know it has been checked, therefore this cannot fail
    let request = pdu.as_ref()[0];
    let rsp = AttRsp::Error { request, handle, code };
    let pdu = send(connection, AttServer::Response(rsp))?;
    Ok(Reply::new(connection.clone(), Some(pdu)))
}

fn send<'stack, P: PacketPool>(conn: &Connection<'stack, P>, att: AttServer<'_>) -> Result<Pdu<P::Packet>, Error> {
    let mut tx = P::allocate().ok_or(Error::OutOfMemory)?;
    let mut w = WriteCursor::new(tx.as_mut());
    let (mut header, mut data) = w.split(4)?;
    data.write(Att::Server(att))?;

    let mtu = conn.get_att_mtu();
    data.truncate(mtu as usize);
    header.write(data.len() as u16)?;
    header.write(4_u16)?;
    let len = header.len() + data.len();
    Ok(Pdu::new(tx, len))
}

/// A reply to a gatt request.
///
/// The reply may be sent immediately or queued for sending later. To guarantee delivery of a reply
/// in case of a full outbound queue, the async send() should be used rather than relying on the Drop implementation.
pub struct Reply<'stack, P: PacketPool> {
    connection: Connection<'stack, P>,
    pdu: Option<Pdu<P::Packet>>,
}

impl<'stack, P: PacketPool> Reply<'stack, P> {
    fn new(connection: Connection<'stack, P>, pdu: Option<Pdu<P::Packet>>) -> Self {
        Self { connection, pdu }
    }

    /// Send the reply.
    ///
    /// May fail if the outbound queue is full.
    pub fn try_send(mut self) -> Result<(), Error> {
        if let Some(pdu) = self.pdu.take() {
            self.connection.try_send(pdu)
        } else {
            Ok(())
        }
    }

    /// Send the reply.
    pub async fn send(mut self) {
        if let Some(pdu) = self.pdu.take() {
            self.connection.send(pdu).await
        }
    }
}

impl<P: PacketPool> Drop for Reply<'_, P> {
    fn drop(&mut self) {
        if let Some(pdu) = self.pdu.take() {
            if self.connection.try_send(pdu).is_err() {
                warn!("[gatt] error sending reply (outbound buffer full)");
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
pub struct GattClient<'reference, T: Controller, P: PacketPool, const MAX_SERVICES: usize> {
    known_services: RefCell<Vec<ServiceHandle, MAX_SERVICES>>,
    rx: DynamicReceiver<'reference, (ConnHandle, Pdu<P::Packet>)>,
    stack: &'reference Stack<'reference, T, P>,
    connection: Connection<'reference, P>,
    response_channel: Channel<NoopRawMutex, (ConnHandle, Pdu<P::Packet>), 1>,

    // TODO: Wait for something like https://github.com/rust-lang/rust/issues/132980 (min_generic_const_args) to allow using P::MTU
    notifications: PubSubChannel<NoopRawMutex, Notification<512>, NOTIF_QSIZE, MAX_NOTIF, 1>,
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

pub(crate) struct Response<P> {
    pdu: Pdu<P>,
    handle: ConnHandle,
}

/// Trait with behavior for a gatt client.
pub(crate) trait Client<'d, E, P: PacketPool> {
    /// Perform a gatt request and return the response.
    fn request(&self, req: AttReq<'_>) -> impl Future<Output = Result<Response<P::Packet>, BleHostError<E>>>;
    fn command(&self, cmd: AttCmd<'_>) -> impl Future<Output = Result<(), BleHostError<E>>>;
}

impl<'reference, T: Controller, P: PacketPool, const MAX_SERVICES: usize> Client<'reference, T::Error, P>
    for GattClient<'reference, T, P, MAX_SERVICES>
{
    async fn request(&self, req: AttReq<'_>) -> Result<Response<P::Packet>, BleHostError<T::Error>> {
        let data = Att::Client(AttClient::Request(req));

        self.send_att_data(data).await?;

        let (h, pdu) = self.response_channel.receive().await;

        assert_eq!(h, self.connection.handle());
        Ok(Response { handle: h, pdu })
    }

    async fn command(&self, cmd: AttCmd<'_>) -> Result<(), BleHostError<T::Error>> {
        let data = Att::Client(AttClient::Command(cmd));

        self.send_att_data(data).await?;

        Ok(())
    }
}

impl<'reference, T: Controller, P: PacketPool, const MAX_SERVICES: usize> GattClient<'reference, T, P, MAX_SERVICES> {
    async fn send_att_data(&self, data: Att<'_>) -> Result<(), BleHostError<T::Error>> {
        let header = L2capHeader {
            channel: crate::types::l2cap::L2CAP_CID_ATT,
            length: data.size() as u16,
        };

        let mut buf = P::allocate().ok_or(Error::OutOfMemory)?;
        let mut w = WriteCursor::new(buf.as_mut());
        w.write_hci(&header)?;
        w.write(data)?;
        let len = w.len();

        self.connection.send(Pdu::new(buf, len)).await;
        Ok(())
    }
}

impl<'reference, C: Controller, P: PacketPool, const MAX_SERVICES: usize> GattClient<'reference, C, P, MAX_SERVICES> {
    /// Creates a GATT client capable of processing the GATT protocol using the provided table of attributes.
    pub async fn new(
        stack: &'reference Stack<'reference, C, P>,
        connection: &Connection<'reference, P>,
    ) -> Result<GattClient<'reference, C, P, MAX_SERVICES>, BleHostError<C::Error>> {
        let l2cap = L2capHeader { channel: 4, length: 3 };
        let mut buf = P::allocate().ok_or(Error::OutOfMemory)?;
        let mut w = WriteCursor::new(buf.as_mut());
        w.write_hci(&l2cap)?;
        w.write(att::Att::Client(att::AttClient::Request(att::AttReq::ExchangeMtu {
            mtu: P::MTU as u16 - 4,
        })))?;

        let len = w.len();
        connection.send(Pdu::new(buf, len)).await;
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

            let response = self.request(data).await?;
            let res = Self::response(response.pdu.as_ref())?;
            match res {
                AttRsp::Error { request, handle, code } => {
                    if code == att::AttErrorCode::ATTRIBUTE_NOT_FOUND {
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
                    return Err(Error::UnexpectedGattResponse.into());
                }
            }
        }

        Ok(result)
    }

    /// Discover characteristics in a given service using a UUID.
    pub async fn characteristic_by_uuid<T: AsGatt>(
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
            let response = self.request(data).await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::ReadByType { mut it } => {
                    while let Some(Ok((handle, item))) = it.next() {
                        let expected_items_len = 5;
                        let item_len = item.len();

                        if item_len < expected_items_len {
                            return Err(Error::MalformedCharacteristicDeclaration {
                                expected: expected_items_len,
                                actual: item_len,
                            }
                            .into());
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
                            return Err(Error::InvalidCharacteristicDeclarationData.into());
                        }
                    }
                }
                AttRsp::Error { request, handle, code } => return Err(Error::Att(code).into()),
                _ => {
                    return Err(Error::UnexpectedGattResponse.into());
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

        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::ReadByType { mut it } => {
                if let Some(Ok((handle, item))) = it.next() {
                    // As defined in the bluetooth spec [3.3.3.3. Client Characteristic Configuration](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/generic-attribute-profile--gatt-.html#UUID-09487be3-178b-eeca-f49f-f783e8d462f6)
                    // "The Client Characteristic Configuration declaration is an optional characteristic descriptor" and
                    // "The default value for the Client Characteristic Configuration descriptor value shall be 0x0000."
                    if item.is_empty() {
                        Ok((handle, CCCD(0)))
                    } else {
                        Ok((
                            handle,
                            CCCD(u16::from_le_bytes(
                                item.try_into()
                                    .map_err(|_| Error::InvalidCccdHandleLength(item.len()))?,
                            )),
                        ))
                    }
                } else {
                    Err(Error::NotFound.into())
                }
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Read a characteristic described by a handle.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic<T: AsGatt>(
        &self,
        characteristic: &Characteristic<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        let data = att::AttReq::Read {
            handle: characteristic.handle,
        };

        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Read { data } => {
                let to_copy = data.len().min(dest.len());
                dest[..to_copy].copy_from_slice(&data[..to_copy]);
                Ok(to_copy)
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
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

        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
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
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Write to a characteristic described by a handle.
    pub async fn write_characteristic<T: FromGatt>(
        &self,
        handle: &Characteristic<T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
        let data = att::AttReq::Write {
            handle: handle.handle,
            data: buf,
        };

        let response = self.request(data).await?;
        match Self::response(response.pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Write without waiting for a response to a characteristic described by a handle.
    pub async fn write_characteristic_without_response<T: FromGatt>(
        &self,
        handle: &Characteristic<T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
        let data = att::AttCmd::Write {
            handle: handle.handle,
            data: buf,
        };

        self.command(data).await?;

        Ok(())
    }

    /// Subscribe to indication/notification of a given Characteristic
    ///
    /// A listener is returned, which has a `next()` method
    pub async fn subscribe<T: AsGatt>(
        &self,
        characteristic: &Characteristic<T>,
        indication: bool,
    ) -> Result<NotificationListener<'_, 512>, BleHostError<C::Error>> {
        let properties = u16::to_le_bytes(if indication { 0x02 } else { 0x01 });

        let data = att::AttReq::Write {
            handle: characteristic.cccd_handle.ok_or(Error::NotSupported)?,
            data: &properties,
        };

        // set the CCCD
        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Write => match self.notifications.dyn_subscriber() {
                Ok(listener) => Ok(NotificationListener {
                    listener,
                    handle: characteristic.handle,
                }),
                Err(embassy_sync::pubsub::Error::MaximumSubscribersReached) => {
                    Err(Error::GattSubscriberLimitReached.into())
                }
                Err(_) => Err(Error::Other.into()),
            },
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Unsubscribe from a given Characteristic
    pub async fn unsubscribe<T: AsGatt>(
        &self,
        characteristic: &Characteristic<T>,
    ) -> Result<(), BleHostError<C::Error>> {
        let properties = u16::to_le_bytes(0);
        let data = att::AttReq::Write {
            handle: characteristic.cccd_handle.ok_or(Error::NotSupported)?,
            data: &[0, 0],
        };

        // set the CCCD
        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Handle a notification that was received.
    async fn handle_notification_packet(&self, data: &[u8]) -> Result<(), BleHostError<C::Error>> {
        let mut r = ReadCursor::new(data);
        let value_handle: u16 = r.read()?;
        let value_attr = r.remaining();

        let handle = value_handle;

        // TODO
        let mut data = [0u8; 512];
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
            if pdu.as_ref()[0] == ATT_HANDLE_VALUE_NTF {
                self.handle_notification_packet(&pdu.as_ref()[1..]).await?;
            } else {
                self.response_channel.send((handle, pdu)).await;
            }
        }
    }

    fn response<'a>(data: &'a [u8]) -> Result<AttRsp<'a>, BleHostError<C::Error>> {
        let att = Att::decode(data)?;
        match att {
            Att::Server(AttServer::Response(rsp)) => Ok(rsp),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }
}
