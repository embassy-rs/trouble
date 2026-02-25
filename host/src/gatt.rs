//! GATT server and client implementation.
use core::cell::RefCell;
use core::future::Future;
use core::marker::PhantomData;

use bt_hci::controller::Controller;
use bt_hci::param::{ConnHandle, FrameSpaceInitiator, PhyKind, PhyMask, SpacingTypes, Status};
use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::pubsub::{self, PubSubChannel, WaitResult};
use embassy_time::Duration;
use heapless::Vec;

use crate::att::{
    self, Att, AttCfm, AttClient, AttCmd, AttErrorCode, AttReq, AttRsp, AttServer, AttUns, ATT_HANDLE_VALUE_IND,
    ATT_HANDLE_VALUE_NTF,
};
use crate::attribute::{AttributeData, Characteristic, Uuid};
use crate::attribute_server::{AttributeServer, DynamicAttributeServer};
use crate::connection::Connection;
#[cfg(feature = "security")]
use crate::connection::SecurityLevel;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::pdu::Pdu;
use crate::prelude::{ConnectionEvent, ConnectionParamsRequest};
#[cfg(feature = "security")]
use crate::security_manager::PassKey;
use crate::types::gatt_traits::{AsGatt, FromGatt, FromGattError};
use crate::types::l2cap::L2capHeader;
#[cfg(feature = "security")]
use crate::BondInformation;
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
    /// A request to change the connection parameters.
    ///
    /// [`ConnectionParamsRequest::accept()`] or [`ConnectionParamsRequest::reject()`]
    /// must be called to respond to the request.
    RequestConnectionParams(ConnectionParamsRequest),
    /// The data length was changed for this connection.
    DataLengthUpdated {
        /// Max TX octets.
        max_tx_octets: u16,
        /// Max TX time.
        max_tx_time: u16,
        /// Max RX octets.
        max_rx_octets: u16,
        /// Max RX time.
        max_rx_time: u16,
    },
    /// The frame space was updated for this connection.
    FrameSpaceUpdated {
        /// The negotiated frame space value.
        frame_space: Duration,
        /// Who initiated the frame space update.
        initiator: FrameSpaceInitiator,
        /// PHYs affected.
        phys: PhyMask,
        /// Spacing types affected.
        spacing_types: SpacingTypes,
    },
    /// Connection rate has been changed.
    ConnectionRateChanged {
        /// Connection interval.
        conn_interval: Duration,
        /// Subrate factor.
        subrate_factor: u16,
        /// Peripheral latency.
        peripheral_latency: u16,
        /// Continuation number.
        continuation_number: u16,
        /// Supervision timeout.
        supervision_timeout: Duration,
    },
    /// GATT event.
    Gatt {
        /// The event that was returned
        event: GattEvent<'stack, 'server, P>,
    },

    #[cfg(feature = "security")]
    /// Display pass key
    PassKeyDisplay(PassKey),
    #[cfg(feature = "security")]
    /// Confirm pass key
    PassKeyConfirm(PassKey),
    #[cfg(feature = "security")]
    /// Input the pass key
    PassKeyInput,
    #[cfg(feature = "security")]
    /// Pairing completed
    PairingComplete {
        /// Security level of this pairing
        security_level: SecurityLevel,
        /// Bond information if the devices create a bond with this pairing.
        bond: Option<BondInformation>,
    },
    #[cfg(feature = "security")]
    /// Pairing failed
    PairingFailed(Error),
    #[cfg(feature = "security")]
    /// The peer has lost its bond.
    BondLost,
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

    /// Confirm that the displayed pass key matches the one displayed on the other party
    pub fn pass_key_confirm(&self) -> Result<(), Error> {
        self.connection.pass_key_confirm()
    }

    /// The displayed pass key does not match the one displayed on the other party
    pub fn pass_key_cancel(&self) -> Result<(), Error> {
        self.connection.pass_key_cancel()
    }

    /// Input the pairing pass key
    pub fn pass_key_input(&self, pass_key: u32) -> Result<(), Error> {
        self.connection.pass_key_input(pass_key)
    }

    /// Wait for the next GATT connection event.
    ///
    /// Uses the attribute server to handle the protocol.
    pub async fn next(&self) -> GattConnectionEvent<'stack, 'server, P> {
        match select(self.connection.next(), self.connection.next_gatt()).await {
            Either::First(event) => match event {
                ConnectionEvent::Disconnected { reason } => GattConnectionEvent::Disconnected { reason },
                ConnectionEvent::ConnectionParamsUpdated {
                    conn_interval,
                    peripheral_latency,
                    supervision_timeout,
                } => GattConnectionEvent::ConnectionParamsUpdated {
                    conn_interval,
                    peripheral_latency,
                    supervision_timeout,
                },
                ConnectionEvent::RequestConnectionParams(req) => GattConnectionEvent::RequestConnectionParams(req),
                ConnectionEvent::PhyUpdated { tx_phy, rx_phy } => GattConnectionEvent::PhyUpdated { tx_phy, rx_phy },
                ConnectionEvent::DataLengthUpdated {
                    max_tx_octets,
                    max_tx_time,
                    max_rx_octets,
                    max_rx_time,
                } => GattConnectionEvent::DataLengthUpdated {
                    max_tx_octets,
                    max_tx_time,
                    max_rx_octets,
                    max_rx_time,
                },
                ConnectionEvent::FrameSpaceUpdated {
                    frame_space,
                    initiator,
                    phys,
                    spacing_types,
                } => GattConnectionEvent::FrameSpaceUpdated {
                    frame_space,
                    initiator,
                    phys,
                    spacing_types,
                },
                ConnectionEvent::ConnectionRateChanged {
                    conn_interval,
                    subrate_factor,
                    peripheral_latency,
                    continuation_number,
                    supervision_timeout,
                } => GattConnectionEvent::ConnectionRateChanged {
                    conn_interval,
                    subrate_factor,
                    peripheral_latency,
                    continuation_number,
                    supervision_timeout,
                },

                #[cfg(feature = "security")]
                ConnectionEvent::PassKeyDisplay(key) => GattConnectionEvent::PassKeyDisplay(key),

                #[cfg(feature = "security")]
                ConnectionEvent::PassKeyConfirm(key) => GattConnectionEvent::PassKeyConfirm(key),

                #[cfg(feature = "security")]
                ConnectionEvent::PassKeyInput => GattConnectionEvent::PassKeyInput,

                #[cfg(feature = "security")]
                ConnectionEvent::PairingComplete { security_level, bond } => {
                    GattConnectionEvent::PairingComplete { security_level, bond }
                }

                #[cfg(feature = "security")]
                ConnectionEvent::PairingFailed(err) => GattConnectionEvent::PairingFailed(err),

                #[cfg(feature = "security")]
                ConnectionEvent::BondLost => GattConnectionEvent::BondLost,
            },
            Either::Second(data) => GattConnectionEvent::Gatt {
                event: GattEvent::new(GattData::new(data, self.connection.clone()), self.server),
            },
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
    pub(crate) const fn new(pdu: Pdu<P::Packet>, connection: Connection<'stack, P>) -> Self {
        Self {
            pdu: Some(pdu),
            connection,
        }
    }

    /// Return the characteristic handle that this GATT request is related to, if applicable.
    ///
    /// Returns `None` if the request is not related to a characteristic handle (e.g. a service discovery request).
    pub fn handle(&self) -> Option<u16> {
        match self.incoming() {
            AttClient::Request(AttReq::Write { handle, .. }) => Some(handle),
            AttClient::Command(AttCmd::Write { handle, .. }) => Some(handle),
            AttClient::Request(AttReq::Read { handle }) => Some(handle),
            AttClient::Request(AttReq::ReadBlob { handle, .. }) => Some(handle),
            _ => None,
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
        let pdu = assemble(&self.connection, AttServer::Response(rsp))?;
        self.connection.send(pdu).await;
        Ok(())
    }

    /// Send an unsolicited ATT PDU without having a request (e.g. notification or indication)
    pub async fn send_unsolicited(connection: &Connection<'_, P>, uns: AttUns<'_>) -> Result<(), Error> {
        let pdu = assemble(connection, AttServer::Unsolicited(uns))?;
        connection.send(pdu).await;
        Ok(())
    }
}

/// An event returned while processing GATT requests.
pub enum GattEvent<'stack, 'server, P: PacketPool> {
    /// A characteristic was read.
    Read(ReadEvent<'stack, 'server, P>),
    /// A characteristic was written.
    Write(WriteEvent<'stack, 'server, P>),
    /// Other event.
    Other(OtherEvent<'stack, 'server, P>),
    /// A request was made that was not allowed by the permissions of the attribute.
    NotAllowed(NotAllowedEvent<'stack, 'server, P>),
}

impl<'stack, 'server, P: PacketPool> GattEvent<'stack, 'server, P> {
    /// Create a new GATT event from the provided `GattData` and `DynamicAttributeServer`.
    pub fn new(data: GattData<'stack, P>, server: &'server dyn DynamicAttributeServer<P>) -> Self {
        let att = data.incoming();

        let allowed = match &att {
            AttClient::Command(AttCmd::Write { handle, .. }) => server.can_write(&data.connection, *handle),
            AttClient::Request(req) => match req {
                AttReq::Write { handle, .. } | AttReq::PrepareWrite { handle, .. } => {
                    server.can_write(&data.connection, *handle)
                }
                AttReq::Read { handle } | AttReq::ReadBlob { handle, .. } => server.can_read(&data.connection, *handle),
                AttReq::ReadMultiple { handles } => handles.chunks_exact(2).try_for_each(|handle| {
                    server.can_read(&data.connection, u16::from_le_bytes(handle.try_into().unwrap()))
                }),
                _ => Ok(()),
            },
            _ => Ok(()),
        };

        if let Err(err) = allowed {
            return GattEvent::NotAllowed(NotAllowedEvent { data, err, server });
        }

        match att {
            AttClient::Request(AttReq::Write { .. }) | AttClient::Command(AttCmd::Write { .. }) => {
                GattEvent::Write(WriteEvent { data, server })
            }
            AttClient::Request(AttReq::Read { .. }) | AttClient::Request(AttReq::ReadBlob { .. }) => {
                GattEvent::Read(ReadEvent { data, server })
            }
            _ => GattEvent::Other(OtherEvent { data, server }),
        }
    }

    /// Accept the event, making it processed by the server.
    pub fn accept(self) -> Result<Reply<'stack, P>, Error> {
        match self {
            Self::Read(e) => e.accept(),
            Self::Write(e) => e.accept(),
            Self::Other(e) => e.accept(),
            Self::NotAllowed(e) => e.accept(),
        }
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        match self {
            Self::Read(e) => e.reject(err),
            Self::Write(e) => e.reject(err),
            Self::Other(e) => e.reject(err),
            Self::NotAllowed(e) => e.reject(err),
        }
    }

    /// Get a reference to the underlying `GattData` payload that this event is enclosing
    pub fn payload(&self) -> &GattData<'stack, P> {
        match self {
            Self::Read(e) => e.payload(),
            Self::Write(e) => e.payload(),
            Self::Other(e) => e.payload(),
            Self::NotAllowed(e) => e.payload(),
        }
    }

    /// Convert the event back into the `GattData` payload it is enclosing
    ///
    /// Allows for custom processing of the enclosed data, as in handling payloads
    /// which are not supported yet by the enclosed attribute server.
    /// Note that this will consume the event, so it would be up to the caller to respond
    /// to the incoming payload if needed and however they see fit.
    pub fn into_payload(self) -> GattData<'stack, P> {
        match self {
            Self::Read(e) => e.into_payload(),
            Self::Write(e) => e.into_payload(),
            Self::Other(e) => e.into_payload(),
            Self::NotAllowed(e) => e.into_payload(),
        }
    }
}

/// A characteristic read event returned while processing GATT requests.
pub struct ReadEvent<'stack, 'server, P: PacketPool> {
    data: GattData<'stack, P>,
    server: &'server dyn DynamicAttributeServer<P>,
}

impl<'stack, P: PacketPool> ReadEvent<'stack, '_, P> {
    /// Characteristic handle that was read
    pub fn handle(&self) -> u16 {
        // We know that the unwrap cannot fail, because `ReadEvent` wraps
        // ATT payloads that always do have a handle
        unwrap!(self.data.handle())
    }

    /// Accept the event, making it processed by the server.
    ///
    /// Automatically called if drop() is invoked.
    pub fn accept(mut self) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Ok(()))
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(mut self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Err(err))
    }

    /// Get a reference to the underlying `GattData` payload that this event is enclosing
    pub fn payload(&self) -> &GattData<'stack, P> {
        &self.data
    }

    /// Convert the event back into the `GattData` payload it is enclosing
    ///
    /// Allows for custom processing of the enclosed data, as in handling payloads
    /// which are not supported yet by the enclosed attribute server.
    /// Note that this will consume the event, so it would be up to the caller to respond
    /// to the incoming payload if needed and however they see fit.
    pub fn into_payload(mut self) -> GattData<'stack, P> {
        GattData {
            pdu: self.data.pdu.take(),
            connection: self.data.connection.clone(),
        }
    }
}

impl<P: PacketPool> Drop for ReadEvent<'_, '_, P> {
    fn drop(&mut self) {
        let _ = process(&mut self.data, self.server, Ok(()));
    }
}

/// A characteristic write event returned while processing GATT requests.
pub struct WriteEvent<'stack, 'server, P: PacketPool> {
    data: GattData<'stack, P>,
    server: &'server dyn DynamicAttributeServer<P>,
}

impl<'stack, P: PacketPool> WriteEvent<'stack, '_, P> {
    /// Characteristic handle that was written
    pub fn handle(&self) -> u16 {
        // We know that the unwrap cannot fail, because `ReadEvent` wraps
        // ATT payloads that always do have a handle
        unwrap!(self.data.handle())
    }

    /// Raw data to be written
    pub fn data(&self) -> &[u8] {
        // Note: write event data is always at offset 3, right?
        &self.data.pdu.as_ref().unwrap().as_ref()[3..]
    }

    /// Characteristic data to be written
    pub fn value<T: FromGatt>(&self, _c: &Characteristic<T>) -> Result<T, FromGattError> {
        T::from_gatt(self.data())
    }

    /// Accept the event, making it processed by the server.
    ///
    /// Automatically called if drop() is invoked.
    pub fn accept(mut self) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Ok(()))
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(mut self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Err(err))
    }

    /// Get a reference to the underlying `GattData` payload that this event is enclosing
    pub fn payload(&self) -> &GattData<'stack, P> {
        &self.data
    }

    /// Convert the event back into the `GattData` payload it is enclosing
    ///
    /// Allows for custom processing of the enclosed data, as in handling payloads
    /// which are not supported yet by the enclosed attribute server.
    /// Note that this will consume the event, so it would be up to the caller to respond
    /// to the incoming payload if needed and however they see fit.
    pub fn into_payload(mut self) -> GattData<'stack, P> {
        GattData {
            pdu: self.data.pdu.take(),
            connection: self.data.connection.clone(),
        }
    }
}

impl<P: PacketPool> Drop for WriteEvent<'_, '_, P> {
    fn drop(&mut self) {
        let _ = process(&mut self.data, self.server, Ok(()));
    }
}

/// Other event returned while processing GATT requests (neither read, nor write).
pub struct OtherEvent<'stack, 'server, P: PacketPool> {
    data: GattData<'stack, P>,
    server: &'server dyn DynamicAttributeServer<P>,
}

impl<'stack, P: PacketPool> OtherEvent<'stack, '_, P> {
    /// Accept the event, making it processed by the server.
    ///
    /// Automatically called if drop() is invoked.
    pub fn accept(mut self) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Ok(()))
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(mut self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Err(err))
    }

    /// Get a reference to the underlying `GattData` payload that this event is enclosing
    pub fn payload(&self) -> &GattData<'stack, P> {
        &self.data
    }

    /// Convert the event back into the `GattData` payload it is enclosing
    ///
    /// Allows for custom processing of the enclosed data, as in handling payloads
    /// which are not supported yet by the enclosed attribute server.
    /// Note that this will consume the event, so it would be up to the caller to respond
    /// to the incoming payload if needed and however they see fit.
    pub fn into_payload(mut self) -> GattData<'stack, P> {
        GattData {
            pdu: self.data.pdu.take(),
            connection: self.data.connection.clone(),
        }
    }
}

impl<P: PacketPool> Drop for OtherEvent<'_, '_, P> {
    fn drop(&mut self) {
        let _ = process(&mut self.data, self.server, Ok(()));
    }
}

/// Other event returned while processing GATT requests (neither read, nor write).
pub struct NotAllowedEvent<'stack, 'server, P: PacketPool> {
    data: GattData<'stack, P>,
    err: AttErrorCode,
    server: &'server dyn DynamicAttributeServer<P>,
}

impl<'stack, P: PacketPool> NotAllowedEvent<'stack, '_, P> {
    /// Characteristic handle that was requested
    pub fn handle(&self) -> u16 {
        // We know that the unwrap cannot fail, because `NotAllowedEvent` wraps
        // ATT payloads that always do have a handle
        unwrap!(self.data.handle())
    }

    /// Accept the event, making it processed by the server.
    ///
    /// Automatically called if drop() is invoked.
    pub fn accept(mut self) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Err(self.err))
    }

    /// Reject the event with the provided error code, it will not be processed by the attribute server.
    pub fn reject(mut self, err: AttErrorCode) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Err(err))
    }

    /// Get a reference to the underlying `GattData` payload that this event is enclosing
    pub fn payload(&self) -> &GattData<'stack, P> {
        &self.data
    }

    /// Convert the event back into the `GattData` payload it is enclosing
    ///
    /// Allows for custom processing of the enclosed data, as in handling payloads
    /// which are not supported yet by the enclosed attribute server.
    /// Note that this will consume the event, so it would be up to the caller to respond
    /// to the incoming payload if needed and however they see fit.
    pub fn into_payload(mut self) -> GattData<'stack, P> {
        GattData {
            pdu: self.data.pdu.take(),
            connection: self.data.connection.clone(),
        }
    }
}

impl<P: PacketPool> Drop for NotAllowedEvent<'_, '_, P> {
    fn drop(&mut self) {
        let _ = process(&mut self.data, self.server, Err(self.err));
    }
}

fn process<'stack, P>(
    data: &mut GattData<'stack, P>,
    server: &dyn DynamicAttributeServer<P>,
    result: Result<(), AttErrorCode>,
) -> Result<Reply<'stack, P>, Error>
where
    P: PacketPool,
{
    if let Some(pdu) = data.pdu.take() {
        let res = match result {
            Ok(_) => process_accept(&pdu, &data.connection, server),
            Err(code) => process_reject(&pdu, &data.connection, code),
        };
        res
    } else {
        Ok(Reply::new(data.connection.clone(), None))
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
    // Limit the buffer given to process() so that multi-entry ATT responses
    // (ReadByType, ReadByGroupType, FindInformation) are bounded by the
    // negotiated ATT MTU. Without this, entries are written into the full
    // packet-pool buffer and then post-hoc truncated, which can split an
    // entry in half and produce a malformed PDU.
    let mtu = connection.get_att_mtu() as usize;
    let written = {
        let buf = data.write_buf();
        let limit = buf.len().min(mtu);
        server.process(connection, &att, &mut buf[..limit])?
    };
    if let Some(written) = written {
        data.commit(written)?;
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
    connection: &Connection<'stack, P>,
    code: AttErrorCode,
) -> Result<Reply<'stack, P>, Error> {
    // - The PDU is decodable, as it was already decoded once before adding it to the connection queue
    // - The PDU is of type `Att::Client` because only those types of PDUs are added to the connection queue
    let att = unwrap!(Att::decode(pdu.as_ref()));
    let Att::Client(att) = att else {
        unreachable!("Expected Att::Client, got {:?}", att)
    };
    let handle = match att {
        AttClient::Request(AttReq::Write { handle, .. }) => handle,
        AttClient::Command(AttCmd::Write { handle, .. }) => handle,
        AttClient::Request(AttReq::Read { handle }) => handle,
        AttClient::Request(AttReq::ReadBlob { handle, .. }) => handle,
        _ => 0, // As per spec, if the incoming ATT does not have an ATT handle, we should report with handle 0
    };
    // We know it has been checked, therefore this cannot fail
    let request = pdu.as_ref()[0];
    let rsp = AttRsp::Error { request, handle, code };
    let pdu = assemble(connection, AttServer::Response(rsp))?;
    Ok(Reply::new(connection.clone(), Some(pdu)))
}

pub(crate) fn assemble<'stack, P: PacketPool>(
    conn: &Connection<'stack, P>,
    att: AttServer<'_>,
) -> Result<Pdu<P::Packet>, Error> {
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

#[cfg(test)]
impl<'stack, P: PacketPool> Reply<'stack, P> {
    /// Extract the ATT payload from the response PDU (skipping 4-byte L2CAP header).
    /// Returns None if the reply carried no PDU.
    fn att_payload(&self) -> Option<&[u8]> {
        self.pdu.as_ref().map(|pdu| &pdu.as_ref()[4..])
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ServiceHandle {
    start: u16,
    end: u16,
    uuid: Uuid,
}

impl ServiceHandle {
    /// Get the attribute handles that belong to this service
    pub fn handle_range(&self) -> core::ops::RangeInclusive<u16> {
        self.start..=self.end
    }

    /// Get the UUID of this service
    pub fn uuid(&self) -> Uuid {
        self.uuid.clone()
    }
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

        // Await MTU exchange completion (BT Core Spec requires sequential ATT requests)
        loop {
            let pdu = connection.next_gatt_client().await;
            match pdu.as_ref()[0] {
                att::ATT_EXCHANGE_MTU_RSP | att::ATT_ERROR_RSP => break,
                _ => {
                    warn!("[gatt] unexpected PDU during MTU exchange, discarding");
                }
            }
        }

        // Enable encryption with bonded peers before starting GATT operations
        // (BT Core Spec Vol 3, Part C, Section 10.3.2: client "should" enable encryption on reconnection)
        #[cfg(feature = "security")]
        if connection.is_bonded_peer() {
            match connection.try_enable_encryption().await {
                Ok(_) => {}
                Err(Error::Disconnected) => return Err(Error::Disconnected.into()),
                Err(e) => {
                    warn!("[gatt] failed to enable encryption for bonded peer: {:?}", e);
                }
            }
        }

        Ok(Self {
            known_services: RefCell::new(heapless::Vec::new()),
            stack,
            connection: connection.clone(),

            response_channel: Channel::new(),

            notifications: PubSubChannel::new(),
        })
    }

    /// Discover primary services associated with a UUID.
    pub async fn services(&self) -> Result<Vec<ServiceHandle, MAX_SERVICES>, BleHostError<C::Error>> {
        let mut start: u16 = 0x0001;
        let mut result = Vec::new();

        loop {
            let data = att::AttReq::ReadByGroupType {
                start,
                end: u16::MAX,
                group_type: PRIMARY_SERVICE.into(),
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
                AttRsp::ReadByGroupType { mut it } => {
                    let mut end: u16 = 0;
                    while let Some(res) = it.next() {
                        let (handle, data) = res?;

                        let mut r = ReadCursor::new(data);
                        end = r.read()?;
                        let uuid = Uuid::try_from(r.remaining())?;

                        let svc = ServiceHandle {
                            start: handle,
                            end,
                            uuid,
                        };

                        result.push(svc.clone()).map_err(|_| Error::InsufficientSpace)?;
                        let mut known = self.known_services.borrow_mut();
                        if !known.contains(&svc) {
                            known.push(svc).map_err(|_| Error::InsufficientSpace)?;
                        }
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
                        let mut known = self.known_services.borrow_mut();
                        if !known.contains(&svc) {
                            known.push(svc).map_err(|_| Error::InsufficientSpace)?;
                        }
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

    /// Discover all characteristics in a given service
    pub async fn characteristics<const N: usize>(
        &self,
        service: &ServiceHandle,
    ) -> Result<Vec<Characteristic<[u8]>, N>, BleHostError<C::Error>> {
        let mut start: u16 = service.start;
        let mut characteristics = Vec::new();

        loop {
            let data = att::AttReq::ReadByType {
                start,
                end: service.end,
                attribute_type: CHARACTERISTIC.into(),
            };
            let response = self.request(data).await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::ReadByType { mut it } => {
                    while let Some(res) = it.next() {
                        let (declaration_handle, item) = res?;
                        if declaration_handle == 0xffff {
                            return Err(Error::Att(AttErrorCode::INVALID_HANDLE).into());
                        }

                        let expected_items_len = 5;
                        let item_len = item.len();

                        if item_len < expected_items_len {
                            return Err(Error::MalformedCharacteristicDeclaration {
                                expected: expected_items_len,
                                actual: item_len,
                            }
                            .into());
                        }

                        let AttributeData::Declaration {
                            props,
                            handle,
                            uuid: decl_uuid,
                        } = AttributeData::decode_declaration(item)?
                        else {
                            unreachable!()
                        };

                        characteristics
                            .push(Characteristic {
                                handle,
                                props,
                                cccd_handle: None,
                                phantom: PhantomData,
                            })
                            .map_err(|_| Error::InsufficientSpace)?;

                        start = declaration_handle + 1;
                    }
                }
                AttRsp::Error { request, handle, code } => match code {
                    att::AttErrorCode::ATTRIBUTE_NOT_FOUND => break,
                    _ => return Err(Error::Att(code).into()),
                },
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }

        let mut iter = characteristics.iter_mut().peekable();
        while let Some(characteristic) = iter.next() {
            if characteristic.props.has_cccd() {
                let end = iter.peek().map(|x| x.handle - 2).unwrap_or(service.end);
                characteristic.cccd_handle = match self.get_characteristic_cccd(characteristic.handle + 1, end).await {
                    Ok(handle) => Some(handle),
                    Err(BleHostError::BleHost(Error::NotFound)) => None,
                    Err(err) => return Err(err),
                };
            }
        }

        Ok(characteristics)
    }

    /// Discover characteristics in a given service using a UUID.
    pub async fn characteristic_by_uuid<T: AsGatt + ?Sized>(
        &self,
        service: &ServiceHandle,
        uuid: &Uuid,
    ) -> Result<Characteristic<T>, BleHostError<C::Error>> {
        let mut start: u16 = service.start;
        let mut found_indicate_or_notify_uuid = Option::None;

        loop {
            let data = att::AttReq::ReadByType {
                start,
                end: service.end,
                attribute_type: CHARACTERISTIC.into(),
            };
            let response = self.request(data).await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::ReadByType { mut it } => {
                    while let Some(res) = it.next() {
                        let (handle, item) = res?;
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
                            if let Some((start_handle, _)) = found_indicate_or_notify_uuid {
                                return Ok(Characteristic {
                                    handle: start_handle,
                                    cccd_handle: Some(self.get_characteristic_cccd(start_handle, handle).await?),
                                    props,
                                    phantom: PhantomData,
                                });
                            }

                            if *uuid == decl_uuid {
                                // If there are "notify" and "indicate" characteristic properties we need to find the
                                // next characteristic so we can determine the search space for the CCCD
                                if !props.has_cccd() {
                                    return Ok(Characteristic {
                                        handle,
                                        cccd_handle: None,
                                        props,
                                        phantom: PhantomData,
                                    });
                                }
                                found_indicate_or_notify_uuid = Some((handle, props));
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
                AttRsp::Error { request, handle, code } => match code {
                    att::AttErrorCode::ATTRIBUTE_NOT_FOUND => match found_indicate_or_notify_uuid {
                        Some((handle, props)) => {
                            return Ok(Characteristic {
                                handle,
                                cccd_handle: Some(self.get_characteristic_cccd(handle, service.end).await?),
                                props,
                                phantom: PhantomData,
                            });
                        }
                        None => return Err(Error::NotFound.into()),
                    },
                    _ => return Err(Error::Att(code).into()),
                },
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }
    }

    async fn get_characteristic_cccd(
        &self,
        char_start_handle: u16,
        char_end_handle: u16,
    ) -> Result<u16, BleHostError<C::Error>> {
        let mut start_handle = char_start_handle;

        while start_handle <= char_end_handle {
            let data = att::AttReq::FindInformation {
                start_handle,
                end_handle: char_end_handle,
            };

            let response = self.request(data).await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::FindInformation { mut it } => {
                    while let Some(Ok((handle, uuid))) = it.next() {
                        if uuid == CLIENT_CHARACTERISTIC_CONFIGURATION.into() {
                            return Ok(handle);
                        }
                        start_handle = handle + 1;
                    }
                }
                AttRsp::Error { request, handle, code } => return Err(Error::Att(code).into()),
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }
        Err(Error::NotFound.into())
    }

    /// Read a characteristic described by a handle.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic<T: AsGatt + ?Sized>(
        &self,
        characteristic: &Characteristic<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        let response = self
            .request(att::AttReq::Read {
                handle: characteristic.handle,
            })
            .await?;

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

    /// Read a long characteristic value using blob reads if necessary.
    ///
    /// This method automatically handles characteristics longer than ATT MTU
    /// by using Read Blob requests to fetch the complete value.
    pub async fn read_characteristic_long<T: AsGatt + ?Sized>(
        &self,
        characteristic: &Characteristic<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        // first read, use regular read
        let first_read_len = self.read_characteristic(characteristic, dest).await?;
        let att_mtu = self.connection.att_mtu() as usize;

        if first_read_len != att_mtu - 1 {
            // att_mtu-1 indicates there's more to read
            return Ok(first_read_len);
        }

        // Try at least one blob read to see if there's more data
        let mut offset = first_read_len;
        loop {
            let response = self
                .request(att::AttReq::ReadBlob {
                    handle: characteristic.handle,
                    offset: offset as u16,
                })
                .await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::ReadBlob { data } => {
                    debug!("[read_characteristic_long] Blob read returned {} bytes", data.len());
                    if data.is_empty() {
                        break; // End of attribute
                    }

                    let blob_read_len = data.len();

                    // need to limit length to copy b/c copy_from_slice panics if
                    // the slices' lengths don't match, and `dest` might be too small.
                    let len_to_copy = blob_read_len.min(dest.len() - offset);
                    dest[offset..offset + len_to_copy].copy_from_slice(&data[..len_to_copy]);
                    offset += len_to_copy;

                    // If we got less than MTU-1 bytes, we've read everything
                    // Or if we've filled the destination buffer
                    if blob_read_len < att_mtu - 1 || len_to_copy < blob_read_len {
                        break;
                    }
                }
                AttRsp::Error { code, .. } if code == att::AttErrorCode::INVALID_OFFSET => {
                    trace!("[read_characteristic_long] Got INVALID_OFFSET, no more data");
                    break; // Reached end
                }
                AttRsp::Error { code, .. } if code == att::AttErrorCode::ATTRIBUTE_NOT_LONG => {
                    trace!("[read_characteristic_long] read_handle_long] Attribute not long, no blob reads needed");
                    break; // Attribute fits in single read
                }
                AttRsp::Error { code, .. } => {
                    trace!("[read_characteristic] Got error: {:?}", code);
                    return Err(Error::Att(code).into());
                }
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }
        Ok(offset)
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
    pub async fn write_characteristic<T: AsGatt + ?Sized>(
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
    pub async fn write_characteristic_without_response<T: AsGatt + ?Sized>(
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
    pub async fn subscribe<T: AsGatt + ?Sized>(
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
    pub async fn unsubscribe<T: AsGatt + ?Sized>(
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

    /// Confirm an indication that was received.
    pub async fn confirm_indication(&self) -> Result<(), BleHostError<C::Error>> {
        self.send_att_data(Att::Client(AttClient::Confirmation(AttCfm::ConfirmIndication)))
            .await
    }

    /// Handle a notification that was received.
    async fn handle_notification_packet(&self, data: &[u8]) -> Result<(), BleHostError<C::Error>> {
        let mut r = ReadCursor::new(data);
        let value_handle: u16 = r.read()?;
        let value_attr = r.remaining();

        let handle = value_handle;

        // TODO: Wait for something like https://github.com/rust-lang/rust/issues/132980 (min_generic_const_args) to allow using P::MTU
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
            let handle = self.connection.handle();
            let pdu = self.connection.next_gatt_client().await;
            let data = pdu.as_ref();
            // handle notifications
            if matches!(pdu.as_ref()[0], ATT_HANDLE_VALUE_IND | ATT_HANDLE_VALUE_NTF) {
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

#[cfg(test)]
mod tests {
    extern crate std;

    use core::task::Poll;

    use bt_hci::param::{AddrKind, BdAddr, ConnHandle, LeConnRole};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;
    use crate::att::{self, Att, AttClient, AttReq};
    use crate::attribute::Service;
    use crate::attribute_server::AttributeServer;
    use crate::connection::ConnParams;
    use crate::connection_manager::tests::{setup, ADDR_1};
    use crate::cursor::WriteCursor;
    use crate::pdu::Pdu;
    use crate::prelude::*;

    /// Build a ReadByType ATT request PDU (ATT payload only, no L2CAP header).
    fn build_read_by_type_pdu(start: u16, end: u16, uuid: &Uuid) -> (<DefaultPacketPool as PacketPool>::Packet, usize) {
        let att = Att::Client(AttClient::Request(AttReq::ReadByType {
            start,
            end,
            attribute_type: uuid.clone(),
        }));

        let mut packet = DefaultPacketPool::allocate().unwrap();
        let mut w = WriteCursor::new(packet.as_mut());
        w.write(att).unwrap();
        let len = w.len();
        (packet, len)
    }

    /// Regression test: process_accept must not produce ReadByType responses
    /// with partial entries when the ATT MTU is smaller than the packet pool
    /// buffer.
    ///
    /// Before the fix, process_accept wrote ATT responses into the full
    /// packet-pool buffer (P::MTU - 4 = 247 bytes) and then post-hoc
    /// truncated to the negotiated ATT MTU. For 128-bit UUID characteristic
    /// declarations, each ReadByType entry is 21 bytes. When the ATT MTU
    /// doesn't align to entry boundaries, truncation splits an entry in half,
    /// producing a malformed PDU.
    ///
    /// 9 characteristics is the minimum to trigger at ATT MTU 185:
    ///   floor((185 - 2) / 21) = 8 entries fit, so 9 overflows.
    #[test]
    fn test_process_accept_read_by_type_no_partial_entries() {
        let _ = env_logger::try_init();

        const MAX_ATTRIBUTES: usize = 64;
        const CONNECTIONS_MAX: usize = 3;
        const CCCD_MAX: usize = 64;
        const NUM_CHARACTERISTICS: u8 = 9;
        const ATT_MTU: u16 = 185;

        // Each ReadByType entry for a 128-bit UUID declaration:
        //   2 (handle) + 1 (props) + 2 (value handle) + 16 (UUID) = 21 bytes
        const ENTRY_SIZE: usize = 21;
        const RESPONSE_HEADER_SIZE: usize = 2;

        // Characteristic declaration UUID (0x2803)
        let char_decl_uuid = Uuid::new_short(0x2803);

        // Create attribute table with 9 characteristics (128-bit UUIDs)
        let mut table: AttributeTable<'_, NoopRawMutex, MAX_ATTRIBUTES> = AttributeTable::new();
        {
            let mut svc = table.add_service(Service {
                uuid: Uuid::new_long([0x32; 16]),
            });
            for i in 0..NUM_CHARACTERISTICS {
                let mut uuid_bytes = [0x32u8; 16];
                uuid_bytes[0] = i;
                let _char = svc
                    .add_characteristic_ro::<[u8; 2], _>(Uuid::new_long(uuid_bytes), &[0, 0])
                    .build();
            }
        }

        let server = AttributeServer::<_, DefaultPacketPool, MAX_ATTRIBUTES, CCCD_MAX, CONNECTIONS_MAX>::new(table);

        // Set up a connection with ATT MTU = 185 (typical iOS value)
        let mgr = setup();
        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
        unwrap!(mgr.connect(
            ConnHandle::new(0),
            AddrKind::RANDOM,
            BdAddr::new(ADDR_1),
            LeConnRole::Peripheral,
            ConnParams::new(),
        ));
        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };
        conn.set_att_mtu(ATT_MTU);

        // Walk through characteristic discovery via process_accept, just as a
        // real BLE client would.
        let mut start: u16 = 1;
        let mut total_chars_found: usize = 0;

        loop {
            let (packet, len) = build_read_by_type_pdu(start, u16::MAX, &char_decl_uuid);
            let pdu = Pdu::new(packet, len);
            let reply = process_accept::<DefaultPacketPool>(&pdu, &conn, &server).unwrap();

            let att_bytes = reply
                .att_payload()
                .expect("process_accept should produce a response PDU");

            if att_bytes[0] == att::ATT_ERROR_RSP {
                break;
            }

            assert_eq!(att_bytes[0], att::ATT_READ_BY_TYPE_RSP);
            let entry_len = att_bytes[1] as usize;
            assert_eq!(entry_len, ENTRY_SIZE);

            let payload = &att_bytes[RESPONSE_HEADER_SIZE..];

            // The payload must be an exact multiple of the entry size.
            // Before the fix, this assertion failed: 183 % 21 = 15.
            assert_eq!(
                payload.len() % entry_len,
                0,
                "ReadByType payload length {} is not a multiple of entry size {} — \
                 partial entry detected (ATT MTU truncation bug)",
                payload.len(),
                entry_len,
            );

            let num_entries = payload.len() / entry_len;
            assert!(num_entries > 0);
            total_chars_found += num_entries;

            let last_entry = &payload[(num_entries - 1) * entry_len..];
            let last_handle = u16::from_le_bytes([last_entry[0], last_entry[1]]);
            start = last_handle + 1;

            // Forget the reply without trying to send (no outbound queue in test)
            core::mem::forget(reply);
        }

        assert_eq!(
            total_chars_found, NUM_CHARACTERISTICS as usize,
            "should discover all {} characteristics",
            NUM_CHARACTERISTICS,
        );
    }
}
