//! GATT server and client implementation.
use core::cell::RefCell;
use core::future::Future;
use core::marker::PhantomData;
use core::ops::ControlFlow;

use bt_hci::controller::Controller;
use bt_hci::param::{ConnHandle, FrameSpaceInitiator, PhyKind, PhyMask, SpacingTypes, Status};
use bt_hci::uuid::declarations::{CHARACTERISTIC, PRIMARY_SERVICE};
use bt_hci::uuid::descriptors::CLIENT_CHARACTERISTIC_CONFIGURATION;
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::channel::Channel;
use embassy_sync::pubsub::{self, PubSubChannel, WaitResult};
use embassy_time::{with_timeout, Duration};
use heapless::Vec;

use crate::att::{
    self, Att, AttCfm, AttClient, AttCmd, AttErrorCode, AttReq, AttRsp, AttServer, AttUns, ATT_HANDLE_VALUE_IND,
    ATT_HANDLE_VALUE_NTF,
};
use crate::attribute::{AttributeHandle, Characteristic, CharacteristicProps, Descriptor, Uuid};
use crate::attribute_server::{AttributeServer, DynamicAttributeServer};
use crate::connection::Connection;
#[cfg(feature = "security")]
use crate::connection::SecurityLevel;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::pdu::Pdu;
use crate::prelude::{CharacteristicDeclaration, ConnectionEvent, ConnectionParamsRequest};
#[cfg(feature = "security")]
use crate::security_manager::PassKey;
use crate::types::gatt_traits::{AsGatt, FromGatt, FromGattError};
use crate::types::l2cap::L2capHeader;
#[cfg(feature = "security")]
use crate::BondInformation;
use crate::{config, BleHostError, Error, PacketPool, Stack, MAX_INVALID_DATA_LEN};

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
    #[cfg(feature = "security")]
    /// OOB data is requested during pairing. Respond with [`GattConnection::provide_oob_data()`].
    OobRequest,
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
    pub(crate) fn try_new<'values, M: RawMutex, const AT: usize, const CN: usize>(
        connection: Connection<'stack, P>,
        server: &'server AttributeServer<'values, M, P, AT, CN>,
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

    /// Provide OOB data during pairing.
    ///
    /// Call this when [`GattConnectionEvent::OobRequest`] is received.
    #[cfg(feature = "security")]
    pub fn provide_oob_data(
        &self,
        local_oob: crate::security_manager::OobData,
        peer_oob: crate::security_manager::OobData,
    ) -> Result<(), Error> {
        self.connection.provide_oob_data(local_oob, peer_oob)
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

                #[cfg(feature = "security")]
                ConnectionEvent::OobRequest => GattConnectionEvent::OobRequest,
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

    /// Set the value of an attribute on the local GATT server for this connection.
    pub fn set<T: AttributeHandle>(&self, attribute_handle: &T, input: &T::Value) -> Result<(), Error> {
        let gatt_value = input.as_gatt();
        self.server.set(&self.connection, attribute_handle.handle(), gatt_value)
    }

    /// Get the value of an attribute from the local GATT server for this connection.
    pub fn get<T: AttributeHandle>(&self, attribute_handle: &T) -> Result<T::Value, Error>
    where
        T::Value: FromGatt,
    {
        let mut buf = [0; 512];
        let len = self.server.get(&self.connection, attribute_handle.handle(), &mut buf)?;
        let value_slice = &buf[..len];
        T::Value::from_gatt(value_slice).map_err(|_| {
            let mut invalid_data = [0u8; MAX_INVALID_DATA_LEN];
            let len_to_copy = value_slice.len().min(MAX_INVALID_DATA_LEN);
            invalid_data[..len_to_copy].copy_from_slice(&value_slice[..len_to_copy]);

            Error::CannotConstructGattValue(invalid_data)
        })
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
                AttReq::Write { handle, .. } => server.can_write(&data.connection, *handle),
                #[cfg(feature = "att-queued-writes")]
                AttReq::PrepareWrite { handle, .. } => server.can_write(&data.connection, *handle),
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
            #[cfg(feature = "att-queued-writes")]
            AttClient::Request(AttReq::ExecuteWrite { flags, .. })
                if flags == 0x01 && data.connection.with_prepare_write(|pw| pw.handle != 0) =>
            {
                GattEvent::Write(WriteEvent { data, server })
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

    /// Accept the event without server processing.
    pub fn accept_unprocessed<T: AsGatt + ?Sized>(mut self, data: &T) -> Result<Reply<'stack, P>, Error> {
        let (rsp, offset) = match self.data.incoming() {
            AttClient::Request(AttReq::Read { .. }) => (att::ATT_READ_RSP, 0),
            AttClient::Request(AttReq::ReadBlob { offset, .. }) => (att::ATT_READ_BLOB_RSP, offset as usize),
            _ => unreachable!(),
        };
        self.data.pdu = None;

        let mut tx = P::allocate().ok_or(Error::OutOfMemory)?;
        let mut w = WriteCursor::new(tx.as_mut());
        let (mut header, mut payload) = w.split(4)?;
        // Limit the buffer given to process() so that multi-entry ATT responses
        // (ReadByType, ReadByGroupType, FindInformation) are bounded by the
        // negotiated ATT MTU. Without this, entries are written into the full
        // packet-pool buffer and then post-hoc truncated, which can split an
        // entry in half and produce a malformed PDU.
        let mtu = self.data.connection.get_att_mtu() as usize;
        let len = payload.len().saturating_sub(offset).min(mtu - 1);

        payload.write(rsp)?;
        payload.append(&data.as_gatt()[offset..][..len])?;
        header.write(payload.len() as u16)?;
        header.write(4_u16)?;

        let len = header.len() + payload.len();
        let pdu = Pdu::new(tx, len);
        Ok(Reply::new(self.data.connection.clone(), Some(pdu)))
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
        match self.data.incoming() {
            AttClient::Request(AttReq::Write { handle, .. }) | AttClient::Command(AttCmd::Write { handle, .. }) => {
                handle
            }
            #[cfg(feature = "att-queued-writes")]
            AttClient::Request(AttReq::ExecuteWrite { .. }) => self.data.connection.with_prepare_write(|pw| pw.handle),
            _ => unreachable!(),
        }
    }

    /// Raw data to be written
    pub fn with_data<R>(&self, f: impl FnOnce(usize, &[u8]) -> R) -> R {
        match self.data.incoming() {
            AttClient::Request(AttReq::Write { data, .. }) | AttClient::Command(AttCmd::Write { data, .. }) => {
                f(0, data)
            }
            #[cfg(feature = "att-queued-writes")]
            AttClient::Request(AttReq::ExecuteWrite { .. }) => self.data.connection.with_prepare_write(|pw| {
                let data = &pw.buf[..pw.len as usize];
                f(usize::from(pw.offset), data)
            }),
            _ => unreachable!(),
        }
    }

    /// Characteristic data to be written
    pub fn value<T: FromGatt>(&self, _c: &Characteristic<T>) -> Result<T, FromGattError> {
        self.with_data(|offset, data| {
            if offset == 0 {
                T::from_gatt(data)
            } else {
                Err(FromGattError::InvalidLength)
            }
        })
    }

    /// Validate the offset and length of the write request against the attribute's `len` and `capacity`
    pub fn validate(&self, len: usize, capacity: usize) -> Result<(), AttErrorCode> {
        self.with_data(|offset, data| {
            if offset > len {
                Err(AttErrorCode::INVALID_OFFSET)
            } else if offset + data.len() > capacity {
                Err(AttErrorCode::INVALID_ATTRIBUTE_VALUE_LENGTH)
            } else {
                Ok(())
            }
        })
    }

    /// Accept the event, making it processed by the server.
    ///
    /// Automatically called if drop() is invoked.
    pub fn accept(mut self) -> Result<Reply<'stack, P>, Error> {
        process(&mut self.data, self.server, Ok(()))
    }

    /// Accept the event without server processing.
    pub fn accept_unprocessed(mut self) -> Result<Reply<'stack, P>, Error> {
        let rsp = match self.data.incoming() {
            AttClient::Request(AttReq::Write { .. }) => Some(att::ATT_WRITE_RSP),
            AttClient::Command(AttCmd::Write { .. }) => None,
            #[cfg(feature = "att-queued-writes")]
            AttClient::Request(AttReq::ExecuteWrite { .. }) => {
                self.data.connection.clear_prepare_write();
                Some(att::ATT_EXECUTE_WRITE_RSP)
            }
            _ => unreachable!(),
        };

        self.data.pdu = None;

        if let Some(rsp) = rsp {
            let mut tx = P::allocate().ok_or(Error::OutOfMemory)?;
            let mut w = WriteCursor::new(tx.as_mut());
            w.write(1_u16)?;
            w.write(4_u16)?;
            w.write(rsp)?;
            let len = w.len();
            let pdu = Pdu::new(tx, len);
            Ok(Reply::new(self.data.connection.clone(), Some(pdu)))
        } else {
            Ok(Reply::new(self.data.connection.clone(), None))
        }
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
    handle: Option<u16>,
    listener: pubsub::DynSubscriber<'lst, Notification<MTU>>,
}

impl<'lst, const MTU: usize> NotificationListener<'lst, MTU> {
    #[allow(clippy::should_implement_trait)]
    /// Get the next (len: u16, Packet) tuple from the rx queue
    pub async fn next(&mut self) -> Notification<MTU> {
        loop {
            if let WaitResult::Message(m) = self.listener.next_message().await {
                if self.handle.is_none() || self.handle == Some(m.handle) {
                    return m;
                }
            }
        }
    }
}

const MAX_NOTIF: usize = config::GATT_CLIENT_NOTIFICATION_MAX_SUBSCRIBERS;
const NOTIF_QSIZE: usize = config::GATT_CLIENT_NOTIFICATION_QUEUE_SIZE;

/// BT Core Spec Vol 3, Part F, Section 3.3.3: ATT transaction timeout.
const ATT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(30);

/// A GATT client capable of using the GATT protocol.
pub struct GattClient<'reference, T: Controller, P: PacketPool, const MAX_SERVICES: usize> {
    known_services: RefCell<Vec<ServiceHandle, MAX_SERVICES>>,
    _phantom: PhantomData<T>,
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
    indication: bool,
}

impl<const MTU: usize> Notification<MTU> {
    /// The characteristic value handle this notification is for.
    pub fn handle(&self) -> u16 {
        self.handle
    }

    /// Whether this notification was received as an indication.
    pub fn is_indication(&self) -> bool {
        self.indication
    }
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
        self.uuid
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

        // BT Core Spec Vol 3, Part F, Section 3.3.3: 30-second ATT transaction timeout.
        // If the server does not respond within 30 seconds, the client shall close the
        // ATT bearer (disconnect).
        let (h, pdu) = with_timeout(ATT_TRANSACTION_TIMEOUT, self.response_channel.receive())
            .await
            .map_err(|_| {
                warn!("[gatt] ATT transaction timeout (30s), disconnecting");
                self.connection.disconnect();
                BleHostError::BleHost(Error::Timeout)
            })?;

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
        _stack: &Stack<'_, C, P>,
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
        with_timeout(ATT_TRANSACTION_TIMEOUT, async {
            loop {
                let pdu = connection.next_gatt_client().await.ok_or(Error::Disconnected)?;
                match pdu.as_ref()[0] {
                    att::ATT_EXCHANGE_MTU_RSP | att::ATT_ERROR_RSP => break Ok::<_, BleHostError<C::Error>>(()),
                    _ => {
                        warn!("[gatt] unexpected PDU during MTU exchange, discarding");
                    }
                }
            }
        })
        .await
        .map_err(|_| {
            warn!("[gatt] MTU exchange timeout (30s), disconnecting");
            connection.disconnect();
            BleHostError::BleHost(Error::Timeout)
        })??;

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
            _phantom: PhantomData,
            connection: connection.clone(),

            response_channel: Channel::new(),

            notifications: PubSubChannel::new(),
        })
    }

    /// Discover primary services associated with a UUID.
    pub async fn services(&self) -> Result<Vec<ServiceHandle, MAX_SERVICES>, BleHostError<C::Error>> {
        let mut result = Vec::new();
        let mut pending: Vec<(u16, u16), MAX_SERVICES> = Vec::new();
        let _ = pending.push((0x0001, u16::MAX));

        while let Some((start, range_end)) = pending.pop() {
            let data = att::AttReq::ReadByGroupType {
                start,
                end: range_end,
                group_type: PRIMARY_SERVICE.into(),
            };

            let response = self.request(data).await?;
            let res = Self::response(response.pdu.as_ref())?;
            match res {
                AttRsp::Error { request, handle, code } => {
                    if code == att::AttErrorCode::ATTRIBUTE_NOT_FOUND {
                        continue;
                    }
                    return Err(Error::Att(code).into());
                }
                AttRsp::ReadByGroupType { mut it } => {
                    let mut end: u16 = start.saturating_sub(1);
                    while let Some(res) = it.next() {
                        let (handle, data) = res?;

                        // ReadByGroupType responses have uniform-length attribute
                        // data, so services with a different UUID size are skipped.
                        // Push any gaps onto the pending stack to discover them.
                        if handle > end + 1 {
                            pending
                                .push((end + 1, handle - 1))
                                .map_err(|_| Error::InsufficientSpace)?;
                        }

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
                    if end < range_end {
                        pending
                            .push((end + 1, range_end))
                            .map_err(|_| Error::InsufficientSpace)?;
                    }
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
                            uuid: *uuid,
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
        let mut characteristics: Vec<Characteristic<[u8]>, N> = Vec::new();
        let mut err: Option<BleHostError<C::Error>> = None;

        self.read_by_type(
            service.start,
            service.end,
            &CHARACTERISTIC.into(),
            |declaration_handle, item| {
                if declaration_handle == 0xffff {
                    err = Some(Error::Att(AttErrorCode::INVALID_HANDLE).into());
                    return ControlFlow::Break(());
                }

                let expected_items_len = 5;
                let item_len = item.len();

                if item_len < expected_items_len {
                    err = Some(
                        Error::MalformedCharacteristicDeclaration {
                            expected: expected_items_len,
                            actual: item_len,
                        }
                        .into(),
                    );
                    return ControlFlow::Break(());
                }

                match CharacteristicDeclaration::try_from(item) {
                    Ok(decl) => {
                        if characteristics
                            .push(Characteristic {
                                handle: decl.value_handle,
                                end_handle: 0,
                                props: decl.props,
                                cccd_handle: None,
                                uuid: decl.uuid,
                                phantom: PhantomData,
                            })
                            .is_err()
                        {
                            err = Some(Error::InsufficientSpace.into());
                            return ControlFlow::Break(());
                        }
                        ControlFlow::Continue(())
                    }
                    Err(e) => {
                        err = Some(e.into());
                        ControlFlow::Break(())
                    }
                }
            },
        )
        .await?;

        if let Some(e) = err {
            return Err(e);
        }

        let mut iter = characteristics.iter_mut().peekable();
        while let Some(characteristic) = iter.next() {
            let end = iter.peek().map(|x| x.handle - 2).unwrap_or(service.end);
            characteristic.end_handle = end;
            if characteristic.props.has_cccd() {
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
        let mut found: Option<(u16, CharacteristicProps)> = None;

        trace!(
            "[characteristic_by_uuid] service start={}, end={}, uuid={:?}",
            service.start,
            service.end,
            uuid
        );

        // Iterate through characteristic declarations. When we find the matching UUID,
        // we store (value_handle, props) and continue to find the next declaration
        // to determine end_handle.
        let end = self
            .read_by_type(
                service.start,
                service.end,
                &CHARACTERISTIC.into(),
                |declaration_handle, item| {
                    let expected_items_len = 5;
                    let item_len = item.len();

                    if item_len < expected_items_len {
                        return ControlFlow::Break(Err(Error::MalformedCharacteristicDeclaration {
                            expected: expected_items_len,
                            actual: item_len,
                        }));
                    }

                    match CharacteristicDeclaration::try_from(item) {
                        Ok(decl) => {
                            if found.is_some() {
                                // We already found our match; this is the next declaration,
                                // so we can determine end_handle.
                                return ControlFlow::Break(Ok(declaration_handle));
                            }

                            if *uuid == decl.uuid {
                                found = Some((decl.value_handle, decl.props));
                            }

                            if decl.value_handle == 0xFFFF && found.is_some() {
                                return ControlFlow::Break(Ok(declaration_handle));
                            }

                            ControlFlow::Continue(())
                        }
                        Err(e) => ControlFlow::Break(Err(e)),
                    }
                },
            )
            .await?
            .unwrap_or(Ok(service.end))?;

        match found {
            Some((handle, props)) => {
                // If we broke early, the next declaration_handle gives us the end.
                // If we exhausted the range, use service.end.
                let cccd_handle: Option<u16> = if props.has_cccd() {
                    Some(self.get_characteristic_cccd(handle + 1, end).await?)
                } else {
                    None
                };
                Ok(Characteristic {
                    handle,
                    end_handle: end,
                    cccd_handle,
                    props,
                    uuid: *uuid,
                    phantom: PhantomData,
                })
            }
            None => Err(Error::NotFound.into()),
        }
    }

    async fn paginated_request<R>(
        &self,
        start: u16,
        end: u16,
        mut make_req: impl FnMut(u16, u16) -> AttReq<'static>,
        mut handle_rsp: impl for<'a> FnMut(AttRsp<'a>) -> Result<ControlFlow<R, u16>, Error>,
    ) -> Result<Option<R>, BleHostError<C::Error>> {
        let mut start_handle = start;
        while start_handle <= end {
            let data = make_req(start_handle, end);
            let response = self.request(data).await?;
            match Self::response(response.pdu.as_ref())? {
                AttRsp::Error { code, .. } if code == att::AttErrorCode::ATTRIBUTE_NOT_FOUND => {
                    return Ok(None);
                }
                AttRsp::Error { code, .. } => return Err(Error::Att(code).into()),
                rsp => match handle_rsp(rsp)? {
                    ControlFlow::Break(val) => return Ok(Some(val)),
                    ControlFlow::Continue(next) => start_handle = next,
                },
            }
        }
        Ok(None)
    }

    /// Discover descriptors in a handle range, calling `callback` for each discovered handle/UUID pair.
    ///
    /// Returns `Ok(Some(val))` if `callback` returns `ControlFlow::Break(val)`, or `Ok(None)` if
    /// the entire range was iterated without breaking.
    pub async fn find_information<R>(
        &self,
        start: u16,
        end: u16,
        mut callback: impl FnMut(u16, Uuid) -> ControlFlow<R>,
    ) -> Result<Option<R>, BleHostError<C::Error>> {
        self.paginated_request(
            start,
            end,
            |start_handle, end_handle| AttReq::FindInformation {
                start_handle,
                end_handle,
            },
            |rsp| match rsp {
                AttRsp::FindInformation { mut it } => {
                    let mut next_handle = None;
                    while let Some(Ok((handle, uuid))) = it.next() {
                        next_handle = Some(handle + 1);
                        if let ControlFlow::Break(val) = callback(handle, uuid) {
                            return Ok(ControlFlow::Break(val));
                        }
                    }
                    next_handle
                        .map(ControlFlow::Continue)
                        .ok_or(Error::UnexpectedGattResponse)
                }
                _ => Err(Error::UnexpectedGattResponse),
            },
        )
        .await
    }

    async fn get_characteristic_cccd(
        &self,
        char_start_handle: u16,
        char_end_handle: u16,
    ) -> Result<u16, BleHostError<C::Error>> {
        self.find_information(char_start_handle, char_end_handle, |handle, uuid| {
            if uuid == CLIENT_CHARACTERISTIC_CONFIGURATION.into() {
                ControlFlow::Break(handle)
            } else {
                ControlFlow::Continue(())
            }
        })
        .await?
        .ok_or(Error::NotFound.into())
    }

    /// Discover all descriptors for a characteristic.
    ///
    /// Returns a list of descriptors found in the handle range belonging to the characteristic.
    pub async fn descriptors<T: AsGatt + ?Sized, const N: usize>(
        &self,
        characteristic: &Characteristic<T>,
    ) -> Result<Vec<Descriptor<[u8]>, N>, BleHostError<C::Error>> {
        let start = characteristic.handle + 1;
        let end = characteristic.end_handle;
        if start > end {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        self.find_information(start, end, |handle, uuid| {
            let desc = Descriptor {
                handle,
                uuid,
                phantom: PhantomData,
            };
            if result.push(desc).is_err() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .await?;
        Ok(result)
    }

    /// Find a specific descriptor by UUID for a characteristic.
    ///
    /// Returns the first descriptor matching the given UUID.
    pub async fn descriptor_by_uuid<T: AsGatt + ?Sized, DT: AsGatt + ?Sized>(
        &self,
        characteristic: &Characteristic<T>,
        uuid: &Uuid,
    ) -> Result<Descriptor<DT>, BleHostError<C::Error>> {
        let start = characteristic.handle + 1;
        let end = characteristic.end_handle;
        self.find_information(start, end, |handle, desc_uuid| {
            if desc_uuid == *uuid {
                ControlFlow::Break(Descriptor {
                    handle,
                    uuid: desc_uuid,
                    phantom: PhantomData,
                })
            } else {
                ControlFlow::Continue(())
            }
        })
        .await?
        .ok_or(Error::NotFound.into())
    }

    /// Read attributes by type in a handle range, calling `callback` for each discovered handle/data pair.
    ///
    /// Paginates automatically using successive ATT ReadByType requests.
    /// Returns `Ok(Some(val))` if `callback` returns `ControlFlow::Break(val)`, or `Ok(None)` if
    /// the entire range was iterated without breaking (i.e. ATTRIBUTE_NOT_FOUND was received).
    pub async fn read_by_type<R>(
        &self,
        start: u16,
        end: u16,
        attribute_type: &Uuid,
        mut callback: impl FnMut(u16, &[u8]) -> ControlFlow<R>,
    ) -> Result<Option<R>, BleHostError<C::Error>> {
        self.paginated_request(
            start,
            end,
            |start, end| AttReq::ReadByType {
                start,
                end,
                attribute_type: *attribute_type,
            },
            |rsp| match rsp {
                AttRsp::ReadByType { mut it } => {
                    let mut next_handle = None;
                    while let Some(res) = it.next() {
                        let (handle, data) = res?;
                        next_handle = Some(handle + 1);
                        if let ControlFlow::Break(val) = callback(handle, data) {
                            return Ok(ControlFlow::Break(val));
                        }
                    }
                    next_handle
                        .map(ControlFlow::Continue)
                        .ok_or(Error::UnexpectedGattResponse)
                }
                _ => Err(Error::UnexpectedGattResponse),
            },
        )
        .await
    }

    /// Read a characteristic described by a handle.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic<T: AsGatt + ?Sized>(
        &self,
        characteristic: &Characteristic<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        self.read_handle(characteristic.handle, dest).await
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
        let result = self
            .read_by_type(service.start, service.end, uuid, |_handle, data| {
                let to_copy = data.len().min(dest.len());
                dest[..to_copy].copy_from_slice(&data[..to_copy]);
                ControlFlow::Break(to_copy)
            })
            .await?;
        result.ok_or(Error::NotFound.into())
    }

    /// Write to a characteristic described by a handle.
    pub async fn write_characteristic<T: AsGatt + ?Sized>(
        &self,
        handle: &Characteristic<T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
        self.write_handle(handle.handle, buf).await
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

    /// Read an attribute by raw handle.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_handle(&self, handle: u16, dest: &mut [u8]) -> Result<usize, BleHostError<C::Error>> {
        let response = self.request(att::AttReq::Read { handle }).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Read { data } => {
                let to_copy = data.len().min(dest.len());
                dest[..to_copy].copy_from_slice(&data[..to_copy]);

                let att_mtu = self.connection.att_mtu() as usize;
                if data.len() == att_mtu - 1 && dest.len() > to_copy {
                    let remaining = self
                        .read_handle_blob(handle, to_copy as u16, &mut dest[to_copy..])
                        .await?;
                    Ok(to_copy + remaining)
                } else {
                    Ok(to_copy)
                }
            }
            AttRsp::Error { code, .. } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Read an attribute value by raw handle using Read Blob requests.
    ///
    /// The `offset` parameter specifies the starting offset within the attribute value.
    pub async fn read_handle_blob(
        &self,
        handle: u16,
        offset: u16,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        let att_mtu = self.connection.att_mtu() as usize;
        let mut pos = 0;
        let mut blob_offset = offset as usize;

        loop {
            let response = self
                .request(att::AttReq::ReadBlob {
                    handle,
                    offset: blob_offset as u16,
                })
                .await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::ReadBlob { data } => {
                    if data.is_empty() {
                        break;
                    }

                    let blob_read_len = data.len();
                    let len_to_copy = blob_read_len.min(dest.len() - pos);
                    dest[pos..pos + len_to_copy].copy_from_slice(&data[..len_to_copy]);
                    pos += len_to_copy;
                    blob_offset += blob_read_len;

                    if blob_read_len < att_mtu - 1 || len_to_copy < blob_read_len {
                        break;
                    }
                }
                AttRsp::Error { code, .. } if code == att::AttErrorCode::INVALID_OFFSET => {
                    break;
                }
                AttRsp::Error { code, .. } if code == att::AttErrorCode::ATTRIBUTE_NOT_LONG => {
                    break;
                }
                AttRsp::Error { code, .. } => {
                    return Err(Error::Att(code).into());
                }
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }
        Ok(pos)
    }

    /// Write an attribute by raw handle.
    pub async fn write_handle(&self, handle: u16, buf: &[u8]) -> Result<(), BleHostError<C::Error>> {
        let response = self.request(att::AttReq::Write { handle, data: buf }).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { code, .. } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Write an attribute by raw handle without waiting for a response.
    pub async fn write_handle_without_response(&self, handle: u16, buf: &[u8]) -> Result<(), BleHostError<C::Error>> {
        self.command(att::AttCmd::Write { handle, data: buf }).await
    }

    /// Read a descriptor value.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_descriptor<T: AsGatt + ?Sized>(
        &self,
        descriptor: &Descriptor<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        self.read_handle(descriptor.handle, dest).await
    }

    /// Write a descriptor value.
    pub async fn write_descriptor<T: AsGatt + ?Sized>(
        &self,
        descriptor: &Descriptor<T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
        self.write_handle(descriptor.handle, buf).await
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

        // set the CCCD
        self.write_handle(characteristic.cccd_handle.ok_or(Error::NotSupported)?, &properties)
            .await?;

        match self.notifications.dyn_subscriber() {
            Ok(listener) => Ok(NotificationListener {
                listener,
                handle: Some(characteristic.handle),
            }),
            Err(embassy_sync::pubsub::Error::MaximumSubscribersReached) => {
                Err(Error::GattSubscriberLimitReached.into())
            }
            Err(_) => Err(Error::Other.into()),
        }
    }

    /// Listen for notifications/indications on a given Characteristic without writing the CCCD.
    ///
    /// Use this for reconnection scenarios where the server remembers the subscription
    /// (per BLE spec 10.3.2.2, CCCD values persist across disconnections for bonded devices).
    pub fn listen<T: AsGatt + ?Sized>(
        &self,
        characteristic: &Characteristic<T>,
    ) -> Result<NotificationListener<'_, 512>, BleHostError<C::Error>> {
        match self.notifications.dyn_subscriber() {
            Ok(listener) => Ok(NotificationListener {
                listener,
                handle: Some(characteristic.handle),
            }),
            Err(embassy_sync::pubsub::Error::MaximumSubscribersReached) => {
                Err(Error::GattSubscriberLimitReached.into())
            }
            Err(_) => Err(Error::Other.into()),
        }
    }

    /// Listen for notifications/indications on all characteristics without writing the CCCD.
    ///
    /// Returns a catch-all listener that receives notifications for ALL handles.
    /// Use [`Notification::handle()`] to determine which characteristic the notification is for.
    pub fn listen_all(&self) -> Result<NotificationListener<'_, 512>, BleHostError<C::Error>> {
        match self.notifications.dyn_subscriber() {
            Ok(listener) => Ok(NotificationListener { listener, handle: None }),
            Err(embassy_sync::pubsub::Error::MaximumSubscribersReached) => {
                Err(Error::GattSubscriberLimitReached.into())
            }
            Err(_) => Err(Error::Other.into()),
        }
    }

    /// Unsubscribe from a given Characteristic
    pub async fn unsubscribe<T: AsGatt + ?Sized>(
        &self,
        characteristic: &Characteristic<T>,
    ) -> Result<(), BleHostError<C::Error>> {
        self.write_handle(characteristic.cccd_handle.ok_or(Error::NotSupported)?, &[0, 0])
            .await
    }

    /// Confirm an indication that was received.
    pub async fn confirm_indication(&self) -> Result<(), BleHostError<C::Error>> {
        self.send_att_data(Att::Client(AttClient::Confirmation(AttCfm::ConfirmIndication)))
            .await
    }

    /// Handle a notification or indication that was received.
    async fn handle_notification_packet(&self, data: &[u8], indication: bool) -> Result<(), BleHostError<C::Error>> {
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
            indication,
        };
        self.notifications.immediate_publisher().publish_immediate(n);
        Ok(())
    }

    /// Task which handles GATT rx data (needed for notifications to work)
    pub async fn task(&self) -> Result<(), BleHostError<C::Error>> {
        loop {
            let handle = self.connection.handle();
            let pdu = self.connection.next_gatt_client().await.ok_or(Error::Disconnected)?;
            // handle notifications
            if matches!(pdu.as_ref()[0], ATT_HANDLE_VALUE_IND | ATT_HANDLE_VALUE_NTF) {
                let indication = pdu.as_ref()[0] == ATT_HANDLE_VALUE_IND;
                self.handle_notification_packet(&pdu.as_ref()[1..], indication).await?;
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
    use crate::Address;

    /// Build a ReadByType ATT request PDU (ATT payload only, no L2CAP header).
    fn build_read_by_type_pdu(start: u16, end: u16, uuid: &Uuid) -> (<DefaultPacketPool as PacketPool>::Packet, usize) {
        let att = Att::Client(AttClient::Request(AttReq::ReadByType {
            start,
            end,
            attribute_type: *uuid,
        }));

        let mut packet = DefaultPacketPool::allocate().unwrap();
        let mut w = WriteCursor::new(packet.as_mut());
        w.write(att).unwrap();
        let len = w.len();
        (packet, len)
    }

    /// Build a Write Command ATT PDU (ATT payload only, no L2CAP header).
    fn build_write_cmd_pdu(handle: u16, data: &[u8]) -> (<DefaultPacketPool as PacketPool>::Packet, usize) {
        let att = Att::Client(AttClient::Command(AttCmd::Write { handle, data }));

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

        let server = AttributeServer::<_, DefaultPacketPool, MAX_ATTRIBUTES, CONNECTIONS_MAX>::new(table);

        // Set up a connection with ATT MTU = 185 (typical iOS value)
        let mgr = setup();
        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
        unwrap!(mgr.connect(
            ConnHandle::new(0),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
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

    #[test]
    fn test_write_command_surfaces_gatt_write_event_without_att_response() {
        let _ = env_logger::try_init();

        const MAX_ATTRIBUTES: usize = 16;
        const CONNECTIONS_MAX: usize = 3;
        let mut table: AttributeTable<'_, NoopRawMutex, MAX_ATTRIBUTES> = AttributeTable::new();
        let mut storage = [0u8; 1];
        let characteristic: Characteristic<u8> = table
            .add_service(Service {
                uuid: Uuid::new_long([0x44; 16]),
            })
            .add_characteristic(
                Uuid::new_long([0x45; 16]),
                [CharacteristicProp::Read, CharacteristicProp::WriteWithoutResponse],
                0u8,
                &mut storage[..],
            )
            .build();
        let server = AttributeServer::<_, DefaultPacketPool, MAX_ATTRIBUTES, CONNECTIONS_MAX>::new(table);

        let mgr = setup();
        assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
        unwrap!(mgr.connect(
            ConnHandle::new(0),
            Address::new(AddrKind::RANDOM, BdAddr::new(ADDR_1)),
            LeConnRole::Peripheral,
            ConnParams::new(),
        ));
        let Poll::Ready(conn) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) else {
            panic!("expected connection to be accepted");
        };

        let payload = [0x2a];
        let (packet, len) = build_write_cmd_pdu(characteristic.handle, &payload);
        let pdu = Pdu::new(packet, len);

        let event = GattEvent::new(GattData::new(pdu, conn.clone()), &server);
        match event {
            GattEvent::Write(write) => {
                assert_eq!(write.handle(), characteristic.handle);
                write.with_data(|_, data| assert_eq!(data, &payload));
                let reply = write.accept().unwrap();
                assert!(
                    reply.att_payload().is_none(),
                    "write command must not generate an ATT response"
                );
                core::mem::forget(reply);
            }
            _ => panic!("expected write event for write command"),
        }

        let stored: u8 = server.table().get(&characteristic).unwrap();
        assert_eq!(stored, payload[0]);
    }
}
