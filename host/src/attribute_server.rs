use core::cell::RefCell;

use bt_hci::param::BdAddr;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::att::{self, AttClient, AttCmd, AttErrorCode, AttReq};
use crate::attribute::{Attribute, AttributeData, AttributeTable, CCCD};
use crate::cursor::WriteCursor;
use crate::prelude::Connection;
#[cfg(feature = "security")]
use crate::security_manager::IdentityResolvingKey;
use crate::types::uuid::Uuid;
use crate::{codec, Error};

/// Identity of a peer device
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identity {
    /// Random static or public address
    BdAddr(BdAddr),
    /// Identity Resolving Key
    #[cfg(feature = "security")]
    Irk(IdentityResolvingKey),
}

#[cfg(feature = "defmt")]
impl defmt::Format for Identity {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Self::BdAddr(addr) => defmt::write!(fmt, "BdAddr({:X})", addr),
            Self::Irk(irk) => defmt::write!(fmt, "Irk({:X})", irk),
        }
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::BdAddr(BdAddr::default())
    }
}

impl Identity {
    /// Check whether the address matches the identity
    pub fn match_address(&self, address: &BdAddr) -> bool {
        match self {
            Self::BdAddr(addr) => addr == address,
            Self::Irk(irk) => irk.resolve_address(address),
        }
    }

    /// Check whether the given identity matches current identity
    pub fn match_identity(&self, identity: &Identity) -> bool {
        match (self, identity) {
            (Self::BdAddr(addr1), Self::BdAddr(addr2)) => addr1 == addr2,
            (Self::Irk(irk1), Self::Irk(irk2)) => irk1 == irk2,
            (Self::Irk(irk), Self::BdAddr(addr)) => irk.resolve_address(addr),
            (Self::BdAddr(addr), Self::Irk(irk)) => irk.resolve_address(addr),
        }
    }
}

#[derive(Default)]
struct Client {
    identity: Identity,
    is_connected: bool,
}

impl Client {
    fn set_identity(&mut self, identity: Identity) {
        self.identity = identity;
    }
}

/// A table of CCCD values.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Clone, Debug)]
pub struct CccdTable<const ENTRIES: usize> {
    inner: [(u16, CCCD); ENTRIES],
}

impl<const ENTRIES: usize> Default for CccdTable<ENTRIES> {
    fn default() -> Self {
        Self {
            inner: [(0, CCCD(0)); ENTRIES],
        }
    }
}

impl<const ENTRIES: usize> CccdTable<ENTRIES> {
    /// Create a new CCCD table from an array of (handle, cccd) pairs.
    pub fn new(cccd_values: [(u16, CCCD); ENTRIES]) -> Self {
        Self { inner: cccd_values }
    }

    /// Get the inner array of (handle, cccd) pairs.
    pub fn inner(&self) -> &[(u16, CCCD); ENTRIES] {
        &self.inner
    }

    fn add_handle(&mut self, cccd_handle: u16) {
        for (handle, _) in self.inner.iter_mut() {
            if *handle == 0 {
                *handle = cccd_handle;
                break;
            }
        }
    }

    fn disable_all(&mut self) {
        for (_, value) in self.inner.iter_mut() {
            value.disable();
        }
    }

    fn get_raw(&self, cccd_handle: u16) -> Option<[u8; 2]> {
        for (handle, value) in self.inner.iter() {
            if *handle == cccd_handle {
                return Some(value.raw().to_le_bytes());
            }
        }
        None
    }

    fn set_notify(&mut self, cccd_handle: u16, is_enabled: bool) {
        for (handle, value) in self.inner.iter_mut() {
            if *handle == cccd_handle {
                trace!("[cccd] set_notify({}) = {}", cccd_handle, is_enabled);
                value.set_notify(is_enabled);
                break;
            }
        }
    }

    fn should_notify(&self, cccd_handle: u16) -> bool {
        for (handle, value) in self.inner.iter() {
            if *handle == cccd_handle {
                return value.should_notify();
            }
        }
        false
    }
}

/// A table of CCCD values for each connected client.
struct CccdTables<M: RawMutex, const CCCD_MAX: usize, const CONN_MAX: usize> {
    state: Mutex<M, RefCell<[(Client, CccdTable<CCCD_MAX>); CONN_MAX]>>,
}

impl<M: RawMutex, const CCCD_MAX: usize, const CONN_MAX: usize> CccdTables<M, CCCD_MAX, CONN_MAX> {
    fn new<const ATT_MAX: usize>(att_table: &AttributeTable<'_, M, ATT_MAX>) -> Self {
        let mut values: [(Client, CccdTable<CCCD_MAX>); CONN_MAX] =
            core::array::from_fn(|_| (Client::default(), CccdTable::default()));
        let mut base_cccd_table = CccdTable::default();
        att_table.iterate(|mut at| {
            while let Some(att) = at.next() {
                if let AttributeData::Cccd { .. } = att.data {
                    base_cccd_table.add_handle(att.handle);
                }
            }
        });
        // add the base CCCD table for each potential connected client
        for (_, table) in values.iter_mut() {
            *table = base_cccd_table.clone();
        }
        Self {
            state: Mutex::new(RefCell::new(values)),
        }
    }

    fn connect(&self, peer_identity: &Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            trace!("[server] searching for peer {:?}", peer_identity);
            let mut n = n.borrow_mut();
            let empty_slot = Identity::default();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    // trace!("[server] found! table = {:?}", *table);
                    client.is_connected = true;
                    return Ok(());
                } else if client.identity == empty_slot {
                    //  trace!("[server] empty slot: connecting");
                    client.is_connected = true;
                    client.set_identity(*peer_identity);
                    return Ok(());
                }
            }
            trace!("[server] all slots full...");
            // if we got here all slots are full; replace the first disconnected client
            for (client, table) in n.iter_mut() {
                if !client.is_connected {
                    trace!("[server] booting disconnected peer {:?}", client.identity);
                    client.is_connected = true;
                    client.set_identity(*peer_identity);
                    // erase the previous client's config
                    table.disable_all();
                    return Ok(());
                }
            }
            // Should be unreachable if the max connections (CONN_MAX) matches that defined
            // in HostResources...
            warn!("[server] unable to obtain CCCD slot");
            Err(Error::ConnectionLimitReached)
        })
    }

    fn disconnect(&self, peer_identity: &Identity) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, _) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    client.is_connected = false;
                    break;
                }
            }
        })
    }

    fn get_value(&self, peer_identity: &Identity, cccd_handle: u16) -> Option<[u8; 2]> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return table.get_raw(cccd_handle);
                }
            }
            None
        })
    }

    fn set_notify(&self, peer_identity: &Identity, cccd_handle: u16, is_enabled: bool) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, table) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    table.set_notify(cccd_handle, is_enabled);
                    break;
                }
            }
        })
    }

    fn should_notify(&self, peer_identity: &Identity, cccd_handle: u16) -> bool {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return table.should_notify(cccd_handle);
                }
            }
            false
        })
    }

    fn get_cccd_table(&self, peer_identity: &Identity) -> Option<CccdTable<CCCD_MAX>> {
        self.state.lock(|n| {
            let n = n.borrow();
            for (client, table) in n.iter() {
                if client.identity.match_identity(peer_identity) {
                    return Some(table.clone());
                }
            }
            None
        })
    }

    fn set_cccd_table(&self, peer_identity: &Identity, table: CccdTable<CCCD_MAX>) {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, t) in n.iter_mut() {
                if client.identity.match_identity(peer_identity) {
                    trace!("Setting cccd table {:?} for {:?}", table, peer_identity);
                    *t = table;
                    break;
                }
            }
        })
    }

    fn update_identity(&self, identity: Identity) -> Result<(), Error> {
        self.state.lock(|n| {
            let mut n = n.borrow_mut();
            for (client, _) in n.iter_mut() {
                if identity.match_identity(&client.identity) {
                    client.set_identity(identity);
                    return Ok(());
                }
            }
            return Err(Error::NotFound);
        })
    }
}

/// A GATT server capable of processing the GATT protocol using the provided table of attributes.
pub struct AttributeServer<'values, M: RawMutex, const ATT_MAX: usize, const CCCD_MAX: usize, const CONN_MAX: usize> {
    att_table: AttributeTable<'values, M, ATT_MAX>,
    cccd_tables: CccdTables<M, CCCD_MAX, CONN_MAX>,
}

pub(crate) mod sealed {
    use super::*;

    pub trait DynamicAttributeServer {
        fn connect(&self, connection: &Connection) -> Result<(), Error>;
        fn disconnect(&self, connection: &Connection);
        fn process(&self, connection: &Connection, packet: &AttClient, rx: &mut [u8]) -> Result<Option<usize>, Error>;
        fn should_notify(&self, connection: &Connection, cccd_handle: u16) -> bool;
        fn set(&self, characteristic: u16, input: &[u8]) -> Result<(), Error>;
        fn update_identity(&self, identity: Identity) -> Result<(), Error>;
    }
}

/// Type erased attribute server
pub trait DynamicAttributeServer: sealed::DynamicAttributeServer {}

impl<M: RawMutex, const ATT_MAX: usize, const CCCD_MAX: usize, const CONN_MAX: usize> DynamicAttributeServer
    for AttributeServer<'_, M, ATT_MAX, CCCD_MAX, CONN_MAX>
{
}
impl<M: RawMutex, const ATT_MAX: usize, const CCCD_MAX: usize, const CONN_MAX: usize> sealed::DynamicAttributeServer
    for AttributeServer<'_, M, ATT_MAX, CCCD_MAX, CONN_MAX>
{
    fn connect(&self, connection: &Connection) -> Result<(), Error> {
        AttributeServer::connect(self, connection)
    }

    fn disconnect(&self, connection: &Connection) {
        self.cccd_tables.disconnect(&connection.peer_identity());
    }

    fn process(&self, connection: &Connection, packet: &AttClient, rx: &mut [u8]) -> Result<Option<usize>, Error> {
        let res = AttributeServer::process(self, connection, packet, rx)?;
        Ok(res)
    }

    fn should_notify(&self, connection: &Connection, cccd_handle: u16) -> bool {
        AttributeServer::should_notify(self, connection, cccd_handle)
    }

    fn set(&self, characteristic: u16, input: &[u8]) -> Result<(), Error> {
        self.att_table.set_raw(characteristic, input)
    }

    fn update_identity(&self, identity: Identity) -> Result<(), Error> {
        self.cccd_tables.update_identity(identity)
    }
}

impl<'values, M: RawMutex, const ATT_MAX: usize, const CCCD_MAX: usize, const CONN_MAX: usize>
    AttributeServer<'values, M, ATT_MAX, CCCD_MAX, CONN_MAX>
{
    /// Create a new instance of the AttributeServer
    pub fn new(
        att_table: AttributeTable<'values, M, ATT_MAX>,
    ) -> AttributeServer<'values, M, ATT_MAX, CCCD_MAX, CONN_MAX> {
        let cccd_tables = CccdTables::new(&att_table);
        AttributeServer { att_table, cccd_tables }
    }

    pub(crate) fn connect(&self, connection: &Connection<'_>) -> Result<(), Error> {
        self.cccd_tables.connect(&connection.peer_identity())
    }

    pub(crate) fn should_notify(&self, connection: &Connection<'_>, cccd_handle: u16) -> bool {
        self.cccd_tables.should_notify(&connection.peer_identity(), cccd_handle)
    }

    fn read_attribute_data(
        &self,
        connection: &Connection<'_>,
        offset: usize,
        att: &mut Attribute<'values>,
        data: &mut [u8],
    ) -> Result<usize, AttErrorCode> {
        if let AttributeData::Cccd { .. } = att.data {
            // CCCD values for each connected client are held in the CCCD tables:
            // the value is written back into att.data so att.read() has the final
            // say when parsing at the requested offset.
            if let Some(value) = self.cccd_tables.get_value(&connection.peer_identity(), att.handle) {
                let _ = att.write(0, value.as_slice());
            }
        }
        att.read(offset, data)
    }

    fn write_attribute_data(
        &self,
        connection: &Connection<'_>,
        offset: usize,
        att: &mut Attribute<'values>,
        data: &[u8],
    ) -> Result<(), AttErrorCode> {
        let err = att.write(offset, data);
        if err.is_ok() {
            if let AttributeData::Cccd {
                notifications,
                indications,
            } = att.data
            {
                self.cccd_tables
                    .set_notify(&connection.peer_identity(), att.handle, notifications);
            }
        }
        err
    }

    fn handle_read_by_type_req(
        &self,
        connection: &Connection,
        buf: &mut [u8],
        start: u16,
        end: u16,
        attribute_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        let (mut header, mut body) = data.split(2)?;
        let err = self.att_table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                // trace!("[read_by_type] Check attribute {:?} {}", att.uuid, att.handle);
                if &att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                    body.write(att.handle)?;
                    handle = att.handle;

                    err = self.read_attribute_data(connection, 0, att, body.write_buf());
                    if let Ok(len) = err {
                        body.commit(len)?;
                    }

                    // debug!("[read_by_type] found! {:?} {}", att.uuid, att.handle);
                    break;
                }
            }
            err
        });

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_TYPE_RSP)?;
                header.write(2 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_BY_TYPE_REQ, handle, e)?),
        }
    }

    fn handle_read_by_group_type_req(
        &self,
        connection: &Connection,
        buf: &mut [u8],
        start: u16,
        end: u16,
        group_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        // TODO respond with all finds - not just one
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        let (mut header, mut body) = data.split(2)?;
        let err = self.att_table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                // trace!("[read_by_group] Check attribute {:x} {}", att.uuid, att.handle);
                if &att.uuid == group_type && att.handle >= start && att.handle <= end {
                    // debug!("[read_by_group] found! {:x} {}", att.uuid, att.handle);
                    handle = att.handle;

                    body.write(att.handle)?;
                    body.write(att.last_handle_in_group)?;
                    err = self.read_attribute_data(connection, 0, att, body.write_buf());
                    if let Ok(len) = err {
                        body.commit(len)?;
                    }
                    break;
                }
            }
            err
        });

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_GROUP_TYPE_RSP)?;
                header.write(4 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_BY_GROUP_TYPE_REQ, handle, e)?),
        }
    }

    fn handle_read_req(&self, connection: &Connection, buf: &mut [u8], handle: u16) -> Result<usize, codec::Error> {
        let mut data = WriteCursor::new(buf);

        data.write(att::ATT_READ_RSP)?;

        let err = self.att_table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    err = self.read_attribute_data(connection, 0, att, data.write_buf());
                    if let Ok(len) = err {
                        data.commit(len)?;
                    }
                    break;
                }
            }
            err
        });

        match err {
            Ok(_) => Ok(data.len()),
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_REQ, handle, e)?),
        }
    }

    fn handle_write_cmd(
        &self,
        connection: &Connection,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
    ) -> Result<usize, codec::Error> {
        self.att_table.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle {
                    // Write commands can't respond with an error.
                    let _ = self.write_attribute_data(connection, 0, att, data);
                    break;
                }
            }
        });
        Ok(0)
    }

    fn handle_write_req(
        &self,
        connection: &Connection,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
    ) -> Result<usize, codec::Error> {
        let err = self.att_table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    err = self.write_attribute_data(connection, 0, att, data);
                    break;
                }
            }
            err
        });

        let mut w = WriteCursor::new(buf);
        match err {
            Ok(()) => {
                w.write(att::ATT_WRITE_RSP)?;
                Ok(w.len())
            }
            Err(e) => Ok(Self::error_response(w, att::ATT_WRITE_REQ, handle, e)?),
        }
    }

    fn handle_find_type_value(
        &self,
        buf: &mut [u8],
        start: u16,
        end: u16,
        attr_type: u16,
        attr_value: &[u8],
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        let attr_type = Uuid::new_short(attr_type);

        w.write(att::ATT_FIND_BY_TYPE_VALUE_RSP)?;
        self.att_table.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle >= start && att.handle <= end && att.uuid == attr_type {
                    if let AttributeData::Service { uuid } = &att.data {
                        if uuid.as_raw() == attr_value {
                            if w.available() < 4 + uuid.as_raw().len() {
                                break;
                            }
                            w.write(att.handle)?;
                            w.write(att.last_handle_in_group)?;
                        }
                    }
                }
            }
            Ok::<(), codec::Error>(())
        })?;
        if w.len() > 1 {
            Ok(w.len())
        } else {
            Ok(Self::error_response(
                w,
                att::ATT_FIND_BY_TYPE_VALUE_REQ,
                start,
                AttErrorCode::ATTRIBUTE_NOT_FOUND,
            )?)
        }
    }

    fn handle_find_information(&self, buf: &mut [u8], start: u16, end: u16) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);

        let (mut header, mut body) = w.split(2)?;

        header.write(att::ATT_FIND_INFORMATION_RSP)?;
        let mut t = 0;

        self.att_table.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle >= start && att.handle <= end {
                    if t == 0 {
                        t = att.uuid.get_type();
                    } else if t != att.uuid.get_type() {
                        break;
                    }
                    body.write(att.handle)?;
                    body.append(att.uuid.as_raw())?;
                }
            }
            Ok::<(), codec::Error>(())
        })?;
        header.write(t)?;

        if body.len() > 2 {
            Ok(header.len() + body.len())
        } else {
            Ok(Self::error_response(
                w,
                att::ATT_FIND_INFORMATION_REQ,
                start,
                AttErrorCode::ATTRIBUTE_NOT_FOUND,
            )?)
        }
    }

    fn error_response(
        mut w: WriteCursor<'_>,
        opcode: u8,
        handle: u16,
        code: AttErrorCode,
    ) -> Result<usize, codec::Error> {
        w.reset();
        w.write(att::ATT_ERROR_RSP)?;
        w.write(opcode)?;
        w.write(handle)?;
        w.write(code)?;
        Ok(w.len())
    }

    fn handle_prepare_write(
        &self,
        connection: &Connection,
        buf: &mut [u8],
        handle: u16,
        offset: u16,
        value: &[u8],
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_PREPARE_WRITE_RSP)?;
        w.write(handle)?;
        w.write(offset)?;

        let err = self.att_table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    err = self.write_attribute_data(connection, offset as usize, att, value);
                    w.append(value)?;
                    break;
                }
            }
            err
        });

        match err {
            Ok(()) => Ok(w.len()),
            Err(e) => Ok(Self::error_response(w, att::ATT_PREPARE_WRITE_REQ, handle, e)?),
        }
    }

    fn handle_execute_write(&self, buf: &mut [u8], _flags: u8) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_EXECUTE_WRITE_RSP)?;
        Ok(w.len())
    }

    fn handle_read_blob(
        &self,
        connection: &Connection,
        buf: &mut [u8],
        handle: u16,
        offset: u16,
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_READ_BLOB_RSP)?;

        let err = self.att_table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    err = self.read_attribute_data(connection, offset as usize, att, w.write_buf());
                    if let Ok(n) = err {
                        w.commit(n)?;
                    }
                    break;
                }
            }
            err
        });

        match err {
            Ok(_) => Ok(w.len()),
            Err(e) => Ok(Self::error_response(w, att::ATT_READ_BLOB_REQ, handle, e)?),
        }
    }

    fn handle_read_multiple(&self, buf: &mut [u8], handles: &[u8]) -> Result<usize, codec::Error> {
        let w = WriteCursor::new(buf);
        Self::error_response(
            w,
            att::ATT_READ_MULTIPLE_REQ,
            u16::from_le_bytes([handles[0], handles[1]]),
            AttErrorCode::ATTRIBUTE_NOT_FOUND,
        )
    }

    /// Process an event and produce a response if necessary
    pub fn process(
        &self,
        connection: &Connection,
        packet: &AttClient,
        rx: &mut [u8],
    ) -> Result<Option<usize>, codec::Error> {
        let len = match packet {
            AttClient::Request(AttReq::ReadByType {
                start,
                end,
                attribute_type,
            }) => self.handle_read_by_type_req(connection, rx, *start, *end, attribute_type)?,

            AttClient::Request(AttReq::ReadByGroupType { start, end, group_type }) => {
                self.handle_read_by_group_type_req(connection, rx, *start, *end, group_type)?
            }
            AttClient::Request(AttReq::FindInformation {
                start_handle,
                end_handle,
            }) => self.handle_find_information(rx, *start_handle, *end_handle)?,

            AttClient::Request(AttReq::Read { handle }) => self.handle_read_req(connection, rx, *handle)?,

            AttClient::Command(AttCmd::Write { handle, data }) => {
                self.handle_write_cmd(connection, rx, *handle, data)?;
                0
            }

            AttClient::Request(AttReq::Write { handle, data }) => {
                self.handle_write_req(connection, rx, *handle, data)?
            }

            AttClient::Request(AttReq::ExchangeMtu { mtu }) => 0, // Done outside,

            AttClient::Request(AttReq::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            }) => self.handle_find_type_value(rx, *start_handle, *end_handle, *att_type, att_value)?,

            AttClient::Request(AttReq::PrepareWrite { handle, offset, value }) => {
                self.handle_prepare_write(connection, rx, *handle, *offset, value)?
            }

            AttClient::Request(AttReq::ExecuteWrite { flags }) => self.handle_execute_write(rx, *flags)?,

            AttClient::Request(AttReq::ReadBlob { handle, offset }) => {
                self.handle_read_blob(connection, rx, *handle, *offset)?
            }

            AttClient::Request(AttReq::ReadMultiple { handles }) => self.handle_read_multiple(rx, handles)?,

            AttClient::Confirmation(_) => 0,
        };
        if len > 0 {
            Ok(Some(len))
        } else {
            Ok(None)
        }
    }

    /// Get a reference to the attribute table
    pub fn table(&self) -> &AttributeTable<'values, M, ATT_MAX> {
        &self.att_table
    }

    /// Get the CCCD table for a connection
    pub fn get_cccd_table(&self, connection: &Connection) -> Option<CccdTable<CCCD_MAX>> {
        self.cccd_tables.get_cccd_table(&connection.peer_identity())
    }

    /// Set the CCCD table for a connection
    pub fn set_cccd_table(&self, connection: &Connection, table: CccdTable<CCCD_MAX>) {
        self.cccd_tables.set_cccd_table(&connection.peer_identity(), table);
    }
}
