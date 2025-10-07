use core::cell::RefCell;
use core::marker::PhantomData;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::att::{self, AttClient, AttCmd, AttErrorCode, AttReq};
use crate::attribute::{Attribute, AttributeData, AttributeTable, CCCD};
use crate::cursor::WriteCursor;
use crate::prelude::Connection;
use crate::types::uuid::Uuid;
use crate::{codec, Error, Identity, PacketPool};

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
            Err(Error::NotFound)
        })
    }
}

/// A GATT server capable of processing the GATT protocol using the provided table of attributes.
pub struct AttributeServer<
    'values,
    M: RawMutex,
    P: PacketPool,
    const ATT_MAX: usize,
    const CCCD_MAX: usize,
    const CONN_MAX: usize,
> {
    att_table: AttributeTable<'values, M, ATT_MAX>,
    cccd_tables: CccdTables<M, CCCD_MAX, CONN_MAX>,
    _p: PhantomData<P>, // Q: may we have a comment on the use of this?  Ties 'PacketPool', somehow.
}

pub(crate) mod sealed {
    use super::*;

    pub trait DynamicAttributeServer<P: PacketPool> {
        fn connect(&self, connection: &Connection<'_, P>) -> Result<(), Error>;
        fn disconnect(&self, connection: &Connection<'_, P>);
        fn process(
            &self,
            connection: &Connection<'_, P>,
            packet: &AttClient,
            rx: &mut [u8],
        ) -> Result<Option<usize>, Error>;
        fn should_notify(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool;
        fn set(&self, characteristic: u16, input: &[u8]) -> Result<(), Error>;
        fn update_identity(&self, identity: Identity) -> Result<(), Error>;
    }
}

/// Type erased attribute server
pub trait DynamicAttributeServer<P: PacketPool>: sealed::DynamicAttributeServer<P> {}

impl<M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CCCD_MAX: usize, const CONN_MAX: usize>
    DynamicAttributeServer<P> for AttributeServer<'_, M, P, ATT_MAX, CCCD_MAX, CONN_MAX>
{
}
impl<M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CCCD_MAX: usize, const CONN_MAX: usize>
    sealed::DynamicAttributeServer<P> for AttributeServer<'_, M, P, ATT_MAX, CCCD_MAX, CONN_MAX>
{
    fn connect(&self, connection: &Connection<'_, P>) -> Result<(), Error> {
        AttributeServer::connect(self, connection)
    }

    fn disconnect(&self, connection: &Connection<'_, P>) {
        self.cccd_tables.disconnect(&connection.peer_identity());
    }

    fn process(
        &self,
        connection: &Connection<'_, P>,
        packet: &AttClient,
        rx: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let res = AttributeServer::process(self, connection, packet, rx)?;
        Ok(res)
    }

    fn should_notify(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool {
        AttributeServer::should_notify(self, connection, cccd_handle)
    }

    fn set(&self, characteristic: u16, input: &[u8]) -> Result<(), Error> {
        self.att_table.set_raw(characteristic, input)
    }

    fn update_identity(&self, identity: Identity) -> Result<(), Error> {
        self.cccd_tables.update_identity(identity)
    }
}

impl<'values, M: RawMutex, P: PacketPool, const ATT_MAX: usize, const CCCD_MAX: usize, const CONN_MAX: usize>
    AttributeServer<'values, M, P, ATT_MAX, CCCD_MAX, CONN_MAX>
{
    /// Create a new instance of the AttributeServer
    pub fn new(
        att_table: AttributeTable<'values, M, ATT_MAX>,
    ) -> AttributeServer<'values, M, P, ATT_MAX, CCCD_MAX, CONN_MAX> {
        let cccd_tables = CccdTables::new(&att_table);
        AttributeServer {
            att_table,
            cccd_tables,
            _p: PhantomData,
        }
    }

    pub(crate) fn connect(&self, connection: &Connection<'_, P>) -> Result<(), Error> {
        self.cccd_tables.connect(&connection.peer_identity())
    }

    pub(crate) fn should_notify(&self, connection: &Connection<'_, P>, cccd_handle: u16) -> bool {
        self.cccd_tables.should_notify(&connection.peer_identity(), cccd_handle)
    }

    fn read_attribute_data(
        &self,
        connection: &Connection<'_, P>,
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
        connection: &Connection<'_, P>,
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
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        start: u16,
        end: u16,
        attribute_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        let (mut header, mut body) = data.split(2)?;
        let err = self.att_table.iterate(|mut it| {
            let mut ret = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                // trace!("[read_by_type] Check attribute {:?} {}", att.uuid, att.handle);
                if &att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                    body.write(att.handle)?;
                    handle = att.handle;

                    let new_ret = self.read_attribute_data(connection, 0, att, body.write_buf());
                    match (new_ret, ret) {
                        (Ok(first_length), Err(_)) => {
                            // First successful read, store this length, all subsequent ones must match it.
                            // debug!("[read_by_type] found first entry {:x?}, handle {}", att.uuid, handle);
                            ret = new_ret;
                            body.commit(first_length)?;
                        }
                        (Ok(new_length), Ok(old_length)) => {
                            // Any matching attribute after the first, verify the lengths are identical, if not break.
                            if new_length == old_length {
                                // debug!("[read_by_type] found equal length {}, handle {}", new_length, handle);
                                body.commit(new_length)?;
                            } else {
                                // We encountered a different length,  unwind the handle.
                                // debug!("[read_by_type] different length: {}, old: {}", new_length, old_length);
                                body.truncate(body.len() - 2);
                                // And then break to ensure we respond with the previously found entries.
                                break;
                            }
                        }
                        (Err(error_code), Ok(_old_length)) => {
                            // New read failed, but we had a previous value, return what we had thus far, truncate to
                            // remove the previously written handle.
                            body.truncate(body.len() - 2);
                            // We do silently drop the error here.
                            // debug!("[read_by_group] new error: {:?}, returning result thus far", error_code);
                            break;
                        }
                        (Err(_), Err(_)) => {
                            // Error on the first possible read, return this error.
                            ret = new_ret;
                            break;
                        }
                    }
                    // If we get here, we always have had a successful read, and we can check that we still have space
                    // left in the buffer to write the next entry if it exists.
                    if let Ok(expected_length) = ret {
                        if body.available() < expected_length + 2 {
                            break;
                        }
                    }
                }
            }
            ret
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
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        start: u16,
        end: u16,
        group_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        let mut handle = start;
        let mut data = WriteCursor::new(buf);
        let (mut header, mut body) = data.split(2)?;
        // Multiple entries can be returned in the response as long as they are of equal length.
        let err = self.att_table.iterate(|mut it| {
            // ret either holds the length of the attribute, or the error code encountered.
            let mut ret: Result<usize, AttErrorCode> = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
            while let Some(att) = it.next() {
                // trace!("[read_by_group] Check attribute {:x?} {}", att.uuid, att.handle);
                if &att.uuid == group_type && att.handle >= start && att.handle <= end {
                    // debug!("[read_by_group] found! {:x?} handle: {}", att.uuid, att.handle);
                    handle = att.handle;

                    body.write(att.handle)?;
                    body.write(att.last_handle_in_group)?;
                    let new_ret = self.read_attribute_data(connection, 0, att, body.write_buf());
                    match (new_ret, ret) {
                        (Ok(first_length), Err(_)) => {
                            // First successful read, store this length, all subsequent ones must match it.
                            // debug!("[read_by_group] found first entry {:x?}, handle {}", att.uuid, handle);
                            ret = new_ret;
                            body.commit(first_length)?;
                        }
                        (Ok(new_length), Ok(old_length)) => {
                            // Any matching attribute after the first, verify the lengths are identical, if not break.
                            if new_length == old_length {
                                // debug!("[read_by_group] found equal length {}, handle {}", new_length, handle);
                                body.commit(new_length)?;
                            } else {
                                // We encountered a different length,  unwind the handle and last_handle written.
                                // debug!("[read_by_group] different length: {}, old: {}", new_length, old_length);
                                body.truncate(body.len() - 4);
                                // And then break to ensure we respond with the previously found entries.
                                break;
                            }
                        }
                        (Err(error_code), Ok(_old_length)) => {
                            // New read failed, but we had a previous value, return what we had thus far, truncate to
                            // remove the previously written handle and last handle.
                            body.truncate(body.len() - 4);
                            // We do silently drop the error here.
                            // debug!("[read_by_group] new error: {:?}, returning result thus far", error_code);
                            break;
                        }
                        (Err(_), Err(_)) => {
                            // Error on the first possible read, return this error.
                            ret = new_ret;
                            break;
                        }
                    }
                    // If we get here, we always have had a successful read, and we can check that we still have space
                    // left in the buffer to write the next entry if it exists.
                    if let Ok(expected_length) = ret {
                        if body.available() < expected_length + 4 {
                            break;
                        }
                    }
                }
            }
            ret
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

    fn handle_read_req(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
    ) -> Result<usize, codec::Error> {
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
        connection: &Connection<'_, P>,
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
        connection: &Connection<'_, P>,
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
        connection: &Connection<'_, P>,
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
        connection: &Connection<'_, P>,
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
        connection: &Connection<'_, P>,
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
    pub fn get_cccd_table(&self, connection: &Connection<'_, P>) -> Option<CccdTable<CCCD_MAX>> {
        self.cccd_tables.get_cccd_table(&connection.peer_identity())
    }

    /// Set the CCCD table for a connection
    pub fn set_cccd_table(&self, connection: &Connection<'_, P>, table: CccdTable<CCCD_MAX>) {
        self.cccd_tables.set_cccd_table(&connection.peer_identity(), table);
    }
}

#[cfg(test)]
mod tests {
    use core::task::Poll;

    use bt_hci::param::{AddrKind, BdAddr, ConnHandle, LeConnRole};
    use embassy_sync::blocking_mutex::raw::NoopRawMutex;

    use super::*;
    use crate::connection_manager::tests::{setup, ADDR_1};
    use crate::prelude::*;

    #[test]
    fn test_attribute_server_last_handle_of_group() {
        // This test comes from a situation where a service had exactly 16 handles, this resulted in the
        // last_handle_in_group field of the ReadByGroupType response was 16 aligned (96 to be exact), in this situation
        // the next request will start at 96 + 1, which was one handle beyond the start of the next service.
        //
        // Snippet from the original failure mode:
        // WARN  trouble_host::attribute_server] Looking for group: Uuid16([0, 28]) between 75 and 65535
        // DEBUG trouble_host::attribute_server] [read_by_group] found! Uuid16([0, 28]) 80
        // DEBUG trouble_host::attribute_server] last_handle_in_group: 96
        // DEBUG trouble_host::attribute_server] read_attribute_data: Ok(16)
        // TRACE trouble_host::host] [host] granted send packets = 1, len = 30
        // TRACE trouble_host::host] [host] sent acl packet len = 26
        // TRACE trouble_host::host] [host] inbound l2cap header channel = 4, fragment len = 7, total = 7
        // INFO  main_ble::ble_bas_peripheral] [gatt-attclient]: ReadByGroupType { start: 97, end: 65535, group_type: Uuid16([0, 40]) }
        // INFO  main_ble::ble_bas_peripheral] [gatt] other event
        // WARN  trouble_host::attribute_server] Looking for group: Uuid16([0, 28]) between 97 and 65535
        // WARN  trouble_host::attribute_server] [read_by_group] Dit not find attribute Uuid16([0, 28]) between 97  65535

        // The request:
        // INFO  main_ble::ble_bas_peripheral] [gatt-attclient]: ReadByGroupType { start: 97, end: 65535, group_type: Uuid16([0, 40]) }
        // In trace, the "group_type: Uuid16([0, 40]) }" is decimal, so this becomes group type 0x2800, which is the
        // primary service group.
        let primary_service_group_type = Uuid::new_short(0x2800);

        let _ = env_logger::try_init();
        const MAX_ATTRIBUTES: usize = 1024;
        const CONNECTIONS_MAX: usize = 3;
        const CCCD_MAX: usize = 1024;
        const L2CAP_CHANNELS_MAX: usize = 5;
        type FacadeDummyType = [u8; 0];

        // Instead of only checking the failure mode, we fuzz the length of the interior service to cross over several
        // multiples of 16.
        for interior_handle_count in 0..=64u8 {
            debug!("Testing with interior handle count of {}", interior_handle_count);

            // Create a new table.
            let mut table: AttributeTable<'_, NoopRawMutex, { MAX_ATTRIBUTES }> = AttributeTable::new();

            // Add a first service, contents don't really matter, but the issue doesn't manifest without this.
            {
                let svc = table.add_service(Service {
                    uuid: Uuid::new_long([10; 16]).into(),
                });
            }

            // Add an interior service that has a varying length.
            {
                let mut svc = table.add_service(Service {
                    uuid: Uuid::new_long([0; 16]).into(),
                });

                for c in 0..interior_handle_count {
                    let _service_instance = svc
                        .add_characteristic_ro::<[u8; 2], _>(Uuid::new_long([c; 16]), &[0, 0])
                        .build();
                }
            }
            // Now add the service at the end, contents don't really matter.
            {
                table.add_service(Service {
                    uuid: Uuid::new_long([8; 16]).into(),
                });
            }

            // Print the table for debugging.
            table.iterate(|mut it| {
                while let Some(att) = it.next() {
                    let handle = att.handle;
                    let uuid = &att.uuid;
                    //"last_handle_in_group for 0x{:0>4x?}, 0x{:0>2x?}  0x{:0>2x?}", // "Unknown display hint: '0>4x?' by IDE; does this not get tested? #TEMP
                    trace!(
                        "last_handle_in_group for 0x{:04x}, 0x{:02x}  0x{:02x}", // not sure which is the intended format, here!
                        handle,
                        uuid,
                        att.last_handle_in_group
                    );
                }
            });

            // Create a server.
            let server = AttributeServer::<_, DefaultPacketPool, MAX_ATTRIBUTES, CCCD_MAX, CONNECTIONS_MAX>::new(table);

            // Create the connection manager.
            let mgr = setup();

            // Try to connect.
            assert!(mgr.poll_accept(LeConnRole::Peripheral, &[], None).is_pending());
            unwrap!(mgr.connect(
                ConnHandle::new(0),
                AddrKind::RANDOM,
                BdAddr::new(ADDR_1),
                LeConnRole::Peripheral
            ));

            if let Poll::Ready(conn_handle) = mgr.poll_accept(LeConnRole::Peripheral, &[], None) {
                // We now have a connection, we can send the mocked requests to our attribute server.
                let mut buffer = [0u8; 64];

                let mut start = 0;
                let end = u16::MAX;
                // There are always three services that we should be able to discover.
                for _ in 0..3 {
                    let length = server
                        .handle_read_by_group_type_req(
                            &conn_handle,
                            &mut buffer,
                            start,
                            end,
                            &primary_service_group_type,
                        )
                        .unwrap();
                    let response = &buffer[0..length];
                    #[cfg(false)] // bad format
                    trace!("  0x{:0>2x?}", response);
                    trace!("  0x{:02x}", response);
                    // It should be a successful response, because the service should be found, this will assert if
                    // we failed to retrieve the third service.
                    assert_eq!(response[0], att::ATT_READ_BY_GROUP_TYPE_RSP);
                    // The last handle of this group is at byte 4 & 5, so retrieve that and update the start for the
                    // next cycle. We only check the first response here, and ignore any others that may be in the
                    // response.
                    let last_handle = u16::from_le_bytes([response[4], response[5]]);
                    start = last_handle + 1;
                }
            } else {
                panic!("expected connection to be accepted");
            };
        }
    }
}
