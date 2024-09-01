use core::cell::RefCell;

use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::att::{self, AttErrorCode, AttReq};
use crate::attribute::{AttributeData, AttributeTable};
use crate::codec;
use crate::cursor::WriteCursor;
use crate::types::uuid::Uuid;

#[derive(Debug, PartialEq)]
pub enum WorkResult {
    DidWork,
    GotDisconnected,
}

const MAX_NOTIFICATIONS: usize = 4;
pub struct NotificationTable<const ENTRIES: usize> {
    state: [(u16, ConnHandle); ENTRIES],
}

pub struct AttributeServer<'c, 'd, M: RawMutex, const MAX: usize> {
    pub(crate) table: &'c AttributeTable<'d, M, MAX>,
    pub(crate) notification: Mutex<M, RefCell<NotificationTable<MAX_NOTIFICATIONS>>>,
}

impl<'c, 'd, M: RawMutex, const MAX: usize> AttributeServer<'c, 'd, M, MAX> {
    /// Create a new instance of the AttributeServer
    pub fn new(table: &'c AttributeTable<'d, M, MAX>) -> AttributeServer<'c, 'd, M, MAX> {
        AttributeServer {
            table,
            notification: Mutex::new(RefCell::new(NotificationTable {
                state: [(0, ConnHandle::new(0)); 4],
            })),
        }
    }

    pub(crate) fn should_notify(&self, conn: ConnHandle, cccd_handle: u16) -> bool {
        self.notification.lock(|n| {
            let n = n.borrow();
            for entry in n.state.iter() {
                if entry.0 == cccd_handle && entry.1 == conn {
                    return true;
                }
            }
            false
        })
    }

    fn set_notify(&self, conn: ConnHandle, cccd_handle: u16, enable: bool) {
        self.notification.lock(|n| {
            let mut n = n.borrow_mut();
            if enable {
                for entry in n.state.iter_mut() {
                    if entry.0 == 0 {
                        entry.0 = cccd_handle;
                        entry.1 = conn;
                        return;
                    }
                }
            } else {
                for entry in n.state.iter_mut() {
                    if entry.0 == cccd_handle && entry.1 == conn {
                        entry.0 = 0;
                        entry.1 = ConnHandle::new(0);
                        return;
                    }
                }
            }
        })
    }

    fn handle_read_by_type_req(
        &self,
        buf: &mut [u8],
        start: u16,
        end: u16,
        attribute_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        let (mut header, mut body) = data.split(2)?;
        let err = self.table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                //trace!("Check attribute {:?} {}", att.uuid, att.handle);
                if &att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                    body.write(att.handle)?;
                    handle = att.handle;

                    if att.data.readable() {
                        err = att.data.read(0, body.write_buf());
                        if let Ok(len) = &err {
                            body.commit(*len)?;
                        }
                    }

                    // debug!("found! {:?} {}", att.uuid, att.handle);
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
        buf: &mut [u8],
        start: u16,
        end: u16,
        group_type: &Uuid,
    ) -> Result<usize, codec::Error> {
        // TODO respond with all finds - not just one
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        let (mut header, mut body) = data.split(2)?;
        let err = self.table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                //            trace!("Check attribute {:x} {}", att.uuid, att.handle);
                if &att.uuid == group_type && att.handle >= start && att.handle <= end {
                    //debug!("found! {:x} {}", att.uuid, att.handle);
                    handle = att.handle;

                    body.write(att.handle)?;
                    body.write(att.last_handle_in_group)?;

                    if att.data.readable() {
                        err = att.data.read(0, body.write_buf());
                        if let Ok(len) = &err {
                            body.commit(*len)?;
                        }
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

    fn handle_read_req(&self, buf: &mut [u8], handle: u16) -> Result<usize, codec::Error> {
        let mut data = WriteCursor::new(buf);

        data.write(att::ATT_READ_RSP)?;

        let err = self.table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.readable() {
                        err = att.data.read(0, data.write_buf());
                        if let Ok(len) = err {
                            data.commit(len)?;
                        }
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

    fn handle_write_cmd(&self, buf: &mut [u8], handle: u16, data: &[u8]) -> Result<usize, codec::Error> {
        // TODO: Generate event
        self.table.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.writable() {
                        // Write commands can't respond with an error.
                        att.data.write(0, data).unwrap();
                    }
                    break;
                }
            }
            Ok(0)
        })
    }

    fn handle_write_req(
        &self,
        conn: ConnHandle,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
    ) -> Result<usize, codec::Error> {
        let err = self.table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.writable() {
                        err = att.data.write(0, data);
                        if err.is_ok() {
                            if let AttributeData::Cccd {
                                notifications,
                                indications,
                            } = att.data
                            {
                                self.set_notify(conn, handle, notifications);
                            }
                        }
                    }
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
        self.table.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle >= start && att.handle <= end && att.uuid == attr_type {
                    if let AttributeData::Service { uuid } = &att.data {
                        if uuid.as_raw() == attr_value {
                            if w.available() < 4 + uuid.as_raw().len() {
                                break;
                            }
                            w.write(att.handle)?;
                            w.write(att.last_handle_in_group)?;
                            w.write_ref(uuid)?;
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
                AttErrorCode::AttributeNotFound,
            )?)
        }
    }

    fn handle_find_information(&self, buf: &mut [u8], start: u16, end: u16) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);

        let (mut header, mut body) = w.split(2)?;

        header.write(att::ATT_FIND_INFORMATION_RSP)?;
        let mut t = 0;

        self.table.iterate(|mut it| {
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
                AttErrorCode::AttributeNotFound,
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
        w.write(code as u8)?;
        Ok(w.len())
    }

    fn handle_prepare_write(
        &self,
        buf: &mut [u8],
        handle: u16,
        offset: u16,
        value: &[u8],
    ) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_PREPARE_WRITE_RSP)?;
        w.write(handle)?;
        w.write(offset)?;

        let err = self.table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.writable() {
                        err = att.data.write(offset as usize, value);
                    }
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

    fn handle_read_blob(&self, buf: &mut [u8], handle: u16, offset: u16) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_READ_BLOB_RSP)?;

        let err = self.table.iterate(|mut it| {
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.readable() {
                        err = att.data.read(offset as usize, w.write_buf());
                        if let Ok(n) = &err {
                            w.commit(*n)?;
                        }
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
            AttErrorCode::AttributeNotFound,
        )
    }

    /// Process an event and produce a response if necessary
    pub fn process(&self, conn: ConnHandle, packet: &AttReq, rx: &mut [u8]) -> Result<Option<usize>, codec::Error> {
        let len = match packet {
            AttReq::ReadByType {
                start,
                end,
                attribute_type,
            } => self.handle_read_by_type_req(rx, *start, *end, attribute_type)?,

            AttReq::ReadByGroupType { start, end, group_type } => {
                self.handle_read_by_group_type_req(rx, *start, *end, group_type)?
            }
            AttReq::FindInformation {
                start_handle,
                end_handle,
            } => self.handle_find_information(rx, *start_handle, *end_handle)?,

            AttReq::Read { handle } => self.handle_read_req(rx, *handle)?,

            AttReq::WriteCmd { handle, data } => {
                self.handle_write_cmd(rx, *handle, data)?;
                0
            }

            AttReq::Write { handle, data } => self.handle_write_req(conn, rx, *handle, data)?,

            AttReq::ExchangeMtu { mtu } => 0, // Done outside,

            AttReq::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            } => self.handle_find_type_value(rx, *start_handle, *end_handle, *att_type, att_value)?,

            AttReq::PrepareWrite { handle, offset, value } => self.handle_prepare_write(rx, *handle, *offset, value)?,

            AttReq::ExecuteWrite { flags } => self.handle_execute_write(rx, *flags)?,

            AttReq::ReadBlob { handle, offset } => self.handle_read_blob(rx, *handle, *offset)?,

            AttReq::ReadMultiple { handles } => self.handle_read_multiple(rx, handles)?,
        };
        if len > 0 {
            Ok(Some(len))
        } else {
            Ok(None)
        }
    }
}
