use core::cell::RefCell;

use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::blocking_mutex::Mutex;

use crate::att::{self, AttErrorCode, AttReq};
use crate::attribute::{AttributeData, AttributeTable};
use crate::codec;
use crate::cursor::WriteCursor;
use crate::prelude::AttrDataHandler;
use crate::types::uuid::Uuid;

/// A callback trait for performing operations on attributes
pub trait AttrHandler {
    /// Read data for an attribute
    ///
    /// # Arguments
    /// - `uuid`: The UUID of the attribute
    /// - `handle`: The handle of the attribute
    /// - `offset`: The offset to read from
    /// - `data`: The buffer to write the data to
    ///
    /// Return the number of bytes read
    async fn read(&mut self, uuid: &Uuid, handle: u16, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode>;

    /// Write data to an attribute
    ///
    /// # Arguments
    /// - `uuid`: The UUID of the attribute
    /// - `handle`: The handle of the attribute
    /// - `offset`: The offset to write to
    /// - `data`: The data to write
    async fn write(&mut self, uuid: &Uuid, handle: u16, offset: usize, data: &[u8]) -> Result<(), AttErrorCode>;
}

impl<T> AttrHandler for &mut T
where
    T: AttrHandler,
{
    async fn read(&mut self, uuid: &Uuid, handle: u16, offset: usize, data: &mut [u8]) -> Result<usize, AttErrorCode> {
        (**self).read(uuid, handle, offset, data).await
    }

    async fn write(&mut self, uuid: &Uuid, handle: u16, offset: usize, data: &[u8]) -> Result<(), AttErrorCode> {
        (**self).write(uuid, handle, offset, data).await
    }
}

#[derive(Debug, PartialEq)]
pub enum WorkResult {
    DidWork,
    GotDisconnected,
}

const MAX_NOTIFICATIONS: usize = 4;
pub struct NotificationTable<const ENTRIES: usize> {
    state: [(u16, ConnHandle); ENTRIES],
}

pub struct AttributeServer<'c, M: RawMutex, const MAX: usize> {
    pub(crate) table: &'c AttributeTable<M, MAX>,
    pub(crate) notification: Mutex<M, RefCell<NotificationTable<MAX_NOTIFICATIONS>>>,
}

impl<'c, M: RawMutex, const MAX: usize> AttributeServer<'c, M, MAX> {
    /// Create a new instance of the AttributeServer
    pub fn new(table: &'c AttributeTable<M, MAX>) -> AttributeServer<'c, M, MAX> {
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

    async fn handle_read_by_type_req<R>(
        &self,
        buf: &mut [u8],
        start: u16,
        end: u16,
        attribute_type: &Uuid,
        mut read: R,
    ) -> Result<usize, codec::Error>
    where
        R: AttrHandler,
    {
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        let (mut header, mut body) = data.split(2)?;
        let err = async {
            let mut table = self.table.lock().await;
            let mut it = table.attr_iter();

            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                //trace!("Check attribute {:?} {}", att.uuid, att.handle);
                if &att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                    body.write(att.handle)?;
                    handle = att.handle;

                    if att.data.readable() {
                        err = att
                            .data
                            .read(
                                0,
                                body.write_buf(),
                                &mut AttrDataHandler::new(&mut read, &att.uuid, att.handle),
                            )
                            .await;
                        if let Ok(len) = &err {
                            body.commit(*len)?;
                        }
                    }

                    // debug!("found! {:?} {}", att.uuid, att.handle);
                    break;
                }
            }
            err
        }
        .await;

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_TYPE_RSP)?;
                header.write(2 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_BY_TYPE_REQ, handle, e)?),
        }
    }

    async fn handle_read_by_group_type_req<R>(
        &self,
        buf: &mut [u8],
        start: u16,
        end: u16,
        group_type: &Uuid,
        mut read: R,
    ) -> Result<usize, codec::Error>
    where
        R: AttrHandler,
    {
        // TODO respond with all finds - not just one
        let mut handle = start;
        let mut data = WriteCursor::new(buf);

        let (mut header, mut body) = data.split(2)?;
        let err = async {
            let mut table = self.table.lock().await;
            let mut it = table.attr_iter();
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                //            trace!("Check attribute {:x} {}", att.uuid, att.handle);
                if &att.uuid == group_type && att.handle >= start && att.handle <= end {
                    //debug!("found! {:x} {}", att.uuid, att.handle);
                    handle = att.handle;

                    body.write(att.handle)?;
                    body.write(att.last_handle_in_group)?;

                    if att.data.readable() {
                        err = att
                            .data
                            .read(
                                0,
                                body.write_buf(),
                                &mut AttrDataHandler::new(&mut read, &att.uuid, att.handle),
                            )
                            .await;
                        if let Ok(len) = &err {
                            body.commit(*len)?;
                        }
                    }
                    break;
                }
            }
            err
        }
        .await;

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_GROUP_TYPE_RSP)?;
                header.write(4 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_BY_GROUP_TYPE_REQ, handle, e)?),
        }
    }

    async fn handle_read_req<R>(&self, buf: &mut [u8], handle: u16, mut read: R) -> Result<usize, codec::Error>
    where
        R: AttrHandler,
    {
        let mut data = WriteCursor::new(buf);

        data.write(att::ATT_READ_RSP)?;

        let err = async {
            let mut table = self.table.lock().await;
            let mut it = table.attr_iter();
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.readable() {
                        err = att
                            .data
                            .read(
                                0,
                                data.write_buf(),
                                &mut AttrDataHandler::new(&mut read, &att.uuid, att.handle),
                            )
                            .await;
                        if let Ok(len) = err {
                            data.commit(len)?;
                        }
                    }
                    break;
                }
            }
            err
        }
        .await;

        match err {
            Ok(_) => Ok(data.len()),
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_REQ, handle, e)?),
        }
    }

    async fn handle_write_cmd<T>(
        &self,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
        mut handler: T,
    ) -> Result<usize, codec::Error>
    where
        T: AttrHandler,
    {
        // TODO: Generate event
        let mut table = self.table.lock().await;
        let mut it = table.attr_iter();
        while let Some(att) = it.next() {
            if att.handle == handle {
                if att.data.writable() {
                    // Write commands can't respond with an error.
                    att.data
                        .write(0, data, &mut AttrDataHandler::new(&mut handler, &att.uuid, att.handle))
                        .await
                        .unwrap();
                }
                break;
            }
        }
        Ok(0)
    }

    async fn handle_write_req<T>(
        &self,
        conn: ConnHandle,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
        mut handler: T,
    ) -> Result<usize, codec::Error>
    where
        T: AttrHandler,
    {
        let err = async {
            let mut table = self.table.lock().await;
            let mut it = table.attr_iter();
            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.writable() {
                        err = att
                            .data
                            .write(0, data, &mut AttrDataHandler::new(&mut handler, &att.uuid, att.handle))
                            .await;
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
        }
        .await;

        let mut w = WriteCursor::new(buf);
        match err {
            Ok(()) => {
                w.write(att::ATT_WRITE_RSP)?;
                Ok(w.len())
            }
            Err(e) => Ok(Self::error_response(w, att::ATT_WRITE_REQ, handle, e)?),
        }
    }

    async fn handle_find_type_value(
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

        let mut table = self.table.lock().await;
        let mut it = table.attr_iter();

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

    async fn handle_find_information(&self, buf: &mut [u8], start: u16, end: u16) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);

        let (mut header, mut body) = w.split(2)?;

        header.write(att::ATT_FIND_INFORMATION_RSP)?;
        let mut t = 0;

        let mut table = self.table.lock().await;
        let mut it = table.attr_iter();

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

    async fn handle_prepare_write<T>(
        &self,
        buf: &mut [u8],
        handle: u16,
        offset: u16,
        value: &[u8],
        mut handler: T,
    ) -> Result<usize, codec::Error>
    where
        T: AttrHandler,
    {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_PREPARE_WRITE_RSP)?;
        w.write(handle)?;
        w.write(offset)?;

        let err = async {
            let mut table = self.table.lock().await;
            let mut it = table.attr_iter();

            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.writable() {
                        err = att
                            .data
                            .write(
                                offset as usize,
                                value,
                                &mut AttrDataHandler::new(&mut handler, &att.uuid, att.handle),
                            )
                            .await;
                    }
                    w.append(value)?;
                    break;
                }
            }
            err
        }
        .await;

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

    async fn handle_read_blob<R>(
        &self,
        buf: &mut [u8],
        handle: u16,
        offset: u16,
        mut read: R,
    ) -> Result<usize, codec::Error>
    where
        R: AttrHandler,
    {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_READ_BLOB_RSP)?;

        let err = async {
            let mut table = self.table.lock().await;
            let mut it = table.attr_iter();

            let mut err = Err(AttErrorCode::AttributeNotFound);
            while let Some(att) = it.next() {
                if att.handle == handle {
                    if att.data.readable() {
                        err = att
                            .data
                            .read(
                                offset as usize,
                                w.write_buf(),
                                &mut AttrDataHandler::new(&mut read, &att.uuid, att.handle),
                            )
                            .await;
                        if let Ok(n) = &err {
                            w.commit(*n)?;
                        }
                    }
                    break;
                }
            }
            err
        }
        .await;

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
    pub async fn process<T>(
        &self,
        conn: ConnHandle,
        packet: &AttReq<'_>,
        rx: &mut [u8],
        mut handler: T,
    ) -> Result<Option<usize>, codec::Error>
    where
        T: AttrHandler,
    {
        let len = match packet {
            AttReq::ReadByType {
                start,
                end,
                attribute_type,
            } => {
                self.handle_read_by_type_req(rx, *start, *end, attribute_type, &mut handler)
                    .await?
            }

            AttReq::ReadByGroupType { start, end, group_type } => {
                self.handle_read_by_group_type_req(rx, *start, *end, group_type, &mut handler)
                    .await?
            }
            AttReq::FindInformation {
                start_handle,
                end_handle,
            } => self.handle_find_information(rx, *start_handle, *end_handle).await?,

            AttReq::Read { handle } => self.handle_read_req(rx, *handle, &mut handler).await?,

            AttReq::WriteCmd { handle, data } => {
                self.handle_write_cmd(rx, *handle, data, &mut handler).await?;
                0
            }

            AttReq::Write { handle, data } => self.handle_write_req(conn, rx, *handle, data, &mut handler).await?,

            AttReq::ExchangeMtu { mtu } => 0, // Done outside,

            AttReq::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            } => {
                self.handle_find_type_value(rx, *start_handle, *end_handle, *att_type, att_value)
                    .await?
            }

            AttReq::PrepareWrite { handle, offset, value } => {
                self.handle_prepare_write(rx, *handle, *offset, value, &mut handler)
                    .await?
            }

            AttReq::ExecuteWrite { flags } => self.handle_execute_write(rx, *flags)?,

            AttReq::ReadBlob { handle, offset } => self.handle_read_blob(rx, *handle, *offset, &mut handler).await?,

            AttReq::ReadMultiple { handles } => self.handle_read_multiple(rx, handles)?,
        };
        if len > 0 {
            Ok(Some(len))
        } else {
            Ok(None)
        }
    }
}
