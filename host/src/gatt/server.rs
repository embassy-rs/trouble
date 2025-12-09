use super::{Attribute as _, AttributeKind, AttributeTable};
use crate::att::{self, AttClient, AttErrorCode, AttReq};
use crate::cursor::WriteCursor;
use crate::prelude::Connection;
use crate::types::uuid::Uuid;
use crate::{PacketPool, codec};

/// A GATT server capable of processing the GATT protocol using the provided table of attributes.
pub struct AttributeServer<T: AttributeTable> {
    table: T,
}

impl<T: AttributeTable> AttributeServer<T> {
    /// Create a new instance of the AttributeServer
    pub fn new(table: T) -> AttributeServer<T> {
        AttributeServer { table }
    }

    async fn handle_read_by_type_req<P: PacketPool>(
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
        let mut ret = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
        let mut it = self.table.iter();
        while let Some(att) = it.next() {
            // trace!("[read_by_type] Check attribute {:?} {}", att.uuid, att.handle);
            if &att.uuid() == attribute_type && att.handle() >= start && att.handle() <= end {
                body.write(att.handle())?;
                handle = att.handle();

                let new_ret = att.read(0, body.write_buf()).await.map_err(|e| e.into());
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
                    (Err(e), Err(_)) => {
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

        match ret {
            Ok(len) => {
                header.write(att::ATT_READ_BY_TYPE_RSP)?;
                header.write(2 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_BY_TYPE_REQ, handle, e)?),
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
        let mut it = self.table.iter();
        while let Some(att) = it.next() {
            if att.handle() >= start && att.handle() <= end && att.uuid() == attr_type {
                if let AttributeKind::Service = &att.kind() {
                    let mut uuid = [0; 16];
                    match att.read(0, &mut uuid).await {
                        Ok(len) => {
                            let uuid = &uuid[..len];
                            if uuid == attr_value {
                                if w.available() < 4 + uuid.len() {
                                    break;
                                }
                                w.write(att.handle())?;
                                w.write(att.last())?;
                            }
                        }
                        Err(e) => {
                            break;
                        }
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
                AttErrorCode::ATTRIBUTE_NOT_FOUND,
            )?)
        }
    }

    async fn handle_find_information(&self, buf: &mut [u8], start: u16, end: u16) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);

        let (mut header, mut body) = w.split(2)?;

        header.write(att::ATT_FIND_INFORMATION_RSP)?;
        let mut t = 0;

        let mut it = self.table.iter();
        while let Some(att) = it.next() {
            if att.handle() >= start && att.handle() <= end {
                if t == 0 {
                    t = att.uuid().get_type();
                } else if t != att.uuid().get_type() {
                    break;
                }
                body.write(att.handle())?;
                body.append(att.uuid().as_raw())?;
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
                AttErrorCode::ATTRIBUTE_NOT_FOUND,
            )?)
        }
    }

    /*
    async fn handle_read_by_group_type_req<P: PacketPool>(
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

    async fn handle_read_req<P: PacketPool>(
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

    async fn handle_write_cmd<P: PacketPool>(
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



    async fn handle_prepare_write<P: PacketPool>(
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

    async fn handle_execute_write(&self, buf: &mut [u8], _flags: u8) -> Result<usize, codec::Error> {
        let mut w = WriteCursor::new(buf);
        w.write(att::ATT_EXECUTE_WRITE_RSP)?;
        Ok(w.len())
    }

    async fn handle_read_blob<P: PacketPool>(
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
    }*/

    async fn handle_write_req<P: PacketPool>(
        &self,
        connection: &Connection<'_, P>,
        buf: &mut [u8],
        handle: u16,
        data: &[u8],
    ) -> Result<usize, codec::Error> {
        let mut err = Err(AttErrorCode::ATTRIBUTE_NOT_FOUND);
        let mut it = self.table.iter();
        while let Some(att) = it.next() {
            if att.handle() == handle {
                err = att.write(0, data).await.map_err(|e| e.into());
                break;
            }
        }

        let mut w = WriteCursor::new(buf);
        match err {
            Ok(()) => {
                w.write(att::ATT_WRITE_RSP)?;
                Ok(w.len())
            }
            Err(e) => Ok(Self::error_response(w, att::ATT_WRITE_REQ, handle, e)?),
        }
    }

    async fn handle_read_multiple(&self, buf: &mut [u8], handles: &[u8]) -> Result<usize, codec::Error> {
        let w = WriteCursor::new(buf);
        Self::error_response(
            w,
            att::ATT_READ_MULTIPLE_REQ,
            u16::from_le_bytes([handles[0], handles[1]]),
            AttErrorCode::ATTRIBUTE_NOT_FOUND,
        )
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

    /// Process an event and produce a response if necessary
    pub async fn process<P: PacketPool>(
        &self,
        connection: &Connection<'_, P>,
        packet: &AttClient<'_>,
        rx: &mut [u8],
    ) -> Result<Option<usize>, codec::Error> {
        let len = match packet {
            AttClient::Request(AttReq::ReadByType {
                start,
                end,
                attribute_type,
            }) => {
                self.handle_read_by_type_req(connection, rx, *start, *end, attribute_type)
                    .await?
            }

            // AttClient::Request(AttReq::ReadByGroupType { start, end, group_type }) => {
            //     self.handle_read_by_group_type_req(connection, rx, *start, *end, group_type)
            //         .await?
            // }
            AttClient::Request(AttReq::FindInformation {
                start_handle,
                end_handle,
            }) => self.handle_find_information(rx, *start_handle, *end_handle).await?,

            // AttClient::Request(AttReq::Read { handle }) => self.handle_read_req(connection, rx, *handle).await?,
            // AttClient::Command(AttCmd::Write { handle, data }) => {
            //     self.handle_write_cmd(connection, rx, *handle, data).await?;
            //     0
            // }
            AttClient::Request(AttReq::Write { handle, data }) => {
                self.handle_write_req(connection, rx, *handle, data).await?
            }

            AttClient::Request(AttReq::ExchangeMtu { mtu }) => 0, // Done outside,

            AttClient::Request(AttReq::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            }) => {
                self.handle_find_type_value(rx, *start_handle, *end_handle, *att_type, att_value)
                    .await?
            }

            // AttClient::Request(AttReq::PrepareWrite { handle, offset, value }) => {
            //     self.handle_prepare_write(connection, rx, *handle, *offset, value)
            //         .await?
            // }
            // AttClient::Request(AttReq::ExecuteWrite { flags }) => self.handle_execute_write(rx, *flags).await?,

            // AttClient::Request(AttReq::ReadBlob { handle, offset }) => {
            //     self.handle_read_blob(connection, rx, *handle, *offset).await?
            // }

            // AttClient::Request(AttReq::ReadMultiple { handles }) => self.handle_read_multiple(rx, handles).await?,
            AttClient::Confirmation(_) => 0,
            _ => unreachable!(),
        };
        if len > 0 { Ok(Some(len)) } else { Ok(None) }
    }
}
