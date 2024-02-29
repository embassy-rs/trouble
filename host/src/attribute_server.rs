use bt_hci::data::AclPacket;

use crate::{
    att::{self, Att, AttDecodeError, AttErrorCode, Uuid},
    attribute::{Attribute, PRIMARY_SERVICE_UUID16},
    byte_writer::ByteWriter,
};

/// The default value of MTU, which can be upgraded through negotiation
/// with the client.
pub const BASE_MTU: u16 = 23;

#[cfg(feature = "mtu128")]
pub const MTU: u16 = 128;

#[cfg(feature = "mtu256")]
pub const MTU: u16 = 256;

#[cfg(not(any(feature = "mtu128", feature = "mtu256")))]
pub const MTU: u16 = 23;

#[derive(Debug, PartialEq)]
pub enum WorkResult {
    DidWork,
    GotDisconnected,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AttributeServerError {
    AttError(AttDecodeError),
}

impl From<AttDecodeError> for AttributeServerError {
    fn from(err: AttDecodeError) -> Self {
        AttributeServerError::AttError(err)
    }
}

/*
#[derive(Debug)]
pub struct NotificationData {
    pub(crate) handle: u16,
    pub(crate) data: Data,
}

impl NotificationData {
    pub fn new(handle: u16, data: &[u8]) -> Self {
        Self {
            handle,
            data: Data::new(data),
        }
    }
}
*/

pub struct AttributeServer<'a, 'd> {
    pub(crate) buf: [u8; MTU as usize],
    pub(crate) mtu: u16,
    pub(crate) attributes: &'a mut [Attribute<'d>],
}

impl<'a, 'd> AttributeServer<'a, 'd> {
    /// Create a new instance of the AttributeServer
    ///
    /// When _NOT_ using the `crypto` feature you can pass a mutual reference to `bleps::no_rng::NoRng`
    pub fn new(attributes: &'a mut [Attribute<'d>]) -> AttributeServer<'a, 'd> {
        AttributeServer::new_inner(attributes)
    }

    fn new_inner(attributes: &'a mut [Attribute<'d>]) -> AttributeServer<'a, 'd> {
        trace!("{:#x}", &attributes);

        AttributeServer {
            mtu: BASE_MTU,
            attributes,
            buf: [0; MTU as usize],
        }
    }

    fn handle_read_by_type_req(
        &mut self,
        start: u16,
        end: u16,
        attribute_type: Uuid,
    ) -> Result<Option<&[u8]>, AttributeServerError> {
        let mut handle = start;
        let mut data = ByteWriter::new(&mut self.buf);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        data.reserve(2);
        for att in self.attributes.iter_mut() {
            //            trace!("Check attribute {:x} {}", att.uuid, att.handle);
            if att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                data.write_u16_le(att.handle);
                handle = att.handle;

                if att.data.readable() {
                    let mut writer = data.prepare();
                    err = att.data.read(0, writer.as_mut());
                    if let Ok(len) = &err {
                        writer.commit(*len);
                    }
                }

                //                debug!("found! {:x} {}", att.uuid, att.handle);
                break;
            }
        }

        match err {
            Ok(len) => {
                data.set(0, att::ATT_READ_BY_TYPE_RESPONSE_OPCODE);
                data.set(1, 2 + len as u8);
                Ok(Some(data.done()))
            }
            Err(e) => Ok(Self::error_response(
                data,
                att::ATT_READ_BY_TYPE_REQUEST_OPCODE,
                handle,
                e,
            )),
        }
    }

    fn handle_read_by_group_type_req(
        &mut self,
        start: u16,
        end: u16,
        group_type: Uuid,
    ) -> Result<Option<&[u8]>, AttributeServerError> {
        // TODO respond with all finds - not just one
        let mut handle = start;
        let mut data = ByteWriter::new(&mut self.buf);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        data.reserve(2);
        for att in self.attributes.iter_mut() {
            //            trace!("Check attribute {:x} {}", att.uuid, att.handle);
            if att.uuid == group_type && att.handle >= start && att.handle <= end {
                //                debug!("found! {:x} {}", att.uuid, att.handle);
                handle = att.handle;

                data.write_u16_le(att.handle);
                data.write_u16_le(att.last_handle_in_group);

                if att.data.readable() {
                    let mut writer = data.prepare();
                    err = att.data.read(0, writer.as_mut());
                    if let Ok(len) = &err {
                        writer.commit(*len);
                    }
                }
                break;
            }
        }

        match err {
            Ok(len) => {
                data.set(0, att::ATT_READ_BY_GROUP_TYPE_RESPONSE_OPCODE);
                data.set(1, 4 + len as u8);
                Ok(Some(data.done()))
            }
            Err(e) => Ok(Self::error_response(
                data,
                att::ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE,
                handle,
                e,
            )),
        }
    }

    pub fn get_characteristic_value(&mut self, handle: u16, offset: u16, buffer: &mut [u8]) -> Option<usize> {
        let att = &mut self.attributes[handle as usize];

        if att.data.readable() {
            att.data.read(offset as usize, buffer).ok()
        } else {
            None
        }
    }

    /*
    pub fn update_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error<T::Error>> {
        self.ble
            .write_command(Command::LeSetAdvertisingData { data }.encode().as_slice())
            .await?;
        self.ble
            .wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)
            .await?
            .check_command_completed()
    }

    pub fn disconnect(&mut self, reason: u8) -> Result<EventType, Error<T::Error>> {
        self.ble
            .write_command(
                Command::Disconnect {
                    connection_handle: 0,
                    reason,
                }
                .encode()
                .as_slice(),
            )
            .await?;
        Ok(EventType::Unknown)
    }*/

    fn handle_read_req(&mut self, handle: u16) -> Result<Option<&[u8]>, AttributeServerError> {
        let mut data = ByteWriter::new(&mut self.buf);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        data.write_u8(att::ATT_READ_RESPONSE_OPCODE);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    let mut b = data.prepare();
                    err = att.data.read(0, b.as_mut());
                    if let Ok(len) = err {
                        b.commit(len);
                    }
                }
                break;
            }
        }

        match err {
            Ok(_) => {
                data.truncate(self.mtu as usize);
                Ok(Some(data.done()))
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_REQUEST_OPCODE, handle, e)),
        }
    }

    fn handle_write_cmd(&mut self, handle: u16, data: &[u8]) -> Result<Option<&[u8]>, AttributeServerError> {
        // TODO: Generate event
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    // Write commands can't respond with an error.
                    att.data.write(0, data).unwrap();
                }
                break;
            }
        }
        Ok(None)
    }

    fn handle_write_req(&mut self, handle: u16, data: &[u8]) -> Result<Option<&[u8]>, AttributeServerError> {
        let mut err = Err(AttErrorCode::AttributeNotFound);
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    err = att.data.write(0, data);
                }
                break;
            }
        }

        match err {
            Ok(()) => Ok(Some(&[att::ATT_WRITE_RESPONSE_OPCODE])),
            Err(e) => Ok(Self::error_response(
                ByteWriter::new(&mut self.buf),
                att::ATT_WRITE_REQUEST_OPCODE,
                handle,
                e,
            )),
        }
    }

    fn handle_exchange_mtu(&mut self, mtu: u16) -> Result<Option<&[u8]>, AttributeServerError> {
        self.mtu = mtu.min(MTU);
        debug!("Requested MTU {}, returning {}", mtu, self.mtu);
        let mut b = ByteWriter::new(&mut self.buf);
        b.write_u8(att::ATT_EXCHANGE_MTU_RESPONSE_OPCODE);
        b.write_u16_le(self.mtu);
        Ok(Some(b.done()))
    }

    fn handle_find_type_value(
        &mut self,
        start: u16,
        _end: u16,
        _attr_type: u16,
        _attr_value: u16,
    ) -> Result<Option<&[u8]>, AttributeServerError> {
        // TODO for now just return an error

        // respond with error
        Ok(Self::error_response(
            ByteWriter::new(&mut self.buf),
            att::ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
            start,
            AttErrorCode::AttributeNotFound,
        ))
    }

    fn handle_find_information(&mut self, start: u16, end: u16) -> Result<Option<&[u8]>, AttributeServerError> {
        let mut w = ByteWriter::new(&mut self.buf);
        w.write_u8(att::ATT_FIND_INFORMATION_RSP_OPCODE);
        w.write_u8(0);

        for att in self.attributes.iter_mut() {
            if att.handle >= start && att.handle <= end {
                if w.get(1) == 0 {
                    w.set(1, att.uuid.get_type());
                } else if w.get(1) != att.uuid.get_type() {
                    break;
                }
                w.write_u16_le(att.handle);
                w.append_uuid(&att.uuid);
            }
        }

        if w.len() > 2 {
            Ok(Some(w.done()))
        } else {
            Ok(Self::error_response(
                w,
                att::ATT_FIND_INFORMATION_REQ_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ))
        }
    }

    fn error_response<'m>(mut w: ByteWriter<'m>, opcode: u8, handle: u16, code: AttErrorCode) -> Option<&'m [u8]> {
        w.truncate(0);
        w.write_u8(att::ATT_ERROR_RESPONSE_OPCODE);
        w.write_u8(opcode);
        w.write_u16_le(handle);
        w.write_u8(code as u8);
        Some(w.done())
    }

    fn handle_prepare_write(
        &mut self,
        handle: u16,
        offset: u16,
        value: &[u8],
    ) -> Result<Option<&[u8]>, AttributeServerError> {
        let mut w = ByteWriter::new(&mut self.buf);
        w.write_u8(att::ATT_PREPARE_WRITE_RESP_OPCODE);
        w.write_u16_le(handle);
        w.write_u16_le(offset);

        let mut err = Err(AttErrorCode::AttributeNotFound);
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    err = att.data.write(offset as usize, value);
                }
                w.append(value);
                break;
            }
        }

        match err {
            Ok(()) => Ok(Some(w.done())),
            Err(e) => Ok(Self::error_response(w, att::ATT_PREPARE_WRITE_REQ_OPCODE, handle, e)),
        }
    }

    fn handle_execute_write(&mut self, _flags: u8) -> Result<Option<&[u8]>, AttributeServerError> {
        Ok(Some(&[att::ATT_EXECUTE_WRITE_RESP_OPCODE]))
    }

    fn handle_read_blob(&mut self, handle: u16, offset: u16) -> Result<Option<&[u8]>, AttributeServerError> {
        let mut w = ByteWriter::new(&mut self.buf);
        w.write_u8(att::ATT_READ_BLOB_RESP_OPCODE);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    let mut buf = w.prepare();
                    err = att.data.read(offset as usize, buf.as_mut());
                    if let Ok(n) = &err {
                        buf.commit(*n);
                    }
                }
                break;
            }
        }

        match err {
            Ok(_) => Ok(Some(w.done())),
            Err(e) => Ok(Self::error_response(w, att::ATT_READ_BLOB_REQ_OPCODE, handle, e)),
        }
    }

    /// Process an adapter event and produce a response if necessary
    pub fn process(&mut self, packet: Att) -> Result<Option<&[u8]>, AttributeServerError> {
        match packet {
            Att::ReadByTypeReq {
                start,
                end,
                attribute_type,
            } => Ok(self.handle_read_by_type_req(start, end, attribute_type)?),

            Att::ReadByGroupTypeReq { start, end, group_type } => {
                Ok(self.handle_read_by_group_type_req(start, end, group_type)?)
            }
            Att::FindInformation {
                start_handle,
                end_handle,
            } => Ok(self.handle_find_information(start_handle, end_handle)?),

            Att::ReadReq { handle } => Ok(self.handle_read_req(handle)?),

            Att::WriteCmd { handle, data } => {
                self.handle_write_cmd(handle, data)?;
                Ok(None)
            }

            Att::WriteReq { handle, data } => Ok(self.handle_write_req(handle, data)?),

            Att::ExchangeMtu { mtu } => Ok(self.handle_exchange_mtu(mtu)?),

            Att::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            } => Ok(self.handle_find_type_value(start_handle, end_handle, att_type, att_value)?),

            Att::FindInformation {
                start_handle,
                end_handle,
            } => Ok(self.handle_find_information(start_handle, end_handle)?),

            Att::PrepareWriteReq { handle, offset, value } => Ok(self.handle_prepare_write(handle, offset, value)?),

            Att::ExecuteWriteReq { flags } => Ok(self.handle_execute_write(flags)?),

            Att::ReadBlobReq { handle, offset } => Ok(self.handle_read_blob(handle, offset)?),
        }
    }
}
