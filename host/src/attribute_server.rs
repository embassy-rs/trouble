use crate::{
    att::{self, Att, AttDecodeError, AttErrorCode},
    attribute::Attribute,
    codec,
    cursor::WriteCursor,
    types::uuid::Uuid,
    ATT_MTU,
};

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

impl From<codec::Error> for AttributeServerError {
    fn from(err: codec::Error) -> Self {
        AttributeServerError::AttError(err.into())
    }
}

pub struct AttributeServer<'a, 'd> {
    pub(crate) buf: [u8; ATT_MTU],
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
        // trace!("{:#x}", &attributes);

        AttributeServer {
            mtu: ATT_MTU as u16,
            attributes,
            buf: [0; ATT_MTU],
        }
    }

    fn handle_read_by_type_req(
        &mut self,
        start: u16,
        end: u16,
        attribute_type: Uuid,
    ) -> Result<usize, AttributeServerError> {
        let mut handle = start;
        let mut data = WriteCursor::new(&mut self.buf);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        let (mut header, mut body) = data.split(2)?;
        for att in self.attributes.iter_mut() {
            //            trace!("Check attribute {:x} {}", att.uuid, att.handle);
            if att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                body.write(att.handle)?;
                handle = att.handle;

                if att.data.readable() {
                    let mut writer = body.write_buf();
                    err = att.data.read(0, writer.as_mut());
                    if let Ok(len) = &err {
                        writer.finish(*len)?;
                    }
                }

                //debug!("found! {:x} {}", att.uuid, att.handle);
                break;
            }
        }

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_TYPE_RESPONSE_OPCODE)?;
                header.write(2 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(
                data,
                att::ATT_READ_BY_TYPE_REQUEST_OPCODE,
                handle,
                e,
            )?),
        }
    }

    fn handle_read_by_group_type_req(
        &mut self,
        start: u16,
        end: u16,
        group_type: Uuid,
    ) -> Result<usize, AttributeServerError> {
        // TODO respond with all finds - not just one
        let mut handle = start;
        let mut data = WriteCursor::new(&mut self.buf);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        let (mut header, mut body) = data.split(2)?;
        for att in self.attributes.iter_mut() {
            //            trace!("Check attribute {:x} {}", att.uuid, att.handle);
            if att.uuid == group_type && att.handle >= start && att.handle <= end {
                //debug!("found! {:x} {}", att.uuid, att.handle);
                handle = att.handle;

                body.write(att.handle)?;
                body.write(att.last_handle_in_group)?;

                if att.data.readable() {
                    let mut writer = body.write_buf();
                    err = att.data.read(0, writer.as_mut());
                    if let Ok(len) = &err {
                        writer.finish(*len)?;
                    }
                }
                break;
            }
        }

        match err {
            Ok(len) => {
                header.write(att::ATT_READ_BY_GROUP_TYPE_RESPONSE_OPCODE)?;
                header.write(4 + len as u8)?;
                Ok(header.len() + body.len())
            }
            Err(e) => Ok(Self::error_response(
                data,
                att::ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE,
                handle,
                e,
            )?),
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

    fn handle_read_req(&mut self, handle: u16) -> Result<usize, AttributeServerError> {
        let mut data = WriteCursor::new(&mut self.buf);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        data.write(att::ATT_READ_RESPONSE_OPCODE)?;

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    let mut b = data.write_buf();
                    err = att.data.read(0, b.as_mut());
                    if let Ok(len) = err {
                        b.finish(len)?;
                    }
                }
                break;
            }
        }

        match err {
            Ok(_) => {
                data.truncate(self.mtu as usize)?;
                Ok(data.len())
            }
            Err(e) => Ok(Self::error_response(data, att::ATT_READ_REQUEST_OPCODE, handle, e)?),
        }
    }

    fn handle_write_cmd(&mut self, handle: u16, data: &[u8]) -> Result<usize, AttributeServerError> {
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
        Ok(0)
    }

    fn handle_write_req(&mut self, handle: u16, data: &[u8]) -> Result<usize, AttributeServerError> {
        let mut err = Err(AttErrorCode::AttributeNotFound);
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    err = att.data.write(0, data);
                }
                break;
            }
        }

        let mut w = WriteCursor::new(&mut self.buf);

        match err {
            Ok(()) => {
                w.write(att::ATT_WRITE_RESPONSE_OPCODE)?;
                Ok(w.len())
            }
            Err(e) => Ok(Self::error_response(w, att::ATT_WRITE_REQUEST_OPCODE, handle, e)?),
        }
    }

    fn handle_exchange_mtu(&mut self, mtu: u16) -> Result<usize, AttributeServerError> {
        self.mtu = mtu.min(ATT_MTU as u16);
        let mut b = WriteCursor::new(&mut self.buf);
        b.write(att::ATT_EXCHANGE_MTU_RESPONSE_OPCODE)?;
        b.write(self.mtu)?;
        Ok(b.len())
    }

    fn handle_find_type_value(
        &mut self,
        start: u16,
        _end: u16,
        _attr_type: u16,
        _attr_value: u16,
    ) -> Result<usize, AttributeServerError> {
        // TODO for now just return an error

        // respond with error
        Ok(Self::error_response(
            WriteCursor::new(&mut self.buf),
            att::ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
            start,
            AttErrorCode::AttributeNotFound,
        )?)
    }

    fn handle_find_information(&mut self, start: u16, end: u16) -> Result<usize, AttributeServerError> {
        let mut w = WriteCursor::new(&mut self.buf);

        let (mut header, mut body) = w.split(2)?;

        header.write(att::ATT_FIND_INFORMATION_RSP_OPCODE)?;
        let mut t = 0;

        for att in self.attributes.iter_mut() {
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
                att::ATT_FIND_INFORMATION_REQ_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            )?)
        }
    }

    fn error_response<'m>(
        mut w: WriteCursor<'m>,
        opcode: u8,
        handle: u16,
        code: AttErrorCode,
    ) -> Result<usize, codec::Error> {
        w.reset();
        w.write(att::ATT_ERROR_RESPONSE_OPCODE)?;
        w.write(opcode)?;
        w.write(handle)?;
        w.write(code as u8)?;
        Ok(w.len())
    }

    fn handle_prepare_write(&mut self, handle: u16, offset: u16, value: &[u8]) -> Result<usize, AttributeServerError> {
        let mut w = WriteCursor::new(&mut self.buf);
        w.write(att::ATT_PREPARE_WRITE_RESP_OPCODE)?;
        w.write(handle)?;
        w.write(offset)?;

        let mut err = Err(AttErrorCode::AttributeNotFound);
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    err = att.data.write(offset as usize, value);
                }
                w.append(value)?;
                break;
            }
        }

        match err {
            Ok(()) => Ok(w.len()),
            Err(e) => Ok(Self::error_response(w, att::ATT_PREPARE_WRITE_REQ_OPCODE, handle, e)?),
        }
    }

    fn handle_execute_write(&mut self, _flags: u8) -> Result<usize, AttributeServerError> {
        let mut w = WriteCursor::new(&mut self.buf);
        w.write(att::ATT_EXECUTE_WRITE_RESP_OPCODE)?;
        Ok(w.len())
    }

    fn handle_read_blob(&mut self, handle: u16, offset: u16) -> Result<usize, AttributeServerError> {
        let mut w = WriteCursor::new(&mut self.buf);
        w.write(att::ATT_READ_BLOB_RESP_OPCODE)?;
        let mut err = Err(AttErrorCode::AttributeNotFound);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    let mut buf = w.write_buf();
                    err = att.data.read(offset as usize, buf.as_mut());
                    if let Ok(n) = &err {
                        buf.finish(*n)?;
                    }
                }
                break;
            }
        }

        match err {
            Ok(_) => Ok(w.len()),
            Err(e) => Ok(Self::error_response(w, att::ATT_READ_BLOB_REQ_OPCODE, handle, e)?),
        }
    }

    /// Process an adapter event and produce a response if necessary
    pub fn process(&mut self, packet: Att) -> Result<Option<&[u8]>, AttributeServerError> {
        let len = match packet {
            Att::ReadByTypeReq {
                start,
                end,
                attribute_type,
            } => self.handle_read_by_type_req(start, end, attribute_type)?,

            Att::ReadByGroupTypeReq { start, end, group_type } => {
                self.handle_read_by_group_type_req(start, end, group_type)?
            }
            Att::FindInformation {
                start_handle,
                end_handle,
            } => self.handle_find_information(start_handle, end_handle)?,

            Att::ReadReq { handle } => self.handle_read_req(handle)?,

            Att::WriteCmd { handle, data } => {
                self.handle_write_cmd(handle, data)?;
                0
            }

            Att::WriteReq { handle, data } => self.handle_write_req(handle, data)?,

            Att::ExchangeMtu { mtu } => self.handle_exchange_mtu(mtu)?,

            Att::FindByTypeValue {
                start_handle,
                end_handle,
                att_type,
                att_value,
            } => self.handle_find_type_value(start_handle, end_handle, att_type, att_value)?,

            Att::PrepareWriteReq { handle, offset, value } => self.handle_prepare_write(handle, offset, value)?,

            Att::ExecuteWriteReq { flags } => self.handle_execute_write(flags)?,

            Att::ReadBlobReq { handle, offset } => self.handle_read_blob(handle, offset)?,
        };
        if len > 0 {
            Ok(Some(&self.buf[..len]))
        } else {
            Ok(None)
        }
    }
}
