use bt_hci::data::AclPacket;

use crate::{
    att::{
        self, Att, AttDecodeError, AttErrorCode, Uuid, ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
        ATT_FIND_INFORMATION_REQ_OPCODE, ATT_PREPARE_WRITE_REQ_OPCODE, ATT_READ_BLOB_REQ_OPCODE,
        ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE, ATT_READ_BY_TYPE_REQUEST_OPCODE, ATT_READ_REQUEST_OPCODE,
        ATT_WRITE_REQUEST_OPCODE,
    },
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
        info!(
            "TYPE REQ (start = {}, end = {}, type = {:x})",
            start, end, attribute_type
        );

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
                        info!("write {} bytes of attr data", len);
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
            }
            Err(e) => {
                data.set(0, att::ATT_ERROR_RESPONSE_OPCODE);
                data.set(1, att::ATT_READ_BY_TYPE_REQUEST_OPCODE);
                data.write_u16_le(handle);
                data.write_u8(e as u8);
            }
        }
        Ok(Some(data.done()))
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
        info!(
            "GROUP TYPE REQ (start = {}, end = {}, type = {:x})",
            start, end, group_type
        );

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
            }
            Err(e) => {
                data.set(0, att::ATT_ERROR_RESPONSE_OPCODE);
                data.set(1, att::ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE);
                data.write_u16_le(handle);
                data.write_u8(e as u8);
            }
        }
        Ok(Some(data.done()))
    }

    /*
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



    fn handle_read_req(&mut self, handle: u16) -> Result<Att, AttributeServerError> {
        let mut data = Data::new_att_read_response();
        let mut err = Err(AttErrorCode::AttributeNotFound);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    err = att.data.read(0, data.as_slice_mut());
                    if let Ok(len) = err {
                        data.append_len(len);
                    }
                }
                break;
            }
        }

        let response = match err {
            Ok(_) => {
                data.limit_len(self.mtu as usize);
                data
            }
            Err(e) => Data::new_att_error_response(ATT_READ_REQUEST_OPCODE, handle, e),
        };

        Ok(self.response(response))
    }

    fn handle_write_cmd(&mut self, handle: u16, data: Data) -> Result<(), AttributeServerError> {
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    // Write commands can't respond with an error.
                    att.data.write(0, data.as_slice()).unwrap();
                }
                break;
            }
        }
        Ok(())
    }

    fn handle_write_req(&mut self, handle: u16, data: Data) -> Result<AclPacket, AttributeServerError> {
        let mut err = Err(AttErrorCode::AttributeNotFound);
        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    err = att.data.write(0, data.as_slice());
                }
                break;
            }
        }

        let response = match err {
            Ok(()) => Data::new_att_write_response(),
            Err(e) => Data::new_att_error_response(ATT_WRITE_REQUEST_OPCODE, handle, e),
        };
        Ok(self.response(response))
    }

    fn handle_exchange_mtu(&mut self, mtu: u16) -> Result<AclPacket, AttributeServerError> {
        self.mtu = mtu.min(MTU);
        debug!("Requested MTU {}, returning {}", mtu, self.mtu);
        Ok(self.response(Data::new_att_exchange_mtu_response(self.mtu)))
    }

    fn handle_find_type_value(
        &mut self,
        start: u16,
        _end: u16,
        _attr_type: u16,
        _attr_value: u16,
    ) -> Result<AclPacket, AttributeServerError> {
        // TODO for now just return an error

        // respond with error
        Ok(self.response(Data::new_att_error_response(
            ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
            start,
            AttErrorCode::AttributeNotFound,
        )))
    }

    fn handle_find_information(&mut self, start: u16, end: u16) -> Result<AclPacket, AttributeServerError> {
        let mut data = Data::new_att_find_information_response();

        for att in self.attributes.iter_mut() {
            trace!("Check attribute {:x} {}", att.uuid, att.handle);
            if att.handle >= start && att.handle <= end {
                if !data.append_att_find_information_response(att.handle, &att.uuid) {
                    break;
                }
                debug!("found! {:x} {}", att.uuid, att.handle);
            }
        }

        if data.has_att_find_information_response_data() {
            return Ok(self.response(data));
        }

        debug!("not found");

        // respond with error
        Ok(self.response(Data::new_att_error_response(
            ATT_FIND_INFORMATION_REQ_OPCODE,
            start,
            AttErrorCode::AttributeNotFound,
        )))
    }

    fn handle_prepare_write(
        &mut self,
        handle: u16,
        offset: u16,
        value: Data,
    ) -> Result<AclPacket, AttributeServerError> {
        let mut data = Data::new_att_prepare_write_response(handle, offset);
        let mut err = Err(AttErrorCode::AttributeNotFound);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.writable() {
                    err = att.data.write(offset as usize, value.as_slice());
                }
                data.append(value.as_slice());
                break;
            }
        }

        let response = match err {
            Ok(()) => data,
            Err(e) => Data::new_att_error_response(ATT_PREPARE_WRITE_REQ_OPCODE, handle, e),
        };
        Ok(self.response(response))
    }

    fn handle_execute_write(&mut self, _flags: u8) -> Result<AclPacket, AttributeServerError> {
        // for now we don't do anything here
        Ok(self.response(Data::new_att_execute_write_response()))
    }

    fn handle_read_blob(&mut self, handle: u16, offset: u16, buf: &mut [u8]) -> Result<usize, AttributeServerError> {
        let mut err = Err(AttErrorCode::AttributeNotFound);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    err = att.data.read(offset as usize, &mut buf);
                }
                break;
            }
        }

        match err {
            Ok(l) => Ok(core::cmp::min(self.mtu, l)),
            Err(e) => Data::new_att_error_response(ATT_READ_BLOB_REQ_OPCODE, handle, e),
        };

        Ok(())
    }

    /*
    fn response(&mut self, handle: u16, data: Data) -> AclPacket {
        /**/
        let res = L2capPacket::encode(data);
        let res = AclPacket::new(
            handle,
            BoundaryFlag::FirstNonAutoFlushable,
            HostBroadcastFlag::NoBroadcast,
            res,
        );
        res
    }*/
    */

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
            _ => unimplemented!(), /*
                                   Att::ReadByGroupTypeReq { start, end, group_type } => Ok(Some(HciMessage::Data(
                                       self.handle_read_by_group_type_req(start, end, group_type)?,
                                   ))),

                                                              Att::ReadReq { handle } => Ok(Some(HciMessage::Data(self.handle_read_req(handle)?))),

                                                              Att::WriteCmd { handle, data } => {
                                                                  self.handle_write_cmd(handle, data)?;
                                                                  Ok(None)
                                                              }

                                                              Att::WriteReq { handle, data } => Ok(Some(HciMessage::Data(self.handle_write_req(handle, data)?))),

                                                              Att::ExchangeMtu { mtu } => Ok(Some(HciMessage::Data(self.handle_exchange_mtu(mtu)?))),

                                                              Att::FindByTypeValue {
                                                                  start_handle,
                                                                  end_handle,
                                                                  att_type,
                                                                  att_value,
                                                              } => Ok(Some(HciMessage::Data(
                                                                  self.handle_find_type_value(end_handle, att_type, att_value)?,
                                                              ))),

                                                              Att::FindInformation {
                                                                  start_handle,
                                                                  end_handle,
                                                              } => Ok(Some(HciMessage::Data(
                                                                  self.handle_find_information(start_handle, end_handle)?,
                                                              ))),

                                                              Att::PrepareWriteReq { handle, offset, value } => Ok(Some(HciMessage::Data(
                                                                  self.handle_prepare_write(handle, offset, value)?,
                                                              ))),

                                                              Att::ExecuteWriteReq { flags } => Ok(Some(HciMessage::Data(self.handle_execute_write(flags)?))),

                                                              Att::ReadBlobReq { handle, offset } => Ok(Some(HciMessage::Data(self.handle_read_blob(handle, offset)?))),
                                                          */
        }
    }
}
