#[cfg(not(feature = "crypto"))]
use core::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "crypto")]
use crate::sm::SecurityManager;
use crate::{
    acl::{AclPacket, BoundaryFlag, HostBroadcastFlag},
    att::{
        Att, AttDecodeError, AttErrorCode, Uuid, ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
        ATT_FIND_INFORMATION_REQ_OPCODE, ATT_PREPARE_WRITE_REQ_OPCODE, ATT_READ_BLOB_REQ_OPCODE,
        ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE, ATT_READ_BY_TYPE_REQUEST_OPCODE, ATT_READ_REQUEST_OPCODE,
        ATT_WRITE_REQUEST_OPCODE,
    },
    attribute::Attribute,
    command::{Command, LE_OGF, SET_ADVERTISING_DATA_OCF},
    driver::HciDriver,
    event::EventType,
    l2cap::{L2capDecodeError, L2capPacket},
    Addr, Ble, Data, Error,
};
use core::cell::RefCell;
use critical_section::Mutex;
use futures::future::Either;
use futures::pin_mut;

pub const PRIMARY_SERVICE_UUID16: Uuid = Uuid::Uuid16(0x2800);
pub const CHARACTERISTIC_UUID16: Uuid = Uuid::Uuid16(0x2803);
pub const GENERIC_ATTRIBUTE_UUID16: Uuid = Uuid::Uuid16(0x1801);

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
pub enum AttributeServerError<E> {
    L2capError(L2capDecodeError),
    AttError(AttDecodeError),
    SecurityManagerError,
    Connection(Error<E>),
}

impl<E> From<L2capDecodeError> for AttributeServerError<E> {
    fn from(err: L2capDecodeError) -> Self {
        AttributeServerError::L2capError(err)
    }
}

impl<E> From<AttDecodeError> for AttributeServerError<E> {
    fn from(err: AttDecodeError) -> Self {
        AttributeServerError::AttError(err)
    }
}

impl<E> From<crate::Error<E>> for AttributeServerError<E> {
    fn from(err: crate::Error<E>) -> Self {
        AttributeServerError::Connection(err)
    }
}

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

pub struct AttributeServer<'a, T, R: CryptoRng + RngCore>
where
    T: HciDriver,
{
    pub(crate) ble: &'a mut Ble<T>,
    pub(crate) src_handle: u16,
    pub(crate) mtu: u16,
    pub(crate) attributes: &'a mut [Attribute<'a>],

    #[cfg(feature = "crypto")]
    pub(crate) security_manager: AsyncSecurityManager<'a, Ble<T>, R>,

    #[cfg(feature = "crypto")]
    pub(crate) pin_callback: Option<&'a mut dyn FnMut(u32)>,

    #[cfg(not(feature = "crypto"))]
    phantom: PhantomData<R>,
}

impl<'a, T, R: CryptoRng + RngCore> AttributeServer<'a, T, R>
where
    T: HciDriver,
{
    /// Create a new instance of the AttributeServer
    ///
    /// When _NOT_ using the `crypto` feature you can pass a mutual reference to `bleps::no_rng::NoRng`
    pub fn new(ble: &'a mut Ble<T>, attributes: &'a mut [Attribute<'a>], rng: &'a mut R) -> AttributeServer<'a, T, R> {
        AttributeServer::new_with_ltk(ble, attributes, Addr::from_le_bytes(false, [0u8; 6]), None, rng)
    }

    /// Create a new instance, optionally provide an LTK
    pub fn new_with_ltk(
        ble: &'a mut Ble<T>,
        attributes: &'a mut [Attribute<'a>],
        _local_addr: Addr,
        _ltk: Option<u128>,
        _rng: &'a mut R,
    ) -> AttributeServer<'a, T, R> {
        for (i, attr) in attributes.iter_mut().enumerate() {
            attr.handle = i as u16 + 1;
        }

        let mut last_in_group = attributes.last().unwrap().handle;
        for i in (0..attributes.len()).rev() {
            attributes[i].last_handle_in_group = last_in_group;

            if attributes[i].uuid == Uuid::Uuid16(0x2800) && i > 0 {
                last_in_group = attributes[i - 1].handle;
            }
        }

        trace!("{:#x?}", &attributes);

        #[cfg(feature = "crypto")]
        let mut security_manager = AsyncSecurityManager::new(_rng);
        #[cfg(feature = "crypto")]
        {
            security_manager.local_address = Some(_local_addr);
            security_manager.ltk = _ltk;
        }

        AttributeServer {
            ble,
            src_handle: 0,
            mtu: crate::attribute_server::BASE_MTU,
            attributes,

            #[cfg(feature = "crypto")]
            security_manager,

            #[cfg(feature = "crypto")]
            pin_callback: None,

            #[cfg(not(feature = "crypto"))]
            phantom: PhantomData::default(),
        }
    }

    /// Get the current LTK
    pub fn get_ltk(&self) -> Option<u128> {
        #[cfg(feature = "crypto")]
        return self.security_manager.ltk;

        #[cfg(not(feature = "crypto"))]
        None
    }

    pub fn get_characteristic_value(&mut self, handle: u16, offset: u16, buffer: &mut [u8]) -> Option<usize> {
        let att = &mut self.attributes[handle as usize];

        if att.data.readable() {
            att.data.read(offset as usize, buffer).ok()
        } else {
            None
        }
    }

    pub async fn update_le_advertising_data(&mut self, data: Data) -> Result<EventType, Error<T::Error>> {
        self.ble
            .write_bytes(Command::LeSetAdvertisingData { data }.encode().as_slice())
            .await?;
        self.ble
            .wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)
            .await?
            .check_command_completed()
    }

    pub async fn disconnect(&mut self, reason: u8) -> Result<EventType, Error<T::Error>> {
        self.ble
            .write_bytes(
                Command::Disconnect {
                    connection_handle: 0,
                    reason,
                }
                .encode()
                .as_slice(),
            )
            .await?;
        Ok(EventType::Unknown)
    }

    pub async fn do_work(&mut self) -> Result<WorkResult, AttributeServerError<T::Error>> {
        self.do_work_with_notification(None).await
    }

    pub async fn do_work_with_notification(
        &mut self,
        notification_data: Option<NotificationData>,
    ) -> Result<WorkResult, AttributeServerError<T::Error>> {
        if let Some(notification_data) = notification_data {
            let mut answer = notification_data.data;
            answer.limit_len(self.mtu as usize - 3);
            let mut data = Data::new_att_value_ntf(notification_data.handle);
            data.append(&answer.as_slice());
            self.write_att(self.src_handle, data).await?;
        }

        let packet = self.ble.poll().await?;

        if packet.is_some() {
            trace!("polled: {:?}", packet);
        }

        match packet {
            None => Ok(WorkResult::DidWork),
            Some(packet) => match packet {
                crate::PollResult::Event(EventType::DisconnectComplete {
                    handle: _,
                    status: _,
                    reason: _,
                }) => {
                    // Reset the MTU; the next connection will need to renegotiate it.
                    self.mtu = BASE_MTU;
                    Ok(WorkResult::GotDisconnected)
                }
                crate::PollResult::Event(EventType::ConnectionComplete {
                    status: _status,
                    handle: _,
                    role: _,
                    peer_address: _peer_address,
                    interval: _,
                    latency: _,
                    timeout: _,
                }) => {
                    #[cfg(feature = "crypto")]
                    if _status == 0 {
                        self.security_manager.peer_address = Some(_peer_address);
                    }
                    Ok(WorkResult::DidWork)
                }
                crate::PollResult::Event(EventType::LongTermKeyRequest {
                    handle: _handle,
                    random: _,
                    diversifier: _,
                }) => {
                    #[cfg(feature = "crypto")]
                    {
                        if let Some(ltk) = self.security_manager.ltk {
                            self.ble.cmd_long_term_key_request_reply(_handle, ltk).await.unwrap();
                        } else {
                            // TODO handle this via long term key request negative reply
                        }
                    }
                    Ok(WorkResult::DidWork)
                }
                crate::PollResult::Event(_) => Ok(WorkResult::DidWork),
                crate::PollResult::AsyncData(packet) => {
                    let (src_handle, l2cap_packet) = L2capPacket::decode(packet)?;
                    if l2cap_packet.channel == 6 {
                        // handle SM
                        #[cfg(feature = "crypto")]
                        self.security_manager
                            .handle(self.ble, src_handle, l2cap_packet.payload, &mut self.pin_callback)
                            .await?;
                        Ok(WorkResult::DidWork)
                    } else {
                        let packet = Att::decode(l2cap_packet)?;
                        trace!("att: {:x?}", packet);
                        match packet {
                            Att::ReadByGroupTypeReq { start, end, group_type } => {
                                self.handle_read_by_group_type_req(src_handle, start, end, group_type)
                                    .await?;
                            }

                            Att::ReadByTypeReq {
                                start,
                                end,
                                attribute_type,
                            } => {
                                self.handle_read_by_type_req(src_handle, start, end, attribute_type)
                                    .await?;
                            }

                            Att::ReadReq { handle } => {
                                self.handle_read_req(src_handle, handle).await?;
                            }

                            Att::WriteCmd { handle, data } => {
                                self.src_handle = src_handle;
                                self.handle_write_cmd(src_handle, handle, data).await?;
                            }

                            Att::WriteReq { handle, data } => {
                                self.src_handle = src_handle;
                                self.handle_write_req(src_handle, handle, data).await?;
                            }

                            Att::ExchangeMtu { mtu } => {
                                self.handle_exchange_mtu(src_handle, mtu).await?;
                            }

                            Att::FindByTypeValue {
                                start_handle,
                                end_handle,
                                att_type,
                                att_value,
                            } => {
                                self.handle_find_type_value(src_handle, start_handle, end_handle, att_type, att_value)
                                    .await?;
                            }

                            Att::FindInformation {
                                start_handle,
                                end_handle,
                            } => {
                                self.handle_find_information(src_handle, start_handle, end_handle)
                                    .await?;
                            }

                            Att::PrepareWriteReq { handle, offset, value } => {
                                self.handle_prepare_write(src_handle, handle, offset, value).await?;
                            }

                            Att::ExecuteWriteReq { flags } => {
                                self.handle_execute_write(src_handle, flags).await?;
                            }

                            Att::ReadBlobReq { handle, offset } => {
                                self.handle_read_blob(src_handle, handle, offset).await?;
                            }
                        }

                        Ok(WorkResult::DidWork)
                    }
                }
            },
        }
    }

    async fn handle_read_by_group_type_req(
        &mut self,
        src_handle: u16,
        start: u16,
        end: u16,
        group_type: Uuid,
    ) -> Result<(), Error<T::Error>> {
        // TODO respond with all finds - not just one
        let mut handle = start;
        let mut data = Data::new_att_read_by_group_type_response();
        let mut val = Err(AttErrorCode::AttributeNotFound);
        for att in self.attributes.iter_mut() {
            trace!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.uuid == group_type && att.handle >= start && att.handle <= end {
                debug!("found! {:x?}", att.handle);
                handle = att.handle;
                val = att.value();
                if let Ok(val) = val {
                    data.append_att_read_by_group_type_response(att.handle, att.last_handle_in_group, &Uuid::from(val));
                }
                break;
            }
        }

        let response = match val {
            Ok(_) => data,
            Err(e) => Data::new_att_error_response(ATT_READ_BY_GROUP_TYPE_REQUEST_OPCODE, handle, e),
        };
        self.write_att(src_handle, response).await?;
        Ok(())
    }

    async fn handle_read_by_type_req(
        &mut self,
        src_handle: u16,
        start: u16,
        end: u16,
        attribute_type: Uuid,
    ) -> Result<(), Error<T::Error>> {
        // TODO respond with all finds - not just one
        let mut handle = start;
        let mut data = Data::new_att_read_by_type_response();
        let mut err = Err(AttErrorCode::AttributeNotFound);
        for att in self.attributes.iter_mut() {
            trace!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.uuid == attribute_type && att.handle >= start && att.handle <= end {
                data.append_value(att.handle);
                handle = att.handle;

                if att.data.readable() {
                    err = att.data.read(0, data.as_slice_mut());
                    if let Ok(len) = err {
                        data.append_len(len);
                        data.append_att_read_by_type_response();
                    }
                }

                debug!("found! {:x?} {}", att.uuid, att.handle);
                break;
            }
        }

        let response = match err {
            Ok(_) => data,
            Err(e) => Data::new_att_error_response(ATT_READ_BY_TYPE_REQUEST_OPCODE, handle, e),
        };
        self.write_att(src_handle, response).await?;
        Ok(())
    }

    async fn handle_read_req(&mut self, src_handle: u16, handle: u16) -> Result<(), Error<T::Error>> {
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

        self.write_att(src_handle, response).await?;
        Ok(())
    }

    async fn handle_write_cmd(&mut self, _src_handle: u16, handle: u16, data: Data) -> Result<(), Error<T::Error>> {
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

    async fn handle_write_req(&mut self, src_handle: u16, handle: u16, data: Data) -> Result<(), Error<T::Error>> {
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
        self.write_att(src_handle, response).await?;
        Ok(())
    }

    async fn handle_exchange_mtu(&mut self, src_handle: u16, mtu: u16) -> Result<(), Error<T::Error>> {
        self.mtu = mtu.min(MTU);
        debug!("Requested MTU {mtu}, returning {}", self.mtu);
        self.write_att(src_handle, Data::new_att_exchange_mtu_response(self.mtu))
            .await?;
        Ok(())
    }

    async fn handle_find_type_value(
        &mut self,
        src_handle: u16,
        start: u16,
        _end: u16,
        _attr_type: u16,
        _attr_value: u16,
    ) -> Result<(), Error<T::Error>> {
        // TODO for now just return an error

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(
                ATT_FIND_BY_TYPE_VALUE_REQUEST_OPCODE,
                start,
                AttErrorCode::AttributeNotFound,
            ),
        )
        .await?;
        Ok(())
    }

    async fn handle_find_information(&mut self, src_handle: u16, start: u16, end: u16) -> Result<(), Error<T::Error>> {
        let mut data = Data::new_att_find_information_response();

        for att in self.attributes.iter_mut() {
            trace!("Check attribute {:x?} {}", att.uuid, att.handle);
            if att.handle >= start && att.handle <= end {
                if !data.append_att_find_information_response(att.handle, &att.uuid) {
                    break;
                }
                debug!("found! {:x?} {}", att.uuid, att.handle);
            }
        }

        if data.has_att_find_information_response_data() {
            self.write_att(src_handle, data).await?;
            return Ok(());
        }

        debug!("not found");

        // respond with error
        self.write_att(
            src_handle,
            Data::new_att_error_response(ATT_FIND_INFORMATION_REQ_OPCODE, start, AttErrorCode::AttributeNotFound),
        )
        .await?;
        Ok(())
    }

    async fn handle_prepare_write(
        &mut self,
        src_handle: u16,
        handle: u16,
        offset: u16,
        value: Data,
    ) -> Result<(), Error<T::Error>> {
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

        self.write_att(src_handle, response).await?;
        Ok(())
    }

    async fn handle_execute_write(&mut self, src_handle: u16, _flags: u8) -> Result<(), Error<T::Error>> {
        // for now we don't do anything here
        self.write_att(src_handle, Data::new_att_execute_write_response())
            .await?;
        Ok(())
    }

    async fn handle_read_blob(&mut self, src_handle: u16, handle: u16, offset: u16) -> Result<(), Error<T::Error>> {
        let mut data = Data::new_att_read_blob_response();
        let mut err = Err(AttErrorCode::AttributeNotFound);

        for att in self.attributes.iter_mut() {
            if att.handle == handle {
                if att.data.readable() {
                    err = att.data.read(offset as usize, data.as_slice_mut());
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
            Err(e) => Data::new_att_error_response(ATT_READ_BLOB_REQ_OPCODE, handle, e),
        };

        self.write_att(src_handle, response).await?;
        Ok(())
    }

    async fn write_att(&mut self, handle: u16, data: Data) -> Result<(), Error<T::Error>> {
        debug!("src_handle {}", handle);
        debug!("data {:x?}", data.as_slice());

        let res = L2capPacket::encode(data);
        trace!("encoded_l2cap {:x?}", res.as_slice());

        let res = AclPacket::encode(
            handle,
            BoundaryFlag::FirstAutoFlushable,
            HostBroadcastFlag::NoBroadcast,
            res,
        );
        trace!("writing {:x?}", res.as_slice());
        self.ble.write_bytes(res.as_slice()).await?;
        Ok(())
    }

    /// Run the GATT server until disconnect
    pub async fn run<F, N>(&mut self, notifier: &'a mut F) -> Result<(), AttributeServerError<T::Error>>
    where
        F: FnMut() -> N,
        N: core::future::Future<Output = NotificationData>,
    {
        let notification_to_send = Mutex::new(RefCell::new(None));
        loop {
            let notifier_future = async { notifier().await };
            let worker_future = async {
                let notification: Option<NotificationData> =
                    critical_section::with(|cs| notification_to_send.borrow_ref_mut(cs).take());

                // check if notifications are enabled for the characteristic handle
                let notification = if let Some(notification) = notification {
                    let attr = self
                        .attributes
                        .iter()
                        .enumerate()
                        .find(|(_idx, attr)| attr.handle == notification.handle);
                    let enabled = if let Some((idx, _)) = attr {
                        // assume the next descriptor is the "Client Characteristic Configuration" Descriptor
                        // which is always true when using the macro
                        if self.attributes.len() > idx + 1 && self.attributes[idx + 1].uuid == Uuid::Uuid16(0x2902) {
                            let mut cccd = [0u8; 1];
                            let cccd_len = self.get_characteristic_value((idx + 1) as u16, 0, &mut cccd[..]);
                            if let Some(1) = cccd_len {
                                cccd[0] == 1
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if enabled {
                        Some(notification)
                    } else {
                        None
                    }
                } else {
                    None
                };

                self.do_work_with_notification(notification).await
            };
            pin_mut!(notifier_future);
            pin_mut!(worker_future);

            let notification = match futures::future::select(notifier_future, worker_future).await {
                Either::Left((notification, _)) => Some(notification),
                Either::Right((value, _)) => {
                    if value? == WorkResult::GotDisconnected {
                        break;
                    }
                    None
                }
            };

            if let Some(notification) = notification {
                critical_section::with(|cs| {
                    notification_to_send.borrow_ref_mut(cs).replace(notification);
                });
            }
        }

        Ok(())
    }
}
