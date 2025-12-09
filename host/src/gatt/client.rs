/// Notification listener for GATT client.
pub struct NotificationListener<'lst, const MTU: usize> {
    handle: u16,
    listener: pubsub::DynSubscriber<'lst, Notification<MTU>>,
}

impl<'lst, const MTU: usize> NotificationListener<'lst, MTU> {
    #[allow(clippy::should_implement_trait)]
    /// Get the next (len: u16, Packet) tuple from the rx queue
    pub async fn next(&mut self) -> Notification<MTU> {
        loop {
            if let WaitResult::Message(m) = self.listener.next_message().await {
                if m.handle == self.handle {
                    return m;
                }
            }
        }
    }
}

const MAX_NOTIF: usize = config::GATT_CLIENT_NOTIFICATION_MAX_SUBSCRIBERS;
const NOTIF_QSIZE: usize = config::GATT_CLIENT_NOTIFICATION_QUEUE_SIZE;

/// A GATT client capable of using the GATT protocol.
pub struct GattClient<'reference, T: Controller, P: PacketPool, const MAX_SERVICES: usize> {
    known_services: RefCell<Vec<ServiceHandle, MAX_SERVICES>>,
    stack: &'reference Stack<'reference, T, P>,
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
}

impl<const MTU: usize> AsRef<[u8]> for Notification<MTU> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Handle for a GATT service.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Clone)]
pub struct ServiceHandle {
    start: u16,
    end: u16,
    uuid: Uuid,
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

        let (h, pdu) = self.response_channel.receive().await;

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
        stack: &'reference Stack<'reference, C, P>,
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
        Ok(Self {
            known_services: RefCell::new(heapless::Vec::new()),
            stack,
            connection: connection.clone(),

            response_channel: Channel::new(),

            notifications: PubSubChannel::new(),
        })
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
                            uuid: uuid.clone(),
                        };
                        result.push(svc.clone()).map_err(|_| Error::InsufficientSpace)?;
                        self.known_services
                            .borrow_mut()
                            .push(svc)
                            .map_err(|_| Error::InsufficientSpace)?;
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

    /// Discover characteristics in a given service using a UUID.
    pub async fn characteristic_by_uuid<T: AsGatt>(
        &self,
        service: &ServiceHandle,
        uuid: &Uuid,
    ) -> Result<Characteristic<T>, BleHostError<C::Error>> {
        let mut start: u16 = service.start;
        let mut found_indicate_or_notify_uuid = Option::None;

        loop {
            let data = att::AttReq::ReadByType {
                start,
                end: service.end,
                attribute_type: CHARACTERISTIC.into(),
            };
            let response = self.request(data).await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::ReadByType { mut it } => {
                    while let Some(Ok((handle, item))) = it.next() {
                        let expected_items_len = 5;
                        let item_len = item.len();

                        if item_len < expected_items_len {
                            return Err(Error::MalformedCharacteristicDeclaration {
                                expected: expected_items_len,
                                actual: item_len,
                            }
                            .into());
                        }
                        if let AttributeData::Declaration {
                            props,
                            handle,
                            uuid: decl_uuid,
                        } = AttributeData::decode_declaration(item)?
                        {
                            if let Some(start_handle) = found_indicate_or_notify_uuid {
                                return Ok(Characteristic {
                                    handle: start_handle,
                                    cccd_handle: Some(self.get_characteristic_cccd(start_handle, handle).await?),
                                    phantom: PhantomData,
                                });
                            }

                            if *uuid == decl_uuid {
                                // If there are "notify" and "indicate" characteristic properties we need to find the
                                // next characteristic so we can determine the search space for the CCCD
                                if !props.any(&[CharacteristicProp::Indicate, CharacteristicProp::Notify]) {
                                    return Ok(Characteristic {
                                        handle,
                                        cccd_handle: None,
                                        phantom: PhantomData,
                                    });
                                }
                                found_indicate_or_notify_uuid = Some(handle);
                            }

                            if handle == 0xFFFF {
                                return Err(Error::NotFound.into());
                            }
                            start = handle + 1;
                        } else {
                            return Err(Error::InvalidCharacteristicDeclarationData.into());
                        }
                    }
                }
                AttRsp::Error { request, handle, code } => match code {
                    att::AttErrorCode::ATTRIBUTE_NOT_FOUND => match found_indicate_or_notify_uuid {
                        Some(handle) => {
                            return Ok(Characteristic {
                                handle,
                                cccd_handle: Some(self.get_characteristic_cccd(handle, service.end).await?),
                                phantom: PhantomData,
                            });
                        }
                        None => return Err(Error::NotFound.into()),
                    },
                    _ => return Err(Error::Att(code).into()),
                },
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }
    }

    async fn get_characteristic_cccd(
        &self,
        char_start_handle: u16,
        char_end_handle: u16,
    ) -> Result<u16, BleHostError<C::Error>> {
        let mut start_handle = char_start_handle;

        while start_handle <= char_end_handle {
            let data = att::AttReq::FindInformation {
                start_handle,
                end_handle: char_end_handle,
            };

            let response = self.request(data).await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::FindInformation { mut it } => {
                    while let Some(Ok((handle, uuid))) = it.next() {
                        if uuid == CLIENT_CHARACTERISTIC_CONFIGURATION.into() {
                            return Ok(handle);
                        }
                        start_handle = handle + 1;
                    }
                }
                AttRsp::Error { request, handle, code } => return Err(Error::Att(code).into()),
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }
        Err(Error::NotFound.into())
    }

    /// Read a characteristic described by a handle.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic<T: AsGatt>(
        &self,
        characteristic: &Characteristic<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        let response = self
            .request(att::AttReq::Read {
                handle: characteristic.handle,
            })
            .await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Read { data } => {
                let to_copy = data.len().min(dest.len());
                dest[..to_copy].copy_from_slice(&data[..to_copy]);
                Ok(to_copy)
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Read a long characteristic value using blob reads if necessary.
    ///
    /// This method automatically handles characteristics longer than ATT MTU
    /// by using Read Blob requests to fetch the complete value.
    pub async fn read_characteristic_long<T: AsGatt>(
        &self,
        characteristic: &Characteristic<T>,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<C::Error>> {
        // first read, use regular read
        let first_read_len = self.read_characteristic(characteristic, dest).await?;
        let att_mtu = self.connection.att_mtu() as usize;

        if first_read_len != att_mtu - 1 {
            // att_mtu-1 indicates there's more to read
            return Ok(first_read_len);
        }

        // Try at least one blob read to see if there's more data
        let mut offset = first_read_len;
        loop {
            let response = self
                .request(att::AttReq::ReadBlob {
                    handle: characteristic.handle,
                    offset: offset as u16,
                })
                .await?;

            match Self::response(response.pdu.as_ref())? {
                AttRsp::ReadBlob { data } => {
                    debug!("[read_characteristic_long] Blob read returned {} bytes", data.len());
                    if data.is_empty() {
                        break; // End of attribute
                    }

                    let blob_read_len = data.len();

                    // need to limit length to copy b/c copy_from_slice panics if
                    // the slices' lengths don't match, and `dest` might be too small.
                    let len_to_copy = blob_read_len.min(dest.len() - offset);
                    dest[offset..offset + len_to_copy].copy_from_slice(&data[..len_to_copy]);
                    offset += len_to_copy;

                    // If we got less than MTU-1 bytes, we've read everything
                    // Or if we've filled the destination buffer
                    if blob_read_len < att_mtu - 1 || len_to_copy < blob_read_len {
                        break;
                    }
                }
                AttRsp::Error { code, .. } if code == att::AttErrorCode::INVALID_OFFSET => {
                    trace!("[read_characteristic_long] Got INVALID_OFFSET, no more data");
                    break; // Reached end
                }
                AttRsp::Error { code, .. } if code == att::AttErrorCode::ATTRIBUTE_NOT_LONG => {
                    trace!("[read_characteristic_long] read_handle_long] Attribute not long, no blob reads needed");
                    break; // Attribute fits in single read
                }
                AttRsp::Error { code, .. } => {
                    trace!("[read_characteristic] Got error: {:?}", code);
                    return Err(Error::Att(code).into());
                }
                _ => return Err(Error::UnexpectedGattResponse.into()),
            }
        }
        Ok(offset)
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
        let data = att::AttReq::ReadByType {
            start: service.start,
            end: service.end,
            attribute_type: uuid.clone(),
        };

        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::ReadByType { mut it } => {
                let mut to_copy = 0;
                if let Some(item) = it.next() {
                    let (_handle, data) = item?;
                    to_copy = data.len().min(dest.len());
                    dest[..to_copy].copy_from_slice(&data[..to_copy]);
                }
                Ok(to_copy)
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Write to a characteristic described by a handle.
    pub async fn write_characteristic<T: FromGatt>(
        &self,
        handle: &Characteristic<T>,
        buf: &[u8],
    ) -> Result<(), BleHostError<C::Error>> {
        let data = att::AttReq::Write {
            handle: handle.handle,
            data: buf,
        };

        let response = self.request(data).await?;
        match Self::response(response.pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Write without waiting for a response to a characteristic described by a handle.
    pub async fn write_characteristic_without_response<T: FromGatt>(
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

    /// Subscribe to indication/notification of a given Characteristic
    ///
    /// A listener is returned, which has a `next()` method
    pub async fn subscribe<T: AsGatt>(
        &self,
        characteristic: &Characteristic<T>,
        indication: bool,
    ) -> Result<NotificationListener<'_, 512>, BleHostError<C::Error>> {
        let properties = u16::to_le_bytes(if indication { 0x02 } else { 0x01 });

        let data = att::AttReq::Write {
            handle: characteristic.cccd_handle.ok_or(Error::NotSupported)?,
            data: &properties,
        };

        // set the CCCD
        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Write => match self.notifications.dyn_subscriber() {
                Ok(listener) => Ok(NotificationListener {
                    listener,
                    handle: characteristic.handle,
                }),
                Err(embassy_sync::pubsub::Error::MaximumSubscribersReached) => {
                    Err(Error::GattSubscriberLimitReached.into())
                }
                Err(_) => Err(Error::Other.into()),
            },
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Unsubscribe from a given Characteristic
    pub async fn unsubscribe<T: AsGatt>(
        &self,
        characteristic: &Characteristic<T>,
    ) -> Result<(), BleHostError<C::Error>> {
        let properties = u16::to_le_bytes(0);
        let data = att::AttReq::Write {
            handle: characteristic.cccd_handle.ok_or(Error::NotSupported)?,
            data: &[0, 0],
        };

        // set the CCCD
        let response = self.request(data).await?;

        match Self::response(response.pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::UnexpectedGattResponse.into()),
        }
    }

    /// Handle a notification that was received.
    async fn handle_notification_packet(&self, data: &[u8]) -> Result<(), BleHostError<C::Error>> {
        let mut r = ReadCursor::new(data);
        let value_handle: u16 = r.read()?;
        let value_attr = r.remaining();

        let handle = value_handle;

        // TODO
        let mut data = [0u8; 512];
        let to_copy = data.len().min(value_attr.len());
        data[..to_copy].copy_from_slice(&value_attr[..to_copy]);
        let n = Notification {
            handle,
            data,
            len: to_copy,
        };
        self.notifications.immediate_publisher().publish_immediate(n);
        Ok(())
    }

    /// Task which handles GATT rx data (needed for notifications to work)
    pub async fn task(&self) -> Result<(), BleHostError<C::Error>> {
        loop {
            let handle = self.connection.handle();
            let pdu = self.connection.next_gatt_client().await;
            let data = pdu.as_ref();
            // handle notifications
            if pdu.as_ref()[0] == ATT_HANDLE_VALUE_NTF {
                self.handle_notification_packet(&pdu.as_ref()[1..]).await?;
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
