use bt_hci::controller::Controller;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::{DynamicReceiver, DynamicSender};
use heapless::Vec;

use crate::att::{self, AttReq, AttRsp, ATT_HANDLE_VALUE_NTF};
use crate::attribute::server::AttributeServer;
use crate::attribute::{Characteristic, Uuid, CHARACTERISTIC_UUID16, PRIMARY_SERVICE_UUID16};
use crate::connection::Connection;
use crate::connection_manager::DynamicConnectionManager;
use crate::cursor::{ReadCursor, WriteCursor};
use crate::host::BleHost;
use crate::pdu::Pdu;
use crate::types::l2cap::L2capHeader;
use crate::{BleHostError, Error};

pub struct GattServer<'reference, 'values, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize> {
    pub(crate) server: AttributeServer<'reference, 'values, M, MAX>,
    pub(crate) tx: DynamicSender<'reference, (ConnHandle, Pdu)>,
    pub(crate) rx: DynamicReceiver<'reference, (ConnHandle, Pdu)>,
    pub(crate) connections: &'reference dyn DynamicConnectionManager,
}

impl<'reference, 'values, M: RawMutex, const MAX: usize, const L2CAP_MTU: usize>
    GattServer<'reference, 'values, M, MAX, L2CAP_MTU>
{
    /// Process GATT requests and update the attribute table accordingly.
    ///
    /// If attributes are written or read, an event will be returned describing the handle
    /// and the connection causing the event.
    pub async fn next(&self) -> Result<GattEvent<'reference>, Error> {
        loop {
            let (handle, pdu) = self.rx.receive().await;
            if let Some(connection) = self.connections.get_connected_handle(handle) {
                match AttReq::decode(pdu.as_ref()) {
                    Ok(att) => {
                        let mut tx = [0; L2CAP_MTU];
                        let mut w = WriteCursor::new(&mut tx);
                        let (mut header, mut data) = w.split(4)?;

                        match self.server.process(handle, &att, data.write_buf()) {
                            Ok(Some(written)) => {
                                let mtu = self.connections.get_att_mtu(handle);
                                data.commit(written)?;
                                data.truncate(mtu as usize);
                                header.write(written as u16)?;
                                header.write(4_u16)?;
                                let len = header.len() + data.len();

                                let event = match att {
                                    AttReq::Write { handle, data } => Some(GattEvent::Write {
                                        connection,
                                        handle: self.server.table.find_characteristic_by_value_handle(handle)?,
                                    }),

                                    AttReq::Read { handle } => Some(GattEvent::Read {
                                        connection,
                                        handle: self.server.table.find_characteristic_by_value_handle(handle)?,
                                    }),

                                    AttReq::ReadBlob { handle, offset } => Some(GattEvent::Read {
                                        connection,
                                        handle: self.server.table.find_characteristic_by_value_handle(handle)?,
                                    }),
                                    _ => None,
                                };

                                let mut packet = pdu.packet;
                                packet.as_mut()[..len].copy_from_slice(&tx[..len]);
                                self.tx.send((handle, Pdu::new(packet, len))).await;
                                if let Some(event) = event {
                                    return Ok(event);
                                }
                            }
                            Ok(None) => {
                                debug!("No response sent");
                            }
                            Err(e) => {
                                warn!("Error processing attribute: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Error decoding attribute request: {:?}", e);
                    }
                }
            }
        }
    }

    /// Write a value to a characteristic, and notify a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be notified.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub async fn notify<T: Controller>(
        &self,
        ble: &BleHost<'_, T>,
        handle: Characteristic,
        connection: &Connection<'_>,
        value: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let conn = connection.handle();
        self.server.table.set(handle, value)?;

        let cccd_handle = handle.cccd_handle.ok_or(Error::Other)?;

        if !self.server.should_notify(conn, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        let mut tx = [0; L2CAP_MTU];
        let mut w = WriteCursor::new(&mut tx[..]);
        let (mut header, mut data) = w.split(4)?;
        data.write(ATT_HANDLE_VALUE_NTF)?;
        data.write(handle.handle)?;
        data.append(value)?;

        header.write(data.len() as u16)?;
        header.write(4_u16)?;
        let total = header.len() + data.len();
        ble.acl(conn, 1).await?.send(&tx[..total]).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub enum GattEvent<'reference> {
    Read {
        connection: Connection<'reference>,
        handle: Characteristic,
    },
    Write {
        connection: Connection<'reference>,
        handle: Characteristic,
    },
}

pub struct GattClient<'reference, 'resources, T: Controller, const MAX: usize, const L2CAP_MTU: usize = 27> {
    pub(crate) services: Vec<ServiceHandle, MAX>,
    pub(crate) rx: DynamicReceiver<'reference, (ConnHandle, Pdu)>,
    pub(crate) ble: &'reference BleHost<'resources, T>,
    pub(crate) connection: Connection<'reference>,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Clone)]
pub struct ServiceHandle {
    start: u16,
    end: u16,
    uuid: Uuid,
}

impl<'reference, 'resources, T: Controller, const MAX: usize, const L2CAP_MTU: usize>
    GattClient<'reference, 'resources, T, MAX, L2CAP_MTU>
{
    async fn request(&mut self, req: AttReq<'_>) -> Result<Pdu, BleHostError<T::Error>> {
        let header = L2capHeader {
            channel: crate::types::l2cap::L2CAP_CID_ATT,
            length: req.size() as u16,
        };

        let mut buf = [0; L2CAP_MTU];
        let mut w = WriteCursor::new(&mut buf);
        w.write_hci(&header)?;
        w.write(req)?;

        let mut grant = self.ble.acl(self.connection.handle(), 1).await?;
        grant.send(w.finish()).await?;

        let (h, pdu) = self.rx.receive().await;
        assert_eq!(h, self.connection.handle());
        Ok(pdu)
    }

    /// Discover primary services associated with a UUID.
    pub async fn services_by_uuid(&mut self, uuid: &Uuid) -> Result<&[ServiceHandle], BleHostError<T::Error>> {
        let mut start: u16 = 0x0001;

        loop {
            let data = att::AttReq::FindByTypeValue {
                start_handle: start,
                end_handle: 0xffff,
                att_type: PRIMARY_SERVICE_UUID16.as_short(),
                att_value: uuid.as_raw(),
            };

            let pdu = self.request(data).await?;
            match AttRsp::decode(pdu.as_ref())? {
                AttRsp::Error { request, handle, code } => {
                    if code == att::AttErrorCode::AttributeNotFound {
                        break;
                    }
                    return Err(Error::Att(code).into());
                }
                AttRsp::FindByTypeValue { mut it } => {
                    let mut end: u16 = 0;
                    while let Some(res) = it.next() {
                        let (handle, e) = res?;
                        end = e;
                        self.services
                            .push(ServiceHandle {
                                start: handle,
                                end,
                                uuid: *uuid,
                            })
                            .unwrap();
                    }
                    if end == 0xFFFF {
                        break;
                    }
                    start = end + 1;
                }
                _ => {
                    return Err(Error::InvalidValue.into());
                }
            }
        }

        Ok(&self.services[..])
    }

    /// Discover characteristics in a given service using a UUID.
    pub async fn characteristic_by_uuid(
        &mut self,
        service: &ServiceHandle,
        uuid: &Uuid,
    ) -> Result<Characteristic, BleHostError<T::Error>> {
        let mut start: u16 = service.start;
        loop {
            let data = att::AttReq::ReadByType {
                start,
                end: service.end,
                attribute_type: CHARACTERISTIC_UUID16,
            };
            let pdu = self.request(data).await?;

            match AttRsp::decode(pdu.as_ref())? {
                AttRsp::ReadByType { mut it } => {
                    while let Some(Ok((handle, item))) = it.next() {
                        if item.len() < 5 {
                            return Err(Error::InvalidValue.into());
                        }
                        let mut r = ReadCursor::new(item);
                        let _props: u8 = r.read()?;
                        let value_handle: u16 = r.read()?;
                        let value_uuid: Uuid = Uuid::from_slice(r.remaining());

                        if uuid == &value_uuid {
                            return Ok(Characteristic {
                                handle: value_handle,
                                cccd_handle: None,
                            });
                        }

                        if handle == 0xFFFF {
                            return Err(Error::NotFound.into());
                        }
                        start = handle + 1;
                    }
                }
                AttRsp::Error { request, handle, code } => return Err(Error::Att(code).into()),
                _ => {
                    return Err(Error::InvalidValue.into());
                }
            }
        }
    }

    /// Read a characteristic described by a handle.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic(
        &mut self,
        characteristic: &Characteristic,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<T::Error>> {
        let data = att::AttReq::Read {
            handle: characteristic.handle,
        };

        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::Read { data } => {
                let to_copy = data.len().min(dest.len());
                dest[..to_copy].copy_from_slice(&data[..to_copy]);
                Ok(to_copy)
            }
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Read a characteristic described by a UUID.
    ///
    /// The number of bytes copied into the provided buffer is returned.
    pub async fn read_characteristic_by_uuid(
        &mut self,
        service: &ServiceHandle,
        uuid: &Uuid,
        dest: &mut [u8],
    ) -> Result<usize, BleHostError<T::Error>> {
        let data = att::AttReq::ReadByType {
            start: service.start,
            end: service.end,
            attribute_type: *uuid,
        };

        let pdu = self.request(data).await?;

        match AttRsp::decode(pdu.as_ref())? {
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
            _ => Err(Error::InvalidValue.into()),
        }
    }

    /// Write to a characteristic described by a handle.
    pub async fn write_characteristic(
        &mut self,
        handle: &Characteristic,
        buf: &[u8],
    ) -> Result<(), BleHostError<T::Error>> {
        let data = att::AttReq::Write {
            handle: handle.handle,
            data: buf,
        };

        let pdu = self.request(data).await?;
        match AttRsp::decode(pdu.as_ref())? {
            AttRsp::Write => Ok(()),
            AttRsp::Error { request, handle, code } => Err(Error::Att(code).into()),
            _ => Err(Error::InvalidValue.into()),
        }
    }
}
