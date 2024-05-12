use core::fmt;

use bt_hci::controller::Controller;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::DynamicReceiver;

use crate::adapter::HciController;
use crate::att::{self, Att, ATT_HANDLE_VALUE_NTF_OPTCODE};
use crate::attribute::CharacteristicHandle;
use crate::attribute_server::AttributeServer;
use crate::connection::Connection;
use crate::connection_manager::DynamicConnectionManager;
use crate::cursor::WriteCursor;
use crate::packet_pool::{AllocId, DynamicPacketPool};
use crate::pdu::Pdu;
use crate::{StackError, Error};

pub struct GattServer<'reference, 'values, 'resources, M: RawMutex, T: Controller, const MAX: usize> {
    pub(crate) server: AttributeServer<'reference, 'values, M, MAX>,
    pub(crate) rx: DynamicReceiver<'reference, (ConnHandle, Pdu<'resources>)>,
    pub(crate) tx: HciController<'reference, T>,
    pub(crate) pool_id: AllocId,
    pub(crate) pool: &'resources dyn DynamicPacketPool<'resources>,
    pub(crate) connections: &'reference dyn DynamicConnectionManager,
}

impl<'reference, 'values, 'resources, M: RawMutex, T: Controller, const MAX: usize>
    GattServer<'reference, 'values, 'resources, M, T, MAX>
{
    pub async fn next(&self) -> Result<GattEvent<'reference, 'values>, StackError<T::Error>> {
        loop {
            let (handle, pdu) = self.rx.receive().await;
            match Att::decode(pdu.as_ref()) {
                Ok(att) => {
                    let Some(mut response) = self.pool.alloc(self.pool_id) else {
                        return Err(Error::OutOfMemory.into());
                    };
                    let mut w = WriteCursor::new(response.as_mut());
                    let (mut header, mut data) = w.split(4)?;

                    match att {
                        Att::ExchangeMtu { mtu } => {
                            let mtu = self.connections.exchange_att_mtu(handle, mtu);
                            data.write(att::ATT_EXCHANGE_MTU_RESPONSE_OPCODE)?;
                            data.write(mtu)?;

                            header.write(data.len() as u16)?;
                            header.write(4_u16)?;
                            let len = header.len() + data.len();
                            self.tx.send(handle, Pdu::new(response, len).as_ref()).await?;
                        }
                        _ => match self.server.process(handle, att, data.write_buf()) {
                            Ok(Some(written)) => {
                                let mtu = self.connections.get_att_mtu(handle);
                                data.commit(written)?;
                                data.truncate(mtu as usize);
                                header.write(written as u16)?;
                                header.write(4_u16)?;
                                let len = header.len() + data.len();
                                self.tx.send(handle, Pdu::new(response, len).as_ref()).await?;
                            }
                            Ok(None) => {
                                debug!("No response sent");
                            }
                            Err(e) => {
                                warn!("Error processing attribute: {:?}", e);
                            }
                        },
                    }
                }
                Err(e) => {
                    warn!("Error decoding attribute request: {:?}", e);
                }
            }
        }
    }

    /// Write a value to a characteristic, and notify a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be notified.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub async fn notify(
        &self,
        handle: CharacteristicHandle,
        connection: &Connection,
        value: &[u8],
    ) -> Result<(), StackError<T::Error>> {
        let conn = connection.handle();
        self.server.table.set(handle, value)?;

        let cccd_handle = handle.cccd_handle.ok_or(Error::Other)?;

        if !self.server.should_notify(conn, cccd_handle) {
            // No reason to fail?
            return Ok(());
        }

        let Some(mut packet) = self.pool.alloc(self.pool_id) else {
            return Err(Error::OutOfMemory.into());
        };
        let mut w = WriteCursor::new(packet.as_mut());
        let (mut header, mut data) = w.split(4)?;
        data.write(ATT_HANDLE_VALUE_NTF_OPTCODE)?;
        data.write(handle.handle)?;
        data.append(value)?;

        header.write(data.len() as u16)?;
        header.write(4_u16)?;
        let total = header.len() + data.len();
        self.tx.send(conn, Pdu::new(packet, total).as_ref()).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub enum GattEvent<'reference, 'values> {
    Write {
        connection: &'reference Connection,
        handle: CharacteristicHandle,
        value: &'values [u8],
    },
}

impl<'reference, 'values> fmt::Debug for GattEvent<'reference, 'values> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write {
                connection: _,
                handle: _,
                value: _,
            } => f.debug_struct("GattEvent::Write").finish(),
        }
    }
}

#[cfg(feature = "defmt")]
impl<'reference, 'values> defmt::Format for GattEvent<'reference, 'values> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{}", defmt::Debug2Format(self))
    }
}
