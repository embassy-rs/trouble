use core::fmt;

use bt_hci::controller::Controller;
use bt_hci::param::ConnHandle;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::channel::DynamicReceiver;

use crate::att::{Att, ATT_HANDLE_VALUE_NTF_OPTCODE};
use crate::attribute::CharacteristicHandle;
use crate::attribute_server::AttributeServer;
use crate::connection::Connection;
use crate::connection_manager::DynamicConnectionManager;
use crate::cursor::WriteCursor;
use crate::host::BleHost;
use crate::pdu::Pdu;
use crate::{BleHostError, Error};

pub struct GattServer<
    'reference,
    'values,
    'resources,
    M: RawMutex,
    T: Controller,
    const MAX: usize,
    const ATT_MTU: usize = 23,
> {
    pub(crate) server: AttributeServer<'reference, 'values, M, MAX>,
    pub(crate) rx: DynamicReceiver<'reference, (ConnHandle, Pdu)>,
    pub(crate) tx: &'reference BleHost<'resources, T>,
    pub(crate) connections: &'reference dyn DynamicConnectionManager,
}

impl<'reference, 'values, 'resources, M: RawMutex, T: Controller, const MAX: usize, const ATT_MTU: usize>
    GattServer<'reference, 'values, 'resources, M, T, MAX, ATT_MTU>
{
    pub async fn next(&self) -> Result<GattEvent<'reference, 'values>, BleHostError<T::Error>> {
        loop {
            let (handle, pdu) = self.rx.receive().await;
            match Att::decode(pdu.as_ref()) {
                Ok(att) => {
                    let mut tx = [0; ATT_MTU];
                    let mut w = WriteCursor::new(&mut tx);
                    let (mut header, mut data) = w.split(4)?;

                    match self.server.process(handle, att, data.write_buf()) {
                        Ok(Some(written)) => {
                            let mtu = self.connections.get_att_mtu(handle);
                            data.commit(written)?;
                            data.truncate(mtu as usize);
                            header.write(written as u16)?;
                            header.write(4_u16)?;
                            let len = header.len() + data.len();
                            self.tx.acl(handle, 1).await?.send(&tx[..len]).await?;
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

    /// Write a value to a characteristic, and notify a connection with the new value of the characteristic.
    ///
    /// If the provided connection has not subscribed for this characteristic, it will not be notified.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub async fn notify(
        &self,
        handle: CharacteristicHandle,
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

        let mut tx = [0; ATT_MTU];
        let mut w = WriteCursor::new(&mut tx[..]);
        let (mut header, mut data) = w.split(4)?;
        data.write(ATT_HANDLE_VALUE_NTF_OPTCODE)?;
        data.write(handle.handle)?;
        data.append(value)?;

        header.write(data.len() as u16)?;
        header.write(4_u16)?;
        let total = header.len() + data.len();
        self.tx.acl(conn, 1).await?.send(&tx[..total]).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub enum GattEvent<'reference, 'values> {
    Write {
        connection: &'reference Connection<'reference>,
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
