use super::{AttributeServer, AttributeTable, PeerState};
use crate::att::{Att, AttServer};
use crate::cursor::WriteCursor;
use crate::pdu::Pdu;
use crate::prelude::{Connection, ConnectionEvent};
use crate::{Error, PacketPool};
use embassy_futures::select::{Either, select};

/// Used to manage a GATT connection with a client.
pub struct GattConnection<'stack, 'server, P: PacketPool, T: AttributeTable, C: PeerState> {
    connection: Connection<'stack, P>,
    peer: &'server C,
    server: &'server AttributeServer<T>,
}

impl<P: PacketPool, T: AttributeTable, C: PeerState> Drop for GattConnection<'_, '_, P, T, C> {
    fn drop(&mut self) {
        trace!("[gatt {}] disconnecting from server", self.connection.handle().raw());
        let _ = self.peer.disconnect(&self.connection.peer_identity());
    }
}

impl<'stack, 'server, P: PacketPool, T: AttributeTable, C: PeerState> GattConnection<'stack, 'server, P, T, C> {
    /// Creates a GATT connection from the given BLE connection and `AttributeServer`:
    /// this will register the client within the server's CCCD table.
    pub(crate) fn try_new(
        connection: Connection<'stack, P>,
        server: &'server AttributeServer<T>,
        peer: &'server C,
    ) -> Result<Self, Error> {
        trace!("[gatt {}] connecting to server", connection.handle().raw());
        peer.connect(&connection.peer_identity())?;
        Ok(Self {
            connection,
            server,
            peer,
        })
    }

    pub(crate) fn peer(&self) -> &C {
        &self.peer
    }

    /// Confirm that the displayed pass key matches the one displayed on the other party
    pub fn pass_key_confirm(&self) -> Result<(), Error> {
        self.connection.pass_key_confirm()
    }

    /// The displayed pass key does not match the one displayed on the other party
    pub fn pass_key_cancel(&self) -> Result<(), Error> {
        self.connection.pass_key_cancel()
    }

    /// Input the pairing pass key
    pub fn pass_key_input(&self, pass_key: u32) -> Result<(), Error> {
        self.connection.pass_key_input(pass_key)
    }

    /// Wait for the next GATT connection event.
    ///
    /// Uses the attribute server to handle the protocol.
    pub async fn next(&self) -> Result<ConnectionEvent, Error> {
        loop {
            match select(self.connection.next(), self.connection.next_gatt()).await {
                Either::First(event) => return Ok(event),
                Either::Second(pdu) => {
                    // - The PDU is decodable, as it was already decoded once before adding it to the connection queue
                    // - The PDU is of type `Att::Client` because only those types of PDUs are added to the connection queue
                    let att = unwrap!(Att::decode(pdu.as_ref()));
                    let Att::Client(att) = att else {
                        unreachable!("Expected Att::Client, got {:?}", att)
                    };
                    let mut tx = P::allocate().ok_or(Error::OutOfMemory)?;
                    let mut w = WriteCursor::new(tx.as_mut());
                    let (mut header, mut data) = w.split(4)?;
                    if let Some(written) = self.server.process(&self.connection, &att, data.write_buf()).await? {
                        let mtu = self.connection.get_att_mtu();
                        data.commit(written)?;
                        data.truncate(mtu as usize);
                        header.write(data.len() as u16)?;
                        header.write(4_u16)?;
                        let len = header.len() + data.len();
                        let pdu = Pdu::new(tx, len);
                        self.connection.send(pdu).await;
                    }
                }
            }
        }
    }

    /// Get a reference to the underlying BLE connection.
    pub fn raw(&self) -> &Connection<'stack, P> {
        &self.connection
    }
}

pub(crate) fn assemble<'stack, P: PacketPool>(
    conn: &Connection<'stack, P>,
    att: AttServer<'_>,
) -> Result<Pdu<P::Packet>, Error> {
    let mut tx = P::allocate().ok_or(Error::OutOfMemory)?;
    let mut w = WriteCursor::new(tx.as_mut());
    let (mut header, mut data) = w.split(4)?;
    data.write(Att::Server(att))?;

    let mtu = conn.get_att_mtu();
    data.truncate(mtu as usize);
    header.write(data.len() as u16)?;
    header.write(4_u16)?;
    let len = header.len() + data.len();
    Ok(Pdu::new(tx, len))
}
