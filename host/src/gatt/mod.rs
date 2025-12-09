//! GATT logic
#![allow(async_fn_in_trait)]
use crate::att::AttErrorCode;
use crate::types::uuid::Uuid;
use crate::{Error, Identity};

//pub mod cccd;
//pub mod client;
mod connection;
mod server;

pub use connection::*;
pub use server::*;

/// Represents a table of attributes that is read or written
///
pub trait AttributeTable {
    /// Iterator type
    type Iterator: Iterator<Item = Self::Attribute>;
    /// Attribute type
    type Attribute: Attribute;

    /// Create an iterator over the attributes in the table
    fn iter(&self) -> Self::Iterator;
}

/// Represents an attribute value
pub trait Attribute {
    /// Error returned when reading or writing attributes;
    type Error: Into<AttErrorCode>;

    /// Handle of this attribute.
    fn handle(&self) -> u16;
    /// UUID of this attribute.
    fn uuid(&self) -> Uuid;
    /// End of group handle.
    fn last(&self) -> u16;
    /// Kind of attribute.
    fn kind(&self) -> AttributeKind;

    /// Read the value of this attribute from the offset.
    ///
    /// Returns the number of bytes copied to the output buffer.
    async fn read(&self, offset: u16, output: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write the value of this attribute at the provided offset
    async fn write(&self, offset: u16, input: &[u8]) -> Result<(), Self::Error>;
}

/// Which kind of attribute data
pub enum AttributeKind {
    /// Service attribute.
    Service,
    /// Data attribute.
    Data,
    /// Attribute declaration.
    Declaration,
    /// Attribute properties.
    Cccd,
}

/// Represents the current state of a peers.
pub trait PeerState {
    /// Error returned when updating client state.
    type Error;

    /// Signal connection established to a peer.
    fn connect(&self, peer: &Identity) -> Result<(), Error>;

    /// Signal disconnection from peer.
    fn disconnect(&self, peer: &Identity) -> Result<(), Error>;

    /// Signal that peer has subscribed/unsubscribed for notifications for attribute handle.
    fn set_notify(&self, peer: &Identity, handle: u16, enable: bool);

    /// Signal that peer has subscribed/unsubscribed for indications for attribute handle.
    fn set_indicate(&self, peer: &Identity, handle: u16, enable: bool);

    /// Query whether or not a peer is subscribed to notifications for a handle
    fn should_notify(&self, peer: &Identity, handle: u16) -> bool;

    /// Query whether or not a peer is subscribed to indications for a handle
    fn should_indicate(&self, peer: &Identity, handle: u16) -> bool;
}
